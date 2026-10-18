//! Classic in-memory manual mapping for Windows PE DLLs.
//!
//! Steps (mirroring the well-documented manual-map flow):
//!
//! 1. Parse the PE and validate architecture against the target process.
//! 2. Allocate `SizeOfImage` in the target and copy headers + sections.
//! 3. Apply base relocations for the remote base.
//! 4. Resolve imports: load missing dependency DLLs remotely and write the IAT
//!    by reading each dependency's export directory in the target.
//! 5. Apply per-section page protections.
//! 6. Optionally erase the PE headers (see [`crate::stealth`]).
//! 7. Call the entry point (`DllMain`) in a remote thread.
//!
//! The module is PE-level and platform-agnostic: every syscall goes through
//! the [`ProcessAccessLayer`] trait, so it compiles and is unit-testable on
//! Linux even though the Windows path is what runs in practice.

use crate::error::{InjectError, InjectResult};
use crate::pe::{resolve_export_at, ExportResolution, PeImage};
use engine_pal::types::{Address, CpuArchitecture, ProtectionFlags};
use engine_pal::ProcessAccessLayer;
use tracing::{debug, info};

/// Options controlling a manual-map injection.
#[derive(Debug, Clone)]
pub struct ManualMapOptions {
    /// Write the PE headers into the mapped image (usually `false` for stealth).
    pub include_headers: bool,
    /// Zero the headers after mapping so no `MZ`/`PE` signature remains.
    pub erase_headers: bool,
    /// Create a remote thread to run the entry point (`DllMain`).
    pub call_entry_point: bool,
    /// Reject the injection if image and target architectures differ.
    pub enforce_architecture: bool,
    /// Maximum time to wait for the entry-point thread.
    pub entry_timeout_ms: u64,
}

impl Default for ManualMapOptions {
    fn default() -> Self {
        ManualMapOptions {
            include_headers: false,
            erase_headers: true,
            call_entry_point: true,
            enforce_architecture: true,
            entry_timeout_ms: 15_000,
        }
    }
}

/// Outcome of a successful manual-map injection.
#[derive(Debug, Clone)]
pub struct ManualMapResult {
    pub base: Address,
    pub entry_point: Option<Address>,
    pub size_of_image: usize,
    pub relocations_applied: usize,
    pub imports_resolved: usize,
    /// Number of dependency DLLs that had to be loaded into the target.
    pub dependencies_loaded: usize,
}

/// Manual-map injector bound to an attached [`ProcessAccessLayer`].
pub struct ManualMapInjector<'a> {
    pal: &'a dyn ProcessAccessLayer,
    options: ManualMapOptions,
}

impl<'a> ManualMapInjector<'a> {
    pub fn new(pal: &'a dyn ProcessAccessLayer, options: ManualMapOptions) -> Self {
        ManualMapInjector { pal, options }
    }

    /// Convenience constructor with default (stealthy) options.
    pub fn with_defaults(pal: &'a dyn ProcessAccessLayer) -> Self {
        ManualMapInjector::new(pal, ManualMapOptions::default())
    }

    /// Inject `image_bytes` (a raw DLL) into the attached process.
    pub fn inject(&self, image_bytes: &[u8]) -> InjectResult<ManualMapResult> {
        let pe = PeImage::parse(image_bytes.to_vec())?;
        let target_arch = self.pal.architecture();

        if self.options.enforce_architecture && pe.architecture != target_arch {
            return Err(InjectError::ArchitectureMismatch {
                image: format!("{:?}", pe.architecture),
                target: format!("{target_arch:?}"),
                pid: self.pal.attached_pid().unwrap_or(0),
            });
        }

        info!(
            size_of_image = pe.size_of_image,
            image_base = format_args!("0x{:X}", pe.image_base),
            imports = pe.imports.len(),
            "manual map: parsed PE"
        );

        // 2. Allocate image memory as RW so we can lay it down, then flip
        //    per-section protections after relocations/imports are done.
        let base = self
            .pal
            .allocate_memory(pe.size_of_image as usize, ProtectionFlags::RW)
            .map_err(|e| InjectError::RemoteMemory(format!("allocate image: {e}")))?;

        // 3. Build the local in-memory image and apply relocations.
        let mut local = pe.build_local_image(self.options.include_headers);
        let delta = base.as_u64() as i64 - pe.image_base as i64;
        let relocs = if delta != 0 {
            pe.apply_relocations(&mut local, delta)?
        } else {
            0
        };

        self.pal
            .write_raw(base, &local)
            .map_err(|e| InjectError::RemoteMemory(format!("write image: {e}")))?;

        // 4. Resolve imports against the now-relocated IAT.
        let (imports_resolved, deps_loaded) = self.resolve_imports(&pe, base)?;
        debug!(imports_resolved, deps_loaded, "manual map: imports resolved");

        // 5. Per-section protections.
        self.apply_section_protections(&pe, base)?;

        // 6. Optional header erasure happens after protections are final so
        //    the zeroed header region keeps the first section's protection.
        if self.options.erase_headers {
            self.erase_headers(base, &pe)?;
        }

        let entry_point = if pe.entry_point_rva != 0 {
            Some(base + pe.entry_point_rva as usize)
        } else {
            None
        };

        // 7. Run DllMain(base, DLL_PROCESS_ATTACH, NULL) in a remote thread.
        if self.options.call_entry_point {
            if let Some(entry) = entry_point {
                self.call_entry_point(entry, base)?;
            }
        }

        Ok(ManualMapResult {
            base,
            entry_point,
            size_of_image: pe.size_of_image as usize,
            relocations_applied: relocs,
            imports_resolved,
            dependencies_loaded: deps_loaded,
        })
    }

    /// Load any not-yet-loaded dependency DLLs and write resolved addresses
    /// into the image's IAT (at `first_thunk`), walking the lookup table.
    ///
    /// Returns `(imports_resolved, dependencies_freshly_loaded)`.
    fn resolve_imports(&self, pe: &PeImage, base: Address) -> InjectResult<(usize, usize)> {
        let mut resolved = 0usize;
        let mut loaded = 0usize;

        for desc in &pe.imports {
            if desc.name.is_empty() || desc.first_thunk == 0 {
                continue;
            }

            let (module_base, was_loaded) = self.load_or_find_module(&desc.name)?;
            let module_base = module_base.ok_or_else(|| InjectError::SymbolResolution {
                symbol: desc.name.clone(),
                reason: "dependency could not be loaded into target".into(),
            })?;
            if was_loaded {
                loaded += 1;
            }

            // Walk the lookup table (OriginalFirstThunk preferred, else IAT).
            let lookup_rva = if desc.original_first_thunk != 0 {
                desc.original_first_thunk
            } else {
                desc.first_thunk
            };

            let pointer_size = pe.architecture.pointer_size();
            let mut index = 0u32;
            loop {
                let thunk_rva = lookup_rva + index * pointer_size as u32;
                let iat_rva = desc.first_thunk + index * pointer_size as u32;

                let thunk_val = self.read_thunk(base + thunk_rva as usize, pointer_size)?;
                if thunk_val == 0 {
                    break;
                }

                let func_addr = self.resolve_thunk(pe, base, module_base, thunk_val)?;
                self.write_thunk(base + iat_rva as usize, pointer_size, func_addr)?;
                resolved += 1;
                index += 1;
            }
        }

        Ok((resolved, loaded))
    }

    /// Find a module by name, loading it remotely if absent.
    /// Returns `(base, was_freshly_loaded)`.
    fn load_or_find_module(&self, name: &str) -> InjectResult<(Option<Address>, bool)> {
        // Already loaded?
        if let Some(base) = self.find_loaded_module(name) {
            return Ok((Some(base), false));
        }

        // Not loaded: ask the target to load it by path. On Windows this is
        // LoadLibraryW; on Linux, dlopen. The name may be a bare module name
        // ("KERNEL32.dll"); resolve it to a path where possible.
        let path = self.resolve_dependency_path(name)?;
        match self.pal.remote_load_library(&path) {
            Ok(base) => {
                debug!(module = name, base = %base, "manual map: loaded dependency");
                Ok((Some(base), true))
            }
            Err(e) => {
                debug!(module = name, error = %e, "manual map: dependency load failed");
                Ok((None, false))
            }
        }
    }

    fn find_loaded_module(&self, name: &str) -> Option<Address> {
        let target = name.to_lowercase();
        self.pal
            .enumerate_modules()
            .ok()?
            .into_iter()
            .find(|m| m.name.to_lowercase() == target)
            .map(|m| m.base_address)
    }

    /// Best-effort mapping from a bare import name to a loadable path.
    fn resolve_dependency_path(&self, name: &str) -> InjectResult<String> {
        // If it already looks like a path, pass through.
        if name.contains('/') || name.contains('\\') {
            return Ok(name.to_string());
        }
        // Try to locate an already-loaded module with a full path first.
        if let Some(path) = self.pal.enumerate_modules().ok().and_then(|mods| {
            mods.into_iter()
                .find(|m| m.name.eq_ignore_ascii_case(name))
                .map(|m| m.path)
                .filter(|p| !p.is_empty())
        }) {
            return Ok(path);
        }
        // Fall back to the bare name and let the loader search the standard
        // directories (kernel32.dll / user32.dll etc. resolve this way).
        Ok(name.to_string())
    }

    /// Read one thunk entry (32- or 64-bit) from the target.
    fn read_thunk(&self, addr: Address, pointer_size: usize) -> InjectResult<u64> {
        let bytes = self
            .pal
            .read_raw(addr, pointer_size)
            .map_err(|e| InjectError::RemoteMemory(format!("read thunk at {addr}: {e}")))?;
        let mut buf = [0u8; 8];
        buf[..pointer_size].copy_from_slice(&bytes[..pointer_size]);
        Ok(u64::from_le_bytes(buf))
    }

    /// Write one thunk entry back into the target.
    fn write_thunk(&self, addr: Address, pointer_size: usize, value: u64) -> InjectResult<()> {
        let bytes = &value.to_le_bytes()[..pointer_size];
        self.pal
            .write_raw(addr, bytes)
            .map_err(|e| InjectError::RemoteMemory(format!("write thunk at {addr}: {e}")))
    }

    /// Resolve a single import thunk value to an absolute address.
    ///
    /// For a name import the thunk holds an RVA of an `IMAGE_IMPORT_BY_NAME`
    /// structure located inside the *mapped* image (`image_base + rva`). The
    /// symbol itself is resolved against the *dependency* module
    /// (`module_base`). Ordinal imports are rejected (they require a module's
    /// export-by-ordinal table, uncommon for system DLLs).
    fn resolve_thunk(
        &self,
        pe: &PeImage,
        image_base: Address,
        module_base: Address,
        thunk_val: u64,
    ) -> InjectResult<u64> {
        let is_64 = pe.architecture == CpuArchitecture::X86_64;
        let ordinal_flag: u64 = if is_64 { 1 << 63 } else { 1 << 31 };

        if thunk_val & ordinal_flag != 0 {
            let ordinal = (thunk_val & 0xFFFF) as u16;
            return Err(InjectError::SymbolResolution {
                symbol: format!("ordinal #{ordinal}"),
                reason: "ordinal imports are not supported".into(),
            });
        }

        let rva = thunk_val & 0x7FFF_FFFF;
        let by_name_addr = image_base + rva as usize;
        // IMAGE_IMPORT_BY_NAME: hint(u16) then NUL-terminated ASCII name.
        let name_bytes = self.pal.read_raw(by_name_addr + 2, 256).map_err(|e| {
            InjectError::RemoteMemory(format!("read import name at {by_name_addr}: {e}"))
        })?;
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
        if name.is_empty() {
            return Err(InjectError::SymbolResolution {
                symbol: format!("rva 0x{rva:X}"),
                reason: "empty import name".into(),
            });
        }

        self.resolve_export_symbol(module_base, &name, 0)
    }

    fn resolve_export_symbol(
        &self,
        module_base: Address,
        name: &str,
        depth: usize,
    ) -> InjectResult<u64> {
        if depth > 8 {
            return Err(InjectError::SymbolResolution {
                symbol: name.to_string(),
                reason: "export forwarder recursion limit exceeded".into(),
            });
        }
        let pal = self.pal;
        let read_at = move |addr: u64, size: usize| -> InjectResult<Vec<u8>> {
            pal.read_raw(Address(addr), size).map_err(|e| e.into())
        };
        match resolve_export_at(&read_at, module_base.as_u64(), name)? {
            ExportResolution::Address(addr) => Ok(addr),
            ExportResolution::Forwarder(fwd) => {
                let (target_mod, target_sym) = fwd.split_once('.').ok_or_else(|| {
                    InjectError::SymbolResolution {
                        symbol: name.to_string(),
                        reason: format!("malformed forwarder string '{fwd}'"),
                    }
                })?;
                let dll_name = if target_mod.ends_with(".dll") {
                    target_mod.to_string()
                } else {
                    format!("{target_mod}.dll")
                };
                let (mod_base, _) = self.load_or_find_module(&dll_name)?;
                let mod_base = mod_base.ok_or_else(|| InjectError::SymbolResolution {
                    symbol: fwd.clone(),
                    reason: format!("forwarder target module '{dll_name}' could not be loaded"),
                })?;
                self.resolve_export_symbol(mod_base, target_sym, depth + 1)
            }
        }
    }

    fn apply_section_protections(&self, pe: &PeImage, base: Address) -> InjectResult<()> {
        // Header region: read-only (or none if we're about to erase it).
        let header_size = align_up(pe.size_of_headers as usize, 0x1000);
        if header_size > 0 {
            let _ = self
                .pal
                .protect_memory(base, header_size, ProtectionFlags::READ);
        }

        for section in &pe.sections {
            let size = align_up(section.virtual_size.max(section.raw_size) as usize, 0x1000);
            if size == 0 {
                continue;
            }
            let prot = section_protection(section.characteristics);
            match self.pal.protect_memory(base + section.virtual_address as usize, size, prot) {
                Ok(_) => {}
                Err(e) => {
                    // Non-fatal: some backends may not support per-section
                    // protection; the whole image stays RW from allocation.
                    debug!(section = %section.name, error = %e, "protect section failed");
                }
            }
        }
        Ok(())
    }

    fn erase_headers(&self, base: Address, pe: &PeImage) -> InjectResult<()> {
        let header_len = (pe.size_of_headers as usize).min(pe.size_of_image as usize);
        crate::stealth::StealthOps::new(self.pal).erase_headers(base, header_len)?;
        debug!(base = %base, header_len, "manual map: headers erased");
        Ok(())
    }

    fn call_entry_point(&self, entry: Address, base: Address) -> InjectResult<()> {
        let thread = self
            .pal
            .create_remote_thread(entry, base)
            .map_err(|e| InjectError::RemoteThread(format!("create entry thread: {e}")))?;

        let wait = self.pal.wait_for_thread(thread, self.options.entry_timeout_ms);
        let _ = self.pal.close_remote_thread(thread);

        match wait {
            Ok(code) => {
                // DllMain returns TRUE (1) on success; 0 means the DLL refused
                // to load. Treat 0 as an error.
                if code == 0 {
                    return Err(InjectError::RemoteThread(
                        "DllMain returned FALSE (0)".to_string(),
                    ));
                }
                debug!(exit_code = code, "manual map: entry point returned");
                Ok(())
            }
            Err(e) => {
                // Timeout or wait failure: the thread may still be running
                // (e.g. a DLL that spawns work). Report but don't fail hard.
                debug!(error = %e, "manual map: entry wait did not complete cleanly");
                Ok(())
            }
        }
    }
}

/// Map PE section characteristics to [`ProtectionFlags`].
fn section_protection(characteristics: u32) -> ProtectionFlags {
    const EXECUTE: u32 = 0x2000_0000;
    const READ: u32 = 0x4000_0000;
    const WRITE: u32 = 0x8000_0000;

    let mut prot = ProtectionFlags::NONE;
    if characteristics & READ != 0 {
        prot |= ProtectionFlags::READ;
    }
    if characteristics & WRITE != 0 {
        prot |= ProtectionFlags::WRITE;
    }
    if characteristics & EXECUTE != 0 {
        prot |= ProtectionFlags::EXECUTE;
    }
    // A section with no explicit read but present is still readable.
    if prot == ProtectionFlags::NONE {
        prot = ProtectionFlags::READ;
    }
    prot
}

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_protection_maps_characteristics() {
        // READ | EXECUTE (no write) -> RX
        assert_eq!(section_protection(0x6000_0000), ProtectionFlags::RX);
        // READ | WRITE | EXECUTE -> RWX
        assert_eq!(section_protection(0xE000_0000), ProtectionFlags::RWX);
        // READ | EXECUTE | CNT_CODE -> RX
        assert_eq!(section_protection(0x6000_0020), ProtectionFlags::RX);
        // WRITE only is unusual but maps to WRITE
        assert_eq!(section_protection(0x8000_0000), ProtectionFlags::WRITE);
        // No characteristics -> default READ
        assert_eq!(section_protection(0), ProtectionFlags::READ);
    }

    #[test]
    fn align_up_rounds_to_page() {
        assert_eq!(align_up(0, 0x1000), 0);
        assert_eq!(align_up(1, 0x1000), 0x1000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
    }
}
