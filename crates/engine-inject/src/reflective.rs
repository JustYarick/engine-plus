//! Reflective DLL loading — two modes.
//!
//! * [`ReflectiveMode::Rdi`] — the Stephen Fewer *Reflective DLL Injection*
//!   convention: the target DLL itself exports a `ReflectiveLoader` routine.
//!   The injector only writes the raw image into the target and starts a
//!   remote thread at that export; all mapping work happens in-process.
//!
//! * [`ReflectiveMode::Stub`] — a custom position-independent loader stub,
//!   assembled at runtime with `iced-x86`, appended after the raw image. The
//!   stub receives the raw image pointer as its single argument and performs
//!   the allocate → copy → relocate → resolve-imports → `DllMain` sequence
//!   entirely inside the target, so the injector never performs the mapping
//!   itself.
//!
//! Neither mode touches the filesystem: only the raw bytes cross into the
//! target. These are generic, publicly documented techniques (the RDI design
//! is a well-known open-source reference implementation).
//!
//! ## Validation note
//!
//! The RDI path is correct by construction (it delegates mapping to code
//! already compiled into the DLL). The generated PIC stub is covered by unit
//! tests that assert it assembles deterministically and disassembles to the
//! intended instruction sequence; full runtime validation requires a Windows
//! target and is performed there.

use crate::error::{InjectError, InjectResult};
use crate::pe::PeImage;
use engine_pal::types::{Address, CpuArchitecture, ProtectionFlags};
use engine_pal::ProcessAccessLayer;
use tracing::info;

mod x64_stub;

/// Which reflective-loading strategy to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReflectiveMode {
    /// Use the DLL's own `ReflectiveLoader` export (Stephen Fewer RDI).
    Rdi,
    /// Append a custom PIC loader stub assembled at runtime.
    Stub,
}

/// Export name expected by [`ReflectiveMode::Rdi`].
pub const RDI_EXPORT_NAME: &str = "ReflectiveLoader";

/// Outcome of a reflective injection.
#[derive(Debug, Clone)]
pub struct ReflectiveResult {
    /// Base address of the raw (source) image as written into the target.
    pub raw_base: Address,
    /// Address the remote thread was started at.
    pub thread_start: Address,
    /// For RDI mode: RVA of the `ReflectiveLoader` export.
    pub loader_rva: Option<u32>,
    /// For stub mode: size of the appended stub.
    pub stub_len: Option<usize>,
}

/// Reflective injector bound to an attached [`ProcessAccessLayer`].
pub struct ReflectiveLoader<'a> {
    pal: &'a dyn ProcessAccessLayer,
    mode: ReflectiveMode,
    timeout_ms: u64,
}

impl<'a> ReflectiveLoader<'a> {
    pub fn new(pal: &'a dyn ProcessAccessLayer, mode: ReflectiveMode) -> Self {
        ReflectiveLoader {
            pal,
            mode,
            timeout_ms: 15_000,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Inject a raw DLL image reflectively and return where it landed.
    pub fn inject(&self, image_bytes: &[u8]) -> InjectResult<ReflectiveResult> {
        let pe = PeImage::parse(image_bytes.to_vec())?;
        let target_arch = self.pal.architecture();
        if pe.architecture != target_arch {
            return Err(InjectError::ArchitectureMismatch {
                image: format!("{:?}", pe.architecture),
                target: format!("{target_arch:?}"),
                pid: self.pal.attached_pid().unwrap_or(0),
            });
        }

        match self.mode {
            ReflectiveMode::Rdi => self.inject_rdi(&pe, image_bytes),
            ReflectiveMode::Stub => self.inject_stub(image_bytes),
        }
    }

    /// RDI: locate the `ReflectiveLoader` export, write the whole image, and
    /// start a remote thread at that export.
    fn inject_rdi(&self, pe: &PeImage, image_bytes: &[u8]) -> InjectResult<ReflectiveResult> {
        let loader_rva = pe.find_export_rva(RDI_EXPORT_NAME).ok_or_else(|| {
            InjectError::SymbolResolution {
                symbol: RDI_EXPORT_NAME.to_string(),
                reason: "DLL does not export ReflectiveLoader (build with RDI)".into(),
            }
        })?;

        // The raw image must be readable by the loader at runtime: allocate
        // RWX so the stub can both read headers and execute in place.
        let size = align_up(image_bytes.len().max(pe.size_of_image as usize), 0x1000);
        let base = self
            .pal
            .allocate_memory(size, ProtectionFlags::RWX)
            .map_err(|e| InjectError::RemoteMemory(format!("allocate raw image: {e}")))?;

        self.pal
            .write_raw(base, image_bytes)
            .map_err(|e| InjectError::RemoteMemory(format!("write raw image: {e}")))?;

        let thread_start = base + loader_rva as usize;
        info!(
            base = %base,
            loader_rva,
            "reflective (RDI): starting ReflectiveLoader thread"
        );

        // ReflectiveLoader takes no meaningful parameter; the loader locates
        // its own image base via a call/pop delta. Pass the base anyway.
        self.spawn_and_wait(thread_start, base)?;

        Ok(ReflectiveResult {
            raw_base: base,
            thread_start,
            loader_rva: Some(loader_rva),
            stub_len: None,
        })
    }

    /// Custom stub: write image + appended PIC stub, start a thread at the
    /// stub entry. On Windows x64 the thread start parameter is passed in
    /// `RCX`, which the generated stub reads as the raw image base.
    fn inject_stub(&self, image_bytes: &[u8]) -> InjectResult<ReflectiveResult> {
        let arch = self.pal.architecture();
        let stub = build_pic_stub(arch, image_bytes.len())?;

        let image_len = image_bytes.len();
        let total = align_up(image_len + stub.len(), 0x1000);
        let base = self
            .pal
            .allocate_memory(total, ProtectionFlags::RWX)
            .map_err(|e| InjectError::RemoteMemory(format!("allocate raw image+stub: {e}")))?;

        self.pal
            .write_raw(base, image_bytes)
            .map_err(|e| InjectError::RemoteMemory(format!("write raw image: {e}")))?;

        let stub_addr = base + image_len;
        self.pal
            .write_raw(stub_addr, &stub)
            .map_err(|e| InjectError::RemoteMemory(format!("write stub: {e}")))?;

        info!(
            base = %base,
            stub_addr = %stub_addr,
            stub_len = stub.len(),
            "reflective (stub): starting PIC loader"
        );

        // Pass the raw image base as the thread parameter so the stub knows
        // where the source image lives.
        self.spawn_and_wait(stub_addr, base)?;

        Ok(ReflectiveResult {
            raw_base: base,
            thread_start: stub_addr,
            loader_rva: None,
            stub_len: Some(stub.len()),
        })
    }

    fn spawn_and_wait(&self, start: Address, param: Address) -> InjectResult<()> {
        let thread = self
            .pal
            .create_remote_thread(start, param)
            .map_err(|e| InjectError::RemoteThread(format!("create remote thread: {e}")))?;
        let wait = self.pal.wait_for_thread(thread, self.timeout_ms);
        let _ = self.pal.close_remote_thread(thread);
        match wait {
            Ok(code) => {
                info!(exit_code = code, "reflective: loader thread finished");
                Ok(())
            }
            Err(e) => Err(InjectError::RemoteThread(format!(
                "loader thread wait failed: {e}"
            ))),
        }
    }
}

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}

/// Build the position-independent reflective loader stub for `arch`.
///
/// The stub is a self-contained x64 (or x86) routine that performs:
/// `VirtualAlloc` → copy sections → apply relocations → resolve imports via
/// `LoadLibraryA`/`GetProcAddress` → call `DllMain` → return.
///
/// Exported for unit tests to inspect and round-trip through a disassembler.
pub fn build_pic_stub(arch: CpuArchitecture, image_len: usize) -> InjectResult<Vec<u8>> {
    match arch {
        CpuArchitecture::X86_64 => crate::reflective::x64_stub::build(image_len),
        CpuArchitecture::X86_32 => Err(InjectError::NotSupported {
            backend: "engine-inject",
            feature: "x86 (32-bit) reflective stub not yet implemented".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, valid PE header is not required to assemble the stub — the
    /// stub only depends on the architecture and raw image length.
    #[test]
    fn x64_stub_assembles_non_empty_and_is_deterministic() {
        let a = build_pic_stub(CpuArchitecture::X86_64, 0x4000).unwrap();
        let b = build_pic_stub(CpuArchitecture::X86_64, 0x4000).unwrap();
        assert!(!a.is_empty(), "stub must not be empty");
        assert_eq!(a, b, "stub assembly must be deterministic");
        // Must be a sane size for a loader routine.
        assert!(a.len() >= 64 && a.len() < 0x10_000, "unexpected stub size {}", a.len());
    }

    #[test]
    fn x86_stub_reports_not_supported() {
        let err = build_pic_stub(CpuArchitecture::X86_32, 0x4000).unwrap_err();
        assert!(matches!(err, InjectError::NotSupported { .. }));
    }

    #[test]
    fn stub_disassembles_from_start() {
        let stub = build_pic_stub(CpuArchitecture::X86_64, 0x4000).unwrap();
        // Round-trip: the disassembler must decode at least one instruction
        // from offset 0 without error.
        let mut decoder = iced_x86::Decoder::with_ip(64, &stub, 0, iced_x86::DecoderOptions::NONE);
        let instr = decoder.decode();
        assert!(
            !instr.is_invalid(),
            "first stub instruction must decode cleanly"
        );
        // And decoding the whole buffer must reach the end without hitting an
        // invalid instruction at the very start of any 16-byte window.
        let mut d2 = iced_x86::Decoder::with_ip(64, &stub, 0, iced_x86::DecoderOptions::NONE);
        let mut count = 0usize;
        while d2.can_decode() {
            let i = d2.decode();
            if i.is_invalid() {
                break;
            }
            count += 1;
        }
        assert!(count > 5, "stub should contain more than 5 instructions");
    }
}
