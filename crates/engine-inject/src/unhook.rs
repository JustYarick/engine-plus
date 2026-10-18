//! Unhooking of system modules.
//!
//! Endpoint-security and anti-cheat products commonly place inline hooks by
//! overwriting the first bytes of hot functions (typically inside
//! `ntdll!Nt*`). Those hooks show up as byte differences between the module
//! as it exists in memory and the pristine image of the same module.
//!
//! Engine+ restores the executable sections of a chosen module from its clean
//! `\KnownDlls\<name>` section mapping (Windows) — no disk I/O, and the clean
//! image is guaranteed to match the loaded version on the same boot.
//!
//! This is the standard "ntdll unhook" used by debuggers and instrumentation
//! tools. It is generic: it neither knows nor cares which product placed the
//! hooks.

use crate::error::{InjectResult, InjectError};
use crate::pe::MappedImage;
use engine_pal::types::{Address, ProtectionFlags};
use engine_pal::ProcessAccessLayer;
use tracing::{debug, info};

/// Default module to restore.
pub const DEFAULT_UNHOOK_MODULE: &str = "ntdll.dll";

/// Summary of an unhook pass.
#[derive(Debug, Clone, Default)]
pub struct UnhookReport {
    pub module: String,
    pub base: Address,
    /// Executable sections compared.
    pub sections_scanned: usize,
    /// Number of separate byte regions that differed and were restored.
    pub regions_patched: usize,
    /// Total bytes written back from the clean image.
    pub bytes_restored: usize,
}

/// Unhooking operations bound to an attached [`ProcessAccessLayer`].
pub struct Unhooker<'a> {
    pal: &'a dyn ProcessAccessLayer,
    /// Merge differing regions separated by at most this many equal bytes.
    gap_merge: usize,
}

impl<'a> Unhooker<'a> {
    pub fn new(pal: &'a dyn ProcessAccessLayer) -> Self {
        Unhooker { pal, gap_merge: 16 }
    }

    /// Convenience: restore `ntdll.dll`.
    pub fn unhook_ntdll(&self) -> InjectResult<UnhookReport> {
        self.unhook_module(DEFAULT_UNHOOK_MODULE)
    }

    /// Restore the executable sections of `module` from its clean image.
    pub fn unhook_module(&self, module: &str) -> InjectResult<UnhookReport> {
        let base = self.find_module_base(module).ok_or_else(|| InjectError::SymbolResolution {
            symbol: module.to_string(),
            reason: "module is not loaded in the target".into(),
        })?;

        // Clean, mapped image (KnownDlls on Windows).
        let clean = self.pal.read_system_module_image(module)?;
        let clean_image = MappedImage::parse(&clean)?;

        // Live headers, to learn the target's section layout (best effort).
        let header_probe = (clean_image.size_of_headers as usize).clamp(0x400, 0x4000);
        if let Ok(live_headers) = self.pal.read_raw(base, header_probe) {
            if let Ok(live_image) = MappedImage::parse(&live_headers) {
                if live_image.size_of_image != clean_image.size_of_image
                    || live_image.sections.len() != clean_image.sections.len()
                {
                    debug!(
                        module,
                        live_image = live_image.size_of_image,
                        clean_image = clean_image.size_of_image,
                        "unhook: live/clean image layouts differ; comparing by clean layout"
                    );
                }
            } else {
                debug!(
                    module,
                    "unhook: live headers could not be parsed (possibly erased); comparing by clean layout"
                );
            }
        }

        let mut report = UnhookReport {
            module: module.to_string(),
            base,
            ..Default::default()
        };

        for section in &clean_image.sections {
            if !section.is_executable() {
                continue;
            }
            let va = section.virtual_address as usize;
            let size = section.virtual_size as usize;
            if size == 0 {
                continue;
            }
            let clean_end = va.saturating_add(size);
            if clean_end > clean.len() {
                debug!(section = %section.name, "unhook: section extends past clean image, skipping");
                continue;
            }

            report.sections_scanned += 1;

            let remote = self
                .pal
                .read_raw(base + va, size)
                .map_err(|e| InjectError::RemoteMemory(format!("read {} section {}: {e}", module, section.name)))?;
            if remote.len() != size {
                debug!(section = %section.name, "unhook: short read, skipping");
                continue;
            }

            let pristine = &clean[va..clean_end];
            let diffs = diff_regions(&remote, pristine, self.gap_merge);
            if diffs.is_empty() {
                continue;
            }

            // Determine the intended protection from the section flags.
            let prot = section_protection(section.characteristics);

            for (start, end) in diffs {
                let addr = base + va + start;
                let len = end - start;
                let prev = self
                    .pal
                    .protect_memory(addr, len, ProtectionFlags::RWX)
                    .ok();
                self.pal
                    .write_raw(addr, &pristine[start..end])
                    .map_err(|e| {
                        InjectError::Protection {
                            address: addr,
                            reason: format!("restore hooked bytes: {e}"),
                        }
                    })?;
                let restore = prev.unwrap_or(prot);
                let _ = self.pal.protect_memory(addr, len, restore);
                report.regions_patched += 1;
                report.bytes_restored += len;
            }
        }

        info!(
            module,
            sections = report.sections_scanned,
            regions = report.regions_patched,
            bytes = report.bytes_restored,
            "unhook complete"
        );
        Ok(report)
    }

    fn find_module_base(&self, name: &str) -> Option<Address> {
        let target = name.to_lowercase();
        self.pal
            .enumerate_modules()
            .ok()?
            .into_iter()
            .find(|m| m.name.to_lowercase() == target)
            .map(|m| m.base_address)
    }
}

/// Compute contiguous differing regions between `live` and `clean`, merging
/// runs separated by at most `gap` equal bytes.
///
/// Returns a list of `(start, end)` half-open byte ranges.
fn diff_regions(live: &[u8], clean: &[u8], gap: usize) -> Vec<(usize, usize)> {
    let len = live.len().min(clean.len());
    let mut regions: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;

    while i < len {
        if live[i] == clean[i] {
            i += 1;
            continue;
        }
        // Start of a difference; extend while differences recur within `gap`.
        let start = i;
        let mut last_diff = i;
        i += 1;
        while i < len {
            if live[i] != clean[i] {
                last_diff = i;
                i += 1;
            } else if i - last_diff <= gap {
                // Within the merge window; keep scanning.
                i += 1;
            } else {
                break;
            }
        }
        let end = last_diff + 1;
        regions.push((start, end));
        i = end;
    }

    regions
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
    if prot == ProtectionFlags::NONE {
        prot = ProtectionFlags::RX;
    }
    prot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_regions_empty_when_identical() {
        let a = vec![0u8; 64];
        assert!(diff_regions(&a, &a, 16).is_empty());
    }

    #[test]
    fn diff_regions_single_run() {
        let mut live = vec![0u8; 64];
        let clean = vec![0u8; 64];
        live[10] = 0xFF;
        live[11] = 0xEE;
        let regions = diff_regions(&live, &clean, 16);
        assert_eq!(regions, vec![(10, 12)]);
    }

    #[test]
    fn diff_regions_merge_close_runs() {
        let mut live = vec![0u8; 64];
        let clean = vec![0u8; 64];
        live[10] = 1;
        live[16] = 1; // gap of 5 equal bytes (< 16) -> merge
        let regions = diff_regions(&live, &clean, 16);
        assert_eq!(regions, vec![(10, 17)]);
    }

    #[test]
    fn diff_regions_keep_far_runs_separate() {
        let mut live = vec![0u8; 128];
        let clean = vec![0u8; 128];
        live[10] = 1;
        live[100] = 1; // gap of 89 > 16 -> separate
        let regions = diff_regions(&live, &clean, 16);
        assert_eq!(regions, vec![(10, 11), (100, 101)]);
    }

    #[test]
    fn section_protection_defaults_to_rx_for_code() {
        assert_eq!(section_protection(0x6000_0020), ProtectionFlags::RX);
        assert_eq!(section_protection(0xE000_0000), ProtectionFlags::RWX);
    }
}
