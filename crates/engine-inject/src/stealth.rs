//! PE header erasure over an already-mapped image.
//!
//! After a DLL has been mapped (manually or reflectively) the DOS/NT headers
//! and section table at the image base are not needed at runtime — most
//! loaders only consult them during the initial load. Zeroing them removes
//! the obvious `MZ` / `PE` signatures that naive memory scanners look for.
//!
//! This is a *generic*, well-known obfuscation step used by legitimate
//! instrumentation and modding tools. It is best-effort: it does not defend
//! against a determined analyst who recovers headers from a module's
//! neighbors or from crash dumps.

use crate::error::{InjectError, InjectResult};
use engine_pal::types::{Address, ProtectionFlags};
use engine_pal::ProcessAccessLayer;

/// Statistics returned after erasing headers.
#[derive(Debug, Clone, Copy, Default)]
pub struct EraseReport {
    /// Number of bytes zeroed at the image base.
    pub bytes_erased: usize,
    /// Previous page protection of the header region (restored afterwards).
    pub previous_protection: Option<ProtectionFlags>,
}

/// Header-erasure operations bound to an attached [`ProcessAccessLayer`].
pub struct StealthOps<'a> {
    pal: &'a dyn ProcessAccessLayer,
}

impl<'a> StealthOps<'a> {
    pub fn new(pal: &'a dyn ProcessAccessLayer) -> Self {
        StealthOps { pal }
    }

    /// Zero the headers of a mapped image at `image_base`.
    ///
    /// `header_len` is the number of bytes to zero (typically the image's
    /// `SizeOfHeaders`). If the header region is currently read-only the
    /// protection is temporarily raised to `RW`, the bytes zeroed, then the
    /// original protection restored.
    pub fn erase_headers(&self, image_base: Address, header_len: usize) -> InjectResult<EraseReport> {
        if header_len == 0 {
            return Err(InjectError::InvalidImage("header_len is zero".into()));
        }

        // Temporarily make the header writable if the backend supports it.
        let previous = self
            .pal
            .protect_memory(image_base, header_len, ProtectionFlags::RW)
            .ok();

        let zeros = vec![0u8; header_len];
        self.pal
            .write_raw(image_base, &zeros)
            .map_err(|e| InjectError::RemoteMemory(format!("erase headers at {image_base}: {e}")))?;

        // Restore the previous protection (ignore failure: leaving the region
        // RW would be a stealth regression but not a correctness bug, and some
        // backends do not report a previous protection).
        if let Some(prev) = previous {
            let _ = self.pal.protect_memory(image_base, header_len, prev);
        }

        Ok(EraseReport {
            bytes_erased: header_len,
            previous_protection: previous,
        })
    }

    /// Verify the image no longer begins with an `MZ` signature.
    pub fn headers_erased(&self, image_base: Address) -> InjectResult<bool> {
        let first2 = self
            .pal
            .read_raw(image_base, 2)
            .map_err(|e| InjectError::RemoteMemory(format!("read header sig: {e}")))?;
        Ok(!(first2.len() == 2 && first2[0] == b'M' && first2[1] == b'Z'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erase_report_default_is_empty() {
        let r = EraseReport::default();
        assert_eq!(r.bytes_erased, 0);
        assert!(r.previous_protection.is_none());
    }
}
