//! Linux shared-object injection.
//!
//! Unlike Windows manual mapping, the idiomatic Linux approach is to have the
//! target itself map the library with `dlopen`. Engine+ drives this from the
//! outside over `ptrace`:
//!
//! 1. `engine-pal` resolves `dlopen` inside the target (relative to the libc
//!    the injector itself uses) and performs a remote call to it.
//! 2. The path string is written into the target's memory, `dlopen(path,
//!    RTLD_NOW)` is invoked, and the returned `void*` handle is the mapped
//!    base reported here.
//!
//! The remote-call machinery lives entirely in `engine-pal`; this module only
//! validates the ELF, manages the on-disk artifact and reports the result.
//!
//! ELF manual mapping (relocating and resolving a `.so` without touching
//! `dlopen`) is intentionally left as a later milestone.

use crate::error::{InjectError, InjectResult};
use engine_pal::types::Address;
use engine_pal::ProcessAccessLayer;
use std::sync::atomic::{AtomicU64, Ordering};

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFCLASS32: u8 = 1;
/// `e_type` value for a position-independent executable / shared object.
const ET_DYN: u16 = 3;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Summary of a successful Linux injection.
#[derive(Debug, Clone)]
pub struct LinuxInjectReport {
    /// Path that was `dlopen`ed in the target.
    pub path: String,
    /// Base address returned by `dlopen` (`void*` handle).
    pub base: Address,
    /// Size of the injected object, when known from a local file.
    pub object_size: usize,
    /// Whether the file was a temporary artifact created by the injector.
    pub temporary: bool,
}

/// Linux `.so` injector bound to an attached [`ProcessAccessLayer`].
pub struct LinuxInjector<'a> {
    pal: &'a dyn ProcessAccessLayer,
}

impl<'a> LinuxInjector<'a> {
    pub fn new(pal: &'a dyn ProcessAccessLayer) -> Self {
        LinuxInjector { pal }
    }

    /// `dlopen` an existing shared object at `path` inside the target.
    pub fn inject_so(&self, path: &str) -> InjectResult<LinuxInjectReport> {
        let bytes = std::fs::read(path)
            .map_err(|e| InjectError::InvalidImage(format!("read '{path}': {e}")))?;
        validate_elf(&bytes)?;

        let base = self
            .pal
            .remote_load_library(path)
            .map_err(|e| InjectError::RemoteMemory(format!("remote dlopen('{path}'): {e}")))?;

        Ok(LinuxInjectReport {
            path: path.to_string(),
            base,
            object_size: bytes.len(),
            temporary: false,
        })
    }

    /// Inject an in-memory shared object.
    ///
    /// The bytes are written to a uniquely named temporary file, `dlopen`ed,
    /// and the file is unlinked again immediately — the kernel keeps the
    /// mapping alive after unlink, so no artifact is left behind.
    pub fn inject_bytes(&self, bytes: &[u8]) -> InjectResult<LinuxInjectReport> {
        validate_elf(bytes)?;

        let path = temp_path();
        std::fs::write(&path, bytes)
            .map_err(|e| InjectError::InvalidImage(format!("write temp object '{path}': {e}")))?;

        let base = match self.pal.remote_load_library(&path) {
            Ok(base) => base,
            Err(e) => {
                // Clean up on failure so we do not leak the artifact.
                let _ = std::fs::remove_file(&path);
                return Err(InjectError::RemoteMemory(format!(
                    "remote dlopen('{path}'): {e}"
                )));
            }
        };

        // Unlink: the mapping survives, the file does not.
        let _ = std::fs::remove_file(&path);

        Ok(LinuxInjectReport {
            path,
            base,
            object_size: bytes.len(),
            temporary: true,
        })
    }
}

/// Validate the ELF header of a candidate shared object.
///
/// This is a sanity check, not a full parser: it rejects non-ELF data and
/// objects whose type is not `ET_DYN` (the only kind `dlopen` accepts).
fn validate_elf(bytes: &[u8]) -> InjectResult<()> {
    if bytes.len() < 20 {
        return Err(InjectError::InvalidImage("file too small for an ELF header".into()));
    }
    if bytes[..4] != ELF_MAGIC {
        return Err(InjectError::InvalidImage("not an ELF object".into()));
    }
    let class = bytes[4];
    if class != ELFCLASS64 && class != ELFCLASS32 {
        return Err(InjectError::InvalidImage(format!(
            "unsupported ELF class {class}"
        )));
    }
    let e_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    if e_type != ET_DYN {
        return Err(InjectError::InvalidImage(format!(
            "ELF e_type {e_type} is not ET_DYN (shared object)"
        )));
    }
    Ok(())
}

fn temp_path() -> String {
    let pid = std::process::id();
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("/tmp/engine-plus-inject-{pid}-{n}-{nanos}.so")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_header(class: u8, e_type: u16) -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[..4].copy_from_slice(&ELF_MAGIC);
        v[4] = class;
        v[16..18].copy_from_slice(&e_type.to_le_bytes());
        v
    }

    #[test]
    fn accepts_elf64_shared_object() {
        assert!(validate_elf(&elf_header(ELFCLASS64, ET_DYN)).is_ok());
    }

    #[test]
    fn rejects_non_elf() {
        let err = validate_elf(b"not an elf file at all........").unwrap_err();
        assert!(matches!(err, InjectError::InvalidImage(_)));
    }

    #[test]
    fn rejects_executable_type() {
        let err = validate_elf(&elf_header(ELFCLASS64, 2)).unwrap_err();
        assert!(matches!(err, InjectError::InvalidImage(_)));
    }

    #[test]
    fn rejects_short_input() {
        assert!(validate_elf(&[0x7F, b'E']).is_err());
    }
}
