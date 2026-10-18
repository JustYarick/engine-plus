//! Stealth primitives: hiding threads, memory and handles.
//!
//! These are *generic* obfuscation techniques used by instrumentation and
//! modding tools. Kernel-level hiding (VAD manipulation, DKOM) is explicitly
//! out of scope; everything here is user-mode and reversible.
//!
//! * **Threads** — [`StealthHider::hide_thread`] clears a thread's debug
//!   reporting so it stops emitting debug events (Windows
//!   `ThreadHideFromDebugger`).
//! * **Memory** — [`StealthHider::allocate_hidden_memory`] and
//!   [`StealthHider::hide_memory_region`] back a region with a page-file
//!   section so it reports as `MEM_MAPPED` instead of `MEM_PRIVATE`.
//! * **Handles** — [`HandleStash`] moves a handle into a separate helper
//!   process via `DuplicateHandle`, so the handle no longer appears in the
//!   original process's handle table. This is handle *hiding by relocation*,
//!   not kernel-level concealment.

use crate::error::{InjectError, InjectResult};
use engine_pal::types::{Address, ProtectionFlags};
use engine_pal::ProcessAccessLayer;

/// Thread / memory hiding operations bound to an attached backend.
pub struct StealthHider<'a> {
    pal: &'a dyn ProcessAccessLayer,
}

impl<'a> StealthHider<'a> {
    pub fn new(pal: &'a dyn ProcessAccessLayer) -> Self {
        StealthHider { pal }
    }

    /// Stop `thread_id` from reporting debug events to any attached debugger.
    pub fn hide_thread(&self, thread_id: u32) -> InjectResult<()> {
        self.pal
            .hide_thread(thread_id)
            .map_err(|e| InjectError::NotSupported {
                backend: self.pal.backend_name(),
                feature: format!("hide_thread: {e}"),
            })
    }

    /// Allocate target memory backed by a page-file section so it appears as
    /// `MEM_MAPPED` (Type) rather than `MEM_PRIVATE`.
    pub fn allocate_hidden_memory(
        &self,
        size: usize,
        protection: ProtectionFlags,
    ) -> InjectResult<Address> {
        self.pal
            .allocate_mapped_memory(size, protection)
            .map_err(|e| InjectError::NotSupported {
                backend: self.pal.backend_name(),
                feature: format!("allocate_mapped_memory: {e}"),
            })
    }

    /// Convert an existing private region into a section-backed mapping.
    ///
    /// See [`ProcessAccessLayer::remap_as_section`] for the caveats: this
    /// briefly releases the original address before remapping, so it must be
    /// used on a suspended or cooperative target.
    pub fn hide_memory_region(&self, address: Address, size: usize) -> InjectResult<Address> {
        self.pal
            .remap_as_section(address, size)
            .map_err(|e| InjectError::NotSupported {
                backend: self.pal.backend_name(),
                feature: format!("remap_as_section: {e}"),
            })
    }
}

/// A helper process that holds duplicated handles on behalf of the injector.
///
/// A handle duplicated into `HandleStash`'s helper process no longer appears
/// in the owning process's handle table. Use [`HandleStash::restore`] to
/// duplicate it back when it is needed again.
///
/// The helper is terminated when the `HandleStash` is dropped, which also
/// destroys any handles it still holds.
#[derive(Debug)]
pub struct HandleStash {
    helper: std::process::Child,
    entries: std::collections::HashMap<u64, u64>,
    next_id: u64,
}

impl HandleStash {
    /// Spawn `helper` (an executable path) as the stashing process.
    ///
    /// On platforms without the required handle-duplication support this
    /// returns `NotSupported`.
    pub fn spawn(helper: &str) -> InjectResult<Self> {
        if !cfg!(target_os = "windows") {
            return Err(InjectError::NotSupported {
                backend: current_backend(),
                feature: "HandleStash requires Windows DuplicateHandle".to_string(),
            });
        }
        let child = std::process::Command::new(helper)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        Ok(Self::from_child(child))
    }

    /// Spawn a fresh copy of *this* executable in helper mode
    /// (`--stash-helper`), which simply parks until terminated while holding
    /// any duplicated handles.
    pub fn spawn_self() -> InjectResult<Self> {
        if !cfg!(target_os = "windows") {
            return Err(InjectError::NotSupported {
                backend: current_backend(),
                feature: "HandleStash requires Windows DuplicateHandle".to_string(),
            });
        }
        let exe = std::env::current_exe().map_err(InjectError::Io)?;
        let child = std::process::Command::new(exe)
            .arg("--stash-helper")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        Ok(Self::from_child(child))
    }

    fn from_child(helper: std::process::Child) -> Self {
        HandleStash {
            helper,
            entries: std::collections::HashMap::new(),
            next_id: 1,
        }
    }

    /// The helper process's PID (needed when duplicating handles into it).
    pub fn pid(&self) -> u32 {
        self.helper.id()
    }

    /// Duplicate `handle` from the current process into the helper, closing
    /// the local copy. Returns an opaque stash id.
    pub fn stash(
        &mut self,
        pal: &dyn ProcessAccessLayer,
        handle: u64,
    ) -> InjectResult<u64> {
        let remote = pal
            .stash_handle(handle, self.helper.id())
            .map_err(|e| InjectError::NotSupported {
                backend: pal.backend_name(),
                feature: format!("stash_handle: {e}"),
            })?;
        let id = self.next_id;
        self.next_id += 1;
        self.entries.insert(id, remote);
        Ok(id)
    }

    /// Duplicate a previously stashed handle back into the current process.
    pub fn restore(
        &self,
        pal: &dyn ProcessAccessLayer,
        id: u64,
    ) -> InjectResult<u64> {
        let remote = *self.entries.get(&id).ok_or_else(|| InjectError::NotSupported {
            backend: pal.backend_name(),
            feature: format!("unknown stash id {id}"),
        })?;
        pal.unstash_handle(remote, self.helper.id())
            .map_err(|e| InjectError::NotSupported {
                backend: pal.backend_name(),
                feature: format!("unstash_handle: {e}"),
            })
    }

    /// Number of handles currently stashed.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Drop for HandleStash {
    fn drop(&mut self) {
        // Terminating the helper closes every handle it was holding.
        let _ = self.helper.kill();
        let _ = self.helper.wait();
    }
}

fn current_backend() -> &'static str {
    if cfg!(target_os = "windows") {
        "Windows WinAPI"
    } else {
        "Linux ProcessVM"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_stash_spawn_is_not_supported_off_windows() {
        if !cfg!(target_os = "windows") {
            let err = HandleStash::spawn("helper").unwrap_err();
            assert!(matches!(err, InjectError::NotSupported { .. }));
        }
    }
}
