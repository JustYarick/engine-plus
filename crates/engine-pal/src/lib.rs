pub mod error;
pub mod traits;
pub mod types;

#[cfg(target_os = "linux")]
pub mod os;

pub use error::{PalError, PalResult};
pub use traits::{MemoryReader, MemoryWriter, ProcessAccessLayer, ProcessEnumerator};
pub use types::{
    Address, BreakpointId, BreakpointType, CpuArchitecture, MemoryRegion, ModuleInfo,
    ProcessEntry, ProcessId, ProtectionFlags, StealthLevel, ThreadInfo,
};

/// Create the default, most performant ProcessAccessLayer backend for the current OS
pub fn default_backend() -> Box<dyn ProcessAccessLayer> {
    #[cfg(target_os = "linux")]
    {
        Box::new(os::linux::ProcessVmBackend::new())
    }
    #[cfg(not(target_os = "linux"))]
    {
        panic!("Platform currently not supported");
    }
}

/// Create the default process enumerator for the current OS
pub fn default_enumerator() -> Box<dyn ProcessEnumerator> {
    #[cfg(target_os = "linux")]
    {
        Box::new(os::linux::LinuxProcessEnumerator)
    }
    #[cfg(not(target_os = "linux"))]
    {
        panic!("Platform currently not supported");
    }
}
