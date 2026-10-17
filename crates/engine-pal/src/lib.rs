pub mod error;
pub mod traits;
pub mod types;

pub mod os;

pub use error::{PalError, PalResult};
pub use traits::{MemoryReader, MemoryWriter, ProcessAccessLayer, ProcessEnumerator};
pub use types::{
    Address, BreakpointId, BreakpointType, CpuArchitecture, CpuRegisters, DebugHit,
    HardwareBreakpointSlot, MemoryRegion, ModuleInfo, ProcessEntry, ProcessId, ProtectionFlags,
    StealthLevel, ThreadInfo, WatchpointCondition, WatchpointSize,
};

/// Create the default, most performant ProcessAccessLayer backend for the current OS
pub fn default_backend() -> Box<dyn ProcessAccessLayer> {
    #[cfg(target_os = "linux")]
    {
        Box::new(os::linux::ProcessVmBackend::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(os::windows::WinApiBackend::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
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
    #[cfg(target_os = "windows")]
    {
        Box::new(os::windows::WindowsProcessEnumerator)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        panic!("Platform currently not supported");
    }
}
