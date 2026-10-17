use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Process identifier
pub type ProcessId = u32;

/// Memory address in target address space
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Address(pub u64);

impl Address {
    pub const NULL: Address = Address(0);

    #[inline]
    pub const fn new(addr: u64) -> Self {
        Address(addr)
    }

    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub fn offset(self, delta: i64) -> Self {
        Address((self.0 as i128 + delta as i128) as u64)
    }

    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, bytes: usize) -> Self {
        Address(self.0.wrapping_add(bytes as u64))
    }

    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, bytes: usize) -> Self {
        Address(self.0.wrapping_sub(bytes as u64))
    }
}

impl std::ops::Add<usize> for Address {
    type Output = Address;
    #[inline]
    fn add(self, rhs: usize) -> Self::Output {
        Address(self.0.wrapping_add(rhs as u64))
    }
}

impl std::ops::Sub<usize> for Address {
    type Output = Address;
    #[inline]
    fn sub(self, rhs: usize) -> Self::Output {
        Address(self.0.wrapping_sub(rhs as u64))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016X}", self.0)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:X}", self.0)
    }
}

impl From<u64> for Address {
    #[inline]
    fn from(val: u64) -> Self {
        Address(val)
    }
}

impl From<usize> for Address {
    #[inline]
    fn from(val: usize) -> Self {
        Address(val as u64)
    }
}

bitflags! {
    /// Protection attributes for virtual memory pages
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct ProtectionFlags: u32 {
        const NONE    = 0;
        const READ    = 1 << 0;
        const WRITE   = 1 << 1;
        const EXECUTE = 1 << 2;
        const RW      = Self::READ.bits() | Self::WRITE.bits();
        const RX      = Self::READ.bits() | Self::EXECUTE.bits();
        const RWX     = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
        const PRIVATE = 1 << 3;
        const SHARED  = 1 << 4;
    }
}

/// A contiguous region of mapped virtual memory
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub start: Address,
    pub end: Address,
    pub size: usize,
    pub protection: ProtectionFlags,
    pub path: Option<String>,
    pub is_anonymous: bool,
}

impl MemoryRegion {
    pub fn new(start: u64, end: u64, protection: ProtectionFlags, path: Option<String>) -> Self {
        let size = (end.saturating_sub(start)) as usize;
        let is_anonymous = path.as_ref().is_none_or(|p| p.is_empty() || p.starts_with('['));
        MemoryRegion {
            start: Address(start),
            end: Address(end),
            size,
            protection,
            path,
            is_anonymous,
        }
    }

    #[inline]
    pub fn contains(&self, addr: Address) -> bool {
        addr >= self.start && addr < self.end
    }

    #[inline]
    pub fn is_readable(&self) -> bool {
        self.protection.contains(ProtectionFlags::READ)
    }

    #[inline]
    pub fn is_writable(&self) -> bool {
        self.protection.contains(ProtectionFlags::WRITE)
    }

    #[inline]
    pub fn is_executable(&self) -> bool {
        self.protection.contains(ProtectionFlags::EXECUTE)
    }
}

/// Information about a loaded dynamic module / binary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base_address: Address,
    pub size: usize,
}

/// Information about an active thread in the target process
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadInfo {
    pub id: u32,
    pub state: Option<String>,
}

/// Target CPU architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CpuArchitecture {
    X86_32,
    X86_64,
}

impl CpuArchitecture {
    pub fn pointer_size(&self) -> usize {
        match self {
            CpuArchitecture::X86_32 => 4,
            CpuArchitecture::X86_64 => 8,
        }
    }
}

/// Types of breakpoints supported by debug backends
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointType {
    /// Software breakpoint (INT3: 0xCC)
    Software,
    /// Hardware execution breakpoint (DR0-DR3)
    HardwareExecute,
    /// Hardware data write watchpoint (DR0-DR3)
    HardwareWrite,
    /// Hardware data read/write watchpoint (DR0-DR3)
    HardwareAccess,
}

/// Unique ID for a registered breakpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BreakpointId(pub u64);

/// Stealth level classification of the active backend
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StealthLevel {
    /// Standard usermode debugging (e.g. ptrace with TracerPid)
    None = 0,
    /// Memory file read/write (e.g. /proc/pid/mem, process_vm_readv)
    Low = 1,
    /// Direct syscalls bypassing standard libc wrappers
    Medium = 2,
    /// Kernel ring0 driver (LKM / KMDF) - completely invisible to usermode
    KernelRing0 = 3,
}

/// Process overview for listing and attaching
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: ProcessId,
    pub name: String,
    pub cmdline: Option<String>,
    pub architecture: CpuArchitecture,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_arithmetic() {
        let addr = Address::new(0x1000);
        assert_eq!(addr.as_u64(), 0x1000);
        assert_eq!(addr.add(0x20).as_u64(), 0x1020);
        assert_eq!(addr.sub(0x10).as_u64(), 0x0FF0);
        assert_eq!(addr.offset(-0x10).as_u64(), 0x0FF0);
        assert_eq!(addr.offset(0x10).as_u64(), 0x1010);
        assert_eq!(format!("{addr}"), "0x1000");
    }

    #[test]
    fn test_memory_region_properties() {
        let region = MemoryRegion::new(
            0x00400000,
            0x00500000,
            ProtectionFlags::RWX,
            Some("/usr/bin/game".to_string()),
        );

        assert_eq!(region.size, 0x00100000);
        assert!(region.is_readable());
        assert!(region.is_writable());
        assert!(region.is_executable());
        assert!(!region.is_anonymous);
        assert!(region.contains(Address::new(0x00400000)));
        assert!(region.contains(Address::new(0x004FFFFF)));
        assert!(!region.contains(Address::new(0x00500000)));
        assert!(!region.contains(Address::new(0x003FFFFF)));
    }

    #[test]
    fn test_architecture_pointer_size() {
        assert_eq!(CpuArchitecture::X86_32.pointer_size(), 4);
        assert_eq!(CpuArchitecture::X86_64.pointer_size(), 8);
    }
}

