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

/// Result of launching code inside the target process via a remote thread.
///
/// `exit_code` is only meaningful once the thread has been waited on and the
/// entry point returned a 32-bit value (e.g. `LoadLibraryW` truncated on x64 —
/// prefer `remote_load_library` which re-resolves the full 64-bit module base).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteThreadHandle {
    /// Operating-system thread identifier (TID)
    pub id: u32,
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

/// Target CPU Registers snapshot (x86_64 / x86_32)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CpuRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

impl CpuRegisters {
    #[inline]
    pub fn cf(&self) -> bool {
        (self.rflags & 0x0001) != 0
    }

    #[inline]
    pub fn pf(&self) -> bool {
        (self.rflags & 0x0004) != 0
    }

    #[inline]
    pub fn af(&self) -> bool {
        (self.rflags & 0x0010) != 0
    }

    #[inline]
    pub fn zf(&self) -> bool {
        (self.rflags & 0x0040) != 0
    }

    #[inline]
    pub fn sf(&self) -> bool {
        (self.rflags & 0x0080) != 0
    }

    #[inline]
    pub fn tf(&self) -> bool {
        (self.rflags & 0x0100) != 0
    }

    #[inline]
    pub fn if_flag(&self) -> bool {
        (self.rflags & 0x0200) != 0
    }

    #[inline]
    pub fn df(&self) -> bool {
        (self.rflags & 0x0400) != 0
    }

    #[inline]
    pub fn of(&self) -> bool {
        (self.rflags & 0x0800) != 0
    }

    pub fn format_display(&self) -> String {
        format!(
            "RAX: 0x{:016X}  RBX: 0x{:016X}  RCX: 0x{:016X}  RDX: 0x{:016X}\n\
             RSI: 0x{:016X}  RDI: 0x{:016X}  RBP: 0x{:016X}  RSP: 0x{:016X}\n\
             R8:  0x{:016X}  R9:  0x{:016X}  R10: 0x{:016X}  R11: 0x{:016X}\n\
             R12: 0x{:016X}  R13: 0x{:016X}  R14: 0x{:016X}  R15: 0x{:016X}\n\
             RIP: 0x{:016X}  RFLAGS: 0x{:08X} [CF:{} ZF:{} SF:{} OF:{}]",
            self.rax, self.rbx, self.rcx, self.rdx,
            self.rsi, self.rdi, self.rbp, self.rsp,
            self.r8, self.r9, self.r10, self.r11,
            self.r12, self.r13, self.r14, self.r15,
            self.rip, self.rflags as u32,
            self.cf() as u8, self.zf() as u8, self.sf() as u8, self.of() as u8
        )
    }
}

/// Hardware watchpoint trigger condition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WatchpointCondition {
    Execution,
    Write,
    Access,
}

/// Hardware watchpoint monitored size (in bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WatchpointSize {
    Bytes1 = 1,
    Bytes2 = 2,
    Bytes4 = 4,
    Bytes8 = 8,
}

impl WatchpointSize {
    pub fn from_bytes(bytes: usize) -> Self {
        match bytes {
            2 => WatchpointSize::Bytes2,
            4 => WatchpointSize::Bytes4,
            8 => WatchpointSize::Bytes8,
            _ => WatchpointSize::Bytes1,
        }
    }

    pub fn byte_count(&self) -> usize {
        *self as usize
    }
}

/// Hardware breakpoint slot (DR0-DR3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HardwareBreakpointSlot {
    Dr0 = 0,
    Dr1 = 1,
    Dr2 = 2,
    Dr3 = 3,
}

impl HardwareBreakpointSlot {
    pub fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(HardwareBreakpointSlot::Dr0),
            1 => Some(HardwareBreakpointSlot::Dr1),
            2 => Some(HardwareBreakpointSlot::Dr2),
            3 => Some(HardwareBreakpointSlot::Dr3),
            _ => None,
        }
    }

    pub fn index(&self) -> usize {
        *self as usize
    }
}

/// Debug register hit record (e.g. from \"What writes to this address?\")
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugHit {
    pub address: Address,
    pub instruction_pointer: Address,
    pub thread_id: Option<u32>,
    pub hit_count: u64,
    pub registers: CpuRegisters,
    pub disassembly: Option<String>,
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

    #[test]
    fn test_cpu_registers_and_watchpoints() {
        let regs = CpuRegisters {
            rax: 0x1234,
            rip: 0x7FFF0000,
            // Set ZF (bit 6) and CF (bit 0)
            rflags: 0x0041,
            ..CpuRegisters::default()
        };
        assert!(regs.zf());
        assert!(regs.cf());
        assert!(!regs.sf());
        assert!(!regs.of());

        let display = regs.format_display();
        assert!(display.contains("RAX: 0x0000000000001234"));
        assert!(display.contains("ZF:1"));

        assert_eq!(WatchpointSize::from_bytes(4), WatchpointSize::Bytes4);
        assert_eq!(WatchpointSize::Bytes4.byte_count(), 4);

        assert_eq!(HardwareBreakpointSlot::from_index(2), Some(HardwareBreakpointSlot::Dr2));
        assert_eq!(HardwareBreakpointSlot::Dr2.index(), 2);
    }
}

