use crate::error::{PalError, PalResult};
use crate::traits::ProcessAccessLayer;
use crate::types::{
    Address, BreakpointId, BreakpointType, CpuArchitecture, MemoryRegion, ModuleInfo, ProcessId,
    ProtectionFlags, StealthLevel, ThreadInfo,
};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
    MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};

/// RAII wrapper for Win32 HANDLE
#[derive(Debug)]
pub struct AutoHandle(HANDLE);

impl AutoHandle {
    pub fn new(handle: HANDLE) -> Option<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(AutoHandle(handle))
        }
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

// Win32 process handles are thread-safe OS kernel objects
unsafe impl Send for AutoHandle {}
unsafe impl Sync for AutoHandle {}

impl Drop for AutoHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Standard Windows PAL backend using Win32 API (`OpenProcess`, `ReadProcessMemory`, `VirtualQueryEx`)
pub struct WinApiBackend {
    attached_pid: Option<ProcessId>,
    process_handle: Option<AutoHandle>,
}

impl WinApiBackend {
    pub fn new() -> Self {
        WinApiBackend {
            attached_pid: None,
            process_handle: None,
        }
    }

    fn ensure_attached(&self) -> PalResult<HANDLE> {
        self.process_handle
            .as_ref()
            .map(|h| h.raw())
            .ok_or(PalError::NotAttached)
    }
}

impl Default for WinApiBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessAccessLayer for WinApiBackend {
    fn attach(&mut self, pid: ProcessId) -> PalResult<()> {
        let desired_access = PROCESS_ALL_ACCESS;
        let mut handle = unsafe { OpenProcess(desired_access, 0, pid) };

        // Fallback to minimal required permissions if full access is denied
        if handle.is_null() {
            let fallback_access = PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION;
            handle = unsafe { OpenProcess(fallback_access, 0, pid) };
        }

        let auto_handle = AutoHandle::new(handle).ok_or_else(|| {
            PalError::AttachFailed(pid, std::io::Error::last_os_error().to_string())
        })?;

        self.attached_pid = Some(pid);
        self.process_handle = Some(auto_handle);
        Ok(())
    }

    fn detach(&mut self) -> PalResult<()> {
        self.process_handle = None;
        self.attached_pid = None;
        Ok(())
    }

    fn is_attached(&self) -> bool {
        self.process_handle.is_some()
    }

    fn attached_pid(&self) -> Option<ProcessId> {
        self.attached_pid
    }

    fn architecture(&self) -> CpuArchitecture {
        #[cfg(target_arch = "x86_64")]
        {
            CpuArchitecture::X86_64
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            CpuArchitecture::X86_32
        }
    }

    fn read_raw(&self, address: Address, size: usize) -> PalResult<Vec<u8>> {
        let handle = self.ensure_attached()?;
        let mut buffer = vec![0u8; size];
        let mut bytes_read: usize = 0;

        let ok = unsafe {
            ReadProcessMemory(
                handle,
                address.as_u64() as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                &mut bytes_read,
            )
        };

        if ok != 0 && bytes_read == size {
            Ok(buffer)
        } else if ok != 0 && bytes_read > 0 {
            buffer.truncate(bytes_read);
            Ok(buffer)
        } else {
            Err(PalError::ReadFailed {
                address,
                size,
                reason: std::io::Error::last_os_error().to_string(),
            })
        }
    }

    fn write_raw(&self, address: Address, data: &[u8]) -> PalResult<()> {
        let handle = self.ensure_attached()?;
        let mut bytes_written: usize = 0;

        let ok = unsafe {
            WriteProcessMemory(
                handle,
                address.as_u64() as *mut c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                &mut bytes_written,
            )
        };

        if ok != 0 && bytes_written == data.len() {
            Ok(())
        } else {
            Err(PalError::WriteFailed {
                address,
                size: data.len(),
                reason: std::io::Error::last_os_error().to_string(),
            })
        }
    }

    fn query_regions(&self) -> PalResult<Vec<MemoryRegion>> {
        let handle = self.ensure_attached()?;
        let mut regions = Vec::new();
        let mut current_address: usize = 0;

        // Query memory regions across the virtual address space
        while current_address < 0x7FFF_FFFF_FFFF_0000 {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            let ret = unsafe {
                VirtualQueryEx(
                    handle,
                    current_address as *const c_void,
                    &mut mbi,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if ret == 0 {
                break;
            }

            let region_base = mbi.BaseAddress as u64;
            let region_size = mbi.RegionSize;

            // Only committed pages contain readable/writable data
            if mbi.State == MEM_COMMIT {
                let protection = map_win32_protection(mbi.Protect);
                let region = MemoryRegion::new(
                    region_base,
                    region_base.saturating_add(region_size as u64),
                    protection,
                    None,
                );
                regions.push(region);
            }

            match current_address.checked_add(region_size) {
                Some(next) if next > current_address => current_address = next,
                _ => break,
            }
        }

        Ok(regions)
    }

    fn enumerate_modules(&self) -> PalResult<Vec<ModuleInfo>> {
        let pid = self.attached_pid.ok_or(PalError::NotAttached)?;
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                pid,
            )
        };

        let auto_snap = AutoHandle::new(snapshot).ok_or_else(|| {
            PalError::ModuleEnumFailed(pid, std::io::Error::last_os_error().to_string())
        })?;

        let mut modules = Vec::new();
        let mut me: MODULEENTRY32W = unsafe { zeroed() };
        me.dwSize = size_of::<MODULEENTRY32W>() as u32;

        if unsafe { Module32FirstW(auto_snap.raw(), &mut me) } != 0 {
            loop {
                let mod_name = wchar_to_string(&me.szModule);
                let mod_path = wchar_to_string(&me.szExePath);

                modules.push(ModuleInfo {
                    name: mod_name,
                    path: mod_path,
                    base_address: Address::new(me.modBaseAddr as u64),
                    size: me.modBaseSize as usize,
                });

                if unsafe { Module32NextW(auto_snap.raw(), &mut me) } == 0 {
                    break;
                }
            }
        }

        Ok(modules)
    }

    fn enumerate_threads(&self) -> PalResult<Vec<ThreadInfo>> {
        Ok(Vec::new())
    }

    fn set_breakpoint(
        &mut self,
        _address: Address,
        _bp_type: BreakpointType,
    ) -> PalResult<BreakpointId> {
        Err(PalError::NotSupported {
            backend: "Windows WinApi",
            feature: "software/hardware breakpoints not yet implemented".to_string(),
        })
    }

    fn remove_breakpoint(&mut self, _id: BreakpointId) -> PalResult<()> {
        Err(PalError::NotSupported {
            backend: "Windows WinApi",
            feature: "software/hardware breakpoints not yet implemented".to_string(),
        })
    }

    fn allocate_memory(&self, size: usize, protection: ProtectionFlags) -> PalResult<Address> {
        let handle = self.ensure_attached()?;
        let win_protect = to_win32_protection(protection);

        let ptr = unsafe {
            VirtualAllocEx(
                handle,
                std::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                win_protect,
            )
        };

        if ptr.is_null() {
            Err(PalError::AllocationFailed {
                size,
                reason: std::io::Error::last_os_error().to_string(),
            })
        } else {
            Ok(Address::new(ptr as u64))
        }
    }

    fn free_memory(&self, address: Address) -> PalResult<()> {
        let handle = self.ensure_attached()?;
        let ok = unsafe {
            VirtualFreeEx(
                handle,
                address.as_u64() as *mut c_void,
                0,
                MEM_RELEASE,
            )
        };

        if ok != 0 {
            Ok(())
        } else {
            Err(PalError::Internal(format!(
                "VirtualFreeEx failed at {address}: {}",
                std::io::Error::last_os_error()
            )))
        }
    }

    fn stealth_level(&self) -> StealthLevel {
        StealthLevel::Low
    }

    fn backend_name(&self) -> &'static str {
        "Windows WinApi (OpenProcess / RPM / WPM)"
    }
}

/// Convert Win32 page protection bit flags into engine-pal ProtectionFlags
fn map_win32_protection(protect: u32) -> ProtectionFlags {
    let mut flags = ProtectionFlags::NONE;
    let base_protect = protect & 0xFF;

    match base_protect {
        PAGE_NOACCESS => flags |= ProtectionFlags::NONE,
        PAGE_READONLY => flags |= ProtectionFlags::READ,
        PAGE_READWRITE | PAGE_WRITECOPY => flags |= ProtectionFlags::RW,
        PAGE_EXECUTE => flags |= ProtectionFlags::EXECUTE,
        PAGE_EXECUTE_READ => flags |= ProtectionFlags::RX,
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY => flags |= ProtectionFlags::RWX,
        _ => {}
    }

    flags
}

/// Convert engine-pal ProtectionFlags to Win32 protection constant
fn to_win32_protection(flags: ProtectionFlags) -> u32 {
    if flags.contains(ProtectionFlags::RWX) {
        PAGE_EXECUTE_READWRITE
    } else if flags.contains(ProtectionFlags::RX) {
        PAGE_EXECUTE_READ
    } else if flags.contains(ProtectionFlags::EXECUTE) {
        PAGE_EXECUTE
    } else if flags.contains(ProtectionFlags::RW) || flags.contains(ProtectionFlags::WRITE) {
        PAGE_READWRITE
    } else if flags.contains(ProtectionFlags::READ) {
        PAGE_READONLY
    } else {
        PAGE_NOACCESS
    }
}

/// Helper to decode null-terminated wide char array (UTF-16) to Rust String
pub(crate) fn wchar_to_string(wchar_slice: &[u16]) -> String {
    let len = wchar_slice
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(wchar_slice.len());
    String::from_utf16_lossy(&wchar_slice[..len])
}
