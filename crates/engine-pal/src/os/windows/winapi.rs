use crate::error::{PalError, PalResult};
use crate::traits::ProcessAccessLayer;
use crate::types::{
    Address, BreakpointId, BreakpointType, CpuArchitecture, MemoryRegion, ModuleInfo, ProcessId,
    ProtectionFlags, RemoteThreadHandle, StealthLevel, ThreadInfo,
};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, WriteProcessMemory,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPTHREAD, Thread32First, Thread32Next,
    THREADENTRY32,
};
use windows_sys::Win32::System::Memory::{
    MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, VirtualAllocEx, VirtualFreeEx,
    VirtualProtectEx, VirtualQueryEx, FILE_MAP_READ, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    SEC_COMMIT, SECTION_ALL_ACCESS,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetCurrentProcess, GetExitCodeThread, OpenProcess, OpenThread,
    ResumeThread, SuspendThread, WaitForSingleObject, PROCESS_ALL_ACCESS, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    THREAD_SET_INFORMATION, THREAD_SUSPEND_RESUME, THREAD_TERMINATE,
};
use windows_sys::Wdk::Storage::FileSystem::NtCreateSection;
use windows_sys::Wdk::System::Memory::{NtMapViewOfSection, ViewUnmap};
use windows_sys::Wdk::System::Threading::{NtSetInformationThread, ThreadHideFromDebugger};

/// Infinite wait constant for [`WaitForSingleObject`]
const INFINITE_WAIT: u32 = 0xFFFF_FFFF;
/// `WAIT_TIMEOUT` returned by WaitForSingleObject
const WAIT_TIMEOUT: u32 = 0x102;

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
    /// Live remote-thread handles keyed by TID so they can be waited on / closed.
    remote_threads: Mutex<std::collections::HashMap<u32, usize>>,
}

impl WinApiBackend {
    pub fn new() -> Self {
        WinApiBackend {
            attached_pid: None,
            process_handle: None,
            remote_threads: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn ensure_attached(&self) -> PalResult<HANDLE> {
        self.process_handle
            .as_ref()
            .map(|h| h.raw())
            .ok_or(PalError::NotAttached)
    }

    /// Find a loaded module's base address in the target by (case-insensitive) name.
    fn find_module_base(&self, name: &str) -> Option<Address> {
        let target = name.to_lowercase();
        self.enumerate_modules()
            .ok()?
            .into_iter()
            .find(|m| m.name.to_lowercase() == target)
            .map(|m| m.base_address)
    }

    /// Resolve an exported function address in a module mapped inside the target.
    ///
    /// Reads the remote PE export directory and walks it to match `name`.
    fn resolve_export(&self, module_base: Address, name: &str) -> Option<Address> {
        // Read DOS header enough to find e_lfanew.
        let dos = self.read_raw(module_base, 0x40).ok()?;
        let pe_offset = u32::from_le_bytes(dos.get(0x3C..0x40)?.try_into().ok()?) as u64;

        let nt = self.read_raw(module_base + pe_offset as usize, 0x108).ok()?;
        // Optional header starts at nt+24; magic at +0.
        let opt_magic = u16::from_le_bytes(nt.get(24..26)?.try_into().ok()?);
        let pe32_plus = opt_magic == 0x20B;

        // DataDirectory[0] (export) file offset within NT headers:
        // PE32+: 24 + 112 = 136; PE32: 24 + 96 = 120.
        let dd = if pe32_plus { 136 } else { 120 };
        let export_rva = u32::from_le_bytes(nt.get(dd..dd + 4)?.try_into().ok()?) as u64;
        let export_size = u32::from_le_bytes(nt.get(dd + 4..dd + 8)?.try_into().ok()?) as u64;
        if export_rva == 0 || export_size == 0 {
            return None;
        }

        let export = self
            .read_raw(module_base + export_rva as usize, 40)
            .ok()?;
        let num_names = u32::from_le_bytes(export.get(24..28)?.try_into().ok()?) as u64;
        let addr_of_funcs = u32::from_le_bytes(export.get(28..32)?.try_into().ok()?) as u64;
        let addr_of_names = u32::from_le_bytes(export.get(32..36)?.try_into().ok()?) as u64;
        let addr_of_ords = u32::from_le_bytes(export.get(36..40)?.try_into().ok()?) as u64;

        let names = self
            .read_raw(module_base + addr_of_names as usize, (num_names * 4) as usize)
            .ok()?;
        let ords = self
            .read_raw(module_base + addr_of_ords as usize, (num_names * 2) as usize)
            .ok()?;

        for i in 0..num_names {
            let name_rva =
                u32::from_le_bytes(names.get((i * 4) as usize..(i * 4 + 4) as usize)?.try_into().ok()?) as u64;
            let remote_name = self.read_c_string(module_base + name_rva as usize, 256).ok()?;
            if remote_name == name {
                let ord_index =
                    u16::from_le_bytes(ords.get((i * 2) as usize..(i * 2 + 2) as usize)?.try_into().ok()?) as u64;
                let func_rva = u32::from_le_bytes(
                    self.read_raw(module_base + addr_of_funcs as usize + (ord_index * 4) as usize, 4)
                        .ok()?
                        .get(0..4)?
                        .try_into()
                        .ok()?,
                ) as u64;
                return Some(module_base + func_rva as usize);
            }
        }
        None
    }

    /// Read a NUL-terminated ASCII string from the target.
    fn read_c_string(&self, address: Address, max_len: usize) -> PalResult<String> {
        let bytes = self.read_raw(address, max_len)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    /// Create a page-file-backed section and map one `ViewUnmap` view of it
    /// into `process`. Returns the mapped address in the target.
    fn map_pagefile_section(
        &self,
        process: HANDLE,
        size: usize,
        section_protection: u32,
        view_protection: u32,
    ) -> PalResult<*mut c_void> {
        let mut section: HANDLE = std::ptr::null_mut();
        let max_size: i64 = size as i64;
        let status = unsafe {
            NtCreateSection(
                &mut section,
                SECTION_ALL_ACCESS,
                std::ptr::null(),
                &max_size,
                section_protection,
                SEC_COMMIT,
                std::ptr::null_mut(),
            )
        };
        if status < 0 {
            return Err(PalError::Internal(format!(
                "NtCreateSection failed: 0x{status:08X}"
            )));
        }
        let auto = AutoHandle::new(section)
            .ok_or_else(|| PalError::Internal("NtCreateSection returned a null handle".into()))?;

        let mut base: *mut c_void = std::ptr::null_mut();
        let mut view_size: usize = 0;
        let status = unsafe {
            NtMapViewOfSection(
                auto.raw(),
                process,
                &mut base,
                0,
                0,
                std::ptr::null_mut(),
                &mut view_size,
                ViewUnmap,
                0,
                view_protection,
            )
        };
        if status < 0 {
            return Err(PalError::Internal(format!(
                "NtMapViewOfSection failed: 0x{status:08X}"
            )));
        }
        Ok(base)
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
        let pid = self.attached_pid.ok_or(PalError::NotAttached)?;
        let mut threads = Vec::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap != INVALID_HANDLE_VALUE {
                let _snap_guard = AutoHandle::new(snap);
                let mut entry: THREADENTRY32 = zeroed();
                entry.dwSize = size_of::<THREADENTRY32>() as u32;
                if Thread32First(snap, &mut entry) != 0 {
                    loop {
                        if entry.th32OwnerProcessID == pid {
                            threads.push(ThreadInfo {
                                id: entry.th32ThreadID,
                                state: None,
                            });
                        }
                        if Thread32Next(snap, &mut entry) == 0 {
                            break;
                        }
                    }
                }
            }
        }
        Ok(threads)
    }

    fn suspend_process(&mut self) -> PalResult<()> {
        let pid = self.attached_pid.ok_or(PalError::NotAttached)?;
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap == INVALID_HANDLE_VALUE {
                return Err(PalError::Io(std::io::Error::last_os_error()));
            }
            let _snap_guard = AutoHandle::new(snap);
            let mut entry: THREADENTRY32 = zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;
            if Thread32First(snap, &mut entry) != 0 {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        let h_thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                        if let Some(_th_guard) = AutoHandle::new(h_thread) {
                            SuspendThread(h_thread);
                        }
                    }
                    if Thread32Next(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn resume_process(&mut self) -> PalResult<()> {
        let pid = self.attached_pid.ok_or(PalError::NotAttached)?;
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap == INVALID_HANDLE_VALUE {
                return Err(PalError::Io(std::io::Error::last_os_error()));
            }
            let _snap_guard = AutoHandle::new(snap);
            let mut entry: THREADENTRY32 = zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;
            if Thread32First(snap, &mut entry) != 0 {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        let h_thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                        if let Some(_th_guard) = AutoHandle::new(h_thread) {
                            ResumeThread(h_thread);
                        }
                    }
                    if Thread32Next(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
        }
        Ok(())
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

    fn protect_memory(
        &self,
        address: Address,
        size: usize,
        protection: ProtectionFlags,
    ) -> PalResult<ProtectionFlags> {
        let handle = self.ensure_attached()?;
        let new_protect = to_win32_protection(protection);
        let mut old_protect: u32 = 0;

        let ok = unsafe {
            VirtualProtectEx(
                handle,
                address.as_u64() as *const c_void,
                size,
                new_protect,
                &mut old_protect,
            )
        };

        if ok != 0 {
            Ok(map_win32_protection(old_protect))
        } else {
            Err(PalError::WriteFailed {
                address,
                size,
                reason: format!(
                    "VirtualProtectEx failed: {}",
                    std::io::Error::last_os_error()
                ),
            })
        }
    }

    fn create_remote_thread(
        &self,
        start: Address,
        param: Address,
    ) -> PalResult<RemoteThreadHandle> {
        let handle = self.ensure_attached()?;
        let mut tid: u32 = 0;

        let thread = unsafe {
            CreateRemoteThread(
                handle,
                std::ptr::null(),
                0,
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut c_void) -> u32,
                >(start.as_u64() as usize)),
                param.as_u64() as *const c_void,
                0,
                &mut tid,
            )
        };

        if thread.is_null() {
            return Err(PalError::Internal(format!(
                "CreateRemoteThread failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        if let Ok(mut map) = self.remote_threads.lock() {
            map.insert(tid, thread as usize);
        }

        Ok(RemoteThreadHandle { id: tid })
    }

    fn wait_for_thread(&self, thread: RemoteThreadHandle, timeout_ms: u64) -> PalResult<u32> {
        let thread_handle = {
            let map = self.remote_threads.lock().map_err(|_| {
                PalError::Internal("remote thread registry lock poisoned".to_string())
            })?;
            (*map.get(&thread.id).ok_or_else(|| {
                PalError::Internal(format!("unknown remote thread {}", thread.id))
            })?) as HANDLE
        };

        let timeout = if timeout_ms >= INFINITE_WAIT as u64 {
            INFINITE_WAIT
        } else {
            timeout_ms as u32
        };

        let wait_result = unsafe { WaitForSingleObject(thread_handle, timeout) };
        if wait_result == WAIT_TIMEOUT {
            return Err(PalError::Internal(format!(
                "remote thread {} did not finish within {timeout_ms} ms",
                thread.id
            )));
        }

        let mut exit_code: u32 = 0;
        let ok = unsafe { GetExitCodeThread(thread_handle, &mut exit_code) };
        if ok != 0 {
            Ok(exit_code)
        } else {
            Err(PalError::Internal(format!(
                "GetExitCodeThread failed: {}",
                std::io::Error::last_os_error()
            )))
        }
    }

    fn close_remote_thread(&self, thread: RemoteThreadHandle) -> PalResult<()> {
        let handle = self
            .remote_threads
            .lock()
            .map_err(|_| PalError::Internal("remote thread registry lock poisoned".to_string()))?
            .remove(&thread.id)
            .ok_or_else(|| {
                PalError::Internal(format!("unknown remote thread {}", thread.id))
            })?;

        unsafe { CloseHandle(handle as HANDLE) };
        Ok(())
    }

    fn remote_load_library(&self, path: &str) -> PalResult<Address> {
        let pid = self.attached_pid.ok_or(PalError::NotAttached)?;

        // Locate LoadLibraryW in our own kernel32 (system DLLs share a base
        // across processes on the same boot), then reuse the target's copy.
        let kernel32 = self.find_module_base("kernel32.dll").ok_or_else(|| {
            PalError::Internal("kernel32.dll not loaded in target".to_string())
        })?;
        let load_library_w = self
            .resolve_export(kernel32, "LoadLibraryW")
            .ok_or_else(|| {
                PalError::Internal("could not resolve LoadLibraryW".to_string())
            })?;

        // Write the wide path into the target.
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let wide_bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_le_bytes()).collect();
        let byte_len = wide_bytes.len();
        let remote_buf = self.allocate_memory(byte_len, ProtectionFlags::RW)?;
        self.write_raw(remote_buf, &wide_bytes)?;

        let thread = self.create_remote_thread(load_library_w, remote_buf)?;
        let _ = self.wait_for_thread(thread, 15_000);
        let _ = self.close_remote_thread(thread);
        let _ = self.free_memory(remote_buf);

        // Resolve the full 64-bit base by re-scanning modules (thread exit
        // codes truncate handles on x64).
        let file_name = std::path::Path::new(path)
            .file_name()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_else(|| path.to_lowercase());

        for module in self.enumerate_modules()? {
            if module.name.to_lowercase() == file_name {
                return Ok(module.base_address);
            }
        }

        let _ = pid;
        Err(PalError::Internal(format!(
            "LoadLibraryW succeeded but module '{file_name}' not found in target"
        )))
    }

    fn hide_thread(&self, thread_id: u32) -> PalResult<()> {
        let thread = unsafe { OpenThread(THREAD_SET_INFORMATION | THREAD_TERMINATE, 0, thread_id) };
        let auto = AutoHandle::new(thread).ok_or_else(|| {
            PalError::Internal(format!(
                "OpenThread({thread_id}) failed: {}",
                std::io::Error::last_os_error()
            ))
        })?;

        let status = unsafe {
            NtSetInformationThread(
                auto.raw(),
                ThreadHideFromDebugger,
                std::ptr::null(),
                0,
            )
        };

        // NT_SUCCESS: severity bits 30-31 == 00
        if (status as u32) >> 30 == 0 {
            Ok(())
        } else {
            Err(PalError::Internal(format!(
                "NtSetInformationThread(ThreadHideFromDebugger) returned 0x{status:08X}"
            )))
        }
    }

    fn read_system_module_image(&self, name: &str) -> PalResult<Vec<u8>> {
        let full = if name.starts_with('\\') {
            name.to_string()
        } else {
            format!("\\KnownDlls\\{name}")
        };
        let wide: Vec<u16> = full.encode_utf16().chain(std::iter::once(0)).collect();

        let mapping = unsafe { OpenFileMappingW(FILE_MAP_READ, 0, wide.as_ptr()) };
        let auto = AutoHandle::new(mapping).ok_or_else(|| {
            PalError::Internal(format!(
                "OpenFileMappingW({full}) failed: {}",
                std::io::Error::last_os_error()
            ))
        })?;

        let view = unsafe { MapViewOfFile(auto.raw(), FILE_MAP_READ, 0, 0, 0) };
        let base = view.Value;
        if base.is_null() {
            return Err(PalError::Internal(format!(
                "MapViewOfFile({full}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let result = unsafe { copy_mapped_image(base as *const u8) };
        unsafe {
            UnmapViewOfFile(view);
        }
        result
    }

    fn allocate_mapped_memory(
        &self,
        size: usize,
        protection: ProtectionFlags,
    ) -> PalResult<Address> {
        let handle = self.ensure_attached()?;
        let win_prot = to_win32_protection(protection);
        let section_prot = if protection.contains(ProtectionFlags::EXECUTE) {
            PAGE_EXECUTE_READWRITE
        } else {
            PAGE_READWRITE
        };
        let mapped = self.map_pagefile_section(handle, size, section_prot, win_prot)?;
        Ok(Address::new(mapped as u64))
    }

    fn remap_as_section(&self, address: Address, size: usize) -> PalResult<Address> {
        let handle = self.ensure_attached()?;
        // Snapshot the contents before releasing the private region.
        let contents = self.read_raw(address, size)?;

        let mut section: HANDLE = std::ptr::null_mut();
        let max_size: i64 = size as i64;
        let status = unsafe {
            NtCreateSection(
                &mut section,
                SECTION_ALL_ACCESS,
                std::ptr::null(),
                &max_size,
                PAGE_READWRITE,
                SEC_COMMIT,
                std::ptr::null_mut(),
            )
        };
        if status < 0 {
            return Err(PalError::Internal(format!(
                "NtCreateSection failed: 0x{status:08X}"
            )));
        }
        let auto = AutoHandle::new(section)
            .ok_or_else(|| PalError::Internal("NtCreateSection returned a null handle".into()))?;

        // Release the original private pages so the address is free.
        let freed = unsafe {
            VirtualFreeEx(handle, address.as_u64() as *mut c_void, 0, MEM_RELEASE)
        };
        if freed == 0 {
            return Err(PalError::Internal(format!(
                "VirtualFreeEx({address}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut base: *mut c_void = address.as_u64() as *mut c_void;
        let mut view_size: usize = 0;
        let status = unsafe {
            NtMapViewOfSection(
                auto.raw(),
                handle,
                &mut base,
                0,
                0,
                std::ptr::null_mut(),
                &mut view_size,
                ViewUnmap,
                0,
                PAGE_READWRITE,
            )
        };
        if status < 0 {
            return Err(PalError::Internal(format!(
                "NtMapViewOfSection (remap) failed: 0x{status:08X}"
            )));
        }

        let mapped = Address::new(base as u64);
        self.write_raw(mapped, &contents)?;
        Ok(mapped)
    }

    fn stash_handle(&self, handle: u64, target_pid: u32) -> PalResult<u64> {
        let target = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, target_pid) };
        let auto = AutoHandle::new(target).ok_or_else(|| {
            PalError::Internal(format!(
                "OpenProcess(PROCESS_DUP_HANDLE, {target_pid}) failed: {}",
                std::io::Error::last_os_error()
            ))
        })?;

        let mut out: HANDLE = std::ptr::null_mut();
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle as usize as HANDLE,
                auto.raw(),
                &mut out,
                0,
                0,
                DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
            )
        };
        if ok == 0 {
            return Err(PalError::Internal(format!(
                "DuplicateHandle (stash) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(out as usize as u64)
    }

    fn unstash_handle(&self, remote_handle: u64, source_pid: u32) -> PalResult<u64> {
        let source = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, source_pid) };
        let auto = AutoHandle::new(source).ok_or_else(|| {
            PalError::Internal(format!(
                "OpenProcess(PROCESS_DUP_HANDLE, {source_pid}) failed: {}",
                std::io::Error::last_os_error()
            ))
        })?;

        let mut out: HANDLE = std::ptr::null_mut();
        let ok = unsafe {
            DuplicateHandle(
                auto.raw(),
                remote_handle as usize as HANDLE,
                GetCurrentProcess(),
                &mut out,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            return Err(PalError::Internal(format!(
                "DuplicateHandle (unstash) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(out as usize as u64)
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

/// Copy the in-memory image whose PE headers start at `base` into a `Vec<u8>`.
///
/// `base` must point at a valid, readable mapped image (e.g. a `\KnownDlls`
/// view). The image length is taken from its `SizeOfImage` field.
///
/// # Safety
/// `base` must point to a readable copy of a PE image.
unsafe fn copy_mapped_image(base: *const u8) -> PalResult<Vec<u8>> {
    // e_lfanew is at offset 0x3C.
    let e_lfanew = std::ptr::read_unaligned(base.add(0x3C) as *const u32) as usize;
    if !(0x40..0x1000).contains(&e_lfanew) {
        return Err(PalError::Internal(format!(
            "implausible e_lfanew 0x{e_lfanew:X} in mapped image"
        )));
    }
    // Optional header starts at e_lfanew + 4 (sig) + 20 (COFF); SizeOfImage at +56.
    let opt = e_lfanew + 24;
    let size_of_image = std::ptr::read_unaligned(base.add(opt + 56) as *const u32) as usize;
    if size_of_image == 0 || size_of_image > 0x2000_0000 {
        return Err(PalError::Internal(format!(
            "implausible SizeOfImage 0x{size_of_image:X} in mapped image"
        )));
    }
    let slice = std::slice::from_raw_parts(base, size_of_image);
    Ok(slice.to_vec())
}
