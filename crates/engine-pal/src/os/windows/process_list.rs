use crate::error::{PalError, PalResult};
use crate::os::windows::winapi::{wchar_to_string, AutoHandle};
use crate::traits::ProcessEnumerator;
use crate::types::{CpuArchitecture, ProcessEntry};
use std::mem::{size_of, zeroed};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

/// Process enumerator for Windows using Toolhelp32 snapshot API
pub struct WindowsProcessEnumerator;

impl ProcessEnumerator for WindowsProcessEnumerator {
    fn list_processes(&self) -> PalResult<Vec<ProcessEntry>> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        let auto_snap = AutoHandle::new(snapshot).ok_or_else(|| {
            PalError::Internal(format!(
                "Failed to snapshot processes: {}",
                std::io::Error::last_os_error()
            ))
        })?;

        let mut processes = Vec::new();
        let mut pe: PROCESSENTRY32W = unsafe { zeroed() };
        pe.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        if unsafe { Process32FirstW(auto_snap.raw(), &mut pe) } != 0 {
            loop {
                let name = wchar_to_string(&pe.szExeFile);
                let pid = pe.th32ProcessID;

                processes.push(ProcessEntry {
                    pid,
                    name,
                    cmdline: None,
                    architecture: CpuArchitecture::X86_64,
                });

                if unsafe { Process32NextW(auto_snap.raw(), &mut pe) } == 0 {
                    break;
                }
            }
        }

        Ok(processes)
    }
}

impl WindowsProcessEnumerator {
    pub fn find_process_by_name(&self, name: &str) -> PalResult<Vec<ProcessEntry>> {
        let all = self.list_processes()?;
        let query = name.to_lowercase();
        Ok(all
            .into_iter()
            .filter(|p| p.name.to_lowercase().contains(&query))
            .collect())
    }
}
