use crate::error::PalResult;
use crate::traits::ProcessEnumerator;
use crate::types::{CpuArchitecture, ProcessEntry, ProcessId};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

/// Linux implementation of process enumeration via /proc filesystem
pub struct LinuxProcessEnumerator;

impl ProcessEnumerator for LinuxProcessEnumerator {
    fn list_processes(&self) -> PalResult<Vec<ProcessEntry>> {
        let mut processes = Vec::new();

        let entries = match fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => return Ok(processes),
        };

        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // Check if directory name is numeric (PID)
            if let Ok(pid) = name_str.parse::<ProcessId>() {
                if let Some(proc_entry) = inspect_process(pid) {
                    processes.push(proc_entry);
                }
            }
        }

        // Sort by PID ascending
        processes.sort_by_key(|p| p.pid);

        Ok(processes)
    }
}

/// Inspect a single process in /proc/<pid>
pub fn inspect_process(pid: ProcessId) -> Option<ProcessEntry> {
    let proc_dir = format!("/proc/{pid}");
    if !Path::new(&proc_dir).exists() {
        return None;
    }

    // 1. Get process name from /proc/<pid>/comm (or fallback to /proc/<pid>/cmdline)
    let name = fs::read_to_string(format!("{proc_dir}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| {
            fs::read_to_string(format!("{proc_dir}/cmdline"))
                .map(|s| s.split('\0').next().unwrap_or("unknown").to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        });

    // 2. Get full command line
    let cmdline = fs::read(format!("{proc_dir}/cmdline"))
        .ok()
        .map(|bytes| {
            bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|s| !s.is_empty());

    // 3. Detect architecture from /proc/<pid>/exe ELF header
    let architecture = detect_process_arch(pid).unwrap_or(CpuArchitecture::X86_64);

    Some(ProcessEntry {
        pid,
        name,
        cmdline,
        architecture,
    })
}

/// Detect whether process is 32-bit or 64-bit by reading ELF ident of /proc/<pid>/exe
pub fn detect_process_arch(pid: ProcessId) -> Option<CpuArchitecture> {
    let exe_path = format!("/proc/{pid}/exe");
    let mut file = File::open(exe_path).ok()?;
    let mut header = [0u8; 5];
    file.read_exact(&mut header).ok()?;

    // Verify ELF magic: 0x7F, 'E', 'L', 'F'
    if header[0..4] != [0x7F, b'E', b'L', b'F'] {
        return None;
    }

    // Byte 4: EI_CLASS (1 = 32-bit, 2 = 64-bit)
    match header[4] {
        1 => Some(CpuArchitecture::X86_32),
        2 => Some(CpuArchitecture::X86_64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_current_process() {
        let enumerator = LinuxProcessEnumerator;
        let procs = enumerator.list_processes().expect("Should list processes");
        let my_pid = std::process::id();

        let found = procs.iter().find(|p| p.pid == my_pid);
        assert!(found.is_some(), "Current process must be present in /proc list");
    }

    #[test]
    fn test_detect_current_arch() {
        let my_pid = std::process::id();
        let arch = detect_process_arch(my_pid).expect("Should detect current process architecture");
        #[cfg(target_pointer_width = "64")]
        assert_eq!(arch, CpuArchitecture::X86_64);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(arch, CpuArchitecture::X86_32);
    }
}
