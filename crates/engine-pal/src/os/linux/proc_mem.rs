use crate::error::{PalError, PalResult};
use crate::os::linux::proc_maps::{parse_process_maps, parse_process_modules};
use crate::os::linux::process_list::detect_process_arch;
use crate::traits::ProcessAccessLayer;
use crate::types::{
    Address, BreakpointId, BreakpointType, CpuArchitecture, MemoryRegion, ModuleInfo,
    ProcessId, ProtectionFlags, StealthLevel, ThreadInfo,
};
use nix::sys::uio::{pread, pwrite};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;

/// Linux backend using /proc/<pid>/mem direct file descriptors with atomic pread/pwrite
pub struct ProcMemBackend {
    attached_pid: Option<ProcessId>,
    mem_file: Option<File>,
    architecture: CpuArchitecture,
}

impl ProcMemBackend {
    pub fn new() -> Self {
        ProcMemBackend {
            attached_pid: None,
            mem_file: None,
            architecture: CpuArchitecture::X86_64,
        }
    }
}

impl Default for ProcMemBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessAccessLayer for ProcMemBackend {
    fn attach(&mut self, pid: ProcessId) -> PalResult<()> {
        let mem_path = format!("/proc/{pid}/mem");

        // Try opening read-write, fallback to read-only
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_LARGEFILE)
            .open(&mem_path)
            .or_else(|_| {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_LARGEFILE)
                    .open(&mem_path)
            })
            .map_err(|e| PalError::AttachFailed(pid, format!("Cannot open {mem_path}: {e}")))?;

        self.architecture = detect_process_arch(pid).unwrap_or(CpuArchitecture::X86_64);
        self.attached_pid = Some(pid);
        self.mem_file = Some(file);

        Ok(())
    }

    fn detach(&mut self) -> PalResult<()> {
        self.attached_pid = None;
        self.mem_file = None;
        Ok(())
    }

    fn is_attached(&self) -> bool {
        self.attached_pid.is_some() && self.mem_file.is_some()
    }

    fn attached_pid(&self) -> Option<ProcessId> {
        self.attached_pid
    }

    fn architecture(&self) -> CpuArchitecture {
        self.architecture
    }

    fn read_raw(&self, address: Address, size: usize) -> PalResult<Vec<u8>> {
        let file = self.mem_file.as_ref().ok_or(PalError::NotAttached)?;
        let mut buf = vec![0u8; size];

        match pread(file, &mut buf, address.as_u64() as i64) {
            Ok(bytes_read) => {
                if bytes_read < size {
                    buf.truncate(bytes_read);
                }
                Ok(buf)
            }
            Err(errno) => Err(PalError::ReadFailed {
                address,
                size,
                reason: errno.to_string(),
            }),
        }
    }

    fn write_raw(&self, address: Address, data: &[u8]) -> PalResult<()> {
        let file = self.mem_file.as_ref().ok_or(PalError::NotAttached)?;

        match pwrite(file, data, address.as_u64() as i64) {
            Ok(bytes_written) => {
                if bytes_written == data.len() {
                    Ok(())
                } else {
                    Err(PalError::WriteFailed {
                        address,
                        size: data.len(),
                        reason: format!("Partial write: {bytes_written} of {} bytes", data.len()),
                    })
                }
            }
            Err(errno) => Err(PalError::WriteFailed {
                address,
                size: data.len(),
                reason: errno.to_string(),
            }),
        }
    }

    fn query_regions(&self) -> PalResult<Vec<MemoryRegion>> {
        let pid = self.attached_pid.ok_or(PalError::NotAttached)?;
        parse_process_maps(pid)
    }

    fn enumerate_modules(&self) -> PalResult<Vec<ModuleInfo>> {
        let pid = self.attached_pid.ok_or(PalError::NotAttached)?;
        parse_process_modules(pid)
    }

    fn enumerate_threads(&self) -> PalResult<Vec<ThreadInfo>> {
        let pid = self.attached_pid.ok_or(PalError::NotAttached)?;
        let task_dir = format!("/proc/{pid}/task");

        let mut threads = Vec::new();
        if let Ok(entries) = fs::read_dir(task_dir) {
            for entry in entries.flatten() {
                if let Ok(tid) = entry.file_name().to_string_lossy().parse::<u32>() {
                    threads.push(ThreadInfo {
                        id: tid,
                        state: None,
                    });
                }
            }
        }
        threads.sort_by_key(|t| t.id);
        Ok(threads)
    }

    fn set_breakpoint(
        &mut self,
        _address: Address,
        _bp_type: BreakpointType,
    ) -> PalResult<BreakpointId> {
        Err(PalError::NotSupported {
            backend: self.backend_name(),
            feature: "Breakpoints require ptrace or kernel driver backend".to_string(),
        })
    }

    fn remove_breakpoint(&mut self, _id: BreakpointId) -> PalResult<()> {
        Err(PalError::NotSupported {
            backend: self.backend_name(),
            feature: "Breakpoints require ptrace or kernel driver backend".to_string(),
        })
    }

    fn allocate_memory(&self, _size: usize, _protection: ProtectionFlags) -> PalResult<Address> {
        Err(PalError::NotSupported {
            backend: self.backend_name(),
            feature: "Remote allocation requires ptrace injection or kernel driver".to_string(),
        })
    }

    fn free_memory(&self, _address: Address) -> PalResult<()> {
        Err(PalError::NotSupported {
            backend: self.backend_name(),
            feature: "Remote free requires ptrace injection or kernel driver".to_string(),
        })
    }

    fn stealth_level(&self) -> StealthLevel {
        StealthLevel::Low
    }

    fn backend_name(&self) -> &'static str {
        "Linux /proc/pid/mem"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MemoryReader;

    #[test]
    fn test_proc_mem_read_self() {
        let mut backend = ProcMemBackend::new();
        let my_pid = std::process::id();
        backend.attach(my_pid).expect("Should attach to self via /proc/pid/mem");

        let test_val: u64 = 0xDEAD_CAFE_BABE_F00D;
        let addr = Address::new(&test_val as *const u64 as u64);

        let read_val = backend.read_u64(addr).expect("Should read u64 from self");
        assert_eq!(read_val, test_val);
    }
}
