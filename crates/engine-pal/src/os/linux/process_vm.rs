use crate::error::{PalError, PalResult};
use crate::os::linux::proc_maps::{parse_process_maps, parse_process_modules};
use crate::os::linux::process_list::detect_process_arch;
use crate::traits::ProcessAccessLayer;
use crate::types::{
    Address, BreakpointId, BreakpointType, CpuArchitecture, MemoryRegion, ModuleInfo,
    ProcessId, ProtectionFlags, StealthLevel, ThreadInfo,
};
use nix::sys::uio::{process_vm_readv, process_vm_writev, RemoteIoVec};
use nix::unistd::Pid;
use std::fs;
use std::io::{IoSlice, IoSliceMut};
use std::path::Path;

/// High-speed usermode backend using Linux `process_vm_readv` / `process_vm_writev` syscalls
pub struct ProcessVmBackend {
    attached_pid: Option<ProcessId>,
    architecture: CpuArchitecture,
}

impl ProcessVmBackend {
    pub fn new() -> Self {
        ProcessVmBackend {
            attached_pid: None,
            architecture: CpuArchitecture::X86_64,
        }
    }
}

impl Default for ProcessVmBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessAccessLayer for ProcessVmBackend {
    fn attach(&mut self, pid: ProcessId) -> PalResult<()> {
        let proc_path = format!("/proc/{pid}");
        if !Path::new(&proc_path).exists() {
            return Err(PalError::ProcessNotFound(pid));
        }

        self.architecture = detect_process_arch(pid).unwrap_or(CpuArchitecture::X86_64);
        self.attached_pid = Some(pid);
        Ok(())
    }

    fn detach(&mut self) -> PalResult<()> {
        self.attached_pid = None;
        Ok(())
    }

    fn is_attached(&self) -> bool {
        self.attached_pid.is_some()
    }

    fn attached_pid(&self) -> Option<ProcessId> {
        self.attached_pid
    }

    fn architecture(&self) -> CpuArchitecture {
        self.architecture
    }

    fn read_raw(&self, address: Address, size: usize) -> PalResult<Vec<u8>> {
        let pid = self.attached_pid.ok_or(PalError::NotAttached)?;
        let mut buf = vec![0u8; size];

        let mut local_iov = [IoSliceMut::new(&mut buf)];
        let remote_iov = [RemoteIoVec {
            base: address.as_u64() as usize,
            len: size,
        }];

        match process_vm_readv(Pid::from_raw(pid as i32), &mut local_iov, &remote_iov) {
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
        let pid = self.attached_pid.ok_or(PalError::NotAttached)?;

        let local_iov = [IoSlice::new(data)];
        let remote_iov = [RemoteIoVec {
            base: address.as_u64() as usize,
            len: data.len(),
        }];

        match process_vm_writev(Pid::from_raw(pid as i32), &local_iov, &remote_iov) {
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

    fn suspend_process(&mut self) -> PalResult<()> {
        let pid = self.attached_pid.ok_or(PalError::NotAttached)?;
        nix::sys::signal::kill(Pid::from_raw(pid as i32), nix::sys::signal::Signal::SIGSTOP)
            .map_err(|e| PalError::Io(std::io::Error::from_raw_os_error(e as i32)))
    }

    fn resume_process(&mut self) -> PalResult<()> {
        let pid = self.attached_pid.ok_or(PalError::NotAttached)?;
        nix::sys::signal::kill(Pid::from_raw(pid as i32), nix::sys::signal::Signal::SIGCONT)
            .map_err(|e| PalError::Io(std::io::Error::from_raw_os_error(e as i32)))
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
        "Linux process_vm_readv"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MemoryReader;

    #[test]
    fn test_process_vm_read_self() {
        let mut backend = ProcessVmBackend::new();
        let my_pid = std::process::id();
        backend.attach(my_pid).expect("Should attach to self");

        let test_val: u32 = 0x1337BEEF;
        let addr = Address::new(&test_val as *const u32 as u64);

        let read_val = backend.read_u32(addr).expect("Should read u32 from self");
        assert_eq!(read_val, test_val);

        let regions = backend.query_regions().expect("Should query regions of self");
        assert!(!regions.is_empty(), "Memory regions should not be empty");

        let modules = backend.enumerate_modules().expect("Should query modules of self");
        assert!(!modules.is_empty(), "Modules should not be empty");
    }
}
