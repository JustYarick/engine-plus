use crate::error::PalResult;
use crate::types::{
    Address, BreakpointId, BreakpointType, CpuArchitecture, CpuRegisters, DebugHit, MemoryRegion,
    ModuleInfo, ProcessEntry, ProcessId, ProtectionFlags, RemoteThreadHandle, StealthLevel,
    ThreadInfo,
};
use byteorder::{ByteOrder, LittleEndian};

/// Process Access Layer (PAL) — Primary abstraction for operating system and process interaction.
pub trait ProcessAccessLayer: Send + Sync {
    /// Connect to a running target process
    fn attach(&mut self, pid: ProcessId) -> PalResult<()>;

    /// Disconnect from the current process
    fn detach(&mut self) -> PalResult<()>;

    /// Check if currently attached to a target
    fn is_attached(&self) -> bool;

    /// Get PID of attached process, if any
    fn attached_pid(&self) -> Option<ProcessId>;

    /// Target process architecture (x86_32 or x86_64)
    fn architecture(&self) -> CpuArchitecture;

    /// Read raw bytes from target virtual memory
    fn read_raw(&self, address: Address, size: usize) -> PalResult<Vec<u8>>;

    /// Write raw bytes into target virtual memory
    fn write_raw(&self, address: Address, data: &[u8]) -> PalResult<()>;

    /// Query mapped virtual memory regions
    fn query_regions(&self) -> PalResult<Vec<MemoryRegion>>;

    /// Enumerate loaded dynamic modules (binaries, shared libraries)
    fn enumerate_modules(&self) -> PalResult<Vec<ModuleInfo>>;

    /// Enumerate active threads
    fn enumerate_threads(&self) -> PalResult<Vec<ThreadInfo>>;

    /// Set an execution or data watchpoint
    fn set_breakpoint(
        &mut self,
        address: Address,
        bp_type: BreakpointType,
    ) -> PalResult<BreakpointId>;

    /// Remove a previously set breakpoint
    fn remove_breakpoint(&mut self, id: BreakpointId) -> PalResult<()>;

    /// Suspend execution of the target process
    fn suspend_process(&mut self) -> PalResult<()> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "suspend_process not implemented".to_string(),
        })
    }

    /// Resume execution of the target process
    fn resume_process(&mut self) -> PalResult<()> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "resume_process not implemented".to_string(),
        })
    }

    /// Read CPU register state from target process or specific thread
    fn get_registers(&self, _thread_id: Option<ProcessId>) -> PalResult<CpuRegisters> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "get_registers not implemented".to_string(),
        })
    }

    /// Write CPU register state to target process or specific thread
    fn set_registers(&mut self, _thread_id: Option<ProcessId>, _regs: &CpuRegisters) -> PalResult<()> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "set_registers not implemented".to_string(),
        })
    }

    /// Advance target process or thread by a single instruction (Single Step)
    fn single_step(&mut self, _thread_id: Option<ProcessId>) -> PalResult<CpuRegisters> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "single_step not implemented".to_string(),
        })
    }

    /// Trace hardware watchpoint hits on memory address (writes or accesses)
    fn trace_watchpoint(
        &mut self,
        _address: Address,
        _size: usize,
        _duration_ms: u64,
    ) -> PalResult<Vec<DebugHit>> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "Hardware watchpoint tracing not supported by this backend".to_string(),
        })
    }

    /// Allocate virtual memory in target process
    fn allocate_memory(&self, size: usize, protection: ProtectionFlags) -> PalResult<Address>;

    /// Free allocated virtual memory in target process
    fn free_memory(&self, address: Address) -> PalResult<()>;

    /// Change page protection over a memory range, returning the previous protection.
    ///
    /// This is a core primitive for manual-mapping (setting per-section
    /// protections) and unhooking (temporarily making `.text` writable).
    fn protect_memory(
        &self,
        address: Address,
        size: usize,
        protection: ProtectionFlags,
    ) -> PalResult<ProtectionFlags> {
        let _ = (address, size, protection);
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "protect_memory not implemented".to_string(),
        })
    }

    /// Launch a thread in the target process starting at `start` with `param`.
    ///
    /// Returns a [`RemoteThreadHandle`] that can be waited on with
    /// [`ProcessAccessLayer::wait_for_thread`].
    fn create_remote_thread(
        &self,
        _start: Address,
        _param: Address,
    ) -> PalResult<RemoteThreadHandle> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "create_remote_thread not implemented".to_string(),
        })
    }

    /// Wait for a remote thread to finish and return its 32-bit exit code.
    fn wait_for_thread(&self, _thread: RemoteThreadHandle, _timeout_ms: u64) -> PalResult<u32> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "wait_for_thread not implemented".to_string(),
        })
    }

    /// Close a remote thread handle obtained from [`create_remote_thread`].
    fn close_remote_thread(&self, _thread: RemoteThreadHandle) -> PalResult<()> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "close_remote_thread not implemented".to_string(),
        })
    }

    /// Invoke a function inside the target process with up to 6 arguments,
    /// returning the raw 64-bit register result.
    ///
    /// On Linux this is implemented with a ptrace register-context swap; on
    /// Windows it is *not* directly supported (remote threads only pass a
    /// single parameter) and callers should use `create_remote_thread` or the
    /// higher-level [`ProcessAccessLayer::remote_load_library`].
    fn remote_call(&self, _func: Address, _args: &[u64]) -> PalResult<u64> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "remote_call not implemented".to_string(),
        })
    }

    /// Load a dynamic library into the target process by absolute path and
    /// return its resolved base address.
    ///
    /// Higher-level convenience used by classic `LoadLibrary` / `dlopen`
    /// injection. Implementations must resolve the *full* 64-bit base rather
    /// than trusting a truncated 32-bit thread exit code.
    fn remote_load_library(&self, _path: &str) -> PalResult<Address> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "remote_load_library not implemented".to_string(),
        })
    }

    /// Mark a thread so it no longer reports debug events to any attached
    /// debugger (Windows: `ThreadHideFromDebugger`).
    fn hide_thread(&self, _thread_id: u32) -> PalResult<()> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "hide_thread not implemented".to_string(),
        })
    }

    /// Read a pristine, memory-mapped copy of a system module's image.
    ///
    /// On Windows this maps the module's `\KnownDlls\<name>` section; the
    /// returned buffer is a *mapped view* (sections already at their virtual
    /// addresses), suitable for byte-for-byte comparison against a live
    /// module as part of unhooking. Platforms without an equivalent return
    /// `NotSupported`.
    fn read_system_module_image(&self, _name: &str) -> PalResult<Vec<u8>> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "read_system_module_image not implemented".to_string(),
        })
    }

    /// Allocate target memory backed by a page-file section, so the region
    /// reports as `MEM_MAPPED` rather than `MEM_PRIVATE`.
    fn allocate_mapped_memory(
        &self,
        _size: usize,
        _protection: ProtectionFlags,
    ) -> PalResult<Address> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "allocate_mapped_memory not implemented".to_string(),
        })
    }

    /// Convert an existing private region at `address` into a section-backed
    /// mapping of the same size, returning the mapped base.
    ///
    /// The region is briefly released before the section view is created at
    /// the same address, so the target must be suspended or cooperative.
    fn remap_as_section(&self, _address: Address, _size: usize) -> PalResult<Address> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "remap_as_section not implemented".to_string(),
        })
    }

    /// Duplicate a handle owned by the current process into `target_pid`
    /// (openable with `PROCESS_DUP_HANDLE`), closing the local copy.
    /// Returns the handle value valid in the target process.
    fn stash_handle(&self, _handle: u64, _target_pid: u32) -> PalResult<u64> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "stash_handle not implemented".to_string(),
        })
    }

    /// Duplicate a handle from `source_pid` back into the current process.
    fn unstash_handle(&self, _remote_handle: u64, _source_pid: u32) -> PalResult<u64> {
        Err(crate::error::PalError::NotSupported {
            backend: self.backend_name(),
            feature: "unstash_handle not implemented".to_string(),
        })
    }

    /// Get stealth rating of this backend
    fn stealth_level(&self) -> StealthLevel;

    /// Human-readable backend name (e.g. "Linux ProcessVM", "Kernel Driver")
    fn backend_name(&self) -> &'static str;
}

/// Provider for enumerating running processes in the operating system
pub trait ProcessEnumerator: Send + Sync {
    /// List all accessible running processes
    fn list_processes(&self) -> PalResult<Vec<ProcessEntry>>;
}

/// Ergonomic typed memory reading utilities. Automatically implemented for any `ProcessAccessLayer`.
pub trait MemoryReader {
    fn read_i8(&self, address: Address) -> PalResult<i8>;
    fn read_u8(&self, address: Address) -> PalResult<u8>;
    fn read_i16(&self, address: Address) -> PalResult<i16>;
    fn read_u16(&self, address: Address) -> PalResult<u16>;
    fn read_i32(&self, address: Address) -> PalResult<i32>;
    fn read_u32(&self, address: Address) -> PalResult<u32>;
    fn read_i64(&self, address: Address) -> PalResult<i64>;
    fn read_u64(&self, address: Address) -> PalResult<u64>;
    fn read_f32(&self, address: Address) -> PalResult<f32>;
    fn read_f64(&self, address: Address) -> PalResult<f64>;
    fn read_pointer(&self, address: Address, arch: CpuArchitecture) -> PalResult<Address>;
    fn read_string(&self, address: Address, max_len: usize) -> PalResult<String>;
}

impl<T: ProcessAccessLayer + ?Sized> MemoryReader for T {
    fn read_i8(&self, address: Address) -> PalResult<i8> {
        let bytes = self.read_raw(address, 1)?;
        Ok(bytes[0] as i8)
    }

    fn read_u8(&self, address: Address) -> PalResult<u8> {
        let bytes = self.read_raw(address, 1)?;
        Ok(bytes[0])
    }

    fn read_i16(&self, address: Address) -> PalResult<i16> {
        let bytes = self.read_raw(address, 2)?;
        Ok(LittleEndian::read_i16(&bytes))
    }

    fn read_u16(&self, address: Address) -> PalResult<u16> {
        let bytes = self.read_raw(address, 2)?;
        Ok(LittleEndian::read_u16(&bytes))
    }

    fn read_i32(&self, address: Address) -> PalResult<i32> {
        let bytes = self.read_raw(address, 4)?;
        Ok(LittleEndian::read_i32(&bytes))
    }

    fn read_u32(&self, address: Address) -> PalResult<u32> {
        let bytes = self.read_raw(address, 4)?;
        Ok(LittleEndian::read_u32(&bytes))
    }

    fn read_i64(&self, address: Address) -> PalResult<i64> {
        let bytes = self.read_raw(address, 8)?;
        Ok(LittleEndian::read_i64(&bytes))
    }

    fn read_u64(&self, address: Address) -> PalResult<u64> {
        let bytes = self.read_raw(address, 8)?;
        Ok(LittleEndian::read_u64(&bytes))
    }

    fn read_f32(&self, address: Address) -> PalResult<f32> {
        let bytes = self.read_raw(address, 4)?;
        Ok(LittleEndian::read_f32(&bytes))
    }

    fn read_f64(&self, address: Address) -> PalResult<f64> {
        let bytes = self.read_raw(address, 8)?;
        Ok(LittleEndian::read_f64(&bytes))
    }

    fn read_pointer(&self, address: Address, arch: CpuArchitecture) -> PalResult<Address> {
        match arch {
            CpuArchitecture::X86_32 => {
                let val = self.read_u32(address)?;
                Ok(Address(val as u64))
            }
            CpuArchitecture::X86_64 => {
                let val = self.read_u64(address)?;
                Ok(Address(val))
            }
        }
    }

    fn read_string(&self, address: Address, max_len: usize) -> PalResult<String> {
        let bytes = self.read_raw(address, max_len)?;
        let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..null_pos]).into_owned())
    }
}

/// Ergonomic typed memory writing utilities. Automatically implemented for any `ProcessAccessLayer`.
pub trait MemoryWriter {
    fn write_i8(&self, address: Address, val: i8) -> PalResult<()>;
    fn write_u8(&self, address: Address, val: u8) -> PalResult<()>;
    fn write_i16(&self, address: Address, val: i16) -> PalResult<()>;
    fn write_u16(&self, address: Address, val: u16) -> PalResult<()>;
    fn write_i32(&self, address: Address, val: i32) -> PalResult<()>;
    fn write_u32(&self, address: Address, val: u32) -> PalResult<()>;
    fn write_i64(&self, address: Address, val: i64) -> PalResult<()>;
    fn write_u64(&self, address: Address, val: u64) -> PalResult<()>;
    fn write_f32(&self, address: Address, val: f32) -> PalResult<()>;
    fn write_f64(&self, address: Address, val: f64) -> PalResult<()>;
    fn write_pointer(
        &self,
        address: Address,
        target: Address,
        arch: CpuArchitecture,
    ) -> PalResult<()>;
}

impl<T: ProcessAccessLayer + ?Sized> MemoryWriter for T {
    fn write_i8(&self, address: Address, val: i8) -> PalResult<()> {
        self.write_raw(address, &[val as u8])
    }

    fn write_u8(&self, address: Address, val: u8) -> PalResult<()> {
        self.write_raw(address, &[val])
    }

    fn write_i16(&self, address: Address, val: i16) -> PalResult<()> {
        let mut buf = [0u8; 2];
        LittleEndian::write_i16(&mut buf, val);
        self.write_raw(address, &buf)
    }

    fn write_u16(&self, address: Address, val: u16) -> PalResult<()> {
        let mut buf = [0u8; 2];
        LittleEndian::write_u16(&mut buf, val);
        self.write_raw(address, &buf)
    }

    fn write_i32(&self, address: Address, val: i32) -> PalResult<()> {
        let mut buf = [0u8; 4];
        LittleEndian::write_i32(&mut buf, val);
        self.write_raw(address, &buf)
    }

    fn write_u32(&self, address: Address, val: u32) -> PalResult<()> {
        let mut buf = [0u8; 4];
        LittleEndian::write_u32(&mut buf, val);
        self.write_raw(address, &buf)
    }

    fn write_i64(&self, address: Address, val: i64) -> PalResult<()> {
        let mut buf = [0u8; 8];
        LittleEndian::write_i64(&mut buf, val);
        self.write_raw(address, &buf)
    }

    fn write_u64(&self, address: Address, val: u64) -> PalResult<()> {
        let mut buf = [0u8; 8];
        LittleEndian::write_u64(&mut buf, val);
        self.write_raw(address, &buf)
    }

    fn write_f32(&self, address: Address, val: f32) -> PalResult<()> {
        let mut buf = [0u8; 4];
        LittleEndian::write_f32(&mut buf, val);
        self.write_raw(address, &buf)
    }

    fn write_f64(&self, address: Address, val: f64) -> PalResult<()> {
        let mut buf = [0u8; 8];
        LittleEndian::write_f64(&mut buf, val);
        self.write_raw(address, &buf)
    }

    fn write_pointer(
        &self,
        address: Address,
        target: Address,
        arch: CpuArchitecture,
    ) -> PalResult<()> {
        match arch {
            CpuArchitecture::X86_32 => self.write_u32(address, target.0 as u32),
            CpuArchitecture::X86_64 => self.write_u64(address, target.0),
        }
    }
}
