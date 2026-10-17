use crate::error::{PalError, PalResult};
use crate::types::{Address, CpuRegisters, DebugHit, ProcessId, ProtectionFlags};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Execute remote syscall in target process using ptrace code injection
#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_arguments)]
pub fn remote_syscall(
    pid: ProcessId,
    syscall_nr: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> PalResult<u64> {
    let pid_t = Pid::from_raw(pid as i32);
    nix::sys::ptrace::attach(pid_t).map_err(|e| {
        PalError::AttachFailed(
            pid,
            format!("ptrace attach failed: {e} (check ptrace_scope or run with permissions)"),
        )
    })?;
    let _ = waitpid(pid_t, None);

    let mut orig_regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let res = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid_t.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            &mut orig_regs as *mut _ as *mut libc::c_void,
        )
    };
    if res != 0 {
        let _ = nix::sys::ptrace::detach(pid_t, None);
        return Err(PalError::AccessDenied(
            pid,
            "Failed to read registers via PTRACE_GETREGS".into(),
        ));
    }

    let orig_rip = orig_regs.rip;

    // Read original word at RIP to restore later
    let orig_word = unsafe {
        libc::ptrace(
            libc::PTRACE_PEEKTEXT,
            pid_t.as_raw(),
            orig_rip as *mut libc::c_void,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };

    // Injected machine code: `syscall; int3` (0x0F 0x05 0xCC ...)
    let injected_word = (orig_word as u64 & !0xFFFF_FFFF) | 0x0090_90CC_050F_u64;
    unsafe {
        libc::ptrace(
            libc::PTRACE_POKETEXT,
            pid_t.as_raw(),
            orig_rip as *mut libc::c_void,
            injected_word as *mut libc::c_void,
        );
    }

    let mut new_regs = orig_regs;
    new_regs.rax = syscall_nr;
    new_regs.rdi = arg1;
    new_regs.rsi = arg2;
    new_regs.rdx = arg3;
    new_regs.r10 = arg4;
    new_regs.r8 = arg5;
    new_regs.r9 = arg6;

    unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid_t.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            &new_regs as *const _ as *mut libc::c_void,
        );
    }

    // Step the syscall instruction
    let step_res = nix::sys::ptrace::step(pid_t, None);
    let _ = waitpid(pid_t, None);

    let mut result_regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    if step_res.is_ok() {
        unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGS,
                pid_t.as_raw(),
                std::ptr::null_mut::<libc::c_void>(),
                &mut result_regs as *mut _ as *mut libc::c_void,
            );
        }
    }

    // Restore original word at RIP and restore original registers
    unsafe {
        libc::ptrace(
            libc::PTRACE_POKETEXT,
            pid_t.as_raw(),
            orig_rip as *mut libc::c_void,
            orig_word as *mut libc::c_void,
        );
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid_t.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            &orig_regs as *const _ as *mut libc::c_void,
        );
    }

    let _ = nix::sys::ptrace::detach(pid_t, None);

    let ret = result_regs.rax;
    if (ret as i64) < 0 && (ret as i64) >= -4095 {
        Err(PalError::Io(std::io::Error::from_raw_os_error(-(ret as i32))))
    } else {
        Ok(ret)
    }
}

/// Allocate remote virtual memory in target process via mmap syscall
pub fn remote_allocate(pid: ProcessId, size: usize, protection: ProtectionFlags) -> PalResult<Address> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut prot: u64 = 0;
        if protection.contains(ProtectionFlags::READ) {
            prot |= 0x1; // PROT_READ
        }
        if protection.contains(ProtectionFlags::WRITE) {
            prot |= 0x2; // PROT_WRITE
        }
        if protection.contains(ProtectionFlags::EXECUTE) {
            prot |= 0x4; // PROT_EXEC
        }

        // SYS_mmap (9): addr=0, length=size, prot, flags=MAP_PRIVATE|MAP_ANONYMOUS (0x22), fd=-1, offset=0
        let ret = remote_syscall(pid, 9, 0, size as u64, prot, 0x22, !0u64, 0)?;
        Ok(Address::new(ret))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Err(PalError::NotSupported {
            backend: "Linux ptrace",
            feature: "remote_allocate on non-x86_64 architecture".to_string(),
        })
    }
}

/// Free remote virtual memory in target process via munmap syscall
pub fn remote_free(pid: ProcessId, address: Address, size: usize) -> PalResult<()> {
    #[cfg(target_arch = "x86_64")]
    {
        // SYS_munmap (11): addr=address, length=size
        let _ = remote_syscall(pid, 11, address.as_u64(), size as u64, 0, 0, 0, 0)?;
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Err(PalError::NotSupported {
            backend: "Linux ptrace",
            feature: "remote_free on non-x86_64 architecture".to_string(),
        })
    }
}

/// Read all CPU registers from target process/thread
pub fn read_cpu_registers(pid: ProcessId) -> PalResult<CpuRegisters> {
    let pid_t = Pid::from_raw(pid as i32);
    nix::sys::ptrace::attach(pid_t).map_err(|e| {
        PalError::AttachFailed(pid, format!("ptrace attach failed: {e}"))
    })?;
    let _ = waitpid(pid_t, None);

    let mut user_regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let res = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid_t.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            &mut user_regs as *mut _ as *mut libc::c_void,
        )
    };
    let _ = nix::sys::ptrace::detach(pid_t, None);

    if res != 0 {
        return Err(PalError::AccessDenied(
            pid,
            "Failed to read CPU registers".into(),
        ));
    }

    Ok(CpuRegisters {
        rax: user_regs.rax,
        rbx: user_regs.rbx,
        rcx: user_regs.rcx,
        rdx: user_regs.rdx,
        rsi: user_regs.rsi,
        rdi: user_regs.rdi,
        rbp: user_regs.rbp,
        rsp: user_regs.rsp,
        r8: user_regs.r8,
        r9: user_regs.r9,
        r10: user_regs.r10,
        r11: user_regs.r11,
        r12: user_regs.r12,
        r13: user_regs.r13,
        r14: user_regs.r14,
        r15: user_regs.r15,
        rip: user_regs.rip,
        rflags: user_regs.eflags,
    })
}

/// Advance execution by a single CPU instruction (Single Step)
pub fn step_instruction(pid: ProcessId) -> PalResult<CpuRegisters> {
    let pid_t = Pid::from_raw(pid as i32);
    nix::sys::ptrace::attach(pid_t).map_err(|e| {
        PalError::AttachFailed(pid, format!("ptrace attach failed: {e}"))
    })?;
    let _ = waitpid(pid_t, None);

    let _ = nix::sys::ptrace::step(pid_t, None);
    let _ = waitpid(pid_t, None);

    let mut user_regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let res = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid_t.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            &mut user_regs as *mut _ as *mut libc::c_void,
        )
    };
    let _ = nix::sys::ptrace::detach(pid_t, None);

    if res != 0 {
        return Err(PalError::AccessDenied(
            pid,
            "Failed to read CPU registers after step".into(),
        ));
    }

    Ok(CpuRegisters {
        rax: user_regs.rax,
        rbx: user_regs.rbx,
        rcx: user_regs.rcx,
        rdx: user_regs.rdx,
        rsi: user_regs.rsi,
        rdi: user_regs.rdi,
        rbp: user_regs.rbp,
        rsp: user_regs.rsp,
        r8: user_regs.r8,
        r9: user_regs.r9,
        r10: user_regs.r10,
        r11: user_regs.r11,
        r12: user_regs.r12,
        r13: user_regs.r13,
        r14: user_regs.r14,
        r15: user_regs.r15,
        rip: user_regs.rip,
        rflags: user_regs.eflags,
    })
}

/// Set hardware watchpoint on target address (DR0) and monitor for writes during duration_ms
pub fn trace_hardware_watchpoint(
    pid: ProcessId,
    target_addr: Address,
    size: usize,
    duration_ms: u64,
) -> PalResult<Vec<DebugHit>> {
    let pid_t = Pid::from_raw(pid as i32);
    nix::sys::ptrace::attach(pid_t).map_err(|e| {
        PalError::AttachFailed(
            pid,
            format!("ptrace attach failed: {e} (check ptrace_scope or run with permissions)"),
        )
    })?;
    let _ = waitpid(pid_t, None);

    // Calculate DR7 control bits for slot 0:
    // condition = write (0b01)
    // size: 1B -> 0b00, 2B -> 0b01, 8B -> 0b10, 4B -> 0b11
    let len_bits: u64 = match size {
        1 => 0b00,
        2 => 0b01,
        8 => 0b10,
        _ => 0b11,
    };

    // Bit 0: Local DR0 enable
    // Bit 8: Exact breakpoint enable
    // Bits 16..17: Condition (0b01: Write)
    // Bits 18..19: Length
    // Bit 10: Invariant 1 (0x400)
    let dr7_val: u64 = 0x400 | (1 << 0) | (1 << 8) | (0b01 << 16) | (len_bits << 18);

    // Write DR0 (offset 848) and DR7 (offset 904)
    unsafe {
        libc::ptrace(
            libc::PTRACE_POKEUSER,
            pid_t.as_raw(),
            848 as *mut libc::c_void,
            target_addr.as_u64() as *mut libc::c_void,
        );
        libc::ptrace(
            libc::PTRACE_POKEUSER,
            pid_t.as_raw(),
            904 as *mut libc::c_void,
            dr7_val as *mut libc::c_void,
        );
    }

    // Resume execution with watchpoint armed
    let _ = nix::sys::ptrace::cont(pid_t, None);

    let mut hits_map: HashMap<u64, DebugHit> = HashMap::new();
    let start_time = Instant::now();
    let max_duration = Duration::from_millis(duration_ms);

    while start_time.elapsed() < max_duration {
        match waitpid(pid_t, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {
                // Check DR6 (offset 896) to see if DR0 triggered (bit 0)
                let dr6 = unsafe {
                    libc::ptrace(
                        libc::PTRACE_PEEKUSER,
                        pid_t.as_raw(),
                        896 as *mut libc::c_void,
                        std::ptr::null_mut::<libc::c_void>(),
                    )
                } as u64;

                if (dr6 & 0x1) != 0 {
                    let mut user_regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_GETREGS,
                            pid_t.as_raw(),
                            std::ptr::null_mut::<libc::c_void>(),
                            &mut user_regs as *mut _ as *mut libc::c_void,
                        );
                    }

                    let regs = CpuRegisters {
                        rax: user_regs.rax,
                        rbx: user_regs.rbx,
                        rcx: user_regs.rcx,
                        rdx: user_regs.rdx,
                        rsi: user_regs.rsi,
                        rdi: user_regs.rdi,
                        rbp: user_regs.rbp,
                        rsp: user_regs.rsp,
                        r8: user_regs.r8,
                        r9: user_regs.r9,
                        r10: user_regs.r10,
                        r11: user_regs.r11,
                        r12: user_regs.r12,
                        r13: user_regs.r13,
                        r14: user_regs.r14,
                        r15: user_regs.r15,
                        rip: user_regs.rip,
                        rflags: user_regs.eflags,
                    };

                    let hit_entry = hits_map.entry(user_regs.rip).or_insert_with(|| DebugHit {
                        address: target_addr,
                        instruction_pointer: Address::new(user_regs.rip),
                        thread_id: Some(pid),
                        hit_count: 0,
                        registers: regs,
                        disassembly: None,
                    });
                    hit_entry.hit_count += 1;
                    hit_entry.registers = regs;

                    // Clear DR6
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_POKEUSER,
                            pid_t.as_raw(),
                            896 as *mut libc::c_void,
                            std::ptr::null_mut::<libc::c_void>(),
                        );
                    }
                }

                // Resume target execution
                let _ = nix::sys::ptrace::cont(pid_t, None);
            }
            Ok(WaitStatus::Stopped(_, sig)) => {
                // If stopped by another signal, pass it along
                let _ = nix::sys::ptrace::cont(pid_t, Some(sig));
            }
            Ok(WaitStatus::StillAlive) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            _ => break,
        }
    }

    // Stop process briefly to safely clear DR0/DR7
    let _ = nix::sys::signal::kill(pid_t, Signal::SIGSTOP);
    let _ = waitpid(pid_t, None);

    unsafe {
        // Clear DR0
        libc::ptrace(
            libc::PTRACE_POKEUSER,
            pid_t.as_raw(),
            848 as *mut libc::c_void,
            std::ptr::null_mut::<libc::c_void>(),
        );
        // Clear DR7 back to standard 0x400
        libc::ptrace(
            libc::PTRACE_POKEUSER,
            pid_t.as_raw(),
            904 as *mut libc::c_void,
            0x400 as *mut libc::c_void,
        );
    }

    let _ = nix::sys::ptrace::detach(pid_t, None);
    let _ = nix::sys::signal::kill(pid_t, Signal::SIGCONT);

    Ok(hits_map.into_values().collect())
}
