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

// ---------------------------------------------------------------------------
// Remote function call / library loading (ptrace-based)
// ---------------------------------------------------------------------------

use std::ffi::c_void;

extern "C" {
    /// `dlopen` lives in libc on glibc >= 2.34, in libdl.so.2 on older
    /// systems. We resolve it relative to whichever module actually contains
    /// it (see [`remote_load_library`]).
    fn dlopen(filename: *const libc::c_char, flag: libc::c_int) -> *mut c_void;
}

/// Write a byte buffer into the target's memory using `PTRACE_POKEDATA`,
/// padding the final partial word. The target must be stopped.
fn poke_bytes(pid_t: Pid, addr: u64, bytes: &[u8]) -> PalResult<()> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let mut word = [0u8; 8];
        let n = (bytes.len() - offset).min(8);
        word[..n].copy_from_slice(&bytes[offset..offset + n]);
        let val = u64::from_le_bytes(word);
        let res = unsafe {
            libc::ptrace(
                libc::PTRACE_POKEDATA,
                pid_t.as_raw(),
                (addr + offset as u64) as *mut c_void,
                val as *mut c_void,
            )
        };
        if res != 0 {
            return Err(PalError::WriteFailed {
                address: Address::new(addr + offset as u64),
                size: n,
                reason: "PTRACE_POKEDATA failed".into(),
            });
        }
        offset += 8;
    }
    Ok(())
}

/// Emit `mov r64, imm64` for the low eight GPRs (opcode B8+r).
fn emit_mov_r64_imm64(stub: &mut Vec<u8>, opcode: u8, imm: u64) {
    stub.push(0x48); // REX.W
    stub.push(opcode);
    stub.extend_from_slice(&imm.to_le_bytes());
}

/// Emit `mov r8/r9, imm64` (needs a REX.B prefix).
fn emit_mov_r8_imm64(stub: &mut Vec<u8>, opcode: u8, imm: u64) {
    stub.push(0x49); // REX.W + REX.B
    stub.push(opcode);
    stub.extend_from_slice(&imm.to_le_bytes());
}

/// Build the x86-64 call stub: load up to six SysV argument registers, `call`
/// the target function and trap with `int3` so the caller can read RAX.
fn build_call_stub(func: u64, args: &[u64]) -> Vec<u8> {
    let mut stub = Vec::with_capacity(80);
    emit_mov_r64_imm64(&mut stub, 0xB8, func); // mov rax, func
    // SysV arg registers: rdi, rsi, rdx, rcx, r8, r9
    let opcodes = [0xBFu8, 0xBE, 0xBA, 0xB9];
    for (i, &arg) in args.iter().take(4).enumerate() {
        emit_mov_r64_imm64(&mut stub, opcodes[i], arg);
    }
    if let Some(&a) = args.get(4) {
        emit_mov_r8_imm64(&mut stub, 0xB8, a); // mov r8, a
    }
    if let Some(&a) = args.get(5) {
        emit_mov_r8_imm64(&mut stub, 0xB9, a); // mov r9, a
    }
    stub.push(0xFF);
    stub.push(0xD0); // call rax
    stub.push(0xCC); // int3
    stub
}

/// Invoke `func` inside the target with up to six arguments, returning RAX.
///
/// A small stub (`mov rax, func; mov rdi.. ; call rax; int3`) is written into
/// scratch memory and the target thread's RIP/RSP are redirected to it. All
/// original registers are restored afterwards, so execution continues exactly
/// where it was suspended.
#[cfg(target_arch = "x86_64")]
pub fn remote_call(pid: ProcessId, func: Address, args: &[u64]) -> PalResult<u64> {
    let pid_t = Pid::from_raw(pid as i32);

    let stub = build_call_stub(func.as_u64(), args);
    let stub_page = remote_allocate(pid, 0x1000, ProtectionFlags::RWX)?;
    let stack_size = 0x2_0000usize; // 128 KiB scratch stack
    let stack = remote_allocate(pid, stack_size, ProtectionFlags::READ | ProtectionFlags::WRITE)?;
    let stack_top = (stack.as_u64() + stack_size as u64) & !0xF; // 16-byte aligned

    nix::sys::ptrace::attach(pid_t).map_err(|e| {
        PalError::AttachFailed(
            pid,
            format!("ptrace attach failed: {e} (check ptrace_scope or run with permissions)"),
        )
    })?;
    let _ = waitpid(pid_t, None);

    let mut orig_regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let got = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid_t.as_raw(),
            std::ptr::null_mut::<c_void>(),
            &mut orig_regs as *mut _ as *mut c_void,
        )
    };
    if got != 0 {
        let _ = nix::sys::ptrace::detach(pid_t, None);
        let _ = remote_free(pid, stub_page, 0x1000);
        let _ = remote_free(pid, stack, stack_size);
        return Err(PalError::AccessDenied(
            pid,
            "PTRACE_GETREGS failed before remote_call".into(),
        ));
    }

    // Redirect execution into the stub on our scratch stack.
    if let Err(e) = poke_bytes(pid_t, stub_page.as_u64(), &stub) {
        let _ = nix::sys::ptrace::detach(pid_t, None);
        let _ = remote_free(pid, stub_page, 0x1000);
        let _ = remote_free(pid, stack, stack_size);
        return Err(e);
    }

    let mut new_regs = orig_regs;
    new_regs.rip = stub_page.as_u64();
    new_regs.rsp = stack_top;
    new_regs.rbp = stack_top;
    unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid_t.as_raw(),
            std::ptr::null_mut::<c_void>(),
            &new_regs as *const _ as *mut c_void,
        );
    }

    // Continue until the int3 fires.
    let mut result = 0u64;
    let cont = nix::sys::ptrace::cont(pid_t, None);
    if cont.is_ok() {
        let _ = waitpid(pid_t, None);
        let mut out_regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGS,
                pid_t.as_raw(),
                std::ptr::null_mut::<c_void>(),
                &mut out_regs as *mut _ as *mut c_void,
            );
        }
        result = out_regs.rax;
    }

    // Restore the original context and detach.
    unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid_t.as_raw(),
            std::ptr::null_mut::<c_void>(),
            &orig_regs as *const _ as *mut c_void,
        );
    }
    let _ = nix::sys::ptrace::detach(pid_t, None);

    let _ = remote_free(pid, stub_page, 0x1000);
    let _ = remote_free(pid, stack, stack_size);

    Ok(result)
}

#[cfg(not(target_arch = "x86_64"))]
pub fn remote_call(_pid: ProcessId, _func: Address, _args: &[u64]) -> PalResult<u64> {
    Err(PalError::NotSupported {
        backend: "Linux ptrace",
        feature: "remote_call on non-x86_64 architecture".to_string(),
    })
}

/// Change page protection of a range in the target via the `mprotect` syscall.
#[cfg(target_arch = "x86_64")]
pub fn remote_protect(
    pid: ProcessId,
    address: Address,
    size: usize,
    protection: ProtectionFlags,
) -> PalResult<()> {
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
    // SYS_mprotect (10): addr, len, prot
    let _ = remote_syscall(pid, 10, address.as_u64(), size as u64, prot, 0, 0, 0)?;
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub fn remote_protect(
    _pid: ProcessId,
    _address: Address,
    _size: usize,
    _protection: ProtectionFlags,
) -> PalResult<()> {
    Err(PalError::NotSupported {
        backend: "Linux ptrace",
        feature: "remote_protect on non-x86_64 architecture".to_string(),
    })
}

/// Lowest mapped address of the module whose path contains `needle`.
pub fn module_base_from_maps(pid: ProcessId, needle: &str) -> Option<u64> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let mut best: Option<u64> = None;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let range = match parts.next() {
            Some(r) => r,
            None => continue,
        };
        let path = parts.nth(4); // perms, offset, dev, inode -> 5th token
        let path = match path {
            Some(p) => p,
            None => continue,
        };
        if !path.contains(needle) {
            continue;
        }
        let start = match range.split('-').next().and_then(|s| u64::from_str_radix(s, 16).ok()) {
            Some(v) => v,
            None => continue,
        };
        best = Some(best.map_or(start, |b| b.min(start)));
    }
    best
}

/// Path of the module mapping that contains `addr` in `pid`.
pub fn module_path_for_addr(pid: ProcessId, addr: u64) -> Option<String> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let range = match parts.next() {
            Some(r) => r,
            None => continue,
        };
        let path = parts.nth(4);
        let path = match path {
            Some(p) => p,
            None => continue,
        };
        let mut r = range.split('-');
        let start = match r.next().and_then(|s| u64::from_str_radix(s, 16).ok()) {
            Some(v) => v,
            None => continue,
        };
        let end = match r.next().and_then(|s| u64::from_str_radix(s, 16).ok()) {
            Some(v) => v,
            None => continue,
        };
        if addr >= start && addr < end {
            return Some(path.to_string());
        }
    }
    None
}

/// Write raw bytes into the target using `process_vm_writev`.
fn write_bytes_remote(pid: ProcessId, addr: Address, data: &[u8]) -> PalResult<()> {
    let local = libc::iovec {
        iov_base: data.as_ptr() as *mut c_void,
        iov_len: data.len(),
    };
    let remote = libc::iovec {
        iov_base: addr.as_u64() as *mut c_void,
        iov_len: data.len(),
    };
    let n = unsafe {
        libc::process_vm_writev(
            pid as i32,
            &local,
            1,
            &remote,
            1,
            0,
        )
    };
    if n == data.len() as isize {
        Ok(())
    } else {
        Err(PalError::WriteFailed {
            address: addr,
            size: data.len(),
            reason: format!("process_vm_writev wrote {n} bytes"),
        })
    }
}

/// Load a shared object into the target by absolute path via remote `dlopen`,
/// returning the mapped base address.
///
/// `dlopen` is resolved by locating it in the injector's own address space,
/// computing its offset within its containing module (libc or libdl) and
/// applying that offset to the same module's base in the target. This is
/// valid when the injector and target share the same libc — the normal case
/// for native Linux processes on one host.
pub fn remote_load_library(pid: ProcessId, path: &str) -> PalResult<Address> {
    let local_dlopen = dlopen as *const () as usize as u64;
    let self_pid = std::process::id() as ProcessId;

    let containing = module_path_for_addr(self_pid, local_dlopen).ok_or_else(|| {
        PalError::Internal("could not locate dlopen's module in our own maps".into())
    })?;
    let our_base = module_base_from_maps(self_pid, &containing).ok_or_else(|| {
        PalError::Internal("could not determine dlopen module base locally".into())
    })?;
    let offset = local_dlopen.saturating_sub(our_base);

    let file_name = std::path::Path::new(&containing)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(&containing);
    let target_base = module_base_from_maps(pid, &containing)
        .or_else(|| module_base_from_maps(pid, file_name))
        .ok_or_else(|| {
            PalError::Internal(format!(
                "module '{containing}' (providing dlopen) is not loaded in target {pid}"
            ))
        })?;
    let remote_dlopen = Address::new(target_base + offset);

    // Write the path (NUL-terminated) into the target.
    let mut bytes = path.as_bytes().to_vec();
    bytes.push(0);
    let page = ((bytes.len() / 0x1000) + 1) * 0x1000;
    let path_addr = remote_allocate(pid, page, ProtectionFlags::READ | ProtectionFlags::WRITE)?;
    write_bytes_remote(pid, path_addr, &bytes)?;

    // dlopen(path, RTLD_NOW=2)
    const RTLD_NOW: u64 = 2;
    let handle = remote_call(pid, remote_dlopen, &[path_addr.as_u64(), RTLD_NOW])?;

    let _ = remote_free(pid, path_addr, page);

    if handle == 0 {
        return Err(PalError::Internal(format!(
            "remote dlopen('{path}') returned NULL"
        )));
    }
    Ok(Address::new(handle))
}

