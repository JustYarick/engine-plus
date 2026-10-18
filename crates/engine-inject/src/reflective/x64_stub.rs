//! Position-independent reflective-loader stub for **Windows x64**.
//!
//! [`build`] assembles a small, self-contained x64 routine with `iced-x86`.
//! The bytes are appended after a raw PE (PE32+) image by
//! [`super::ReflectiveLoader::inject_stub`] and started with
//! `CreateRemoteThread`, which passes the *raw* image pointer in `RCX`.
//!
//! # What the stub does
//!
//! The routine performs a complete in-process *manual map* and never relies on
//! the OS loader, the filesystem, or any import of its own:
//!
//! 1. Save `RCX` (raw source image base) in `R15`.
//! 2. Walk the PEB (`gs:[0x60]`) to find `kernel32.dll`'s base address.
//! 3. Resolve `LoadLibraryA`, `GetProcAddress` and `VirtualAlloc` by walking
//!    `kernel32`'s export directory *by name* (a generic resolver lives in the
//!    stub itself; the three names are embedded as RIP-relative ASCII data).
//! 4. `VirtualAlloc(NULL, SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)`
//!    to obtain the destination base.
//! 5. Copy the headers (`SizeOfHeaders` bytes) and every section
//!    (`SizeOfRawData` from `PointerToRawData` to `VirtualAddress`).
//! 6. Apply base relocations (`IMAGE_REL_BASED_HIGHLOW` + `IMAGE_REL_BASED_DIR64`).
//! 7. For every import descriptor: `LoadLibraryA` the dependency and
//!    `GetProcAddress` each symbol, writing the resolved address into the
//!    mapped image's IAT.
//! 8. Call the mapped entry point as
//!    `DllMain(mapped_base, DLL_PROCESS_ATTACH, NULL)` and return its `BOOL`
//!    result in `EAX` (the remote-thread exit code); `0` on any hard failure.
//! 9. Restore every callee-saved register it used and `RET`.
//!
//! # Position independence & determinism
//!
//! The stub contains no absolute addresses. Strings are referenced
//! RIP-relatively and branch targets are fixed up by `iced_x86::BlockEncoder`
//! relative to a base IP of `0`, so the same input always yields the same
//! bytes (the assembly is a pure function of `image_len`).
//!
//! # Known limitations (documented, by design)
//!
//! * **Forwarder exports are not resolved.** The name resolver returns whatever
//!   RVA `kernel32` advertises. This is the standard Reflective-DLL-Injection
//!   assumption: `kernel32!LoadLibraryA`, `kernel32!GetProcAddress` and
//!   `kernel32!VirtualAlloc` are present as ordinary exports reachable this
//!   way. If a target re-exports them as forwarders, resolution would yield a
//!   pointer into the export directory instead of the real function.
//! * **PE32+ (64-bit) images only.** `ReflectiveLoader` routes 32-bit images to
//!   `InjectError::NotSupported`, so import thunks are always 64-bit here. The
//!   optional-header *magic* is still inspected so the same resolver works for
//!   both optional-header layouts (defensive; the source image is x64).
//! * **`kernel32` is located by fixed module-list position** (3rd entry of the
//!   `InMemoryOrderModuleList`: exe, ntdll, kernel32). This is stable for every
//!   normal Windows process a remote thread can be created in.
//! * The stub does not call `DllMain(DLL_PROCESS_DETACH)` and does not honour
//!   TLS callbacks or exception directories.

use crate::error::{InjectError, InjectResult};

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand,
    Register, RepPrefixKind,
};

// ---------------------------------------------------------------------------
// Stack frame layout
// ---------------------------------------------------------------------------

/// Total size of the local frame reserved by the stub prologue.
///
/// At the thread entry point `RSP % 16 == 8` (Windows x64 calling convention).
/// Eight callee-saved pushes keep that parity, so subtracting a frame size that
/// is `8 (mod 16)` leaves `RSP` 16-byte aligned for every `CALL` we make.
/// `0xC8 = 200`, and `200 % 16 == 8`.
const FRAME_SIZE: usize = 0xC8;

// Shadow space is `[RSP .. RSP + 0x20)`; locals therefore start at `0x20`.
/// `LoadLibraryA` address.
const L_LL: i64 = 0x20;
/// `GetProcAddress` address.
const L_GPA: i64 = 0x28;
/// `VirtualAlloc` address.
const L_VA: i64 = 0x30;
/// Raw (source) image base.
const L_SRC: i64 = 0x38;
/// Mapped (destination) image base.
const L_DST: i64 = 0x40;
/// `SizeOfImage` of the source image.
const L_SIZE: i64 = 0x48;
/// Preferred `ImageBase` of the source image.
const L_OLD: i64 = 0x50;
/// `destination - preferred_base`, the relocation delta.
const L_DELTA: i64 = 0x58;
/// Entry-point RVA.
const L_EP: i64 = 0x60;
/// `SizeOfHeaders` of the source image.
const L_HDRSZ: i64 = 0x68;
/// `NumberOfSections`.
const L_NUM: i64 = 0x70;
/// Pointer to the next section header to copy.
const L_SEC: i64 = 0x78;
/// Pointer to the optional header's `DataDirectory` array.
const L_DATADIR: i64 = 0x80;
/// Pointer to the next base-relocation block.
const L_RELOC: i64 = 0x88;
/// End of the base-relocation directory.
const L_RELOC_END: i64 = 0x90;
/// Pointer to the next import descriptor.
const L_IDESC: i64 = 0x98;

// ---------------------------------------------------------------------------
// Embedded string data
// ---------------------------------------------------------------------------

/// Name of `kernel32` export #1 (resolved directly from the export directory).
const STR_LOADLIBRARY: &[u8] = b"LoadLibraryA";
/// Name of `kernel32` export #2.
const STR_GETPROCADDR: &[u8] = b"GetProcAddress";
/// Name of `kernel32` export #3.
const STR_VIRTUALALLOC: &[u8] = b"VirtualAlloc";

/// Offset of `STR_LOADLIBRARY` inside the appended data section.
const OFF_LOADLIBRARY: u64 = 0;
/// Offset of `STR_GETPROCADDR` inside the appended data section.
const OFF_GETPROCADDR: u64 = OFF_LOADLIBRARY + STR_LOADLIBRARY.len() as u64 + 1;
/// Offset of `STR_VIRTUALALLOC` inside the appended data section.
const OFF_VIRTUALALLOC: u64 = OFF_GETPROCADDR + STR_GETPROCADDR.len() as u64 + 1;
/// Total length of the appended data section (NUL-terminated strings, back to
/// back).
const STR_TOTAL: usize = (OFF_VIRTUALALLOC + STR_VIRTUALALLOC.len() as u64 + 1) as usize;

/// Zero bytes inserted between the encoded code and the string data. This keeps
/// the (external) RIP-relative string targets strictly greater than every
/// synthetic instruction IP, so `BlockEncoder` never mistakes a data reference
/// for a branch target.
const DATA_PAD: usize = 16;

/// Pass-1 placeholder for the data section's virtual offset. Any value that
/// fits in an `i32` displacement from the code (base IP `0`) is fine; the exact
/// code length is discovered and fed back in pass 2.
const DATA_PLACEHOLDER: u64 = 0x10_0000;

// ---------------------------------------------------------------------------
// Memory-operand helpers
// ---------------------------------------------------------------------------

/// `[base + disp]`. `displ_size = 1` lets the encoder pick the smallest
/// encoding (disp8 or disp32); in 64-bit mode `displ_size == 8` is the only
/// value that maps to a raw disp32, and `1` falls back to it automatically when
/// the displacement does not fit in a signed byte.
fn m_at(base: Register, disp: i64) -> MemoryOperand {
    MemoryOperand::with_base_displ_size(base, disp, 1)
}

/// `[base + index*scale + disp]`.
fn m_idx(base: Register, index: Register, scale: u32, disp: i64) -> MemoryOperand {
    MemoryOperand::with_base_index_scale_displ_size(base, index, scale, disp, 1)
}

/// `gs:[disp]` (used for the PEB at `gs:[0x60]`).
fn m_gs(disp: i64) -> MemoryOperand {
    MemoryOperand::new(Register::None, Register::None, 1, disp, 4, false, Register::GS)
}

/// RIP-relative reference to an absolute (post-layout) address. `BlockEncoder`
/// rewrites the displacement relative to the instruction's new IP.
fn m_rip(target: u64) -> MemoryOperand {
    MemoryOperand::with_base_displ_size(Register::RIP, target as i64, 4)
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map an `iced-x86` encoding error into the crate's error type.
fn map_iced(err: iced_x86::IcedError) -> InjectError {
    InjectError::Malformed(format!("x64 reflective stub: iced-x86 error: {err}"))
}

// ---------------------------------------------------------------------------
// Instruction builder with label fixups
// ---------------------------------------------------------------------------

/// Instruction stream under construction.
///
/// Branch and `CALL` instructions are emitted with a *symbolic* target and
/// patched in [`Stub::finalize`]. Every instruction is then given a unique
/// synthetic IP (`index + 1`); `BlockEncoder` uses those IPs to resolve
/// branches and RIP-relative references while assigning the real layout.
struct Stub {
    code: Vec<Instruction>,
    /// `(label, index of the next instruction)`.
    labels: Vec<(&'static str, usize)>,
    /// `(branch instruction index, target label)`.
    fixups: Vec<(usize, &'static str)>,
}

impl Stub {
    fn new() -> Self {
        Stub {
            code: Vec::new(),
            labels: Vec::new(),
            fixups: Vec::new(),
        }
    }

    fn push(&mut self, instr: Instruction) {
        self.code.push(instr);
    }

    /// Declare `name` as an alias for the *next* instruction to be emitted.
    fn label(&mut self, name: &'static str) {
        self.labels.push((name, self.code.len()));
    }

    /// Emit a `CALL`/`JMP`/`Jcc` whose target is a label.
    fn branch(&mut self, code: Code, target: &'static str) -> InjectResult<()> {
        let instr = Instruction::with_branch(code, 0).map_err(map_iced)?;
        self.fixups.push((self.code.len(), target));
        self.code.push(instr);
        Ok(())
    }

    /// `rep movsb` (`RCX` bytes from `[RSI]` to `[RDI]`).
    fn rep_movsb(&mut self) -> InjectResult<()> {
        let instr =
            Instruction::with_movsb(64, Register::None, RepPrefixKind::Repe).map_err(map_iced)?;
        self.code.push(instr);
        Ok(())
    }

    /// Resolve symbolic branch targets and assign synthetic IPs.
    fn finalize(mut self) -> InjectResult<Vec<Instruction>> {
        let fixups = std::mem::take(&mut self.fixups);
        for (index, name) in fixups {
            let target = self
                .labels
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, i)| *i)
                .ok_or_else(|| {
                    InjectError::Malformed(format!(
                        "x64 reflective stub: unresolved label '{name}'"
                    ))
                })?;
            // Instruction `k` owns synthetic IP `k + 1`.
            self.code[index].set_near_branch64(target as u64 + 1);
        }
        for (index, instr) in self.code.iter_mut().enumerate() {
            instr.set_ip(index as u64 + 1);
        }
        Ok(self.code)
    }
}

// Small macros that forward the `iced-x86` fallible constructors, propagating
// encoding errors with `?` from the enclosing `assemble`.
macro_rules! i0 {
    ($s:ident, $c:expr) => {{
        $s.push(Instruction::with($c));
    }};
}
macro_rules! i1 {
    ($s:ident, $c:expr, $a:expr) => {{
        $s.push(Instruction::with1($c, $a).map_err(map_iced)?);
    }};
}
macro_rules! i2 {
    ($s:ident, $c:expr, $a:expr, $b:expr) => {{
        $s.push(Instruction::with2($c, $a, $b).map_err(map_iced)?);
    }};
}
// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/// Build the instruction stream. `data_start` is the (0-based) address at which
/// the appended string section will live; it is only used to form the
/// RIP-relative string references.
fn assemble(data_start: u64) -> InjectResult<Vec<Instruction>> {
    let mut s = Stub::new();
    s.label("main");

    // -- prologue: save every callee-saved register we touch ----------------
    i1!(s, Code::Push_r64, Register::RBX);
    i1!(s, Code::Push_r64, Register::RBP);
    i1!(s, Code::Push_r64, Register::RDI);
    i1!(s, Code::Push_r64, Register::RSI);
    i1!(s, Code::Push_r64, Register::R12);
    i1!(s, Code::Push_r64, Register::R13);
    i1!(s, Code::Push_r64, Register::R14);
    i1!(s, Code::Push_r64, Register::R15);
    i2!(s, Code::Sub_rm64_imm32, Register::RSP, FRAME_SIZE as i32);

    // Raw source image base arrives in RCX; keep it in R15 for the whole stub
    // (R15 is callee-saved and untouched by `LoadLibraryA`/etc.).
    i2!(s, Code::Mov_r64_rm64, Register::R15, Register::RCX);
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_SRC), Register::R15);

    // -- locate kernel32.dll by walking the PEB module list ------------------
    //
    // PEB at gs:[0x60]; PEB->Ldr at +0x18; Ldr->InMemoryOrderModuleList is a
    // LIST_ENTRY whose head lives at +0x20. Following Flink twice from the head
    // lands on the *third* entry, which is kernel32.dll (1st = exe, 2nd =
    // ntdll). A `LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks` sits at entry+0x10
    // and `DllBase` at entry+0x30, so `DllBase == *(links + 0x20)`.
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_gs(0x60));
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RAX, 0x18));
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RAX, 0x20));
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RAX, 0x00));
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RAX, 0x00));
    i2!(s, Code::Mov_r64_rm64, Register::RBX, m_at(Register::RAX, 0x20));

    // -- resolve Kernel32's three exports by name ---------------------------
    i2!(s, Code::Mov_r64_rm64, Register::RCX, Register::RBX);
    i2!(s, Code::Lea_r64_m, Register::RDX, m_rip(data_start + OFF_LOADLIBRARY));
    s.branch(Code::Call_rel32_64, "resolve")?;
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_LL), Register::RAX);

    i2!(s, Code::Mov_r64_rm64, Register::RCX, Register::RBX);
    i2!(s, Code::Lea_r64_m, Register::RDX, m_rip(data_start + OFF_GETPROCADDR));
    s.branch(Code::Call_rel32_64, "resolve")?;
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_GPA), Register::RAX);

    i2!(s, Code::Mov_r64_rm64, Register::RCX, Register::RBX);
    i2!(s, Code::Lea_r64_m, Register::RDX, m_rip(data_start + OFF_VIRTUALALLOC));
    s.branch(Code::Call_rel32_64, "resolve")?;
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_VA), Register::RAX);

    // -- parse the source PE headers ----------------------------------------
    // e_lfanew (u32 @ 0x3C) -> NT headers in RBP; OptionalHeader is NT+0x18.
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::R15, 0x3C));
    i2!(s, Code::Lea_r64_m, Register::RBP, m_idx(Register::R15, Register::RAX, 1, 0));
    i2!(s, Code::Movzx_r32_rm16, Register::ECX, m_at(Register::RBP, 0x18));
    i2!(s, Code::Mov_r32_imm32, Register::EDX, 0x20B); // PE32+ magic
    i2!(s, Code::Cmp_r32_rm32, Register::ECX, Register::EDX);
    s.branch(Code::Jne_rel32_64, "pe32")?;

    // PE32+ (ImageBase is 8 bytes; DataDirectory at OptionalHeader+0x70).
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RBP, 0x18 + 0x18));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_OLD), Register::RAX);
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RBP, 0x18 + 0x38));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_SIZE), Register::RAX);
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RBP, 0x18 + 0x3C));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_HDRSZ), Register::RAX);
    i2!(s, Code::Lea_r64_m, Register::RAX, m_at(Register::RBP, 0x18 + 0x70));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_DATADIR), Register::RAX);
    s.branch(Code::Jmp_rel32_64, "opt_done")?;

    // PE32 (ImageBase is 4 bytes; DataDirectory at OptionalHeader+0x60).
    s.label("pe32");
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RBP, 0x18 + 0x1C));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_OLD), Register::RAX);
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RBP, 0x18 + 0x38));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_SIZE), Register::RAX);
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RBP, 0x18 + 0x3C));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_HDRSZ), Register::RAX);
    i2!(s, Code::Lea_r64_m, Register::RAX, m_at(Register::RBP, 0x18 + 0x60));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_DATADIR), Register::RAX);

    s.label("opt_done");
    // AddressOfEntryPoint (RVA) is at the same offset for both magics.
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RBP, 0x18 + 0x10));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_EP), Register::RAX);

    // -- allocate the destination image -------------------------------------
    // VirtualAlloc(NULL, SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    i2!(s, Code::Xor_r32_rm32, Register::ECX, Register::ECX);
    i2!(s, Code::Mov_r64_rm64, Register::RDX, m_at(Register::RSP, L_SIZE));
    i2!(s, Code::Mov_r32_imm32, Register::R8D, 0x3000);
    i2!(s, Code::Mov_r32_imm32, Register::R9D, 0x40);
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RSP, L_VA));
    i1!(s, Code::Call_rm64, Register::RAX);
    i2!(s, Code::Test_rm64_r64, Register::RAX, Register::RAX);
    s.branch(Code::Je_rel32_64, "fail")?;
    i2!(s, Code::Mov_r64_rm64, Register::R14, Register::RAX);
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_DST), Register::R14);

    // -- copy headers then sections -----------------------------------------
    i2!(s, Code::Mov_r64_rm64, Register::RCX, m_at(Register::RSP, L_HDRSZ));
    i2!(s, Code::Mov_r64_rm64, Register::RSI, Register::R15);
    i2!(s, Code::Mov_r64_rm64, Register::RDI, Register::R14);
    s.rep_movsb()?;

    // Section headers start right after the optional header. The loop counter
    // is kept in R12 because `rep movsb` clobbers RSI/RDI/RCX.
    i2!(s, Code::Movzx_r32_rm16, Register::ECX, m_at(Register::RBP, 0x06));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_NUM), Register::RCX);
    i2!(s, Code::Movzx_r32_rm16, Register::EAX, m_at(Register::RBP, 0x14));
    i2!(s, Code::Lea_r64_m, Register::RBX, m_idx(Register::RBP, Register::RAX, 1, 0x18));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_SEC), Register::RBX);
    i2!(s, Code::Xor_r32_rm32, Register::R12D, Register::R12D);

    s.label("sec_loop");
    i2!(s, Code::Cmp_r32_rm32, Register::R12D, m_at(Register::RSP, L_NUM));
    s.branch(Code::Jae_rel32_64, "sec_done")?;
    i2!(s, Code::Mov_r64_rm64, Register::RBX, m_at(Register::RSP, L_SEC));
    i2!(s, Code::Mov_r32_rm32, Register::ECX, m_at(Register::RBX, 0x10)); // SizeOfRawData
    i2!(s, Code::Test_rm32_r32, Register::ECX, Register::ECX);
    s.branch(Code::Je_rel32_64, "sec_next")?;
    i2!(s, Code::Mov_r32_rm32, Register::EDX, m_at(Register::RBX, 0x14)); // PointerToRawData
    i2!(s, Code::Mov_r32_rm32, Register::R8D, m_at(Register::RBX, 0x0C)); // VirtualAddress
    i2!(s, Code::Lea_r64_m, Register::RSI, m_idx(Register::R15, Register::RDX, 1, 0));
    i2!(s, Code::Lea_r64_m, Register::RDI, m_idx(Register::R14, Register::R8, 1, 0));
    s.rep_movsb()?;

    s.label("sec_next");
    i2!(s, Code::Mov_r64_rm64, Register::RBX, m_at(Register::RSP, L_SEC));
    i2!(s, Code::Add_rm64_imm32, Register::RBX, 40);
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_SEC), Register::RBX);
    i1!(s, Code::Inc_rm32, Register::R12D);
    s.branch(Code::Jmp_rel32_64, "sec_loop")?;
    s.label("sec_done");

    // -- apply base relocations ---------------------------------------------
    // delta = mapped_base - preferred_base.
    i2!(s, Code::Mov_r64_rm64, Register::RAX, Register::R14);
    i2!(s, Code::Sub_r64_rm64, Register::RAX, m_at(Register::RSP, L_OLD));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_DELTA), Register::RAX);

    // DataDirectory[5] = base-relocation table (RVA at +0x28, size at +0x2C).
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RSP, L_DATADIR));
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RAX, 0x28));
    i2!(s, Code::Test_rm32_r32, Register::EAX, Register::EAX);
    s.branch(Code::Je_rel32_64, "reloc_done")?;
    i2!(s, Code::Lea_r64_m, Register::RCX, m_idx(Register::R14, Register::RAX, 1, 0));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_RELOC), Register::RCX);
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RSP, L_DATADIR));
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RAX, 0x2C)); // table size
    i2!(s, Code::Mov_r64_rm64, Register::RCX, m_at(Register::RSP, L_RELOC));
    i2!(s, Code::Lea_r64_m, Register::RDX, m_idx(Register::RCX, Register::RAX, 1, 0));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_RELOC_END), Register::RDX);

    s.label("reloc_block");
    i2!(s, Code::Mov_r64_rm64, Register::RBX, m_at(Register::RSP, L_RELOC));
    i2!(s, Code::Cmp_r64_rm64, Register::RBX, m_at(Register::RSP, L_RELOC_END));
    s.branch(Code::Jae_rel32_64, "reloc_done")?;
    i2!(s, Code::Mov_r32_rm32, Register::R10D, m_at(Register::RBX, 0x00)); // page RVA
    i2!(s, Code::Mov_r32_rm32, Register::R11D, m_at(Register::RBX, 0x04)); // SizeOfBlock
    i2!(s, Code::Test_rm32_r32, Register::R11D, Register::R11D);
    s.branch(Code::Je_rel32_64, "reloc_done")?;
    i2!(s, Code::Lea_r64_m, Register::R9, m_idx(Register::R14, Register::R10, 1, 0)); // page base
    // entry count = (SizeOfBlock - 8) / 2
    i2!(s, Code::Mov_r32_rm32, Register::ECX, Register::R11D);
    i2!(s, Code::Sub_rm32_imm32, Register::ECX, 8);
    i2!(s, Code::Shr_rm32_imm8, Register::ECX, 1);
    i2!(s, Code::Lea_r64_m, Register::RDX, m_at(Register::RBX, 0x08)); // entries
    i2!(s, Code::Xor_r32_rm32, Register::ESI, Register::ESI);

    s.label("reloc_ent");
    i2!(s, Code::Cmp_r32_rm32, Register::ESI, Register::ECX);
    s.branch(Code::Jae_rel32_64, "reloc_next_block")?;
    i2!(s, Code::Movzx_r32_rm16, Register::EAX, m_idx(Register::RDX, Register::RSI, 2, 0));
    i2!(s, Code::Mov_r32_rm32, Register::R8D, Register::EAX);
    i2!(s, Code::And_rm32_imm32, Register::R8D, 0xF000); // type (high nibble)
    i2!(s, Code::And_rm32_imm32, Register::EAX, 0x0FFF); // offset (low 12 bits)
    i2!(s, Code::Mov_r32_rm32, Register::R11D, Register::EAX);
    i2!(s, Code::Cmp_rm32_imm32, Register::R8D, 0x3000); // IMAGE_REL_BASED_HIGHLOW
    s.branch(Code::Je_rel32_64, "reloc_highlow")?;
    i2!(s, Code::Cmp_rm32_imm32, Register::R8D, 0xA000); // IMAGE_REL_BASED_DIR64
    s.branch(Code::Je_rel32_64, "reloc_dir64")?;
    // Type 0 (ABSOLUTE) and anything else are skipped.
    s.branch(Code::Jmp_rel32_64, "reloc_ent_next")?;

    s.label("reloc_dir64");
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RSP, L_DELTA));
    i2!(s, Code::Add_rm64_r64, m_idx(Register::R9, Register::R11, 1, 0), Register::RAX);
    s.branch(Code::Jmp_rel32_64, "reloc_ent_next")?;

    s.label("reloc_highlow");
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RSP, L_DELTA));
    i2!(s, Code::Add_rm32_r32, m_idx(Register::R9, Register::R11, 1, 0), Register::EAX);

    s.label("reloc_ent_next");
    i1!(s, Code::Inc_rm32, Register::ESI);
    s.branch(Code::Jmp_rel32_64, "reloc_ent")?;

    s.label("reloc_next_block");
    i2!(s, Code::Mov_r64_rm64, Register::RBX, m_at(Register::RSP, L_RELOC));
    i2!(s, Code::Mov_r32_rm32, Register::R11D, m_at(Register::RBX, 0x04));
    i2!(s, Code::Add_r64_rm64, Register::RBX, Register::R11);
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_RELOC), Register::RBX);
    s.branch(Code::Jmp_rel32_64, "reloc_block")?;
    s.label("reloc_done");

    // -- resolve imports into the mapped image ------------------------------
    // DataDirectory[1] = import table (RVA at +0x08).
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RSP, L_DATADIR));
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RAX, 0x08));
    i2!(s, Code::Test_rm32_r32, Register::EAX, Register::EAX);
    s.branch(Code::Je_rel32_64, "imp_done")?;
    i2!(s, Code::Lea_r64_m, Register::RAX, m_idx(Register::R14, Register::RAX, 1, 0));
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_IDESC), Register::RAX);

    s.label("imp_desc");
    i2!(s, Code::Mov_r64_rm64, Register::RBX, m_at(Register::RSP, L_IDESC));
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RBX, 0x0C)); // Name RVA
    i2!(s, Code::Test_rm32_r32, Register::EAX, Register::EAX);
    s.branch(Code::Je_rel32_64, "imp_done")?;
    // LoadLibraryA(mapped_base + Name)
    i2!(s, Code::Lea_r64_m, Register::RCX, m_idx(Register::R14, Register::RAX, 1, 0));
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RSP, L_LL));
    i1!(s, Code::Call_rm64, Register::RAX);
    i2!(s, Code::Test_rm64_r64, Register::RAX, Register::RAX);
    s.branch(Code::Je_rel32_64, "fail")?;
    i2!(s, Code::Mov_r64_rm64, Register::R12, Register::RAX); // hModule
    // OriginalFirstThunk (falling back to FirstThunk when it is zero).
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RBX, 0x00));
    i2!(s, Code::Test_rm32_r32, Register::EAX, Register::EAX);
    s.branch(Code::Jne_rel32_64, "imp_ilt")?;
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RBX, 0x10));
    s.label("imp_ilt");
    i2!(s, Code::Lea_r64_m, Register::R13, m_idx(Register::R14, Register::RAX, 1, 0)); // ILT
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RBX, 0x10)); // FirstThunk
    i2!(s, Code::Lea_r64_m, Register::RBP, m_idx(Register::R14, Register::RAX, 1, 0)); // IAT
    i2!(s, Code::Xor_r32_rm32, Register::ESI, Register::ESI);

    s.label("imp_thunk");
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_idx(Register::R13, Register::RSI, 8, 0));
    i2!(s, Code::Test_rm64_r64, Register::RAX, Register::RAX);
    s.branch(Code::Je_rel32_64, "imp_thunk_done")?;
    // Bit 63 set => import by ordinal.
    s.branch(Code::Js_rel32_64, "imp_ordinal")?;
    // Import by name: RVA is the low 31 bits, +2 skips the 16-bit hint.
    i2!(s, Code::Mov_r64_rm64, Register::RCX, Register::R12);
    i2!(s, Code::Mov_r64_rm64, Register::RDX, Register::RAX);
    i2!(s, Code::And_rm32_imm32, Register::EDX, 0x7FFF_FFFF);
    i2!(s, Code::Lea_r64_m, Register::RDX, m_idx(Register::R14, Register::RDX, 1, 2));
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RSP, L_GPA));
    i1!(s, Code::Call_rm64, Register::RAX);
    s.branch(Code::Jmp_rel32_64, "imp_store")?;

    s.label("imp_ordinal");
    i2!(s, Code::Mov_r64_rm64, Register::RCX, Register::R12);
    i2!(s, Code::Movzx_r32_rm16, Register::EDX, Register::AX);
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RSP, L_GPA));
    i1!(s, Code::Call_rm64, Register::RAX);

    s.label("imp_store");
    i2!(s, Code::Mov_rm64_r64, m_idx(Register::RBP, Register::RSI, 8, 0), Register::RAX);
    i1!(s, Code::Inc_rm32, Register::ESI);
    s.branch(Code::Jmp_rel32_64, "imp_thunk")?;

    s.label("imp_thunk_done");
    i2!(s, Code::Mov_r64_rm64, Register::RAX, m_at(Register::RSP, L_IDESC));
    i2!(s, Code::Add_rm64_imm32, Register::RAX, 20); // sizeof(IMAGE_IMPORT_DESCRIPTOR)
    i2!(s, Code::Mov_rm64_r64, m_at(Register::RSP, L_IDESC), Register::RAX);
    s.branch(Code::Jmp_rel32_64, "imp_desc")?;
    s.label("imp_done");

    // -- call DllMain(mapped_base, DLL_PROCESS_ATTACH, NULL) ----------------
    i2!(s, Code::Mov_r64_rm64, Register::RAX, Register::R14);
    i2!(s, Code::Add_r64_rm64, Register::RAX, m_at(Register::RSP, L_EP));
    i2!(s, Code::Mov_r64_rm64, Register::RCX, m_at(Register::RSP, L_EP));
    i2!(s, Code::Test_rm64_r64, Register::RCX, Register::RCX);
    s.branch(Code::Je_rel32_64, "ep_none")?;
    i2!(s, Code::Mov_r64_rm64, Register::RCX, Register::R14);
    i2!(s, Code::Mov_r32_imm32, Register::EDX, 1); // DLL_PROCESS_ATTACH
    i2!(s, Code::Xor_r32_rm32, Register::R8D, Register::R8D);
    i1!(s, Code::Call_rm64, Register::RAX);
    s.branch(Code::Jmp_rel32_64, "epilogue")?;

    // No entry point: treat the map as success.
    s.label("ep_none");
    i2!(s, Code::Mov_r32_imm32, Register::EAX, 1);
    s.branch(Code::Jmp_rel32_64, "epilogue")?;

    // -- failure path -------------------------------------------------------
    s.label("fail");
    i2!(s, Code::Xor_r32_rm32, Register::EAX, Register::EAX);

    // -- epilogue -----------------------------------------------------------
    s.label("epilogue");
    i2!(s, Code::Add_rm64_imm32, Register::RSP, FRAME_SIZE as i32);
    i1!(s, Code::Pop_r64, Register::R15);
    i1!(s, Code::Pop_r64, Register::R14);
    i1!(s, Code::Pop_r64, Register::R13);
    i1!(s, Code::Pop_r64, Register::R12);
    i1!(s, Code::Pop_r64, Register::RSI);
    i1!(s, Code::Pop_r64, Register::RDI);
    i1!(s, Code::Pop_r64, Register::RBP);
    i1!(s, Code::Pop_r64, Register::RBX);
    i0!(s, Code::Retnq);

    // =====================================================================
    // Export-by-name resolver (local subroutine)
    // =====================================================================
    //
    //   in : RCX = DLL image base, RDX = pointer to a NUL-terminated ASCII name
    //   out: RAX = function address, or 0 when not found
    //
    // It parses the PE export directory and linearly scans AddressOfNames,
    // using AddressOfNameOrdinals to index AddressOfFunctions. Exports that are
    // forwarders are returned verbatim (limitation documented at the top).
    // Callee-saved registers used here are saved/restored, so the caller may
    // keep live values across the CALL.
    s.label("resolve");
    i1!(s, Code::Push_r64, Register::RBX);
    i1!(s, Code::Push_r64, Register::RSI);
    i1!(s, Code::Push_r64, Register::RDI);
    i1!(s, Code::Push_r64, Register::R12);
    i1!(s, Code::Push_r64, Register::R13);
    i2!(s, Code::Mov_r64_rm64, Register::RBX, Register::RCX); // base
    i2!(s, Code::Mov_r64_rm64, Register::RDI, Register::RDX); // target name

    // NT headers = base + e_lfanew.
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::RBX, 0x3C));
    i2!(s, Code::Lea_r64_m, Register::RAX, m_idx(Register::RBX, Register::RAX, 1, 0));
    // OptionalHeader magic selects the DataDirectory offset from the NT base:
    // 0x88 (136) for PE32+, 0x78 (120) for PE32.
    i2!(s, Code::Movzx_r32_rm16, Register::R8D, m_at(Register::RAX, 0x18));
    i2!(s, Code::Mov_r32_imm32, Register::R9D, 0x88);
    i2!(s, Code::Cmp_rm32_imm32, Register::R8D, 0x20B);
    s.branch(Code::Je_rel32_64, "rexp_magic_ok")?;
    i2!(s, Code::Mov_r32_imm32, Register::R9D, 0x78);
    s.label("rexp_magic_ok");
    // Export directory RVA lives at NT + offset.
    i2!(s, Code::Mov_r32_rm32, Register::R8D, m_idx(Register::RAX, Register::R9, 1, 0));
    i2!(s, Code::Test_rm32_r32, Register::R8D, Register::R8D);
    s.branch(Code::Je_rel32_64, "rexp_nf")?;
    i2!(s, Code::Lea_r64_m, Register::R8, m_idx(Register::RBX, Register::R8, 1, 0)); // export dir
    i2!(s, Code::Mov_r32_rm32, Register::R9D, m_at(Register::R8, 0x18)); // NumberOfNames
    i2!(s, Code::Test_rm32_r32, Register::R9D, Register::R9D);
    s.branch(Code::Je_rel32_64, "rexp_nf")?;

    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::R8, 0x20)); // AddressOfNames
    i2!(s, Code::Lea_r64_m, Register::R10, m_idx(Register::RBX, Register::RAX, 1, 0));
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::R8, 0x24)); // AddressOfNameOrdinals
    i2!(s, Code::Lea_r64_m, Register::R11, m_idx(Register::RBX, Register::RAX, 1, 0));
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_at(Register::R8, 0x1C)); // AddressOfFunctions
    i2!(s, Code::Lea_r64_m, Register::R8, m_idx(Register::RBX, Register::RAX, 1, 0));

    i2!(s, Code::Xor_r32_rm32, Register::ESI, Register::ESI);
    s.label("rexp_loop");
    i2!(s, Code::Cmp_r32_rm32, Register::ESI, Register::R9D);
    s.branch(Code::Jae_rel32_64, "rexp_nf")?;
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_idx(Register::R10, Register::RSI, 4, 0));
    i2!(s, Code::Lea_r64_m, Register::R12, m_idx(Register::RBX, Register::RAX, 1, 0)); // candidate
    i2!(s, Code::Mov_r64_rm64, Register::R13, Register::RDI); // target

    s.label("rexp_cmp");
    i2!(s, Code::Movzx_r32_rm8, Register::EAX, m_at(Register::R12, 0));
    i2!(s, Code::Movzx_r32_rm8, Register::ECX, m_at(Register::R13, 0));
    i2!(s, Code::Cmp_r32_rm32, Register::EAX, Register::ECX);
    s.branch(Code::Jne_rel32_64, "rexp_next")?;
    i2!(s, Code::Test_rm32_r32, Register::EAX, Register::EAX);
    s.branch(Code::Je_rel32_64, "rexp_found")?;
    i1!(s, Code::Inc_rm64, Register::R12);
    i1!(s, Code::Inc_rm64, Register::R13);
    s.branch(Code::Jmp_rel32_64, "rexp_cmp")?;

    s.label("rexp_next");
    i1!(s, Code::Inc_rm32, Register::ESI);
    s.branch(Code::Jmp_rel32_64, "rexp_loop")?;

    s.label("rexp_found");
    // function = AddressOfFunctions[AddressOfNameOrdinals[i]]
    i2!(s, Code::Movzx_r32_rm16, Register::EAX, m_idx(Register::R11, Register::RSI, 2, 0));
    i2!(s, Code::Mov_r32_rm32, Register::EAX, m_idx(Register::R8, Register::RAX, 4, 0));
    i2!(s, Code::Test_rm32_r32, Register::EAX, Register::EAX);
    s.branch(Code::Je_rel32_64, "rexp_nf")?;
    i2!(s, Code::Lea_r64_m, Register::RAX, m_idx(Register::RBX, Register::RAX, 1, 0));
    s.branch(Code::Jmp_rel32_64, "rexp_done")?;

    s.label("rexp_nf");
    i2!(s, Code::Xor_r32_rm32, Register::EAX, Register::EAX);

    s.label("rexp_done");
    i1!(s, Code::Pop_r64, Register::R13);
    i1!(s, Code::Pop_r64, Register::R12);
    i1!(s, Code::Pop_r64, Register::RDI);
    i1!(s, Code::Pop_r64, Register::RSI);
    i1!(s, Code::Pop_r64, Register::RBX);
    i0!(s, Code::Retnq);

    s.finalize()
}

/// Assemble once and encode with `BlockEncoder` at base IP `0`.
fn encode_stub(data_start: u64) -> InjectResult<Vec<u8>> {
    let instructions = assemble(data_start)?;
    let block = InstructionBlock::new(&instructions, 0);
    let result = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE).map_err(map_iced)?;
    Ok(result.code_buffer)
}

/// The appended NUL-terminated string table (offsets must match `OFF_*`).
fn data_section() -> Vec<u8> {
    let mut data = Vec::with_capacity(STR_TOTAL);
    data.extend_from_slice(STR_LOADLIBRARY);
    data.push(0);
    data.extend_from_slice(STR_GETPROCADDR);
    data.push(0);
    data.extend_from_slice(STR_VIRTUALALLOC);
    data.push(0);
    data
}

/// Assemble the Windows x64 reflective loader stub.
///
/// The returned bytes begin with the stub entry point (start the remote thread
/// there) and end with the embedded API-name strings. `image_len` is accepted
/// for API symmetry with the other reflective modes; the stub is fully
/// position- and size-independent (it reads `SizeOfImage` from the image it is
/// handed at runtime) and is only validated as non-zero.
///
/// # Errors
///
/// Returns [`InjectError::Malformed`] if `image_len` is zero or if `iced-x86`
/// fails to encode the (fixed) instruction stream.
pub fn build(image_len: usize) -> InjectResult<Vec<u8>> {
    if image_len == 0 {
        return Err(InjectError::Malformed(
            "reflective x64 stub: raw image length must be non-zero".to_string(),
        ));
    }

    // Pass 1: discover the encoded code length. RIP-relative displacements are
    // always 4 bytes, so the length is independent of `data_start`, but we
    // recompute to be safe and to keep the function self-consistent.
    let first = encode_stub(DATA_PLACEHOLDER)?;
    let data_start = (first.len() + DATA_PAD) as u64;
    let code = encode_stub(data_start)?;
    if code.len() != first.len() {
        return Err(InjectError::Malformed(
            "reflective x64 stub: code length is not stable across passes".to_string(),
        ));
    }

    let mut out = code;
    out.resize(out.len() + DATA_PAD, 0);
    out.extend_from_slice(&data_section());
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use iced_x86::{Decoder, DecoderOptions};

    /// True when `needle` occurs anywhere in `hay`.
    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|window| window == needle)
    }

    #[test]
    fn assembles_non_empty_and_deterministic() {
        let a = build(0x4000).expect("stub assembly must succeed");
        let b = build(0x4000).expect("stub assembly must succeed");
        assert!(!a.is_empty(), "stub must not be empty");
        assert_eq!(a, b, "stub assembly must be deterministic");
        assert!(
            a.len() >= 64 && a.len() < 0x10_000,
            "unexpected stub size {}",
            a.len()
        );
    }

    #[test]
    fn disassembles_from_start() {
        let stub = build(0x4000).expect("stub assembly must succeed");

        let mut decoder = Decoder::with_ip(64, &stub, 0, DecoderOptions::NONE);
        let first = decoder.decode();
        assert!(!first.is_invalid(), "first stub instruction must decode");

        let mut decoder = Decoder::with_ip(64, &stub, 0, DecoderOptions::NONE);
        let mut count = 0usize;
        while decoder.can_decode() {
            let instr = decoder.decode();
            if instr.is_invalid() {
                break;
            }
            count += 1;
        }
        assert!(count > 5, "stub should contain more than 5 instructions");
    }

    #[test]
    fn embeds_api_name_strings() {
        let stub = build(0x4000).expect("stub assembly must succeed");
        assert!(contains(&stub, b"LoadLibraryA"), "missing LoadLibraryA");
        assert!(contains(&stub, b"GetProcAddress"), "missing GetProcAddress");
        assert!(contains(&stub, b"VirtualAlloc"), "missing VirtualAlloc");
    }

    #[test]
    fn rejects_empty_image() {
        assert!(build(0).is_err());
    }
}
