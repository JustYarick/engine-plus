use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AssemblerError {
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Encoding error: {0}")]
    EncodingError(String),
    #[error("Unsupported instruction: '{0}'")]
    UnsupportedInstruction(String),
    #[error("Invalid bitness: {0} (must be 32 or 64)")]
    InvalidBitness(u32),
}

pub type AssemblerResult<T> = Result<T, AssemblerError>;

/// Compiles assembly source lines into machine code bytes for target architecture
pub fn assemble_code(code: &str, bitness: u32, ip: u64) -> AssemblerResult<Vec<u8>> {
    if bitness != 32 && bitness != 64 {
        return Err(AssemblerError::InvalidBitness(bitness));
    }

    let mut instructions = Vec::new();

    for (line_num, raw_line) in code.lines().enumerate() {
        let trimmed = raw_line.trim();
        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        // Support direct hex byte directives like: `db 0x90, 0x90` or `hex: 90 90`
        if let Some(rest) = trimmed.strip_prefix("db ").or_else(|| trimmed.strip_prefix("DB ")) {
            let bytes = parse_db_directive(rest)
                .map_err(|e| AssemblerError::ParseError(format!("Line {}: {e}", line_num + 1)))?;
            for b in bytes {
                // Encode raw byte or placeholder
                instructions.push(create_db_instruction(b));
            }
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("hex:").or_else(|| trimmed.strip_prefix("HEX:")) {
            let bytes = parse_hex_string(rest)
                .map_err(|e| AssemblerError::ParseError(format!("Line {}: {e}", line_num + 1)))?;
            for b in bytes {
                instructions.push(create_db_instruction(b));
            }
            continue;
        }

        let instr = parse_single_instruction(trimmed, bitness, ip)
            .map_err(|e| AssemblerError::ParseError(format!("Line {}: {e}", line_num + 1)))?;
        instructions.push(instr);
    }

    if instructions.is_empty() {
        return Ok(Vec::new());
    }

    // Encode instructions into machine code
    let block = InstructionBlock::new(&instructions, ip);
    let result = BlockEncoder::encode(bitness, block, BlockEncoderOptions::NONE)
        .map_err(|e| AssemblerError::EncodingError(e.to_string()))?;

    Ok(result.code_buffer)
}

/// Helper to create a raw byte using an encoded form or single byte instruction
fn create_db_instruction(byte: u8) -> Instruction {
    // In iced-x86, db can be represented or we decode it, or use declared bytes
    // For direct bytes, we can use a nop-like single byte or instruction representation
    // Let's create Instruction with Code::DeclareByte
    Instruction::with_declare_byte(&[byte]).unwrap_or_else(|_| Instruction::with(Code::Nopd))
}

/// Create a standard 5-byte x86/x64 relative jump (E9 <rel32>)
pub fn create_relative_jump(from_ip: u64, to_ip: u64) -> AssemblerResult<[u8; 5]> {
    let rel32 = (to_ip as i128) - ((from_ip + 5) as i128);
    if rel32 < (i32::MIN as i128) || rel32 > (i32::MAX as i128) {
        return Err(AssemblerError::EncodingError(format!(
            "Target address 0x{to_ip:X} is out of 32-bit relative range from 0x{from_ip:X}"
        )));
    }

    let rel32_i32 = rel32 as i32;
    let bytes = rel32_i32.to_le_bytes();
    Ok([0xE9, bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Create a 14-byte 64-bit absolute jump: `jmp qword ptr [rip + 0]`
pub fn create_absolute_jump(to_ip: u64) -> [u8; 14] {
    let mut patch = [0u8; 14];
    // FF 25 00 00 00 00: jmp qword ptr [rip + 0]
    patch[0] = 0xFF;
    patch[1] = 0x25;
    patch[2] = 0x00;
    patch[3] = 0x00;
    patch[4] = 0x00;
    patch[5] = 0x00;
    // Followed by 8-byte 64-bit destination address
    patch[6..14].copy_from_slice(&to_ip.to_le_bytes());
    patch
}

/// Create a NOP padding sequence of given length
pub fn create_nop_padding(length: usize) -> Vec<u8> {
    vec![0x90; length]
}

/// Parse common x86/x64 assembly instruction text into an `iced-x86` Instruction
fn parse_single_instruction(line: &str, _bitness: u32, _ip: u64) -> AssemblerResult<Instruction> {
    let line = line.trim();
    let lower = line.to_lowercase();

    // Zero-operand instructions
    match lower.as_str() {
        "nop" => return Ok(Instruction::with(Code::Nopd)),
        "ret" => return Ok(Instruction::with(Code::Retnq)),
        "retn" => return Ok(Instruction::with(Code::Retnq)),
        "int3" => return Ok(Instruction::with(Code::Int3)),
        "int 3" => return Ok(Instruction::with(Code::Int3)),
        "leave" => return Ok(Instruction::with(Code::Leaveq)),
        "cld" => return Ok(Instruction::with(Code::Cld)),
        "std" => return Ok(Instruction::with(Code::Std)),
        _ => {}
    }

    // Split mnemonic from operands
    let mut parts = line.splitn(2, |c: char| c.is_whitespace());
    let mnemonic = parts.next().unwrap_or("").trim().to_lowercase();
    let operands_str = parts.next().unwrap_or("").trim();

    let operands: Vec<&str> = if operands_str.is_empty() {
        Vec::new()
    } else {
        operands_str.split(',').map(|s| s.trim()).collect()
    };

    match mnemonic.as_str() {
        "push" if operands.len() == 1 => {
            if let Some(reg) = parse_register(operands[0]) {
                return Instruction::with1(Code::Push_r64, reg)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
            if let Some(imm) = parse_immediate(operands[0]) {
                return Instruction::with1(Code::Pushq_imm32, imm as i32)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
        }
        "pop" if operands.len() == 1 => {
            if let Some(reg) = parse_register(operands[0]) {
                return Instruction::with1(Code::Pop_r64, reg)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
        }
        "jmp" if operands.len() == 1 => {
            if let Some(target) = parse_immediate(operands[0]) {
                return Instruction::with_branch(Code::Jmp_rel32_64, target)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
            if let Some(reg) = parse_register(operands[0]) {
                return Instruction::with1(Code::Jmp_rm64, reg)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
        }
        "call" if operands.len() == 1 => {
            if let Some(target) = parse_immediate(operands[0]) {
                return Instruction::with_branch(Code::Call_rel32_64, target)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
            if let Some(reg) = parse_register(operands[0]) {
                return Instruction::with1(Code::Call_rm64, reg)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
        }
        "xor" if operands.len() == 2 => {
            if let (Some(r1), Some(r2)) = (parse_register(operands[0]), parse_register(operands[1])) {
                if is_32bit_register(r1) && is_32bit_register(r2) {
                    return Instruction::with2(Code::Xor_r32_rm32, r1, r2)
                        .map_err(|e| AssemblerError::EncodingError(e.to_string()));
                } else {
                    return Instruction::with2(Code::Xor_r64_rm64, r1, r2)
                        .map_err(|e| AssemblerError::EncodingError(e.to_string()));
                }
            }
        }
        "mov" if operands.len() == 2 => {
            // mov reg, reg
            if let (Some(dst), Some(src)) = (parse_register(operands[0]), parse_register(operands[1])) {
                if is_32bit_register(dst) && is_32bit_register(src) {
                    return Instruction::with2(Code::Mov_rm32_r32, dst, src)
                        .map_err(|e| AssemblerError::EncodingError(e.to_string()));
                } else {
                    return Instruction::with2(Code::Mov_rm64_r64, dst, src)
                        .map_err(|e| AssemblerError::EncodingError(e.to_string()));
                }
            }
            // mov reg, imm
            if let (Some(dst), Some(imm)) = (parse_register(operands[0]), parse_immediate(operands[1])) {
                if is_32bit_register(dst) {
                    return Instruction::with2(Code::Mov_r32_imm32, dst, imm as u32)
                        .map_err(|e| AssemblerError::EncodingError(e.to_string()));
                } else {
                    return Instruction::with2(Code::Mov_r64_imm64, dst, imm)
                        .map_err(|e| AssemblerError::EncodingError(e.to_string()));
                }
            }
        }
        "add" if operands.len() == 2 => {
            if let (Some(dst), Some(src)) = (parse_register(operands[0]), parse_register(operands[1])) {
                return Instruction::with2(Code::Add_rm64_r64, dst, src)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
            if let (Some(dst), Some(imm)) = (parse_register(operands[0]), parse_immediate(operands[1])) {
                return Instruction::with2(Code::Add_rm64_imm32, dst, imm as i32)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
        }
        "sub" if operands.len() == 2 => {
            if let (Some(dst), Some(src)) = (parse_register(operands[0]), parse_register(operands[1])) {
                return Instruction::with2(Code::Sub_rm64_r64, dst, src)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
            if let (Some(dst), Some(imm)) = (parse_register(operands[0]), parse_immediate(operands[1])) {
                return Instruction::with2(Code::Sub_rm64_imm32, dst, imm as i32)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
        }
        "cmp" if operands.len() == 2 => {
            if let (Some(r1), Some(r2)) = (parse_register(operands[0]), parse_register(operands[1])) {
                return Instruction::with2(Code::Cmp_rm64_r64, r1, r2)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
            if let (Some(r1), Some(imm)) = (parse_register(operands[0]), parse_immediate(operands[1])) {
                return Instruction::with2(Code::Cmp_rm64_imm32, r1, imm as i32)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
        }
        "test" if operands.len() == 2 => {
            if let (Some(r1), Some(r2)) = (parse_register(operands[0]), parse_register(operands[1])) {
                return Instruction::with2(Code::Test_rm64_r64, r1, r2)
                    .map_err(|e| AssemblerError::EncodingError(e.to_string()));
            }
        }
        _ => {}
    }

    Err(AssemblerError::UnsupportedInstruction(line.to_string()))
}

fn is_32bit_register(reg: Register) -> bool {
    matches!(
        reg,
        Register::EAX
            | Register::EBX
            | Register::ECX
            | Register::EDX
            | Register::ESI
            | Register::EDI
            | Register::EBP
            | Register::ESP
            | Register::R8D
            | Register::R9D
            | Register::R10D
            | Register::R11D
            | Register::R12D
            | Register::R13D
            | Register::R14D
            | Register::R15D
    )
}

fn parse_register(s: &str) -> Option<Register> {
    match s.trim().to_lowercase().as_str() {
        "rax" => Some(Register::RAX),
        "rbx" => Some(Register::RBX),
        "rcx" => Some(Register::RCX),
        "rdx" => Some(Register::RDX),
        "rsi" => Some(Register::RSI),
        "rdi" => Some(Register::RDI),
        "rbp" => Some(Register::RBP),
        "rsp" => Some(Register::RSP),
        "r8" => Some(Register::R8),
        "r9" => Some(Register::R9),
        "r10" => Some(Register::R10),
        "r11" => Some(Register::R11),
        "r12" => Some(Register::R12),
        "r13" => Some(Register::R13),
        "r14" => Some(Register::R14),
        "r15" => Some(Register::R15),
        "eax" => Some(Register::EAX),
        "ebx" => Some(Register::EBX),
        "ecx" => Some(Register::ECX),
        "edx" => Some(Register::EDX),
        "esi" => Some(Register::ESI),
        "edi" => Some(Register::EDI),
        "ebp" => Some(Register::EBP),
        "esp" => Some(Register::ESP),
        "r8d" => Some(Register::R8D),
        "r9d" => Some(Register::R9D),
        "r10d" => Some(Register::R10D),
        "r11d" => Some(Register::R11D),
        "r12d" => Some(Register::R12D),
        "r13d" => Some(Register::R13D),
        "r14d" => Some(Register::R14D),
        "r15d" => Some(Register::R15D),
        _ => None,
    }
}

fn parse_immediate(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if s.ends_with('h') || s.ends_with('H') {
        u64::from_str_radix(&s[..s.len() - 1], 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn parse_db_directive(s: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for part in s.split(',') {
        let val = parse_immediate(part.trim())
            .ok_or_else(|| format!("Invalid byte: '{part}'"))?;
        if val > 0xFF {
            return Err(format!("Byte value {val} out of range (0-255)"));
        }
        bytes.push(val as u8);
    }
    Ok(bytes)
}

fn parse_hex_string(s: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for part in s.split_whitespace() {
        let b = u8::from_str_radix(part, 16)
            .map_err(|e| format!("Invalid hex byte '{part}': {e}"))?;
        bytes.push(b);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assemble_simple_instructions() {
        let code = r#"
            nop
            xor rax, rax
            mov rbx, 0x1234
            ret
        "#;
        let bytes = assemble_code(code, 64, 0x1000).expect("Should assemble");
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 0x90); // nop
    }

    #[test]
    fn test_create_relative_and_absolute_jump() {
        let rel_jmp = create_relative_jump(0x1000, 0x1020).expect("Should build rel jmp");
        assert_eq!(rel_jmp[0], 0xE9);

        let abs_jmp = create_absolute_jump(0x7FFF12345678);
        assert_eq!(&abs_jmp[0..6], &[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        let target = u64::from_le_bytes(abs_jmp[6..14].try_into().unwrap());
        assert_eq!(target, 0x7FFF12345678);
    }

    #[test]
    fn test_assemble_db_and_hex() {
        let code = r#"
            db 0x90, 0xCC, 0xC3
            hex: 48 89 E5
        "#;
        let bytes = assemble_code(code, 64, 0x1000).expect("Should assemble db directives");
        assert_eq!(bytes, vec![0x90, 0xCC, 0xC3, 0x48, 0x89, 0xE5]);
    }
}
