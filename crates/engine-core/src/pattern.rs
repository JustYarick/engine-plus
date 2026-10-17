use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PatternError {
    #[error("Failed to decode instructions: {0}")]
    DecodeError(String),
    #[error("Buffer too short to generate a unique pattern (processed {0} bytes)")]
    BufferTooShort(usize),
}

pub type PatternResult<T> = Result<T, PatternError>;

/// Generates an AOB signature pattern with wildcards (`??`) for volatile relative offsets
pub fn generate_pattern_from_bytes(code_bytes: &[u8], base_ip: u64, bitness: u32, max_length: usize) -> PatternResult<String> {
    let mut decoder = Decoder::with_ip(bitness, code_bytes, base_ip, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut pattern_tokens: Vec<String> = Vec::new();
    let mut bytes_consumed = 0;

    while decoder.can_decode() && bytes_consumed < max_length {
        let instr_ip = decoder.ip();
        decoder.decode_out(&mut instruction);
        let len = instruction.len();
        if len == 0 {
            break;
        }

        let slice_start = (instr_ip - base_ip) as usize;
        let slice_end = slice_start + len;
        if slice_end > code_bytes.len() {
            break;
        }
        let raw_bytes = &code_bytes[slice_start..slice_end];

        // Mask volatile operands based on instruction type
        let masked_tokens = mask_instruction_bytes(&instruction, raw_bytes);
        pattern_tokens.extend(masked_tokens);
        bytes_consumed += len;
    }

    if pattern_tokens.is_empty() {
        return Err(PatternError::BufferTooShort(code_bytes.len()));
    }

    Ok(pattern_tokens.join(" "))
}

/// Helper to mask dynamic relative call/jump targets and RIP displacements with `??`
fn mask_instruction_bytes(instruction: &Instruction, raw_bytes: &[u8]) -> Vec<String> {
    let len = raw_bytes.len();
    let mut tokens = Vec::with_capacity(len);

    // Check if this instruction has volatile relative offsets
    let has_relative_target = (0..instruction.op_count()).any(|i| {
        matches!(
            instruction.op_kind(i),
            OpKind::NearBranch16
                | OpKind::NearBranch32
                | OpKind::NearBranch64
                | OpKind::FarBranch16
                | OpKind::FarBranch32
        )
    });

    let has_rip_relative_mem = (0..instruction.op_count()).any(|i| {
        instruction.op_kind(i) == OpKind::Memory && instruction.is_ip_rel_memory_operand()
    });

    if has_relative_target {
        // Typically: 1st byte is opcode (e.g. 0xE8 for call, 0xE9 for jmp), remaining 4 bytes are relative displacement
        tokens.push(format!("{:02X}", raw_bytes[0]));
        for _ in 1..len {
            tokens.push("??".to_string());
        }
    } else if has_rip_relative_mem && len >= 5 {
        // Preserves opcode prefix, masks the last 4 bytes of displacement
        let fixed_bytes = len - 4;
        for b in &raw_bytes[..fixed_bytes] {
            tokens.push(format!("{:02X}", b));
        }
        for _ in 0..4 {
            tokens.push("??".to_string());
        }
    } else {
        // Exact non-volatile instruction bytes
        for b in raw_bytes {
            tokens.push(format!("{:02X}", b));
        }
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pattern_with_call_masking() {
        // sub rsp, 0x28 (48 83 EC 28)
        // call 0x12345 (E8 ?? ?? ?? ??)
        // test rax, rax (48 85 C0)
        let bytes = [
            0x48, 0x83, 0xEC, 0x28,
            0xE8, 0x40, 0x10, 0x00, 0x00,
            0x48, 0x85, 0xC0
        ];

        let pattern = generate_pattern_from_bytes(&bytes, 0x1000, 64, 32).unwrap();
        assert!(pattern.starts_with("48 83 EC 28"));
        assert!(pattern.contains("E8 ?? ?? ?? ??"));
        assert!(pattern.ends_with("48 85 C0"));
    }
}
