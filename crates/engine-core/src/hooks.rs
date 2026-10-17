use crate::assembler::{create_absolute_jump, create_relative_jump};
use engine_pal::Address;
use iced_x86::{Decoder, DecoderOptions, Instruction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HookError {
    #[error("Instruction decoding failed at offset 0x{offset:X}: {reason}")]
    DecodeError { offset: u64, reason: String },
    #[error("Not enough instructions to cover required patch size ({found} bytes found, {required} bytes needed)")]
    InsufficientBytes { found: usize, required: usize },
    #[error("Jump encoding failed: {0}")]
    JumpError(String),
}

pub type HookResult<T> = Result<T, HookError>;

/// Represents the complete data required to apply and revert an inline detour hook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookPackage {
    pub target_address: Address,
    pub original_bytes: Vec<u8>,
    pub patch_bytes: Vec<u8>,
    pub code_cave_address: Address,
    pub code_cave_bytes: Vec<u8>,
    pub return_address: Address,
}

/// Calculate the exact number of bytes required to safely hook without cutting an instruction
pub fn calculate_stolen_bytes(
    code_slice: &[u8],
    base_ip: u64,
    bitness: u32,
    min_required: usize,
) -> HookResult<usize> {
    let mut decoder = Decoder::with_ip(bitness, code_slice, base_ip, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut total_bytes = 0;

    while decoder.can_decode() && total_bytes < min_required {
        decoder.decode_out(&mut instruction);
        let len = instruction.len();
        if len == 0 {
            return Err(HookError::DecodeError {
                offset: instruction.ip(),
                reason: "Decoded instruction with length 0".to_string(),
            });
        }
        total_bytes += len;
    }

    if total_bytes < min_required {
        return Err(HookError::InsufficientBytes {
            found: total_bytes,
            required: min_required,
        });
    }

    Ok(total_bytes)
}

/// Build a 64-bit or 32-bit inline trampoline hook with custom code cave payload
pub fn build_detour_hook(
    original_code: &[u8],
    target_ip: u64,
    cave_ip: u64,
    bitness: u32,
    custom_payload: &[u8],
) -> HookResult<HookPackage> {
    // In 64-bit mode, an absolute 14-byte jump (FF 25 00000000 <64-bit addr>) guarantees reaching any address.
    // In 32-bit mode, a standard 5-byte relative jump (E9 <rel32>) is used.
    let min_patch_size = if bitness == 64 { 14 } else { 5 };

    let stolen_len = calculate_stolen_bytes(original_code, target_ip, bitness, min_patch_size)?;
    let original_bytes = original_code[..stolen_len].to_vec();

    // 1. Generate patch bytes for the hook location (JMP to cave + NOP padding)
    let mut patch_bytes = Vec::with_capacity(stolen_len);
    if bitness == 64 {
        let abs_jmp = create_absolute_jump(cave_ip);
        patch_bytes.extend_from_slice(&abs_jmp);
    } else {
        let rel_jmp = create_relative_jump(target_ip, cave_ip)
            .map_err(|e| HookError::JumpError(e.to_string()))?;
        patch_bytes.extend_from_slice(&rel_jmp);
    }

    // Pad remaining stolen bytes with NOPs
    while patch_bytes.len() < stolen_len {
        patch_bytes.push(0x90);
    }

    // 2. Build code cave:
    // [custom_payload] -> [original stolen instructions] -> [jump back to target_ip + stolen_len]
    let return_ip = target_ip + (stolen_len as u64);
    let mut cave_bytes = Vec::new();

    // Add custom injected payload (e.g. registers push, custom logic, registers pop)
    cave_bytes.extend_from_slice(custom_payload);

    // Append stolen original instructions
    cave_bytes.extend_from_slice(&original_bytes);

    // Append jump back to original code
    let current_cave_end = cave_ip + (cave_bytes.len() as u64);
    if bitness == 64 {
        let ret_jmp = create_absolute_jump(return_ip);
        cave_bytes.extend_from_slice(&ret_jmp);
    } else {
        let ret_jmp = create_relative_jump(current_cave_end, return_ip)
            .map_err(|e| HookError::JumpError(e.to_string()))?;
        cave_bytes.extend_from_slice(&ret_jmp);
    }

    Ok(HookPackage {
        target_address: Address::new(target_ip),
        original_bytes,
        patch_bytes,
        code_cave_address: Address::new(cave_ip),
        code_cave_bytes: cave_bytes,
        return_address: Address::new(return_ip),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_stolen_bytes_boundary() {
        // sub rsp, 0x28 (4 bytes: 48 83 EC 28) + mov rax, rcx (3 bytes: 48 89 C8) = 7 bytes total
        let code = [0x48, 0x83, 0xEC, 0x28, 0x48, 0x89, 0xC8, 0x90, 0x90];
        let stolen = calculate_stolen_bytes(&code, 0x1000, 64, 5).unwrap();
        // Needs >= 5 bytes, so it must take the full 4 bytes + 3 bytes = 7 bytes (never cuts at 5!)
        assert_eq!(stolen, 7);
    }

    #[test]
    fn test_build_detour_hook_64bit() {
        // 16 bytes of test instructions:
        // 48 89 5C 24 08 (mov [rsp+8], rbx - 5 bytes)
        // 48 89 74 24 10 (mov [rsp+16], rsi - 5 bytes)
        // 57             (push rdi - 1 byte)
        // 48 83 EC 20    (sub rsp, 32 - 4 bytes)
        // 90             (nop - 1 byte)
        let original_code = [
            0x48, 0x89, 0x5C, 0x24, 0x08,
            0x48, 0x89, 0x74, 0x24, 0x10,
            0x57,
            0x48, 0x83, 0xEC, 0x20,
            0x90
        ];

        let target_ip = 0x00401000;
        let cave_ip = 0x00700000;
        let payload = [0x90, 0x90]; // 2 NOPs custom payload

        let hook = build_detour_hook(&original_code, target_ip, cave_ip, 64, &payload)
            .expect("Should build hook package");

        assert_eq!(hook.target_address.as_u64(), target_ip);
        assert_eq!(hook.code_cave_address.as_u64(), cave_ip);
        // Stolen bytes: 5 + 5 + 1 + 4 = 15 bytes (covers 14-byte absolute jump)
        assert_eq!(hook.original_bytes.len(), 15);
        assert_eq!(hook.patch_bytes.len(), 15);
        assert_eq!(hook.patch_bytes[0], 0xFF);
        assert_eq!(hook.patch_bytes[1], 0x25);
        assert_eq!(hook.patch_bytes[14], 0x90); // 1 byte NOP padding
        assert_eq!(hook.return_address.as_u64(), target_ip + 15);
    }

    #[test]
    fn test_build_detour_hook_32bit() {
        // 32-bit instructions:
        // 55 (push ebp - 1 byte)
        // 89 E5 (mov ebp, esp - 2 bytes)
        // 83 EC 10 (sub esp, 16 - 3 bytes)
        // Total = 6 bytes >= 5 bytes (rel32 jmp)
        let original_code = [0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10, 0x90];
        let target_ip = 0x00401000;
        let cave_ip = 0x00402000;
        let hook = build_detour_hook(&original_code, target_ip, cave_ip, 32, &[]).expect("32-bit hook should succeed");
        assert_eq!(hook.patch_bytes[0], 0xE9); // JMP rel32
        assert_eq!(hook.original_bytes.len(), 6);
        assert_eq!(hook.patch_bytes.len(), 6);
        assert_eq!(hook.patch_bytes[5], 0x90); // 1 NOP
        assert_eq!(hook.return_address.as_u64(), target_ip + 6);
    }
}
