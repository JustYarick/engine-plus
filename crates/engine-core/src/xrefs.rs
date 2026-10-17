use engine_pal::Address;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, OpKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XRefType {
    Call,
    Jump,
    RipRelativeLoad,
    AbsolutePointer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRefEntry {
    pub instruction_address: Address,
    pub target_address: Address,
    pub xref_type: XRefType,
    pub instruction_text: String,
}

/// Find all cross-references (calls, jumps, RIP-relative loads) to a target address in code bytes
pub fn find_xrefs_in_code(
    code_bytes: &[u8],
    code_base_ip: u64,
    bitness: u32,
    target_address: u64,
) -> Vec<XRefEntry> {
    let mut results = Vec::new();
    let mut decoder = Decoder::with_ip(bitness, code_bytes, code_base_ip, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut instruction = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        let ip = instruction.ip();

        // 1. Check near branch targets (CALL / JMP)
        for i in 0..instruction.op_count() {
            match instruction.op_kind(i) {
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    let branch_target = instruction.near_branch_target();
                    if branch_target == target_address {
                        let mut instr_text = String::new();
                        formatter.format(&instruction, &mut instr_text);
                        let xref_type = if matches!(instruction.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
                            XRefType::Call
                        } else {
                            XRefType::Jump
                        };
                        results.push(XRefEntry {
                            instruction_address: Address::new(ip),
                            target_address: Address::new(target_address),
                            xref_type,
                            instruction_text: instr_text,
                        });
                    }
                }
                OpKind::Memory if instruction.is_ip_rel_memory_operand() => {
                    let mem_target = instruction.ip_rel_memory_address();
                    if mem_target == target_address {
                        let mut instr_text = String::new();
                        formatter.format(&instruction, &mut instr_text);
                        results.push(XRefEntry {
                            instruction_address: Address::new(ip),
                            target_address: Address::new(target_address),
                            xref_type: XRefType::RipRelativeLoad,
                            instruction_text: instr_text,
                        });
                    }
                }
                OpKind::Memory => {
                    let disp = instruction.memory_displacement64();
                    if disp == target_address {
                        let mut instr_text = String::new();
                        formatter.format(&instruction, &mut instr_text);
                        results.push(XRefEntry {
                            instruction_address: Address::new(ip),
                            target_address: Address::new(target_address),
                            xref_type: XRefType::AbsolutePointer,
                            instruction_text: instr_text,
                        });
                    }
                }
                OpKind::Immediate32 | OpKind::Immediate32to64 => {
                    if (instruction.immediate32() as u64) == target_address {
                        let mut instr_text = String::new();
                        formatter.format(&instruction, &mut instr_text);
                        results.push(XRefEntry {
                            instruction_address: Address::new(ip),
                            target_address: Address::new(target_address),
                            xref_type: XRefType::AbsolutePointer,
                            instruction_text: instr_text,
                        });
                    }
                }
                OpKind::Immediate64 if instruction.immediate64() == target_address => {
                    let mut instr_text = String::new();
                    formatter.format(&instruction, &mut instr_text);
                    results.push(XRefEntry {
                        instruction_address: Address::new(ip),
                        target_address: Address::new(target_address),
                        xref_type: XRefType::AbsolutePointer,
                        instruction_text: instr_text,
                    });
                }
                _ => {}
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_xrefs_call_and_rip_load() {
        // Target: 0x00402000
        // At 0x00401000: call 0x00402000 (E8 FB 0F 00 00)
        // At 0x00401005: lea rax, [rip + 0xFF5] -> 0x0040100C + 0xFF4 = 0x00402000
        let target = 0x00402000;
        let mut code = Vec::new();
        // call target (offset from 0x00401005 to 0x00402000 is 0xFFB)
        code.extend_from_slice(&[0xE8, 0xFB, 0x0F, 0x00, 0x00]);
        // nop
        code.push(0x90);

        let xrefs = find_xrefs_in_code(&code, 0x00401000, 64, target);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].xref_type, XRefType::Call);
        assert_eq!(xrefs[0].target_address.as_u64(), target);
    }
}
