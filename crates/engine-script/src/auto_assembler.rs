use engine_core::assemble_code;
use engine_pal::{Address, ProcessAccessLayer, ProtectionFlags};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AutoAssembleError {
    #[error("Parse error at line {line}: {reason}")]
    ParseError { line: usize, reason: String },
    #[error("Undefined symbol: '{0}'")]
    UndefinedSymbol(String),
    #[error("Assembly error: {0}")]
    AssemblyError(String),
    #[error("PAL error: {0}")]
    PalError(String),
}

pub type AutoAssembleResult<T> = Result<T, AutoAssembleError>;

/// Record of an allocated memory block during AutoAssembler execution
#[derive(Debug, Clone)]
pub struct ScriptAllocation {
    pub name: String,
    pub address: Address,
    pub size: usize,
}

/// Result of executing an AutoAssembler script
#[derive(Debug, Clone, Default)]
pub struct AutoAssemblerReport {
    pub allocations: Vec<ScriptAllocation>,
    pub patches: Vec<(Address, usize)>,
}

/// Executes Cheat Engine style AutoAssembler scripts ([ENABLE] / [DISABLE], alloc, labels, patches)
pub struct AutoAssembler;

impl AutoAssembler {
    pub fn execute(
        script: &str,
        enable: bool,
        pal: &mut dyn ProcessAccessLayer,
        existing_allocations: &mut HashMap<String, Address>,
    ) -> AutoAssembleResult<AutoAssemblerReport> {
        let mut report = AutoAssemblerReport::default();
        let target_section = if enable { "[enable]" } else { "[disable]" };

        let mut in_target_section = false;
        let mut symbols = existing_allocations.clone();
        let mut current_address: Option<Address> = None;
        let mut instruction_buffer: Vec<String> = Vec::new();

        let bitness = match pal.architecture() {
            engine_pal::CpuArchitecture::X86_32 => 32,
            engine_pal::CpuArchitecture::X86_64 => 64,
        };

        let flush_instructions = |instrs: &mut Vec<String>, addr_opt: Option<Address>, syms: &HashMap<String, Address>, p: &mut dyn ProcessAccessLayer| -> AutoAssembleResult<()> {
            if instrs.is_empty() {
                return Ok(());
            }
            let addr = addr_opt.ok_or_else(|| AutoAssembleError::AssemblyError("Instructions without target address".to_string()))?;

            // Replace symbol names in instructions with hex addresses
            let mut resolved_lines = Vec::new();
            for line in instrs.iter() {
                let mut resolved = line.clone();
                for (sym, sym_addr) in syms {
                    resolved = resolved.replace(sym, &format!("0x{:X}", sym_addr.as_u64()));
                }
                resolved_lines.push(resolved);
            }

            let code_str = resolved_lines.join("\n");
            let machine_bytes = assemble_code(&code_str, bitness, addr.as_u64())
                .map_err(|e| AutoAssembleError::AssemblyError(e.to_string()))?;

            if !machine_bytes.is_empty() {
                p.write_raw(addr, &machine_bytes)
                    .map_err(|e| AutoAssembleError::PalError(e.to_string()))?;
            }

            instrs.clear();
            Ok(())
        };

        for (line_idx, raw_line) in script.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = raw_line.trim();

            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            let lower = trimmed.to_lowercase();
            if lower == "[enable]" {
                flush_instructions(&mut instruction_buffer, current_address, &symbols, pal)?;
                in_target_section = target_section == "[enable]";
                continue;
            } else if lower == "[disable]" {
                flush_instructions(&mut instruction_buffer, current_address, &symbols, pal)?;
                in_target_section = target_section == "[disable]";
                continue;
            }

            if !in_target_section {
                continue;
            }

            // alloc(name, size)
            if let Some(rest) = lower.strip_prefix("alloc(").and_then(|s| s.strip_suffix(')')) {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() != 2 {
                    return Err(AutoAssembleError::ParseError {
                        line: line_num,
                        reason: "alloc requires (name, size)".to_string(),
                    });
                }
                let name = parts[0].to_string();
                let size = parts[1].strip_prefix("0x").and_then(|s| usize::from_str_radix(s, 16).ok())
                    .or_else(|| parts[1].parse::<usize>().ok())
                    .ok_or_else(|| AutoAssembleError::ParseError { line: line_num, reason: format!("Invalid alloc size '{}'", parts[1]) })?;

                let allocated_addr = pal.allocate_memory(size, ProtectionFlags::RWX)
                    .map_err(|e| AutoAssembleError::PalError(e.to_string()))?;

                symbols.insert(name.clone(), allocated_addr);
                existing_allocations.insert(name.clone(), allocated_addr);
                report.allocations.push(ScriptAllocation {
                    name,
                    address: allocated_addr,
                    size,
                });
                continue;
            }

            // dealloc(name)
            if let Some(name) = lower.strip_prefix("dealloc(").and_then(|s| s.strip_suffix(')')) {
                let name = name.trim();
                if let Some(addr) = existing_allocations.remove(name) {
                    pal.free_memory(addr).map_err(|e| AutoAssembleError::PalError(e.to_string()))?;
                    symbols.remove(name);
                }
                continue;
            }

            // Address or label definition: "0x7FFF1000:" or "my_label:"
            if trimmed.ends_with(':') {
                flush_instructions(&mut instruction_buffer, current_address, &symbols, pal)?;
                let label_name = trimmed.trim_end_matches(':').trim();

                if let Some(hex_part) = label_name.strip_prefix("0x").or_else(|| label_name.strip_prefix("0X")) {
                    if let Ok(addr_val) = u64::from_str_radix(hex_part, 16) {
                        current_address = Some(Address::new(addr_val));
                        continue;
                    }
                }

                // Named label
                if let Some(&addr) = symbols.get(label_name) {
                    current_address = Some(addr);
                } else {
                    return Err(AutoAssembleError::UndefinedSymbol(label_name.to_string()));
                }
                continue;
            }

            // Otherwise, instruction line
            instruction_buffer.push(trimmed.to_string());
        }

        flush_instructions(&mut instruction_buffer, current_address, &symbols, pal)?;

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_pal::types::{BreakpointId, BreakpointType, CpuArchitecture, MemoryRegion, ModuleInfo, ProcessId, StealthLevel, ThreadInfo};
    use engine_pal::error::PalResult;

    struct MockPal {
        memory: HashMap<u64, Vec<u8>>,
        allocated: Vec<(Address, usize)>,
    }

    impl MockPal {
        fn new() -> Self {
            Self {
                memory: HashMap::new(),
                allocated: Vec::new(),
            }
        }
    }

    impl ProcessAccessLayer for MockPal {
        fn attach(&mut self, _pid: ProcessId) -> PalResult<()> { Ok(()) }
        fn detach(&mut self) -> PalResult<()> { Ok(()) }
        fn is_attached(&self) -> bool { true }
        fn attached_pid(&self) -> Option<ProcessId> { Some(1234) }
        fn architecture(&self) -> CpuArchitecture { CpuArchitecture::X86_64 }
        fn read_raw(&self, address: Address, size: usize) -> PalResult<Vec<u8>> {
            let mut out = vec![0u8; size];
            if let Some(data) = self.memory.get(&address.as_u64()) {
                let to_copy = data.len().min(size);
                out[..to_copy].copy_from_slice(&data[..to_copy]);
            }
            Ok(out)
        }
        fn write_raw(&self, address: Address, data: &[u8]) -> PalResult<()> {
            unsafe {
                let s = self as *const Self as *mut Self;
                (*s).memory.insert(address.as_u64(), data.to_vec());
            }
            Ok(())
        }
        fn query_regions(&self) -> PalResult<Vec<MemoryRegion>> { Ok(Vec::new()) }
        fn enumerate_modules(&self) -> PalResult<Vec<ModuleInfo>> { Ok(Vec::new()) }
        fn enumerate_threads(&self) -> PalResult<Vec<ThreadInfo>> { Ok(Vec::new()) }
        fn set_breakpoint(&mut self, _address: Address, _bp_type: BreakpointType) -> PalResult<BreakpointId> { Ok(BreakpointId(1)) }
        fn remove_breakpoint(&mut self, _id: BreakpointId) -> PalResult<()> { Ok(()) }
        fn allocate_memory(&self, size: usize, _protection: ProtectionFlags) -> PalResult<Address> {
            let addr = Address::new(0x20000);
            unsafe {
                let s = self as *const Self as *mut Self;
                (*s).allocated.push((addr, size));
            }
            Ok(addr)
        }
        fn free_memory(&self, _address: Address) -> PalResult<()> { Ok(()) }
        fn stealth_level(&self) -> StealthLevel { StealthLevel::None }
        fn backend_name(&self) -> &'static str { "MockPal" }
    }

    #[test]
    fn test_auto_assembler_enable() {
        let mut pal = MockPal::new();
        let mut allocs = HashMap::new();

        let script = r#"
            [ENABLE]
            alloc(mycave, 1024)
            mycave:
                nop
                ret

            0x1000:
                nop
        "#;

        let result = AutoAssembler::execute(script, true, &mut pal, &mut allocs);
        assert!(result.is_ok());
        assert_eq!(allocs.contains_key("mycave"), true);

        // Check that instructions were written
        assert!(pal.memory.contains_key(&0x20000));
        assert!(pal.memory.contains_key(&0x1000));
    }

    #[test]
    fn test_auto_assembler_disable() {
        let mut pal = MockPal::new();
        let mut allocs = HashMap::new();

        let script = r#"
            [ENABLE]
            alloc(mycave, 1024)
            mycave:
                nop
                ret

            [DISABLE]
            dealloc(mycave)
            0x1000:
                ret
        "#;

        let res_en = AutoAssembler::execute(script, true, &mut pal, &mut allocs);
        assert!(res_en.is_ok());
        assert!(allocs.contains_key("mycave"));

        let res_dis = AutoAssembler::execute(script, false, &mut pal, &mut allocs);
        assert!(res_dis.is_ok());
        assert!(!allocs.contains_key("mycave"));
    }
}
