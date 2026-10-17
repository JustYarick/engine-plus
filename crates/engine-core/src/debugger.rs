use crate::error::{CoreError, CoreResult};
use engine_pal::{
    Address, BreakpointId, CpuRegisters, DebugHit, ProcessAccessLayer, WatchpointCondition,
    WatchpointSize,
};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, OpKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// x86 / x86_64 Debug Control Register (DR7) bitfield calculator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dr7Register {
    value: u64,
}

impl Default for Dr7Register {
    fn default() -> Self {
        Self::new()
    }
}

impl Dr7Register {
    /// Initial DR7 value has bit 10 set to 1 (Intel architecture invariant)
    pub const fn new() -> Self {
        Dr7Register { value: 0x0000_0400 }
    }

    /// Construct from raw u64 value
    pub const fn from_raw(value: u64) -> Self {
        Dr7Register { value }
    }

    /// Get current raw DR7 value
    pub const fn raw(&self) -> u64 {
        self.value
    }

    /// Enable breakpoint slot (0..=3)
    pub fn enable(&mut self, slot: usize, local: bool) {
        if slot > 3 {
            return;
        }
        let bit = if local { 2 * slot } else { 2 * slot + 1 };
        self.value |= 1 << bit;
        // Also enable Exact Breakpoint Enable (LE: bit 8)
        self.value |= 1 << 8;
    }

    /// Disable breakpoint slot (0..=3)
    pub fn disable(&mut self, slot: usize) {
        if slot > 3 {
            return;
        }
        let local_mask = 1 << (2 * slot);
        let global_mask = 1 << (2 * slot + 1);
        self.value &= !(local_mask | global_mask);
    }

    /// Check if breakpoint slot is enabled
    pub fn is_enabled(&self, slot: usize) -> bool {
        if slot > 3 {
            return false;
        }
        let mask = (1 << (2 * slot)) | (1 << (2 * slot + 1));
        (self.value & mask) != 0
    }

    /// Set trigger condition for breakpoint slot (0..=3)
    pub fn set_condition(&mut self, slot: usize, condition: WatchpointCondition) {
        if slot > 3 {
            return;
        }
        let shift = 16 + 4 * slot;
        let cond_bits: u64 = match condition {
            WatchpointCondition::Execution => 0b00,
            WatchpointCondition::Write => 0b01,
            WatchpointCondition::Access => 0b11,
        };
        self.value &= !(0b11 << shift);
        self.value |= cond_bits << shift;
    }

    /// Set watchpoint monitored length in bytes (1, 2, 4, 8)
    pub fn set_size(&mut self, slot: usize, size: WatchpointSize) {
        if slot > 3 {
            return;
        }
        let shift = 18 + 4 * slot;
        let len_bits: u64 = match size {
            WatchpointSize::Bytes1 => 0b00,
            WatchpointSize::Bytes2 => 0b01,
            WatchpointSize::Bytes8 => 0b10,
            WatchpointSize::Bytes4 => 0b11,
        };
        self.value &= !(0b11 << shift);
        self.value |= len_bits << shift;
    }
}

/// Active hardware breakpoint tracked in DR0-DR3
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareBreakpoint {
    pub slot: usize,
    pub address: Address,
    pub condition: WatchpointCondition,
    pub size: WatchpointSize,
    pub enabled: bool,
}

/// Active software breakpoint (INT3 opcode substitution)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareBreakpoint {
    pub id: BreakpointId,
    pub address: Address,
    pub original_byte: u8,
    pub enabled: bool,
    pub hit_count: u64,
    pub condition: Option<String>,
}

/// Summary description of an active breakpoint for UI and MCP listing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakpointSummary {
    pub id: u64,
    pub address: Address,
    pub kind: String,
    pub enabled: bool,
    pub hit_count: u64,
}

/// Central manager for software and hardware breakpoints
pub struct BreakpointManager {
    software_bps: HashMap<Address, SoftwareBreakpoint>,
    hardware_bps: [Option<HardwareBreakpoint>; 4],
    dr7: Dr7Register,
    dr_addresses: [Address; 4],
    next_id: u64,
}

impl Default for BreakpointManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BreakpointManager {
    pub fn new() -> Self {
        BreakpointManager {
            software_bps: HashMap::new(),
            hardware_bps: [None, None, None, None],
            dr7: Dr7Register::new(),
            dr_addresses: [Address::NULL; 4],
            next_id: 1,
        }
    }

    /// Set a software breakpoint by replacing instruction byte with 0xCC (INT3)
    pub fn set_software_breakpoint(
        &mut self,
        pal: &mut dyn ProcessAccessLayer,
        address: Address,
    ) -> CoreResult<BreakpointId> {
        if let Some(bp) = self.software_bps.get(&address) {
            return Ok(bp.id);
        }

        let original = pal.read_raw(address, 1).map_err(|e| {
            CoreError::Debugger(format!("Failed to read target byte at {address}: {e}"))
        })?;

        let original_byte = original.first().copied().unwrap_or(0x90);

        pal.write_raw(address, &[0xCC]).map_err(|e| {
            CoreError::Debugger(format!("Failed to write INT3 at {address}: {e}"))
        })?;

        let id = BreakpointId(self.next_id);
        self.next_id += 1;

        self.software_bps.insert(
            address,
            SoftwareBreakpoint {
                id,
                address,
                original_byte,
                enabled: true,
                hit_count: 0,
                condition: None,
            },
        );

        Ok(id)
    }

    /// Remove a software breakpoint and restore the original instruction byte
    pub fn remove_software_breakpoint(
        &mut self,
        pal: &mut dyn ProcessAccessLayer,
        id: BreakpointId,
    ) -> CoreResult<()> {
        let addr = self
            .software_bps
            .iter()
            .find(|(_, bp)| bp.id == id)
            .map(|(addr, _)| *addr)
            .ok_or_else(|| CoreError::Debugger(format!("Software breakpoint #{} not found", id.0)))?;

        if let Some(bp) = self.software_bps.remove(&addr) {
            if bp.enabled {
                pal.write_raw(bp.address, &[bp.original_byte]).map_err(|e| {
                    CoreError::Debugger(format!(
                        "Failed to restore original byte at {}: {e}",
                        bp.address
                    ))
                })?;
            }
        }

        Ok(())
    }

    /// Set a hardware execution or watchpoint (DR0-DR3)
    pub fn set_hardware_breakpoint(
        &mut self,
        address: Address,
        condition: WatchpointCondition,
        size: WatchpointSize,
    ) -> CoreResult<usize> {
        let free_slot = self
            .hardware_bps
            .iter()
            .position(|slot| slot.is_none())
            .ok_or_else(|| {
                CoreError::Debugger("All 4 hardware debug registers (DR0-DR3) are currently occupied".to_string())
            })?;

        self.dr7.set_condition(free_slot, condition);
        self.dr7.set_size(free_slot, size);
        self.dr7.enable(free_slot, true);
        self.dr_addresses[free_slot] = address;

        self.hardware_bps[free_slot] = Some(HardwareBreakpoint {
            slot: free_slot,
            address,
            condition,
            size,
            enabled: true,
        });

        Ok(free_slot)
    }

    /// Remove a hardware breakpoint from a slot (0..=3)
    pub fn remove_hardware_breakpoint(&mut self, slot: usize) -> CoreResult<()> {
        if slot > 3 {
            return Err(CoreError::Debugger(format!("Invalid hardware slot {slot} (must be 0..3)")));
        }

        self.dr7.disable(slot);
        self.dr_addresses[slot] = Address::NULL;
        self.hardware_bps[slot] = None;
        Ok(())
    }

    /// Get current DR7 register value
    pub fn dr7(&self) -> u64 {
        self.dr7.raw()
    }

    /// Get current DR0-DR3 linear addresses
    pub fn dr_addresses(&self) -> [Address; 4] {
        self.dr_addresses
    }

    /// List all registered software and hardware breakpoints
    pub fn list_breakpoints(&self) -> Vec<BreakpointSummary> {
        let mut list = Vec::new();

        for bp in self.software_bps.values() {
            list.push(BreakpointSummary {
                id: bp.id.0,
                address: bp.address,
                kind: "Software (INT3)".to_string(),
                enabled: bp.enabled,
                hit_count: bp.hit_count,
            });
        }

        for (i, slot) in self.hardware_bps.iter().enumerate() {
            if let Some(hw) = slot {
                let cond_str = match hw.condition {
                    WatchpointCondition::Execution => "Execute",
                    WatchpointCondition::Write => "Write",
                    WatchpointCondition::Access => "Read/Write",
                };
                list.push(BreakpointSummary {
                    id: 1000 + i as u64,
                    address: hw.address,
                    kind: format!("Hardware DR{i} ({cond_str}, {}B)", hw.size.byte_count()),
                    enabled: hw.enabled,
                    hit_count: 0,
                });
            }
        }

        list.sort_by_key(|b| b.address);
        list
    }

    /// Get a software breakpoint by address
    pub fn get_software_bp(&self, address: Address) -> Option<&SoftwareBreakpoint> {
        self.software_bps.get(&address)
    }

    /// Get a software breakpoint by ID
    pub fn get_software_bp_by_id(&self, id: BreakpointId) -> Option<&SoftwareBreakpoint> {
        self.software_bps.values().find(|bp| bp.id == id)
    }
}

/// Cheat Engine-style tracer: "What writes to this address?" / "What accesses this address?"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitTracer {
    pub target_address: Address,
    pub target_size: usize,
    pub condition: WatchpointCondition,
    pub hits: HashMap<Address, DebugHit>,
}

impl HitTracer {
    pub fn new(target_address: Address, target_size: usize, condition: WatchpointCondition) -> Self {
        HitTracer {
            target_address,
            target_size,
            condition,
            hits: HashMap::new(),
        }
    }

    /// Record an instruction hit modifying or accessing the watched address
    pub fn record_hit(
        &mut self,
        instruction_pointer: Address,
        registers: CpuRegisters,
        disassembly: Option<String>,
        thread_id: Option<u32>,
    ) {
        let entry = self.hits.entry(instruction_pointer).or_insert_with(|| DebugHit {
            address: self.target_address,
            instruction_pointer,
            thread_id,
            hit_count: 0,
            registers,
            disassembly,
        });

        entry.hit_count += 1;
        entry.registers = registers;
    }

    /// Total number of unique instructions that triggered hits
    pub fn unique_instructions_count(&self) -> usize {
        self.hits.len()
    }

    /// Total sum of all hits across instructions
    pub fn total_hits(&self) -> u64 {
        self.hits.values().map(|h| h.hit_count).sum()
    }

    /// Retrieve hits sorted in descending order of hit count
    pub fn sorted_hits(&self) -> Vec<&DebugHit> {
        let mut list: Vec<&DebugHit> = self.hits.values().collect();
        list.sort_by_key(|a| std::cmp::Reverse(a.hit_count));
        list
    }

    /// Format hits as a readable ASCII table (like Cheat Engine's debugger window)
    pub fn format_table(&self) -> String {
        let cond_name = match self.condition {
            WatchpointCondition::Execution => "Execute",
            WatchpointCondition::Write => "Write",
            WatchpointCondition::Access => "Read/Write",
        };

        let mut out = format!(
            "Target Address: {}\nCondition: {} ({} bytes)\nTotal hits: {}\n\n",
            self.target_address,
            cond_name,
            self.target_size,
            self.total_hits()
        );

        out.push_str(&format!(
            "{:<6} | {:<18} | {:<32} | {}\n",
            "Hits", "Instruction Address", "Disassembly", "Context (Registers)"
        ));
        out.push_str(&format!("{:-<6}-+-{:-<18}-+-{:-<32}-+-{:-<20}\n", "", "", "", ""));

        for hit in self.sorted_hits() {
            let disasm = hit.disassembly.as_deref().unwrap_or("unknown");
            let reg_summary = format!(
                "RAX=0x{:X} RBX=0x{:X} RCX=0x{:X} RDX=0x{:X}",
                hit.registers.rax, hit.registers.rbx, hit.registers.rcx, hit.registers.rdx
            );
            out.push_str(&format!(
                "{:<6} | {:<18} | {:<32} | {}\n",
                hit.hit_count, hit.instruction_pointer, disasm, reg_summary
            ));
        }

        out
    }

    /// Convert hits to structured JSON for AI consumption
    pub fn to_json(&self) -> serde_json::Value {
        let items: Vec<serde_json::Value> = self
            .sorted_hits()
            .iter()
            .map(|h| {
                serde_json::json!({
                    "hit_count": h.hit_count,
                    "instruction_address": format!("{}", h.instruction_pointer),
                    "disassembly": h.disassembly,
                    "thread_id": h.thread_id,
                    "registers": {
                        "rax": format!("0x{:X}", h.registers.rax),
                        "rbx": format!("0x{:X}", h.registers.rbx),
                        "rcx": format!("0x{:X}", h.registers.rcx),
                        "rdx": format!("0x{:X}", h.registers.rdx),
                        "rsi": format!("0x{:X}", h.registers.rsi),
                        "rdi": format!("0x{:X}", h.registers.rdi),
                        "rbp": format!("0x{:X}", h.registers.rbp),
                        "rsp": format!("0x{:X}", h.registers.rsp),
                        "rip": format!("0x{:X}", h.registers.rip),
                        "rflags": format!("0x{:X}", h.registers.rflags),
                    }
                })
            })
            .collect();

        serde_json::json!({
            "target_address": format!("{}", self.target_address),
            "condition": match self.condition {
                WatchpointCondition::Execution => "Execute",
                WatchpointCondition::Write => "Write",
                WatchpointCondition::Access => "Access",
            },
            "target_size": self.target_size,
            "total_hits": self.total_hits(),
            "instructions": items
        })
    }

    /// Disassemble instruction at target IP and check if it modifies the memory address
    pub fn analyze_instruction_hit(
        code_bytes: &[u8],
        ip: u64,
        bitness: u32,
        target_address: Address,
        registers: CpuRegisters,
    ) -> Option<DebugHit> {
        if code_bytes.is_empty() {
            return None;
        }

        let mut decoder = Decoder::with_ip(bitness, code_bytes, ip, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();
        let mut instruction = Instruction::default();

        if decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            let mut text = String::new();
            formatter.format(&instruction, &mut text);

            let mut modifies_memory = false;
            for i in 0..instruction.op_count() {
                if instruction.op_kind(i) == OpKind::Memory {
                    modifies_memory = true;
                    break;
                }
            }

            if modifies_memory {
                return Some(DebugHit {
                    address: target_address,
                    instruction_pointer: Address::new(ip),
                    thread_id: None,
                    hit_count: 1,
                    registers,
                    disassembly: Some(text),
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_pal::{
        MemoryRegion, ModuleInfo, ProcessId, ProtectionFlags, StealthLevel, ThreadInfo,
    };
    use std::sync::Mutex;

    struct MockPal {
        memory: Mutex<HashMap<u64, u8>>,
    }

    impl MockPal {
        fn new() -> Self {
            let mut memory = HashMap::new();
            // Put some initial instructions: 0x90 (NOP), 0x48, 0x89, 0xC3
            memory.insert(0x1000, 0x90);
            memory.insert(0x1001, 0x48);
            memory.insert(0x1002, 0x89);
            MockPal {
                memory: Mutex::new(memory),
            }
        }
    }

    impl ProcessAccessLayer for MockPal {
        fn attach(&mut self, _pid: ProcessId) -> Result<(), engine_pal::PalError> { Ok(()) }
        fn detach(&mut self) -> Result<(), engine_pal::PalError> { Ok(()) }
        fn is_attached(&self) -> bool { true }
        fn attached_pid(&self) -> Option<ProcessId> { Some(1234) }
        fn architecture(&self) -> engine_pal::CpuArchitecture { engine_pal::CpuArchitecture::X86_64 }
        fn read_raw(&self, address: Address, size: usize) -> Result<Vec<u8>, engine_pal::PalError> {
            let mem = self.memory.lock().unwrap();
            let mut res = Vec::new();
            for i in 0..size {
                let byte = mem.get(&(address.as_u64() + i as u64)).copied().unwrap_or(0);
                res.push(byte);
            }
            Ok(res)
        }
        fn write_raw(&self, address: Address, data: &[u8]) -> Result<(), engine_pal::PalError> {
            let mut mem = self.memory.lock().unwrap();
            for (i, &b) in data.iter().enumerate() {
                mem.insert(address.as_u64() + i as u64, b);
            }
            Ok(())
        }
        fn query_regions(&self) -> Result<Vec<MemoryRegion>, engine_pal::PalError> { Ok(Vec::new()) }
        fn enumerate_modules(&self) -> Result<Vec<ModuleInfo>, engine_pal::PalError> { Ok(Vec::new()) }
        fn enumerate_threads(&self) -> Result<Vec<ThreadInfo>, engine_pal::PalError> { Ok(Vec::new()) }
        fn set_breakpoint(&mut self, _addr: Address, _bp: engine_pal::BreakpointType) -> Result<BreakpointId, engine_pal::PalError> { Ok(BreakpointId(1)) }
        fn remove_breakpoint(&mut self, _id: BreakpointId) -> Result<(), engine_pal::PalError> { Ok(()) }
        fn allocate_memory(&self, _size: usize, _protection: ProtectionFlags) -> Result<Address, engine_pal::PalError> { Ok(Address::new(0x2000)) }
        fn free_memory(&self, _address: Address) -> Result<(), engine_pal::PalError> { Ok(()) }
        fn stealth_level(&self) -> StealthLevel { StealthLevel::None }
        fn backend_name(&self) -> &'static str { "MockPal" }
    }

    #[test]
    fn test_dr7_register_bitfield() {
        let mut dr7 = Dr7Register::new();
        assert_eq!(dr7.raw(), 0x0000_0400);

        // Enable DR0 local, Write, 4 bytes
        dr7.enable(0, true);
        dr7.set_condition(0, WatchpointCondition::Write);
        dr7.set_size(0, WatchpointSize::Bytes4);

        assert!(dr7.is_enabled(0));
        assert!(!dr7.is_enabled(1));

        // Bit 0 = 1, Bit 8 = 1, Bit 10 = 1
        // Condition Write (01) at shift 16: (1 << 16)
        // Length 4 bytes (11) at shift 18: (3 << 18)
        let expected = 0x0000_0400 | (1 << 0) | (1 << 8) | (1 << 16) | (3 << 18);
        assert_eq!(dr7.raw(), expected);

        dr7.disable(0);
        assert!(!dr7.is_enabled(0));
    }

    #[test]
    fn test_software_breakpoint_install_and_remove() {
        let mut pal = MockPal::new();
        let mut bpm = BreakpointManager::new();

        let bp_addr = Address::new(0x1000);
        // Initial byte is 0x90
        assert_eq!(pal.read_raw(bp_addr, 1).unwrap(), vec![0x90]);

        // Set software breakpoint
        let id = bpm.set_software_breakpoint(&mut pal, bp_addr).unwrap();
        // Memory now contains 0xCC (INT3)
        assert_eq!(pal.read_raw(bp_addr, 1).unwrap(), vec![0xCC]);

        let bp = bpm.get_software_bp(bp_addr).unwrap();
        assert_eq!(bp.original_byte, 0x90);
        assert_eq!(bp.id, id);

        // Remove breakpoint
        bpm.remove_software_breakpoint(&mut pal, id).unwrap();
        // Memory original byte 0x90 restored!
        assert_eq!(pal.read_raw(bp_addr, 1).unwrap(), vec![0x90]);
        assert!(bpm.get_software_bp(bp_addr).is_none());
    }

    #[test]
    fn test_hardware_breakpoint_allocation() {
        let mut bpm = BreakpointManager::new();

        let s0 = bpm.set_hardware_breakpoint(Address::new(0x5000), WatchpointCondition::Write, WatchpointSize::Bytes4).unwrap();
        let s1 = bpm.set_hardware_breakpoint(Address::new(0x6000), WatchpointCondition::Access, WatchpointSize::Bytes8).unwrap();
        assert_eq!(s0, 0);
        assert_eq!(s1, 1);

        let list = bpm.list_breakpoints();
        assert_eq!(list.len(), 2);
        assert!(list[0].kind.contains("Hardware DR0"));
        assert!(list[1].kind.contains("Hardware DR1"));

        bpm.remove_hardware_breakpoint(0).unwrap();
        assert_eq!(bpm.list_breakpoints().len(), 1);
    }

    #[test]
    fn test_hit_tracer_accumulation_and_formatting() {
        let mut tracer = HitTracer::new(Address::new(0x7FFF1000), 4, WatchpointCondition::Write);

        let mut regs = CpuRegisters::default();
        regs.rax = 0x7FFF1000;
        regs.rip = 0x401020;

        tracer.record_hit(Address::new(0x401020), regs, Some("mov [rax], ecx".to_string()), None);
        tracer.record_hit(Address::new(0x401020), regs, Some("mov [rax], ecx".to_string()), None);
        tracer.record_hit(Address::new(0x402050), regs, Some("add [rax], 1".to_string()), None);

        assert_eq!(tracer.unique_instructions_count(), 2);
        assert_eq!(tracer.total_hits(), 3);

        let table = tracer.format_table();
        assert!(table.contains("mov [rax], ecx"));
        assert!(table.contains("add [rax], 1"));

        let json_val = tracer.to_json();
        assert_eq!(json_val["total_hits"], 3);
    }

    #[test]
    fn test_analyze_instruction_hit_with_iced() {
        // mov [rax], ecx -> 89 08
        let code = [0x89, 0x08];
        let mut regs = CpuRegisters::default();
        regs.rax = 0x12345678;

        let hit = HitTracer::analyze_instruction_hit(&code, 0x401000, 64, Address::new(0x12345678), regs);
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.instruction_pointer.as_u64(), 0x401000);
        assert!(hit.disassembly.unwrap().contains("mov [rax],ecx"));
    }
}
