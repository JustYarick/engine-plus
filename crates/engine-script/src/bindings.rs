use crate::auto_assembler::AutoAssembler;
use crate::error::ScriptResult;
use crate::sandbox::create_sandboxed_lua;
use engine_core::{assemble_code, build_detour_hook, parse_aob_pattern, FirstScanMode, MemoryScanner, ScanConfig, ScanValue, ScanValueType};
use engine_pal::{Address, ProcessAccessLayer, ProtectionFlags};
use mlua::{HookTriggers, Lua, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Script execution context shared with sandboxed Lua runtime
pub struct ScriptEngine {
    lua: Lua,
    pal: Arc<Mutex<Box<dyn ProcessAccessLayer>>>,
    scanner: Arc<Mutex<MemoryScanner>>,
    allocations: Arc<Mutex<HashMap<String, Address>>>,
}

impl ScriptEngine {
    pub fn new(
        pal: Arc<Mutex<Box<dyn ProcessAccessLayer>>>,
        scanner: Arc<Mutex<MemoryScanner>>,
    ) -> ScriptResult<Self> {
        Self::with_allocations(pal, scanner, Arc::new(Mutex::new(HashMap::new())))
    }

    pub fn with_allocations(
        pal: Arc<Mutex<Box<dyn ProcessAccessLayer>>>,
        scanner: Arc<Mutex<MemoryScanner>>,
        allocations: Arc<Mutex<HashMap<String, Address>>>,
    ) -> ScriptResult<Self> {
        let lua = create_sandboxed_lua()?;

        let engine = Self {
            lua,
            pal,
            scanner,
            allocations,
        };

        engine.register_core_bindings()?;
        Ok(engine)
    }

    pub fn allocations(&self) -> Arc<Mutex<HashMap<String, Address>>> {
        Arc::clone(&self.allocations)
    }

    /// Register all core Engine+ API modules (memory, scanner, assembler, auto_assemble) in Lua
    fn register_core_bindings(&self) -> ScriptResult<()> {
        let globals = self.lua.globals();

        // 1. memory module
        let memory_table = self.lua.create_table()?;
        {
            let pal = Arc::clone(&self.pal);
            memory_table.set(
                "read_i32",
                self.lua.create_function(move |_, addr_val: Value| {
                    let addr = parse_lua_address(&addr_val)?;
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let bytes = p.read_raw(addr, 4).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    if bytes.len() < 4 {
                        return Err(mlua::Error::RuntimeError("Incomplete read".to_string()));
                    }
                    Ok(i32::from_le_bytes(bytes[..4].try_into().unwrap()))
                })?,
            )?;

            let pal = Arc::clone(&self.pal);
            memory_table.set(
                "read_u32",
                self.lua.create_function(move |_, addr_val: Value| {
                    let addr = parse_lua_address(&addr_val)?;
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let bytes = p.read_raw(addr, 4).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    if bytes.len() < 4 {
                        return Err(mlua::Error::RuntimeError("Incomplete read".to_string()));
                    }
                    Ok(u32::from_le_bytes(bytes[..4].try_into().unwrap()))
                })?,
            )?;

            let pal = Arc::clone(&self.pal);
            memory_table.set(
                "read_f32",
                self.lua.create_function(move |_, addr_val: Value| {
                    let addr = parse_lua_address(&addr_val)?;
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let bytes = p.read_raw(addr, 4).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    if bytes.len() < 4 {
                        return Err(mlua::Error::RuntimeError("Incomplete read".to_string()));
                    }
                    Ok(f32::from_le_bytes(bytes[..4].try_into().unwrap()))
                })?,
            )?;

            let pal = Arc::clone(&self.pal);
            memory_table.set(
                "read_f64",
                self.lua.create_function(move |_, addr_val: Value| {
                    let addr = parse_lua_address(&addr_val)?;
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let bytes = p.read_raw(addr, 8).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    if bytes.len() < 8 {
                        return Err(mlua::Error::RuntimeError("Incomplete read".to_string()));
                    }
                    Ok(f64::from_le_bytes(bytes[..8].try_into().unwrap()))
                })?,
            )?;

            let pal = Arc::clone(&self.pal);
            memory_table.set(
                "read_string",
                self.lua.create_function(move |_, (addr_val, max_len): (Value, usize)| {
                    let addr = parse_lua_address(&addr_val)?;
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let bytes = p.read_raw(addr, max_len).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let s = String::from_utf8_lossy(&bytes);
                    let null_trimmed = s.split('\0').next().unwrap_or("").to_string();
                    Ok(null_trimmed)
                })?,
            )?;

            let pal = Arc::clone(&self.pal);
            memory_table.set(
                "read_bytes",
                self.lua.create_function(move |lua, (addr_val, size): (Value, usize)| {
                    let addr = parse_lua_address(&addr_val)?;
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let bytes = p.read_raw(addr, size).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let table = lua.create_table()?;
                    for (i, b) in bytes.iter().enumerate() {
                        table.set(i + 1, *b)?;
                    }
                    Ok(table)
                })?,
            )?;

            let pal = Arc::clone(&self.pal);
            memory_table.set(
                "write_i32",
                self.lua.create_function(move |_, (addr_val, val): (Value, i32)| {
                    let addr = parse_lua_address(&addr_val)?;
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    p.write_raw(addr, &val.to_le_bytes()).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    Ok(())
                })?,
            )?;

            let pal = Arc::clone(&self.pal);
            memory_table.set(
                "write_f32",
                self.lua.create_function(move |_, (addr_val, val): (Value, f32)| {
                    let addr = parse_lua_address(&addr_val)?;
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    p.write_raw(addr, &val.to_le_bytes()).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    Ok(())
                })?,
            )?;

            let pal = Arc::clone(&self.pal);
            memory_table.set(
                "write_bytes",
                self.lua.create_function(move |_, (addr_val, data_val): (Value, Value)| {
                    let addr = parse_lua_address(&addr_val)?;
                    let bytes = match data_val {
                        Value::String(s) => {
                            let str_bytes = s.as_bytes();
                            let s_str = std::str::from_utf8(str_bytes).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                            let mut b = Vec::new();
                            for t in s_str.split_whitespace() {
                                let clean = t.trim_start_matches("0x").trim_start_matches("0X");
                                b.push(u8::from_str_radix(clean, 16).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?);
                            }
                            b
                        }
                        Value::Table(t) => {
                            let mut b = Vec::new();
                            for i in 1..=t.raw_len() {
                                let byte_val: u8 = t.get(i)?;
                                b.push(byte_val);
                            }
                            b
                        }
                        _ => return Err(mlua::Error::RuntimeError("Expected hex string or table of bytes".to_string())),
                    };

                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    p.write_raw(addr, &bytes).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    Ok(())
                })?,
            )?;

            let pal = Arc::clone(&self.pal);
            memory_table.set(
                "alloc",
                self.lua.create_function(move |_, (size, prot_str): (usize, Option<String>)| {
                    let prot = match prot_str.as_deref().unwrap_or("rwx").to_lowercase().as_str() {
                        "rw" => ProtectionFlags::RW,
                        "rx" => ProtectionFlags::RX,
                        _ => ProtectionFlags::RWX,
                    };
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let addr = p.allocate_memory(size, prot).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    Ok(format!("0x{:X}", addr.as_u64()))
                })?,
            )?;

            let pal = Arc::clone(&self.pal);
            memory_table.set(
                "free",
                self.lua.create_function(move |_, addr_val: Value| {
                    let addr = parse_lua_address(&addr_val)?;
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    p.free_memory(addr).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    Ok(())
                })?,
            )?;
        }
        globals.set("memory", memory_table)?;

        // 2. scanner module
        let scanner_table = self.lua.create_table()?;
        {
            let pal = Arc::clone(&self.pal);
            let scanner = Arc::clone(&self.scanner);
            scanner_table.set(
                "aob_scan",
                self.lua.create_function(move |lua, pattern: String| {
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let mut s = scanner.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let config = ScanConfig::new(ScanValueType::Aob);
                    let parsed = parse_aob_pattern(&pattern).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                    s.first_scan(&**p, &config, &FirstScanMode::Exact(ScanValue::Aob(parsed)))
                        .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                    let results_table = lua.create_table()?;
                    if let Some(res) = s.current_results() {
                        for (i, m) in res.page(0, 100).iter().enumerate() {
                            results_table.set(i + 1, format!("0x{:X}", m.address.as_u64()))?;
                        }
                    }
                    Ok(results_table)
                })?,
            )?;

            let pal = Arc::clone(&self.pal);
            let scanner = Arc::clone(&self.scanner);
            scanner_table.set(
                "first_scan",
                self.lua.create_function(move |_, (val_str, type_str): (String, String)| {
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let mut s = scanner.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                    let val_type = parse_scan_type(&type_str)?;
                    let config = ScanConfig::new(val_type);
                    let parsed_val = ScanValue::parse(&val_str, val_type).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                    let count = s.first_scan(&**p, &config, &FirstScanMode::Exact(parsed_val))
                        .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    Ok(count)
                })?,
            )?;
        }
        globals.set("scanner", scanner_table)?;

        // 3. assembler module
        let asm_table = self.lua.create_table()?;
        {
            asm_table.set(
                "assemble",
                self.lua.create_function(|lua, (code, ip_val, bitness): (String, Option<Value>, Option<u32>)| {
                    let ip = match ip_val {
                        Some(v) => parse_lua_address(&v)?.as_u64(),
                        None => 0x1000,
                    };
                    let bits = bitness.unwrap_or(64);
                    let bytes = assemble_code(&code, bits, ip).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                    let t = lua.create_table()?;
                    for (i, b) in bytes.iter().enumerate() {
                        t.set(i + 1, *b)?;
                    }
                    Ok(t)
                })?,
            )?;

            let pal = Arc::clone(&self.pal);
            asm_table.set(
                "patch",
                self.lua.create_function(move |lua, (addr_val, code): (Value, String)| {
                    let addr = parse_lua_address(&addr_val)?;
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let bitness = match p.architecture() {
                        engine_pal::CpuArchitecture::X86_32 => 32,
                        engine_pal::CpuArchitecture::X86_64 => 64,
                    };

                    let bytes = if let Some(hex_part) = code.strip_prefix("hex:") {
                        let mut b = Vec::new();
                        for token in hex_part.split_whitespace() {
                            let clean = token.trim_start_matches("0x").trim_start_matches("0X");
                            b.push(u8::from_str_radix(clean, 16).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?);
                        }
                        b
                    } else {
                        assemble_code(&code, bitness, addr.as_u64()).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?
                    };

                    let orig = p.read_raw(addr, bytes.len()).unwrap_or_default();
                    p.write_raw(addr, &bytes).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                    let resp = lua.create_table()?;
                    resp.set("address", format!("0x{:X}", addr.as_u64()))?;
                    resp.set("length", bytes.len())?;
                    resp.set("original_hex", orig.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" "))?;
                    resp.set("patch_hex", bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" "))?;
                    Ok(resp)
                })?,
            )?;

            let pal = Arc::clone(&self.pal);
            asm_table.set(
                "hook",
                self.lua.create_function(move |lua, (target_val, cave_val, payload_opt): (Value, Value, Option<String>)| {
                    let target = parse_lua_address(&target_val)?;
                    let cave = parse_lua_address(&cave_val)?;
                    let p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let bitness = match p.architecture() {
                        engine_pal::CpuArchitecture::X86_32 => 32,
                        engine_pal::CpuArchitecture::X86_64 => 64,
                    };

                    let orig_slice = p.read_raw(target, 32).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let payload = if let Some(code) = payload_opt {
                        assemble_code(&code, bitness, cave.as_u64()).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?
                    } else {
                        Vec::new()
                    };

                    let package = build_detour_hook(&orig_slice, target.as_u64(), cave.as_u64(), bitness, &payload)
                        .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                    p.write_raw(cave, &package.code_cave_bytes).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    p.write_raw(target, &package.patch_bytes).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                    let resp = lua.create_table()?;
                    resp.set("target", format!("0x{:X}", target.as_u64()))?;
                    resp.set("cave", format!("0x{:X}", cave.as_u64()))?;
                    resp.set("stolen_bytes", package.original_bytes.len())?;
                    resp.set("return_address", format!("0x{:X}", package.return_address.as_u64()))?;
                    Ok(resp)
                })?,
            )?;
        }
        globals.set("assembler", asm_table)?;

        // 4. auto_assemble global function
        {
            let pal = Arc::clone(&self.pal);
            let allocs = Arc::clone(&self.allocations);
            globals.set(
                "auto_assemble",
                self.lua.create_function(move |lua, (script, enable): (String, Option<bool>)| {
                    let is_enable = enable.unwrap_or(true);
                    let mut p = pal.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                    let mut a = allocs.lock().map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                    let report = AutoAssembler::execute(&script, is_enable, &mut **p, &mut a)
                        .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                    let resp = lua.create_table()?;
                    resp.set("status", if is_enable { "enabled" } else { "disabled" })?;
                    resp.set("allocations_count", report.allocations.len())?;
                    Ok(resp)
                })?,
            )?;
        }

        Ok(())
    }

    /// Execute a Lua script string with active 3-second watchdog timer
    pub fn execute(&self, script: &str) -> ScriptResult<Value<'_>> {
        let start_time = Instant::now();
        let timeout = Duration::from_secs(3);

        // Configure instruction count hook for Watchdog interruption
        self.lua.set_hook(
            HookTriggers::default().every_nth_instruction(1000),
            move |_lua, _debug| {
                if start_time.elapsed() > timeout {
                    Err(mlua::Error::RuntimeError(
                        "Script execution timeout: exceeded 3 seconds (Watchdog triggered)".to_string(),
                    ))
                } else {
                    Ok(())
                }
            },
        );

        let result = self.lua.load(script).eval::<Value>()?;
        self.lua.remove_hook();
        Ok(result)
    }
}

fn parse_lua_address(val: &Value) -> mlua::Result<Address> {
    match val {
        Value::Integer(i) => Ok(Address::new(*i as u64)),
        Value::Number(n) => Ok(Address::new(*n as u64)),
        Value::String(s) => {
            let str_bytes = s.as_bytes();
            let s_str = std::str::from_utf8(str_bytes).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?.trim();
            if let Some(hex_part) = s_str.strip_prefix("0x").or_else(|| s_str.strip_prefix("0X")) {
                u64::from_str_radix(hex_part, 16)
                    .map(Address::new)
                    .map_err(|e| mlua::Error::RuntimeError(format!("Invalid hex address: {e}")))
            } else {
                s_str.parse::<u64>()
                    .map(Address::new)
                    .map_err(|e| mlua::Error::RuntimeError(format!("Invalid decimal address: {e}")))
            }
        }
        _ => Err(mlua::Error::RuntimeError("Address must be hex string or integer".to_string())),
    }
}

fn parse_scan_type(s: &str) -> mlua::Result<ScanValueType> {
    match s.to_lowercase().as_str() {
        "i8" => Ok(ScanValueType::I8),
        "u8" => Ok(ScanValueType::U8),
        "i16" => Ok(ScanValueType::I16),
        "u16" => Ok(ScanValueType::U16),
        "i32" => Ok(ScanValueType::I32),
        "u32" => Ok(ScanValueType::U32),
        "i64" => Ok(ScanValueType::I64),
        "u64" => Ok(ScanValueType::U64),
        "f32" => Ok(ScanValueType::F32),
        "f64" => Ok(ScanValueType::F64),
        "aob" => Ok(ScanValueType::Aob),
        "string" => Ok(ScanValueType::StringUtf8),
        _ => Err(mlua::Error::RuntimeError(format!("Unsupported type '{s}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_pal::types::{BreakpointId, BreakpointType, CpuArchitecture, MemoryRegion, ModuleInfo, ProcessId, StealthLevel, ThreadInfo};
    use engine_pal::error::PalResult;

    struct DummyPal {
        memory: HashMap<u64, Vec<u8>>,
    }

    impl DummyPal {
        fn new() -> Self {
            let mut mem = HashMap::new();
            mem.insert(0x1000, 42i32.to_le_bytes().to_vec());
            Self { memory: mem }
        }
    }

    impl ProcessAccessLayer for DummyPal {
        fn attach(&mut self, _pid: ProcessId) -> PalResult<()> { Ok(()) }
        fn detach(&mut self) -> PalResult<()> { Ok(()) }
        fn is_attached(&self) -> bool { true }
        fn attached_pid(&self) -> Option<ProcessId> { Some(42) }
        fn architecture(&self) -> CpuArchitecture { CpuArchitecture::X86_64 }
        fn read_raw(&self, address: Address, size: usize) -> PalResult<Vec<u8>> {
            let mut out = vec![0u8; size];
            if let Some(d) = self.memory.get(&address.as_u64()) {
                let to_copy = d.len().min(size);
                out[..to_copy].copy_from_slice(&d[..to_copy]);
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
        fn allocate_memory(&self, _size: usize, _protection: ProtectionFlags) -> PalResult<Address> { Ok(Address::new(0x5000)) }
        fn free_memory(&self, _address: Address) -> PalResult<()> { Ok(()) }
        fn stealth_level(&self) -> StealthLevel { StealthLevel::None }
        fn backend_name(&self) -> &'static str { "DummyPal" }
    }

    #[test]
    fn test_script_engine_memory_bindings() {
        let pal: Arc<Mutex<Box<dyn ProcessAccessLayer>>> = Arc::new(Mutex::new(Box::new(DummyPal::new())));
        let scanner = Arc::new(Mutex::new(MemoryScanner::new()));
        let engine = ScriptEngine::new(pal, scanner).expect("Should create script engine");

        let res = engine.execute("return memory.read_i32('0x1000')").expect("Should execute");
        assert_eq!(res, Value::Integer(42));

        engine.execute("memory.write_i32('0x1000', 999)").expect("Should write");
        let res2 = engine.execute("return memory.read_i32('0x1000')").expect("Should read new");
        assert_eq!(res2, Value::Integer(999));
    }

    #[test]
    fn test_script_engine_watchdog_timeout() {
        let pal: Arc<Mutex<Box<dyn ProcessAccessLayer>>> = Arc::new(Mutex::new(Box::new(DummyPal::new())));
        let scanner = Arc::new(Mutex::new(MemoryScanner::new()));
        let engine = ScriptEngine::new(pal, scanner).expect("Should create script engine");

        // Infinite loop should trigger watchdog timeout after ~3 seconds
        let res = engine.execute("while true do end");
        assert!(res.is_err());
        let err_str = res.err().unwrap().to_string();
        assert!(err_str.contains("Watchdog triggered") || err_str.contains("timeout"));
    }

    #[test]
    fn test_script_engine_assembler_bindings() {
        let pal: Arc<Mutex<Box<dyn ProcessAccessLayer>>> = Arc::new(Mutex::new(Box::new(DummyPal::new())));
        let scanner = Arc::new(Mutex::new(MemoryScanner::new()));
        let engine = ScriptEngine::new(pal, scanner).expect("Should create script engine");

        let res = engine.execute("local bytes = assembler.assemble('nop\\nret', '0x1000', 64); return #bytes").expect("Should assemble");
        assert_eq!(res, Value::Integer(2));
    }

    #[test]
    fn test_script_engine_auto_assemble() {
        let pal: Arc<Mutex<Box<dyn ProcessAccessLayer>>> = Arc::new(Mutex::new(Box::new(DummyPal::new())));
        let scanner = Arc::new(Mutex::new(MemoryScanner::new()));
        let engine = ScriptEngine::new(pal, scanner).expect("Should create script engine");

        let script = r#"
            local res = auto_assemble("[ENABLE]\n0x1000:\nnop\n")
            return res.status
        "#;
        let res = engine.execute(script).expect("Should execute auto_assemble");
        assert_eq!(res, Value::String(engine.lua.create_string("enabled").unwrap()));
    }
}
