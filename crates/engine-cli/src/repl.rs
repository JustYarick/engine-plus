use engine_core::{FirstScanMode, MemoryScanner, NextScanMode, ScanConfig, ScanValue, ScanValueType};
use engine_pal::{default_backend, default_enumerator, Address, ProcessAccessLayer, ProcessId};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use std::io::{self, BufRead, Write};

/// Interactive REPL console for Engine+
pub struct InteractiveConsole {
    pal: Box<dyn ProcessAccessLayer>,
    scanner: MemoryScanner,
    attached_pid: Option<ProcessId>,
    attached_name: Option<String>,
    current_scan_type: ScanValueType,
}

impl InteractiveConsole {
    pub fn new() -> Self {
        InteractiveConsole {
            pal: default_backend(),
            scanner: MemoryScanner::new(),
            attached_pid: None,
            attached_name: None,
            current_scan_type: ScanValueType::I32,
        }
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        println!("==================================================================");
        println!("  Engine+ Interactive Console (Reverse Engineering Suite)");
        println!("  Type 'help' for commands, 'exit' or Ctrl+D to quit");
        println!("==================================================================");

        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let mut line = String::new();

        loop {
            // Print prompt with current target
            if let (Some(pid), Some(ref name)) = (self.attached_pid, &self.attached_name) {
                print!("engine-plus [{name}:{pid}]> ");
            } else {
                print!("engine-plus> ");
            }
            io::stdout().flush()?;

            line.clear();
            if reader.read_line(&mut line)? == 0 {
                // EOF (Ctrl+D)
                println!("\nGoodbye!");
                break;
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let mut parts = trimmed.split_whitespace();
            let cmd = parts.next().unwrap_or("").to_lowercase();
            let args: Vec<&str> = parts.collect();

            match cmd.as_str() {
                "exit" | "quit" | "q" => {
                    println!("Goodbye!");
                    break;
                }
                "help" | "?" => {
                    self.print_help();
                }
                "ps" => {
                    let filter = args.first().copied();
                    self.cmd_ps(filter)?;
                }
                "attach" => {
                    if let Some(pid_str) = args.first() {
                        if let Ok(pid) = pid_str.parse::<ProcessId>() {
                            self.cmd_attach(pid)?;
                        } else {
                            println!("Error: Invalid PID '{pid_str}'");
                        }
                    } else {
                        println!("Usage: attach <PID>");
                    }
                }
                "detach" => {
                    self.cmd_detach()?;
                }
                "info" => {
                    self.cmd_info()?;
                }
                "scan" => {
                    if args.len() < 2 {
                        println!("Usage: scan <value> <type> [align]");
                        println!("  Types: i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, aob, string");
                    } else {
                        let val_str = args[0];
                        let type_str = args[1];
                        let align_opt = args.get(2).and_then(|s| s.parse::<usize>().ok());
                        self.cmd_first_scan(val_str, type_str, align_opt)?;
                    }
                }
                "next" => {
                    if args.is_empty() {
                        println!("Usage: next <value|exact|changed|unchanged|increased|decreased>");
                    } else {
                        self.cmd_next_scan(args[0])?;
                    }
                }
                "results" => {
                    let limit = args.first().and_then(|s| s.parse::<usize>().ok()).unwrap_or(20);
                    self.cmd_show_results(limit);
                }
                "read" => {
                    if args.is_empty() {
                        println!("Usage: read <hex_address> [type] [size]");
                        println!("  Types: i32, u32, i64, u64, f32, f64, hex, string");
                    } else {
                        let addr_str = args[0];
                        let type_str = args.get(1).copied().unwrap_or("i32");
                        let size = args.get(2).and_then(|s| s.parse::<usize>().ok()).unwrap_or(4);
                        self.cmd_read(addr_str, type_str, size)?;
                    }
                }
                "write" => {
                    if args.len() < 2 {
                        println!("Usage: write <hex_address> <value> [type]");
                    } else {
                        let addr_str = args[0];
                        let val_str = args[1];
                        let type_str = args.get(2).copied().unwrap_or("i32");
                        self.cmd_write(addr_str, val_str, type_str)?;
                    }
                }
                "disasm" => {
                    if args.is_empty() {
                        println!("Usage: disasm <hex_address> [size] [bitness]");
                    } else {
                        let addr_str = args[0];
                        let size = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(32);
                        let bitness = args.get(2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(64);
                        self.cmd_disasm(addr_str, size, bitness)?;
                    }
                }
                "analyze" => {
                    if args.is_empty() {
                        println!("Usage: analyze <hex_address> [size]");
                    } else {
                        let addr_str = args[0];
                        let size = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(64);
                        self.cmd_analyze(addr_str, size)?;
                    }
                }
                "lua" => {
                    let code = args.join(" ");
                    if code.is_empty() {
                        println!("Usage: lua <lua_code>");
                    } else {
                        self.cmd_lua(&code)?;
                    }
                }
                _ => {
                    println!("Unknown command: '{cmd}'. Type 'help' for available commands.");
                }
            }
        }

        Ok(())
    }

    fn print_help(&self) {
        println!("\nAvailable Commands:");
        println!("  ps [filter]                 - List running processes with optional name filtering");
        println!("  attach <pid>                - Attach to target process by PID");
        println!("  detach                      - Detach from currently attached process");
        println!("  info                        - Show memory regions, loaded modules & architecture");
        println!("  scan <val> <type> [align]   - Perform first memory scan (e.g. 'scan 100 i32')");
        println!("  next <val|mode>             - Filter scan results (exact, changed, unchanged, increased)");
        println!("  results [limit]             - Display found scan addresses (default 20)");
        println!("  read <addr> [type] [size]   - Read memory at hex address (e.g. 'read 0x7FFF1000 i32')");
        println!("  write <addr> <val> [type]   - Write memory at hex address (e.g. 'write 0x7FFF1000 999 i32')");
        println!("  disasm <addr> [size] [bits] - Disassemble memory instructions via iced-x86");
        println!("  analyze <addr> [size]       - Heuristic object structure analyzer (pointers, floats, zeros)");
        println!("  lua <code>                  - Execute script in sandboxed Lua 5.4 environment");
        println!("  exit / quit                 - Quit interactive console\n");
    }

    fn cmd_ps(&self, filter: Option<&str>) -> anyhow::Result<()> {
        let enumerator = default_enumerator();
        let mut procs = enumerator.list_processes()?;

        if let Some(q) = filter {
            let q_lower = q.to_lowercase();
            procs.retain(|p| {
                p.name.to_lowercase().contains(&q_lower)
                    || p.cmdline.as_ref().is_some_and(|c| c.to_lowercase().contains(&q_lower))
            });
        }

        println!("{:<8} {:<8} {:<24} CMDLINE", "PID", "ARCH", "NAME");
        println!("{:-<80}", "");
        for p in procs {
            let arch_str = match p.architecture {
                engine_pal::CpuArchitecture::X86_32 => "x86",
                engine_pal::CpuArchitecture::X86_64 => "x64",
            };
            let cmd = p.cmdline.unwrap_or_default();
            let short_cmd = if cmd.len() > 40 { format!("{}...", &cmd[..37]) } else { cmd };
            println!("{:<8} {:<8} {:<24} {}", p.pid, arch_str, p.name, short_cmd);
        }
        Ok(())
    }

    fn cmd_attach(&mut self, pid: ProcessId) -> anyhow::Result<()> {
        self.pal.attach(pid)?;
        self.scanner.reset();
        self.attached_pid = Some(pid);

        // Find process name
        let enumerator = default_enumerator();
        let name = enumerator
            .list_processes()
            .ok()
            .and_then(|list| list.into_iter().find(|p| p.pid == pid).map(|p| p.name))
            .unwrap_or_else(|| format!("PID_{pid}"));

        println!("Successfully attached to '{name}' (PID: {pid}) via {}", self.pal.backend_name());
        self.attached_name = Some(name);
        Ok(())
    }

    fn cmd_detach(&mut self) -> anyhow::Result<()> {
        self.pal.detach()?;
        self.scanner.reset();
        println!("Detached from process.");
        self.attached_pid = None;
        self.attached_name = None;
        Ok(())
    }

    fn cmd_info(&self) -> anyhow::Result<()> {
        let pid = match self.attached_pid {
            Some(p) => p,
            None => {
                println!("Error: Not attached to any process. Use 'attach <PID>' first.");
                return Ok(());
            }
        };

        println!("Process Information (PID {pid}):");
        println!("  Backend:      {}", self.pal.backend_name());
        println!("  Architecture: {:?}", self.pal.architecture());
        println!("  Stealth:      {:?}", self.pal.stealth_level());

        let regions = self.pal.query_regions()?;
        println!("  Mapped Memory Regions: {}", regions.len());

        let modules = self.pal.enumerate_modules()?;
        println!("  Loaded Modules Count:  {}", modules.len());
        for m in modules.iter().take(8) {
            println!("    - {:<28} Base: {} (Size: 0x{:X})", m.name, m.base_address, m.size);
        }
        if modules.len() > 8 {
            println!("    ... and {} more modules", modules.len() - 8);
        }

        Ok(())
    }

    fn cmd_first_scan(&mut self, val_str: &str, type_str: &str, align_opt: Option<usize>) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <PID>' first.");
            return Ok(());
        }

        let val_type = parse_val_type(type_str)?;
        let scan_val = ScanValue::parse(val_str, val_type)
            .map_err(|e| anyhow::anyhow!("Invalid scan value: {e}"))?;

        let mut config = ScanConfig::new(val_type);
        if let Some(align) = align_opt {
            config.alignment = align;
        }

        self.current_scan_type = val_type;
        println!("Starting first scan for {scan_val} ({val_type:?}) [align={}]...", config.alignment);
        let start = std::time::Instant::now();
        let count = self.scanner.first_scan(&*self.pal, &config, &FirstScanMode::Exact(scan_val))?;
        let elapsed = start.elapsed();

        println!("Found {count} matches in {elapsed:.2?}.");
        self.cmd_show_results(15);
        Ok(())
    }

    fn cmd_next_scan(&mut self, arg: &str) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <PID>' first.");
            return Ok(());
        }

        let mode = match arg.to_lowercase().as_str() {
            "changed" => NextScanMode::Changed,
            "unchanged" => NextScanMode::Unchanged,
            "increased" => NextScanMode::Increased,
            "decreased" => NextScanMode::Decreased,
            val_str => {
                let current_type = self.current_scan_type;
                let scan_val = ScanValue::parse(val_str, current_type)
                    .map_err(|e| anyhow::anyhow!("Invalid next scan value: {e}"))?;
                NextScanMode::Exact(scan_val)
            }
        };

        println!("Starting next scan ({mode:?})...");
        let start = std::time::Instant::now();
        let count = self.scanner.next_scan(&*self.pal, &mode)?;
        let elapsed = start.elapsed();

        println!("Remaining {count} matches in {elapsed:.2?}.");
        self.cmd_show_results(15);
        Ok(())
    }

    fn cmd_show_results(&self, limit: usize) {
        if let Some(results) = self.scanner.current_results() {
            let total = results.len();
            let page = results.page(0, limit);
            println!("\n{:<6} {:<18} VALUE", "#", "ADDRESS");
            println!("{:-<42}", "");
            for (idx, entry) in page.iter().enumerate() {
                println!("{:<6} {:<18} {}", idx + 1, entry.address, entry.current_value);
            }
            if total > limit {
                println!("... and {} more (use 'results <limit>' to show more)", total - limit);
            }
            println!();
        } else {
            println!("No active scan results.");
        }
    }

    fn cmd_read(&self, addr_str: &str, type_str: &str, size: usize) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <PID>' first.");
            return Ok(());
        }

        let addr = parse_hex_or_dec(addr_str)
            .ok_or_else(|| anyhow::anyhow!("Invalid address '{addr_str}'"))?;

        let bytes = self.pal.read_raw(Address::new(addr), size)?;
        match type_str.to_lowercase().as_str() {
            "i32" if bytes.len() >= 4 => println!("{}: {}", addr_str, i32::from_le_bytes(bytes[..4].try_into().unwrap())),
            "u32" if bytes.len() >= 4 => println!("{}: {}", addr_str, u32::from_le_bytes(bytes[..4].try_into().unwrap())),
            "i64" if bytes.len() >= 8 => println!("{}: {}", addr_str, i64::from_le_bytes(bytes[..8].try_into().unwrap())),
            "u64" if bytes.len() >= 8 => println!("{}: {}", addr_str, u64::from_le_bytes(bytes[..8].try_into().unwrap())),
            "f32" if bytes.len() >= 4 => println!("{}: {}", addr_str, f32::from_le_bytes(bytes[..4].try_into().unwrap())),
            "f64" if bytes.len() >= 8 => println!("{}: {}", addr_str, f64::from_le_bytes(bytes[..8].try_into().unwrap())),
            "string" => println!("{}: \"{}\"", addr_str, String::from_utf8_lossy(&bytes)),
            _ => {
                let hex_str = bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                println!("{}: [HEX] {}", addr_str, hex_str);
            }
        }
        Ok(())
    }

    fn cmd_write(&self, addr_str: &str, val_str: &str, type_str: &str) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <PID>' first.");
            return Ok(());
        }

        let addr = parse_hex_or_dec(addr_str)
            .ok_or_else(|| anyhow::anyhow!("Invalid address '{addr_str}'"))?;

        let bytes = match type_str.to_lowercase().as_str() {
            "i32" => val_str.parse::<i32>()?.to_le_bytes().to_vec(),
            "u32" => val_str.parse::<u32>()?.to_le_bytes().to_vec(),
            "f32" => val_str.parse::<f32>()?.to_le_bytes().to_vec(),
            "i64" => val_str.parse::<i64>()?.to_le_bytes().to_vec(),
            "u64" => val_str.parse::<u64>()?.to_le_bytes().to_vec(),
            "hex" => {
                let mut b = Vec::new();
                for t in val_str.split_whitespace() {
                    b.push(u8::from_str_radix(t, 16)?);
                }
                b
            }
            _ => anyhow::bail!("Unsupported type '{type_str}' for write"),
        };

        self.pal.write_raw(Address::new(addr), &bytes)?;
        println!("Successfully wrote {} bytes to 0x{:X}", bytes.len(), addr);
        Ok(())
    }

    fn cmd_disasm(&self, addr_str: &str, size: usize, bitness: u32) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <PID>' first.");
            return Ok(());
        }

        let addr = parse_hex_or_dec(addr_str)
            .ok_or_else(|| anyhow::anyhow!("Invalid address '{addr_str}'"))?;

        let bytes = self.pal.read_raw(Address::new(addr), size)?;
        let mut decoder = Decoder::with_ip(bitness, &bytes, addr, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();
        let mut instruction = Instruction::default();

        println!("Disassembly of 0x{:X} ({} bytes):", addr, bytes.len());
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            let mut instr_str = String::new();
            formatter.format(&instruction, &mut instr_str);
            println!("  0x{:016X}:  {}", instruction.ip(), instr_str);
        }
        Ok(())
    }

    fn cmd_analyze(&self, addr_str: &str, size: usize) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <PID>' first.");
            return Ok(());
        }

        let addr = parse_hex_or_dec(addr_str)
            .ok_or_else(|| anyhow::anyhow!("Invalid address '{addr_str}'"))?;

        let regions = self.pal.query_regions().unwrap_or_default();
        let bytes = self.pal.read_raw(Address::new(addr), size)?;
        let summary = engine_mcp::optimizer::analyze_memory_block(Address::new(addr), &bytes, &regions);

        println!("Structure Analysis at 0x{:X} (Total Size: {} bytes):", addr, summary.total_size);
        for p in &summary.pointers {
            println!("  +{} [POINTER] -> {} ({})", p.offset, p.target_address, p.region_info.as_deref().unwrap_or(""));
        }
        for s in &summary.strings {
            println!("  +{} [STRING] \"{}\" ({})", s.offset, s.text, s.encoding);
        }
        for f in &summary.floats {
            println!("  +{} [FLOAT] {} ({})", f.offset, f.value, f.hint.as_deref().unwrap_or(""));
        }
        for i in &summary.integers {
            println!("  +{} [INT] i32: {}, u32: {}", i.offset, i.as_i32, i.as_u32);
        }
        Ok(())
    }

    fn cmd_lua(&self, code: &str) -> anyhow::Result<()> {
        let lua = engine_script::sandbox::create_sandboxed_lua()
            .map_err(|e| anyhow::anyhow!("Failed to initialize Lua sandbox: {e}"))?;
        let val = lua.load(code).eval::<engine_script::mlua::Value>()
            .map_err(|e| anyhow::anyhow!("Lua error: {e}"))?;
        println!("Lua Result: {val:?}");
        Ok(())
    }
}

fn parse_val_type(s: &str) -> anyhow::Result<ScanValueType> {
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
        "string" | "str" => Ok(ScanValueType::StringUtf8),
        _ => anyhow::bail!("Unsupported type: '{s}'"),
    }
}

fn parse_hex_or_dec(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}
