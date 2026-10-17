use engine_core::{FirstScanMode, MemoryScanner, NextScanMode, ScanConfig, ScanValue, ScanValueType};
use engine_pal::{
    default_backend, default_enumerator, Address, ProcessAccessLayer, ProcessId, ProtectionFlags,
};
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
                "asm" => {
                    if args.is_empty() {
                        println!("Usage: asm <instructions> [bitness]");
                        println!("  Example: asm xor eax, eax; ret");
                    } else {
                        let bitness = args.last().and_then(|s| s.parse::<u32>().ok()).unwrap_or(64);
                        let code = if args.last().is_some_and(|s| s.parse::<u32>().is_ok()) {
                            args[..args.len() - 1].join(" ")
                        } else {
                            args.join(" ")
                        };
                        self.cmd_asm(&code, bitness)?;
                    }
                }
                "patch" => {
                    if args.len() < 2 {
                        println!("Usage: patch <hex_address> <instructions_or_hex>");
                        println!("  Example: patch 0x7FFF1000 nop; nop");
                        println!("  Example: patch 0x7FFF1000 hex: 90 90 90");
                    } else {
                        let addr_str = args[0];
                        let patch_str = args[1..].join(" ");
                        self.cmd_patch(addr_str, &patch_str)?;
                    }
                }
                "hook" => {
                    if args.len() < 2 {
                        println!("Usage: hook <target_address> <cave_address> [payload_asm]");
                        println!("  Example: hook 0x7FFF1000 0x7FFF5000");
                    } else {
                        let target_str = args[0];
                        let cave_str = args[1];
                        let payload_str = if args.len() > 2 { Some(args[2..].join(" ")) } else { None };
                        self.cmd_hook(target_str, cave_str, payload_str.as_deref())?;
                    }
                }
                "pattern" => {
                    if args.is_empty() {
                        println!("Usage: pattern <hex_address> [size]");
                        println!("  Example: pattern 0x7FFF1000 32");
                    } else {
                        let addr_str = args[0];
                        let size = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(32);
                        self.cmd_pattern(addr_str, size)?;
                    }
                }
                "xrefs" => {
                    if args.len() < 2 {
                        println!("Usage: xrefs <target_address> <start_address> [size]");
                        println!("  Example: xrefs 0x7FFF1000 0x7FFF0000 0x10000");
                    } else {
                        let target_str = args[0];
                        let start_str = args[1];
                        let size_str = args.get(2).copied().unwrap_or("65536");
                        self.cmd_xrefs(target_str, start_str, size_str)?;
                    }
                }
                "alloc" => {
                    if args.is_empty() {
                        println!("Usage: alloc <size> [rwx|rw|rx]");
                        println!("  Example: alloc 4096 rwx");
                    } else {
                        let size = args[0].strip_prefix("0x").and_then(|s| usize::from_str_radix(s, 16).ok()).or_else(|| args[0].parse::<usize>().ok()).unwrap_or(4096);
                        let prot_str = args.get(1).copied().unwrap_or("rwx");
                        self.cmd_alloc(size, prot_str)?;
                    }
                }
                "free" => {
                    if args.is_empty() {
                        println!("Usage: free <hex_address>");
                    } else {
                        self.cmd_free(args[0])?;
                    }
                }
                "reclass" => {
                    if args.is_empty() {
                        println!("Usage: reclass <hex_address> [size] [class_name]");
                        println!("  Example: reclass 0x7FFF1000 128 PlayerEntity");
                    } else {
                        let addr_str = args[0];
                        let size = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(128);
                        let name = args.get(2).copied().unwrap_or("ReconstructedClass");
                        self.cmd_reclass(addr_str, size, name)?;
                    }
                }
                "export_struct" | "export" => {
                    if args.is_empty() {
                        println!("Usage: export <hex_address> [size] [cpp|rust|csharp] [class_name]");
                        println!("  Example: export 0x7FFF1000 128 cpp PlayerEntity");
                    } else {
                        let addr_str = args[0];
                        let size = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(128);
                        let lang = args.get(2).copied().unwrap_or("cpp");
                        let name = args.get(3).copied().unwrap_or("ReconstructedClass");
                        self.cmd_export_struct(addr_str, size, lang, name)?;
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
        println!("  reclass <addr> [size] [name]- ReClass-style node memory reconstruction (VTable, Vector3, etc.)");
        println!("  export <addr> [sz] [lang]   - Export reconstructed class into C++, Rust, or C# code");
        println!("  asm <code...> [bits]        - Assemble instructions into machine code (e.g. 'asm xor eax, eax; ret')");
        println!("  patch <addr> <asm|hex:>     - Patch instructions or bytes at address (e.g. 'patch 0x1000 nop; nop')");
        println!("  hook <target> <cave> [asm]  - Build & install detour trampoline hook with code cave");
        println!("  pattern <addr> [size]       - Auto-generate AOB pattern with wildcard relative masks");
        println!("  xrefs <target> <start> [sz] - Find cross-references (calls, jumps, loads) to target address");
        println!("  alloc <size> [prot]         - Allocate memory in target process (e.g. 'alloc 4096 rwx')");
        println!("  free <addr>                 - Free allocated memory in target process");
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

    fn cmd_asm(&self, code: &str, bitness: u32) -> anyhow::Result<()> {
        let normalized = code.replace(';', "\n");
        match engine_core::assemble_code(&normalized, bitness, 0x1000) {
            Ok(bytes) => {
                let hex_str = bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
                println!("Assembled ({} bytes): {}", bytes.len(), hex_str);
            }
            Err(e) => println!("Assembly error: {e}"),
        }
        Ok(())
    }

    fn cmd_patch(&self, addr_str: &str, patch_str: &str) -> anyhow::Result<()> {
        let addr = match parse_hex_or_dec(addr_str).map(Address::new) {
            Some(a) => a,
            None => {
                println!("Invalid address: '{addr_str}'");
                return Ok(());
            }
        };
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <pid>' first.");
            return Ok(());
        }
        let bitness = match self.pal.architecture() {
            engine_pal::CpuArchitecture::X86_32 => 32,
            engine_pal::CpuArchitecture::X86_64 => 64,
        };

        let bytes = if let Some(hex_part) = patch_str.strip_prefix("hex:") {
            let mut b = Vec::new();
            for t in hex_part.split_whitespace() {
                if let Ok(byte) = u8::from_str_radix(t.trim_start_matches("0x").trim_start_matches("0X"), 16) {
                    b.push(byte);
                } else {
                    println!("Invalid hex byte: '{t}'");
                    return Ok(());
                }
            }
            b
        } else {
            let normalized = patch_str.replace(';', "\n");
            match engine_core::assemble_code(&normalized, bitness, addr.as_u64()) {
                Ok(b) => b,
                Err(e) => {
                    println!("Assembly error: {e}");
                    return Ok(());
                }
            }
        };

        if bytes.is_empty() {
            println!("Error: Patch is empty");
            return Ok(());
        }

        let orig = self.pal.read_raw(addr, bytes.len()).unwrap_or_default();
        let orig_hex = orig.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");

        self.pal.write_raw(addr, &bytes)?;
        let patch_hex = bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");

        println!("Patched 0x{:X} ({} bytes):", addr.as_u64(), bytes.len());
        println!("  Original: {}", orig_hex);
        println!("  New:      {}", patch_hex);
        Ok(())
    }

    fn cmd_hook(&self, target_str: &str, cave_str: &str, payload_str: Option<&str>) -> anyhow::Result<()> {
        let target_addr = match parse_hex_or_dec(target_str).map(Address::new) {
            Some(a) => a,
            None => {
                println!("Invalid target address: '{target_str}'");
                return Ok(());
            }
        };
        let cave_addr = match parse_hex_or_dec(cave_str).map(Address::new) {
            Some(a) => a,
            None => {
                println!("Invalid cave address: '{cave_str}'");
                return Ok(());
            }
        };
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <pid>' first.");
            return Ok(());
        }
        let bitness = match self.pal.architecture() {
            engine_pal::CpuArchitecture::X86_32 => 32,
            engine_pal::CpuArchitecture::X86_64 => 64,
        };

        let original_slice = self.pal.read_raw(target_addr, 32)?;
        let payload = if let Some(p) = payload_str {
            let normalized = p.replace(';', "\n");
            engine_core::assemble_code(&normalized, bitness, cave_addr.as_u64()).unwrap_or_default()
        } else {
            Vec::new()
        };

        match engine_core::build_detour_hook(
            &original_slice,
            target_addr.as_u64(),
            cave_addr.as_u64(),
            bitness,
            &payload,
        ) {
            Ok(package) => {
                self.pal.write_raw(cave_addr, &package.code_cave_bytes)?;
                self.pal.write_raw(target_addr, &package.patch_bytes)?;
                println!("Hook installed successfully!");
                println!("  Target:       0x{:X}", target_addr.as_u64());
                println!("  Code Cave:    0x{:X} ({} bytes)", cave_addr.as_u64(), package.code_cave_bytes.len());
                println!("  Stolen bytes: {} bytes", package.original_bytes.len());
                println!("  Return addr:  0x{:X}", package.return_address.as_u64());
            }
            Err(e) => println!("Failed to build detour hook: {e}"),
        }
        Ok(())
    }

    fn cmd_pattern(&self, addr_str: &str, size: usize) -> anyhow::Result<()> {
        let addr = match parse_hex_or_dec(addr_str).map(Address::new) {
            Some(a) => a,
            None => {
                println!("Invalid address: '{addr_str}'");
                return Ok(());
            }
        };
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <pid>' first.");
            return Ok(());
        }
        let bitness = match self.pal.architecture() {
            engine_pal::CpuArchitecture::X86_32 => 32,
            engine_pal::CpuArchitecture::X86_64 => 64,
        };

        let bytes = self.pal.read_raw(addr, size)?;
        match engine_core::generate_pattern_from_bytes(&bytes, addr.as_u64(), bitness, size) {
            Ok(pattern) => {
                let wildcards = pattern.split_whitespace().filter(|t| *t == "??").count();
                println!("Generated AOB Pattern ({} wildcards):", wildcards);
                println!("  {}", pattern);
            }
            Err(e) => println!("Pattern error: {e}"),
        }
        Ok(())
    }

    fn cmd_xrefs(&self, target_str: &str, start_str: &str, size_str: &str) -> anyhow::Result<()> {
        let target_addr = match parse_hex_or_dec(target_str).map(Address::new) {
            Some(a) => a,
            None => {
                println!("Invalid target address: '{target_str}'");
                return Ok(());
            }
        };
        let start_addr = match parse_hex_or_dec(start_str).map(Address::new) {
            Some(a) => a,
            None => {
                println!("Invalid start address: '{start_str}'");
                return Ok(());
            }
        };
        let size = size_str.strip_prefix("0x").and_then(|s| usize::from_str_radix(s, 16).ok()).or_else(|| size_str.parse::<usize>().ok()).unwrap_or(65536);

        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <pid>' first.");
            return Ok(());
        }
        let bitness = match self.pal.architecture() {
            engine_pal::CpuArchitecture::X86_32 => 32,
            engine_pal::CpuArchitecture::X86_64 => 64,
        };

        let bytes = self.pal.read_raw(start_addr, size)?;
        let xrefs = engine_core::find_xrefs_in_code(&bytes, start_addr.as_u64(), bitness, target_addr.as_u64());
        println!("Found {} cross-references to 0x{:X}:", xrefs.len(), target_addr.as_u64());
        for x in xrefs {
            println!("  0x{:X} [{:?}] {}", x.instruction_address.as_u64(), x.xref_type, x.instruction_text);
        }
        Ok(())
    }

    fn cmd_alloc(&self, size: usize, prot_str: &str) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <pid>' first.");
            return Ok(());
        }
        let prot = match prot_str.to_lowercase().as_str() {
            "rw" => ProtectionFlags::RW,
            "rx" => ProtectionFlags::RX,
            "rwx" => ProtectionFlags::RWX,
            _ => ProtectionFlags::RWX,
        };
        match self.pal.allocate_memory(size, prot) {
            Ok(addr) => println!("Allocated {} bytes at 0x{:X} ({})", size, addr.as_u64(), prot_str),
            Err(e) => println!("Allocation error: {e}"),
        }
        Ok(())
    }

    fn cmd_free(&self, addr_str: &str) -> anyhow::Result<()> {
        let addr = match parse_hex_or_dec(addr_str).map(Address::new) {
            Some(a) => a,
            None => {
                println!("Invalid address: '{addr_str}'");
                return Ok(());
            }
        };
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <pid>' first.");
            return Ok(());
        }
        match self.pal.free_memory(addr) {
            Ok(()) => println!("Freed memory at 0x{:X}", addr.as_u64()),
            Err(e) => println!("Free error: {e}"),
        }
        Ok(())
    }

    fn cmd_reclass(&self, addr_str: &str, size: usize, name: &str) -> anyhow::Result<()> {
        let addr = match parse_hex_or_dec(addr_str).map(Address::new) {
            Some(a) => a,
            None => {
                println!("Invalid address: '{addr_str}'");
                return Ok(());
            }
        };
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <pid>' first.");
            return Ok(());
        }

        let bytes = self.pal.read_raw(addr, size)?;
        let regions = self.pal.query_regions().unwrap_or_default();
        let structure = engine_core::ClassStructure::reconstruct(addr, &bytes, &regions, Some(name));

        println!("\nReClass Node Analysis for {} at 0x{:X} (Size: 0x{:X} / {} bytes):", structure.name, addr.as_u64(), structure.total_size, structure.total_size);
        println!("{:<8} {:<16} {:<12} {:<24} COMMENT", "OFFSET", "NAME", "TYPE", "VALUE");
        println!("{:-<80}", "");

        for f in &structure.fields {
            let comment = f.comment.as_deref().unwrap_or("");
            println!("+0x{:04X}  {:<16} {:<12} {:<24} {}", f.offset, f.name, f.field_type.type_name(), f.display_value, comment);
        }
        println!();
        Ok(())
    }

    fn cmd_export_struct(&self, addr_str: &str, size: usize, lang: &str, name: &str) -> anyhow::Result<()> {
        let addr = match parse_hex_or_dec(addr_str).map(Address::new) {
            Some(a) => a,
            None => {
                println!("Invalid address: '{addr_str}'");
                return Ok(());
            }
        };
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <pid>' first.");
            return Ok(());
        }

        let bytes = self.pal.read_raw(addr, size)?;
        let regions = self.pal.query_regions().unwrap_or_default();
        let structure = engine_core::ClassStructure::reconstruct(addr, &bytes, &regions, Some(name));

        let code = match lang.to_lowercase().as_str() {
            "rust" | "rs" => structure.to_rust(),
            "cs" | "csharp" => structure.to_csharp(),
            _ => structure.to_cpp(),
        };

        println!("{code}");
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
