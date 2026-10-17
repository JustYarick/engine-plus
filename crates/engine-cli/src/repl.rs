use engine_core::{
    compute_struct_diff, inspect_dwarf_struct, list_dwarf_structs, lookup_symbols,
    BreakpointManager, FirstScanMode, HitTracer, MemoryScanner, NextScanMode, PointerMap,
    PointerPath, PointerScanner, PointerScannerConfig, ScanConfig, ScanValue, ScanValueType,
    SpeedHackScriptGenerator, TimeDilationState,
};
use engine_pal::{
    default_backend, default_enumerator, Address, BreakpointId, MemoryReader, ProcessAccessLayer,
    ProcessId, ProtectionFlags, WatchpointCondition, WatchpointSize,
};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use std::io::{self, BufRead, Write};

/// Interactive REPL console for Engine+
pub struct InteractiveConsole {
    pal: Box<dyn ProcessAccessLayer>,
    scanner: MemoryScanner,
    debugger: BreakpointManager,
    tracers: std::collections::HashMap<Address, HitTracer>,
    attached_pid: Option<ProcessId>,
    attached_name: Option<String>,
    current_scan_type: ScanValueType,
    allocations: std::collections::HashMap<String, Address>,
    time_dilation: TimeDilationState,
}

impl InteractiveConsole {
    pub fn new() -> Self {
        InteractiveConsole {
            pal: default_backend(),
            scanner: MemoryScanner::new(),
            debugger: BreakpointManager::new(),
            tracers: std::collections::HashMap::new(),
            attached_pid: None,
            attached_name: None,
            current_scan_type: ScanValueType::I32,
            allocations: std::collections::HashMap::new(),
            time_dilation: TimeDilationState::default(),
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
                        println!("  Types: i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, hex, string");
                    } else {
                        let addr_str = args[0];
                        let type_str = args.get(1).copied().unwrap_or("i32");
                        let size = args.get(2).and_then(|s| s.parse::<usize>().ok()).unwrap_or_else(|| match type_str.to_lowercase().as_str() {
                            "i8" | "u8" => 1,
                            "i16" | "u16" => 2,
                            "i64" | "u64" | "f64" => 8,
                            "string" => 32,
                            _ => 4,
                        });
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
                "aa" | "autoassemble" => {
                    if args.is_empty() {
                        println!("Usage: aa <script_or_file> [disable]");
                        println!("  Example: aa \"[ENABLE]; alloc(mycave, 1024); mycave: nop; ret\"");
                    } else {
                        let script_arg = args[0];
                        let script = if std::path::Path::new(script_arg).exists() {
                            std::fs::read_to_string(script_arg)?
                        } else {
                            args.join(" ")
                        };
                        let enable = !args.iter().any(|&s| s.eq_ignore_ascii_case("disable"));
                        self.cmd_aa(&script, enable)?;
                    }
                }
                "bp" => {
                    if args.is_empty() {
                        println!("Usage: bp <hex_address> [software|write|access|execute] [size]");
                        println!("  Example: bp 0x7FFF1000");
                        println!("  Example: bp 0x7FFF123450 write 4");
                    } else {
                        let addr_str = args[0];
                        let bp_type = args.get(1).copied().unwrap_or("software");
                        let size = args.get(2).and_then(|s| s.parse::<usize>().ok()).unwrap_or(4);
                        self.cmd_bp(addr_str, bp_type, size)?;
                    }
                }
                "rbp" => {
                    if args.is_empty() {
                        println!("Usage: rbp <id_or_slot>");
                    } else if let Ok(id) = args[0].parse::<u64>() {
                        self.cmd_rbp(id)?;
                    } else {
                        println!("Error: Invalid breakpoint ID '{}'", args[0]);
                    }
                }
                "bplist" => {
                    self.cmd_bplist()?;
                }
                "whatwrites" | "ww" => {
                    if args.is_empty() {
                        println!("Usage: whatwrites <hex_address> [size]");
                        println!("  Example: whatwrites 0x7FFF123450 4");
                    } else {
                        let addr_str = args[0];
                        let size = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(4);
                        self.cmd_whatwrites(addr_str, size)?;
                    }
                }
                "regs" => {
                    let tid = args.first().and_then(|s| s.parse::<ProcessId>().ok());
                    self.cmd_regs(tid)?;
                }
                "pause" => {
                    self.cmd_pause()?;
                }
                "resume" => {
                    self.cmd_resume()?;
                }
                "step" => {
                    let tid = args.first().and_then(|s| s.parse::<ProcessId>().ok());
                    self.cmd_step(tid)?;
                }
                "ptrscan" => {
                    if args.is_empty() {
                        println!("Usage: ptrscan <hex_target_address> [max_depth] [max_offset] [limit]");
                        println!("  Example: ptrscan 0x7FFF123450 3 0x800 20");
                    } else {
                        let target_str = args[0];
                        let max_depth = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(3);
                        let max_offset = args.get(2).and_then(|s| parse_hex_or_dec(s)).unwrap_or(0x800) as usize;
                        let limit = args.get(3).and_then(|s| s.parse::<usize>().ok()).unwrap_or(20);
                        self.cmd_ptrscan(target_str, max_depth, max_offset, limit)?;
                    }
                }
                "ptrresolve" => {
                    if args.len() < 2 {
                        println!("Usage: ptrresolve <module_name> <base_offset> [offsets...]");
                        println!("  Example: ptrresolve game.exe 0x1000 0x20 0xF8");
                    } else {
                        let module = args[0];
                        let base_offset = args[1];
                        let offsets = &args[2..];
                        self.cmd_ptrresolve(module, base_offset, offsets)?;
                    }
                }
                "speedhack" | "speed" => {
                    if args.is_empty() {
                        let now_ns = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as u64;
                        let virt_time = self.time_dilation.calculate_virtual_time(now_ns);
                        println!("Speed Hack status: {:.2}x (Real: {:.3}s, Virtual: {:.3}s)", self.time_dilation.multiplier, now_ns as f64 / 1_000_000_000.0, virt_time as f64 / 1_000_000_000.0);
                        println!("Usage: speedhack <multiplier>");
                        println!("  Example: speedhack 2.0");
                    } else if let Ok(mult) = args[0].parse::<f64>() {
                        self.cmd_speedhack(mult)?;
                    } else {
                        println!("Error: Invalid multiplier '{}'", args[0]);
                    }
                }
                "speedscript" => {
                    if args.is_empty() {
                        println!("Usage: speedscript <multiplier> [linux|windows]");
                        println!("  Example: speedscript 2.0 linux");
                    } else if let Ok(mult) = args[0].parse::<f64>() {
                        let platform = args.get(1).copied();
                        self.cmd_speedhack_script(mult, platform)?;
                    } else {
                        println!("Error: Invalid multiplier '{}'", args[0]);
                    }
                }
                "modules" | "modlist" => {
                    let filter = args.first().copied();
                    self.cmd_modules(filter)?;
                }
                "symbols" | "sym" => {
                    if args.is_empty() {
                        println!("Usage: symbols <pattern> [module] [limit]");
                        println!("  Example: symbols player");
                        println!("  Example: symbols update ac_client 50");
                    } else {
                        let pattern = args[0];
                        let module = args.get(1).copied();
                        let limit = args.get(2).and_then(|s| s.parse::<usize>().ok()).unwrap_or(50);
                        self.cmd_symbols(pattern, module, limit)?;
                    }
                }
                "structlayout" | "layout" => {
                    if args.is_empty() {
                        println!("Usage: structlayout <name|--all> [module]");
                        println!("  Example: structlayout playerent");
                        println!("  Example: structlayout --all");
                    } else if args[0] == "--all" || args[0] == "-a" {
                        let module = args.get(1).copied();
                        self.cmd_struct_layout_all(module)?;
                    } else {
                        let name = args[0];
                        let module = args.get(1).copied();
                        self.cmd_struct_layout(name, module)?;
                    }
                }
                "diff" => {
                    if args.is_empty() {
                        println!("Usage: diff <hex_address> [size] [interval_ms]");
                        println!("  Example: diff 0x6F7B630 128 500");
                    } else {
                        let addr = args[0];
                        let size = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(128);
                        let interval = args.get(2).and_then(|s| s.parse::<u64>().ok()).unwrap_or(500);
                        self.cmd_diff(addr, size, interval)?;
                    }
                }
                "batch" => {
                    if args.is_empty() {
                        println!("Usage: batch <expr1> [expr2...]");
                        println!("  Example: batch 0x5A3518:u64 linux_64_client+0x1A3518->+0x100:i32");
                    } else {
                        self.cmd_batch(&args)?;
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
        println!("  modules [filter]            - List loaded modules, base addresses and sizes");
        println!("  symbols <pat> [mod] [limit] - Lookup functions & symbols via symbol table & DWARF");
        println!("  structlayout <name|--all>   - Inspect struct layout or list structs from DWARF");
        println!("  diff <addr> [size] [ms]     - Diff structure in memory over time (detect changing fields)");
        println!("  batch <expr1> [expr2...]    - Batch read memory and pointer chains in one shot");
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
        println!("  aa <script|file> [disable]  - Cheat Engine style AutoAssembler script ([ENABLE]/[DISABLE], alloc, labels)");
        println!("  lua <code>                  - Execute script in sandboxed Lua 5.4 environment");
        println!("  bp <addr> [type] [size]     - Set breakpoint (software, write, access, execute)");
        println!("  rbp <id>                    - Remove software/hardware breakpoint by ID");
        println!("  bplist                      - List all active software and hardware breakpoints");
        println!("  whatwrites <addr> [size]    - Cheat Engine 'What writes to this address?' tracer");
        println!("  regs [tid]                  - Snapshot & dump CPU registers (RAX, RBX, RIP, EFLAGS)");
        println!("  pause                       - Pause/freeze target process execution (SIGSTOP)");
        println!("  resume                      - Resume target process execution (SIGCONT)");
        println!("  step [tid]                  - Advance single instruction (Single Step)");
        println!("  ptrscan <addr> [dp] [off]   - Multi-level pointer scanner to find static module paths");
        println!("  ptrresolve <mod> <off> [...] - Resolve multi-level pointer path to target address");
        println!("  speedhack <multiplier>      - Time dilation speed hack multiplier (e.g. 'speedhack 2.0')");
        println!("  speedscript <mult> [os]     - Generate AutoAssembler speed hack script (linux/windows)");
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
            "i8" if !bytes.is_empty() => println!("{}: {}", addr_str, bytes[0] as i8),
            "u8" if !bytes.is_empty() => println!("{}: {} (0x{:02X})", addr_str, bytes[0], bytes[0]),
            "i16" if bytes.len() >= 2 => println!("{}: {}", addr_str, i16::from_le_bytes(bytes[..2].try_into().unwrap())),
            "u16" if bytes.len() >= 2 => println!("{}: {}", addr_str, u16::from_le_bytes(bytes[..2].try_into().unwrap())),
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
            "i8" => vec![val_str.parse::<i8>()? as u8],
            "u8" => vec![val_str.parse::<u8>()?],
            "i16" => val_str.parse::<i16>()?.to_le_bytes().to_vec(),
            "u16" => val_str.parse::<u16>()?.to_le_bytes().to_vec(),
            "i32" => val_str.parse::<i32>()?.to_le_bytes().to_vec(),
            "u32" => val_str.parse::<u32>()?.to_le_bytes().to_vec(),
            "f32" => val_str.parse::<f32>()?.to_le_bytes().to_vec(),
            "i64" => val_str.parse::<i64>()?.to_le_bytes().to_vec(),
            "u64" => val_str.parse::<u64>()?.to_le_bytes().to_vec(),
            "f64" => val_str.parse::<f64>()?.to_le_bytes().to_vec(),
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

    fn cmd_aa(&mut self, script: &str, enable: bool) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            println!("Error: Not attached to any process. Use 'attach <PID>' first.");
            return Ok(());
        }

        let normalized = script.replace(';', "\n");
        match engine_script::AutoAssembler::execute(&normalized, enable, &mut *self.pal, &mut self.allocations) {
            Ok(report) => {
                println!(
                    "AutoAssembler executed successfully ({})",
                    if enable { "ENABLED" } else { "DISABLED" }
                );
                for a in report.allocations {
                    println!("  Allocated '{}' at 0x{:X} ({} bytes)", a.name, a.address.as_u64(), a.size);
                }
            }
            Err(e) => println!("AutoAssembler error: {e}"),
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

    fn cmd_bp(&mut self, addr_str: &str, bp_type: &str, size: usize) -> anyhow::Result<()> {
        let addr_val = parse_hex_or_dec(addr_str)
            .ok_or_else(|| anyhow::anyhow!("Invalid address '{addr_str}'"))?;
        let addr = Address::new(addr_val);

        match bp_type.to_lowercase().as_str() {
            "software" | "sw" | "int3" => {
                if !self.pal.is_attached() {
                    anyhow::bail!("Attach to a process first ('attach <pid>')");
                }
                let id = self.debugger.set_software_breakpoint(&mut *self.pal, addr)?;
                println!("Software breakpoint #{} installed at {addr} (INT3 0xCC written)", id.0);
            }
            "write" | "hw_write" => {
                let slot = self.debugger.set_hardware_breakpoint(addr, WatchpointCondition::Write, WatchpointSize::from_bytes(size))?;
                println!("Hardware watchpoint installed in DR{slot} at {addr} (Write, {size} bytes)");
            }
            "access" | "hw_access" | "rw" => {
                let slot = self.debugger.set_hardware_breakpoint(addr, WatchpointCondition::Access, WatchpointSize::from_bytes(size))?;
                println!("Hardware watchpoint installed in DR{slot} at {addr} (Read/Write, {size} bytes)");
            }
            "execute" | "exec" | "hw_exec" => {
                let slot = self.debugger.set_hardware_breakpoint(addr, WatchpointCondition::Execution, WatchpointSize::from_bytes(size))?;
                println!("Hardware execution breakpoint installed in DR{slot} at {addr}");
            }
            other => anyhow::bail!("Unknown breakpoint type: '{other}' (expected 'software', 'write', 'access', 'execute')"),
        }
        Ok(())
    }

    fn cmd_rbp(&mut self, id: u64) -> anyhow::Result<()> {
        if (1000..=1003).contains(&id) {
            let slot = (id - 1000) as usize;
            self.debugger.remove_hardware_breakpoint(slot)?;
            println!("Hardware breakpoint in DR{slot} removed");
        } else if id <= 3 && self.debugger.list_breakpoints().iter().any(|b| b.id == 1000 + id) {
            self.debugger.remove_hardware_breakpoint(id as usize)?;
            println!("Hardware breakpoint in DR{id} removed");
        } else {
            if !self.pal.is_attached() {
                anyhow::bail!("Attach to a process first ('attach <pid>')");
            }
            self.debugger.remove_software_breakpoint(&mut *self.pal, BreakpointId(id))?;
            println!("Software breakpoint #{id} removed and original byte restored");
        }
        Ok(())
    }

    fn cmd_bplist(&self) -> anyhow::Result<()> {
        let list = self.debugger.list_breakpoints();
        if list.is_empty() {
            println!("No active breakpoints registered.");
            return Ok(());
        }

        println!("{:<6} {:<18} {:<30} STATUS", "ID", "ADDRESS", "KIND");
        println!("{:-<70}", "");
        for bp in list {
            let status = if bp.enabled { "Enabled" } else { "Disabled" };
            println!("{:<6} {:<18} {:<30} {}", bp.id, bp.address, bp.kind, status);
        }
        Ok(())
    }

    fn cmd_whatwrites(&mut self, addr_str: &str, size: usize) -> anyhow::Result<()> {
        let addr_val = parse_hex_or_dec(addr_str)
            .ok_or_else(|| anyhow::anyhow!("Invalid address '{addr_str}'"))?;
        let target_addr = Address::new(addr_val);

        let tracer = self.tracers.entry(target_addr).or_insert_with(|| {
            HitTracer::new(target_addr, size, WatchpointCondition::Write)
        });

        // Scan executable memory for xrefs referencing this address
        if self.pal.is_attached() {
            if let Ok(regions) = self.pal.query_regions() {
                let rx_regions: Vec<_> = regions.into_iter().filter(|r| r.is_executable() && r.is_readable()).collect();
                for r in rx_regions.iter().take(5) {
                    let scan_size = r.size.min(0x40000);
                    if let Ok(bytes) = self.pal.read_raw(r.start, scan_size) {
                        let bitness = match self.pal.architecture() {
                            engine_pal::CpuArchitecture::X86_32 => 32,
                            engine_pal::CpuArchitecture::X86_64 => 64,
                        };
                        let xrefs = engine_core::find_xrefs_in_code(&bytes, r.start.as_u64(), bitness, target_addr.as_u64());
                        for xref in xrefs {
                            let regs = engine_pal::CpuRegisters {
                                rip: xref.instruction_address.as_u64(),
                                ..Default::default()
                            };
                            tracer.record_hit(xref.instruction_address, regs, Some(xref.instruction_text), None);
                        }
                    }
                }
            }
        }

        println!("{}", tracer.format_table());
        Ok(())
    }

    fn cmd_regs(&self, tid: Option<ProcessId>) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            anyhow::bail!("Attach to a process first ('attach <pid>')");
        }
        let regs = self.pal.get_registers(tid)?;
        println!("{}", regs.format_display());
        Ok(())
    }

    fn cmd_pause(&mut self) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            anyhow::bail!("Attach to a process first ('attach <pid>')");
        }
        self.pal.suspend_process()?;
        let pid = self.pal.attached_pid().unwrap_or(0);
        println!("Process {pid} execution paused (frozen)");
        Ok(())
    }

    fn cmd_resume(&mut self) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            anyhow::bail!("Attach to a process first ('attach <pid>')");
        }
        self.pal.resume_process()?;
        let pid = self.pal.attached_pid().unwrap_or(0);
        println!("Process {pid} execution resumed");
        Ok(())
    }

    fn cmd_step(&mut self, tid: Option<ProcessId>) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            anyhow::bail!("Attach to a process first ('attach <pid>')");
        }
        let regs = self.pal.single_step(tid)?;
        println!("Stepped to RIP: 0x{:016X}", regs.rip);
        println!("{}", regs.format_display());
        Ok(())
    }

    fn cmd_ptrscan(&mut self, target_str: &str, max_depth: usize, max_offset: usize, limit: usize) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            anyhow::bail!("Attach to a process first ('attach <pid>')");
        }
        let target_val = parse_hex_or_dec(target_str)
            .ok_or_else(|| anyhow::anyhow!("Invalid target address '{target_str}'"))?;
        let target = Address::new(target_val);

        println!("Building pointer map of target process readable memory...");
        let regions = self.pal.query_regions()?;
        let ptr_size = self.pal.architecture().pointer_size();
        let pmap = PointerMap::build_from_memory(&*self.pal, &regions, ptr_size, ptr_size, true)?;
        println!("Pointer map generated: {} pointers indexed across writable regions", pmap.total_pointers());

        let modules = self.pal.enumerate_modules().unwrap_or_default();
        println!("Scanning for pointer paths to 0x{:X} (Depth: 1..={}, Max Offset: 0x{:X})...", target.as_u64(), max_depth, max_offset);

        let config = PointerScannerConfig {
            max_depth,
            max_offset,
            max_results: limit.max(50),
            writable_only: true,
        };
        let paths = PointerScanner::scan(&pmap, &modules, target, &config);
        println!("Scan complete: Found {} pointer chain(s)", paths.len());

        let display_count = paths.len().min(limit);
        for (i, p) in paths.iter().take(display_count).enumerate() {
            println!("  [#{}] {}", i + 1, p);
        }
        if paths.len() > limit {
            println!("  ... and {} more path(s). Pass limit parameter to view more.", paths.len() - limit);
        }
        Ok(())
    }

    fn cmd_ptrresolve(&self, module: &str, base_offset_str: &str, offsets_strs: &[&str]) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            anyhow::bail!("Attach to a process first ('attach <pid>')");
        }
        let base_offset = parse_hex_or_dec(base_offset_str)
            .ok_or_else(|| anyhow::anyhow!("Invalid base offset '{base_offset_str}'"))?;
        let mut offsets = Vec::new();
        for os in offsets_strs {
            let off = parse_hex_or_dec(os)
                .ok_or_else(|| anyhow::anyhow!("Invalid offset '{os}'"))? as i64;
            offsets.push(off);
        }

        let modules = self.pal.enumerate_modules()?;
        let target_mod = modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(module) || m.name.to_lowercase().contains(&module.to_lowercase()))
            .ok_or_else(|| anyhow::anyhow!("Module '{module}' not found in target process"))?;

        let path = PointerPath {
            module_name: target_mod.name.clone(),
            base_offset,
            offsets,
        };
        let resolved = path.resolve(&*self.pal, target_mod.base_address, self.pal.architecture())?;
        println!("Pointer Path: {}", path);
        println!("  Module Base:      0x{:X}", target_mod.base_address.as_u64());
        println!("  Resolved Address: 0x{:X}", resolved.as_u64());

        if let Ok(bytes) = self.pal.read_raw(resolved, 8) {
            let u32_val = u32::from_le_bytes(bytes[0..4].try_into().unwrap_or_default());
            let i32_val = i32::from_le_bytes(bytes[0..4].try_into().unwrap_or_default());
            let f32_val = f32::from_le_bytes(bytes[0..4].try_into().unwrap_or_default());
            let u64_val = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or_default());
            println!("  Value at target: i32 = {}, u32 = {}, f32 = {:.4}, u64 = 0x{:X}", i32_val, u32_val, f32_val, u64_val);
        }
        Ok(())
    }

    fn cmd_speedhack(&mut self, multiplier: f64) -> anyhow::Result<()> {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        self.time_dilation.set_multiplier(multiplier, now_ns);
        let virt_time = self.time_dilation.calculate_virtual_time(now_ns);
        println!("Speed Hack updated:");
        println!("  Multiplier:   {:.2}x", self.time_dilation.multiplier);
        println!("  Real Time:    {:.3} s", now_ns as f64 / 1_000_000_000.0);
        println!("  Virtual Time: {:.3} s", virt_time as f64 / 1_000_000_000.0);
        Ok(())
    }

    fn cmd_speedhack_script(&self, multiplier: f64, platform: Option<&str>) -> anyhow::Result<()> {
        let script = match platform.map(|s| s.to_lowercase()).as_deref() {
            Some("windows") | Some("win") => SpeedHackScriptGenerator::generate_windows_aa_script(multiplier),
            _ => SpeedHackScriptGenerator::generate_linux_aa_script(multiplier),
        };
        println!("Generated AutoAssembler Speed Hack Script (Multiplier: {:.2}x):", multiplier);
        println!("------------------------------------------------------------");
        println!("{script}");
        println!("------------------------------------------------------------");
        println!("You can apply this script with: aa <paste_script>");
        Ok(())
    }

    fn cmd_modules(&mut self, filter: Option<&str>) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            anyhow::bail!("Attach to a process first ('attach <pid>')");
        }
        let mut modules = self.pal.enumerate_modules()?;
        if let Some(f) = filter {
            let fl = f.to_lowercase();
            modules.retain(|m| m.name.to_lowercase().contains(&fl) || m.path.to_lowercase().contains(&fl));
        }
        println!("Loaded modules (Count: {}):", modules.len());
        println!("{:<32} | {:>18} | {:>10} | Path", "Module Name", "Base Address", "Size");
        println!("{:-<32}-+-{:-<18}-+-{:-<10}-+-{:-<40}", "", "", "", "");
        for m in &modules {
            println!("{:<32} | 0x{:016X} | 0x{:08X} | {}", m.name, m.base_address.as_u64(), m.size, m.path);
        }
        Ok(())
    }

    fn cmd_symbols(&mut self, pattern: &str, module: Option<&str>, limit: usize) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            anyhow::bail!("Attach to a process first ('attach <pid>')");
        }
        let modules = self.pal.enumerate_modules()?;
        let (mod_name, mod_path, mod_base) = if let Some(req) = module {
            if let Some(m) = modules.iter().find(|m| m.name.eq_ignore_ascii_case(req) || m.name.to_lowercase().contains(&req.to_lowercase())) {
                (m.name.clone(), m.path.clone(), m.base_address)
            } else if std::path::Path::new(req).exists() {
                (req.to_string(), req.to_string(), Address::NULL)
            } else {
                anyhow::bail!("Module '{req}' not found");
            }
        } else if let Some(m) = modules.first() {
            (m.name.clone(), m.path.clone(), m.base_address)
        } else {
            anyhow::bail!("No modules found in target process");
        };

        let symbols = lookup_symbols(std::path::Path::new(&mod_path), Some(mod_base), pattern, limit)?;
        println!("Found {} symbol(s) matching '{pattern}' in {mod_name}:", symbols.len());
        println!("{:>18} | {:>10} | {:<8} | {:<8} | {:<12} | Name", "Runtime Addr", "Size", "Kind", "Binding", "Section");
        println!("{:-<18}-+-{:-<10}-+-{:-<8}-+-{:-<8}-+-{:-<12}-+-{:-<30}", "", "", "", "", "", "");
        for s in &symbols {
            let sec = s.section.as_deref().unwrap_or("-");
            println!("0x{:016X} | 0x{:08X} | {:<8} | {:<8} | {:<12} | {}", s.address.as_u64(), s.size, s.kind, s.binding, sec, s.name);
        }
        Ok(())
    }

    fn cmd_struct_layout_all(&mut self, module: Option<&str>) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            anyhow::bail!("Attach to a process first ('attach <pid>')");
        }
        let modules = self.pal.enumerate_modules()?;
        let mod_path = if let Some(req) = module {
            if let Some(m) = modules.iter().find(|m| m.name.eq_ignore_ascii_case(req) || m.name.to_lowercase().contains(&req.to_lowercase())) {
                m.path.clone()
            } else {
                req.to_string()
            }
        } else if let Some(m) = modules.first() {
            m.path.clone()
        } else {
            anyhow::bail!("No modules found");
        };

        let names = list_dwarf_structs(std::path::Path::new(&mod_path), 100)?;
        println!("Found {} structure(s) in DWARF debug info for '{}':", names.len(), mod_path);
        for n in &names {
            println!("  {n}");
        }
        Ok(())
    }

    fn cmd_struct_layout(&mut self, name: &str, module: Option<&str>) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            anyhow::bail!("Attach to a process first ('attach <pid>')");
        }
        let modules = self.pal.enumerate_modules()?;
        let mod_path = if let Some(req) = module {
            if let Some(m) = modules.iter().find(|m| m.name.eq_ignore_ascii_case(req) || m.name.to_lowercase().contains(&req.to_lowercase())) {
                m.path.clone()
            } else {
                req.to_string()
            }
        } else if let Some(m) = modules.first() {
            m.path.clone()
        } else {
            anyhow::bail!("No modules found");
        };

        let layout = inspect_dwarf_struct(std::path::Path::new(&mod_path), name)?;
        println!("Structure '{}' (Total Size: {} bytes, {} members):", layout.name, layout.total_size, layout.members.len());
        println!("{:<10} | {:>6} | {:<24} | Field Name", "Offset", "Size", "Type");
        println!("{:-<10}-+-{:-<6}-+-{:-<24}-+-{:-<24}", "", "", "", "");
        for m in &layout.members {
            println!("{:<10} | {:>6} | {:<24} | {}", m.offset_hex, m.size, m.type_name, m.name);
        }
        println!("\nC++ Struct Definition:\n{}", layout.format_cpp_definition());
        Ok(())
    }

    fn cmd_diff(&mut self, addr_str: &str, size: usize, interval_ms: u64) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            anyhow::bail!("Attach to a process first ('attach <pid>')");
        }
        let addr_val = parse_hex_or_dec(addr_str)
            .ok_or_else(|| anyhow::anyhow!("Invalid address '{addr_str}'"))?;
        let addr = Address::new(addr_val);

        println!("Monitoring address {addr} (size: {size} bytes)...");
        let before = self.pal.read_raw(addr, size)?;
        println!("Captured baseline snapshot. Waiting {interval_ms} ms...");
        std::thread::sleep(std::time::Duration::from_millis(interval_ms));
        let after = self.pal.read_raw(addr, size)?;

        let diffs = compute_struct_diff(addr, &before, &after);
        if diffs.is_empty() {
            println!("No changes detected during {interval_ms} ms interval.");
        } else {
            println!("Detected {} change(s) in structure:", diffs.len());
            println!("{:<10} | {:<20} -> {:<20} | Summary", "Offset", "Old Bytes", "New Bytes");
            println!("{:-<10}-+-{:-<20}-+-{:-<20}-+-{:-<30}", "", "", "", "");
            for d in &diffs {
                println!("{:<10} | {:<20} -> {:<20} | {}", d.offset_hex, d.old_bytes_hex, d.new_bytes_hex, d.summary);
            }
        }
        Ok(())
    }

    fn cmd_batch(&mut self, items: &[&str]) -> anyhow::Result<()> {
        if !self.pal.is_attached() {
            anyhow::bail!("Attach to a process first ('attach <pid>')");
        }
        let modules = self.pal.enumerate_modules().unwrap_or_default();
        let arch = self.pal.architecture();

        println!("Executing batch read of {} item(s):", items.len());
        for (idx, &item) in items.iter().enumerate() {
            let (expr, type_str) = if let Some((e, t)) = item.split_once(':') {
                (e.trim(), t.trim())
            } else {
                (item.trim(), "i32")
            };

            let resolved_addr: Result<Address, anyhow::Error> = if expr.contains("->") {
                let parts: Vec<&str> = expr.split("->").map(|s| s.trim()).collect();
                let base_part = parts[0];
                let mut current_addr = if let Some((mod_name, off_str)) = base_part.split_once('+') {
                    let base_off = parse_hex_or_dec(off_str)
                        .ok_or_else(|| anyhow::anyhow!("Invalid offset '{off_str}'"))?;
                    let m = modules.iter().find(|m| m.name.eq_ignore_ascii_case(mod_name.trim()) || m.name.to_lowercase().contains(&mod_name.to_lowercase()))
                        .ok_or_else(|| anyhow::anyhow!("Module '{mod_name}' not found"))?;
                    m.base_address.add(base_off as usize)
                } else {
                    let a = parse_hex_or_dec(base_part)
                        .ok_or_else(|| anyhow::anyhow!("Invalid base address '{base_part}'"))?;
                    Address::new(a)
                };

                current_addr = self.pal.read_pointer(current_addr, arch)?;
                for (level, &off_str) in parts[1..].iter().enumerate() {
                    let off = if let Some(s) = off_str.strip_prefix('+') {
                        parse_hex_or_dec(s).ok_or_else(|| anyhow::anyhow!("Invalid offset '{off_str}'"))? as i64
                    } else if let Some(s) = off_str.strip_prefix('-') {
                        -(parse_hex_or_dec(s).ok_or_else(|| anyhow::anyhow!("Invalid offset '{off_str}'"))? as i64)
                    } else {
                        parse_hex_or_dec(off_str).ok_or_else(|| anyhow::anyhow!("Invalid offset '{off_str}'"))? as i64
                    };
                    let next = current_addr.offset(off);
                    if level == parts.len() - 2 {
                        current_addr = next;
                    } else {
                        current_addr = self.pal.read_pointer(next, arch)?;
                    }
                }
                Ok(current_addr)
            } else if let Some((mod_name, off_str)) = expr.split_once('+') {
                let base_off = parse_hex_or_dec(off_str)
                    .ok_or_else(|| anyhow::anyhow!("Invalid offset '{off_str}'"))?;
                let m = modules.iter().find(|m| m.name.eq_ignore_ascii_case(mod_name.trim()) || m.name.to_lowercase().contains(&mod_name.to_lowercase()))
                    .ok_or_else(|| anyhow::anyhow!("Module '{mod_name}' not found"))?;
                Ok(m.base_address.add(base_off as usize))
            } else {
                let a = parse_hex_or_dec(expr)
                    .ok_or_else(|| anyhow::anyhow!("Invalid address '{expr}'"))?;
                Ok(Address::new(a))
            };

            match resolved_addr {
                Ok(addr) => {
                    let val_str = match type_str.to_lowercase().as_str() {
                        "i8" => self.pal.read_i8(addr).map(|v| format!("{v}")),
                        "u8" => self.pal.read_u8(addr).map(|v| format!("{v} (0x{v:02X})")),
                        "i16" => self.pal.read_i16(addr).map(|v| format!("{v}")),
                        "u16" => self.pal.read_u16(addr).map(|v| format!("{v} (0x{v:04X})")),
                        "i32" => self.pal.read_i32(addr).map(|v| format!("{v}")),
                        "u32" => self.pal.read_u32(addr).map(|v| format!("{v} (0x{v:08X})")),
                        "i64" => self.pal.read_i64(addr).map(|v| format!("{v}")),
                        "u64" => self.pal.read_u64(addr).map(|v| format!("{v} (0x{v:016X})")),
                        "f32" => self.pal.read_f32(addr).map(|v| format!("{v:.4}")),
                        "f64" => self.pal.read_f64(addr).map(|v| format!("{v:.6}")),
                        "hex" => self.pal.read_raw(addr, 16).map(|b| b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")),
                        _ => self.pal.read_i32(addr).map(|v| format!("{v}")),
                    };
                    match val_str {
                        Ok(v) => println!("  [#{}] {} => {} [{}] = {}", idx + 1, expr, addr, type_str, v),
                        Err(e) => println!("  [#{}] {} => {} [{}] = Error: {}", idx + 1, expr, addr, type_str, e),
                    }
                }
                Err(e) => println!("  [#{}] {} => Error: {}", idx + 1, expr, e),
            }
        }
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
