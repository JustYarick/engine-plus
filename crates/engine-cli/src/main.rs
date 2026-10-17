mod repl;

use clap::{Parser, Subcommand};
use engine_core::{FirstScanMode, MemoryScanner, ScanConfig, ScanValue, ScanValueType};
use engine_pal::{default_backend, default_enumerator, Address, ProcessId, ProtectionFlags};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use repl::InteractiveConsole;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "engine-plus")]
#[command(author = "Yarick <yarick@engine-plus.dev>")]
#[command(version = "0.1.0")]
#[command(about = "Engine+ — High-Performance Reverse Engineering Suite & MCP Server in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Run as standard Model Context Protocol (MCP) server over stdio for AI integration
    #[arg(long)]
    mcp: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start interactive REPL console
    Console,

    /// List active running processes
    Ps {
        #[arg(short, long)]
        filter: Option<String>,
    },

    /// Attach to a target process and print detailed information
    Info {
        #[arg(short, long)]
        pid: ProcessId,
    },

    /// Scan target process memory for a value or pattern
    Scan {
        #[arg(short, long)]
        pid: ProcessId,

        /// Value to search for (e.g. '100', '3.14', or AOB hex pattern '48 8B ?? C3')
        #[arg(short, long)]
        value: String,

        /// Value type: i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, aob, string
        #[arg(short = 't', long, default_value = "i32")]
        val_type: String,

        /// Memory alignment (1, 2, 4, 8)
        #[arg(short, long)]
        alignment: Option<usize>,

        /// Max results to display
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },

    /// Read typed memory or raw hex bytes from an address
    Read {
        #[arg(short, long)]
        pid: ProcessId,

        /// Hex address to read from (e.g. '0x7FFD1234')
        #[arg(short, long)]
        address: String,

        /// Value type: i32, u32, i64, u64, f32, f64, hex, string
        #[arg(short = 't', long, default_value = "i32")]
        val_type: String,

        /// Number of bytes to read
        #[arg(short, long, default_value = "4")]
        size: usize,
    },

    /// Write typed value or raw hex bytes to target memory address
    Write {
        #[arg(short, long)]
        pid: ProcessId,

        /// Hex address to write to (e.g. '0x7FFD1234')
        #[arg(short, long)]
        address: String,

        /// Value to write (number or hex bytes '90 90')
        #[arg(short, long)]
        value: String,

        /// Value type: i32, u32, f32, i64, u64, hex
        #[arg(short = 't', long, default_value = "i32")]
        val_type: String,
    },

    /// Disassemble live machine code from memory at an address
    Disasm {
        #[arg(short, long)]
        pid: ProcessId,

        /// Hex address to disassemble (e.g. '0x555555554000')
        #[arg(short, long)]
        address: String,

        /// Number of bytes to decode
        #[arg(short, long, default_value = "32")]
        size: usize,

        /// Bitness: 32 or 64
        #[arg(short, long, default_value = "64")]
        bitness: u32,
    },

    /// Heuristically analyze structure at an address
    Analyze {
        #[arg(short, long)]
        pid: ProcessId,

        /// Hex address to inspect
        #[arg(short, long)]
        address: String,

        /// Estimated structure size in bytes
        #[arg(short, long, default_value = "64")]
        size: usize,
    },

    /// Static binary analysis tools (ELF & PE headers, strings, disassembly)
    Static {
        #[command(subcommand)]
        subcmd: StaticSubcommands,
    },

    /// Execute script in safe sandboxed Lua 5.4 environment
    Script {
        /// Optional PID to attach and bind to memory/scanner APIs
        #[arg(short, long)]
        pid: Option<ProcessId>,

        /// Direct Lua code to execute
        #[arg(short = 'c', long)]
        code: Option<String>,

        /// Path to Lua script file
        #[arg(short, long)]
        file: Option<PathBuf>,
    },

    /// Execute Cheat Engine style AutoAssembler script ([ENABLE] / [DISABLE], alloc, labels, patches)
    Aa {
        #[arg(short, long)]
        pid: ProcessId,

        /// Script string (lines separated by newlines or ';')
        #[arg(short, long)]
        script: Option<String>,

        /// Path to AutoAssembler script file (.cea, .txt)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Execute [DISABLE] section instead of [ENABLE]
        #[arg(long)]
        disable: bool,
    },

    /// Assemble x86/x64 instructions into machine code bytes
    Assemble {
        /// Assembly instructions separated by ';' or newlines
        #[arg(short, long)]
        code: String,

        /// Instruction pointer hex address (default: 0x1000)
        #[arg(short, long, default_value = "0x1000")]
        ip: String,

        /// Architecture bitness: 32 or 64
        #[arg(short, long, default_value = "64")]
        bitness: u32,
    },

    /// Patch machine code at an address in target process
    Patch {
        #[arg(short, long)]
        pid: ProcessId,

        #[arg(short, long)]
        address: String,

        /// Assembly instructions or hex bytes (e.g. 'nop; nop' or 'hex: 90 90')
        #[arg(short, long)]
        code: String,
    },

    /// Install inline detour/trampoline hook
    Hook {
        #[arg(short, long)]
        pid: ProcessId,

        /// Function address to hook
        #[arg(short, long)]
        target: String,

        /// Code cave memory address
        #[arg(short, long)]
        cave: String,

        /// Optional assembly payload in code cave
        #[arg(short = 'l', long)]
        payload: Option<String>,
    },

    /// Generate unique AOB pattern with wildcard relative masks
    Pattern {
        #[arg(short, long)]
        pid: ProcessId,

        #[arg(short, long)]
        address: String,

        #[arg(short, long, default_value = "32")]
        size: usize,
    },

    /// Scan code for cross-references to a target address
    Xrefs {
        #[arg(short, long)]
        pid: ProcessId,

        #[arg(short, long)]
        target: String,

        #[arg(short, long)]
        start: String,

        #[arg(short, long, default_value = "65536")]
        size: usize,
    },

    /// Allocate virtual memory in target process
    Alloc {
        #[arg(short, long)]
        pid: ProcessId,

        #[arg(short, long, default_value = "4096")]
        size: usize,

        #[arg(short, long, default_value = "rwx")]
        protection: String,
    },

    /// Free allocated virtual memory in target process
    Free {
        #[arg(short, long)]
        pid: ProcessId,

        #[arg(short, long)]
        address: String,
    },

    /// ReClass-style object structure reconstruction and code generation (C++, Rust, C#)
    Struct {
        #[arg(short, long)]
        pid: ProcessId,

        #[arg(short, long)]
        address: String,

        /// Number of bytes to analyze (default: 128)
        #[arg(short, long, default_value = "128")]
        size: usize,

        /// Optional code export language: cpp, rust, csharp
        #[arg(short, long)]
        export: Option<String>,

        /// Class name (default: ReconstructedClass)
        #[arg(short, long, default_value = "ReconstructedClass")]
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum StaticSubcommands {
    /// Analyze headers and sections of an executable file (.dll, .so, .exe)
    Info {
        #[arg(short, long)]
        path: PathBuf,
    },

    /// Extract printable strings from static binary file
    Strings {
        #[arg(short, long)]
        path: PathBuf,

        /// Minimum string length
        #[arg(short, long, default_value = "5")]
        min_len: usize,

        /// Substring filter
        #[arg(short, long)]
        filter: Option<String>,

        /// Maximum results
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// Disassemble static machine code from binary file
    Disasm {
        #[arg(short, long)]
        path: PathBuf,

        /// File offset (hex or dec)
        #[arg(short, long)]
        offset: Option<String>,

        /// Relative Virtual Address (PE only)
        #[arg(short, long)]
        rva: Option<String>,

        /// Number of bytes to decode
        #[arg(short, long, default_value = "64")]
        size: usize,

        /// Bitness: 32 or 64
        #[arg(short, long, default_value = "64")]
        bitness: u32,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    if cli.mcp {
        let server = engine_mcp::McpServer::new();
        server.run_stdio().await?;
        return Ok(());
    }

    match cli.command {
        Some(Commands::Console) | None => {
            let mut repl = InteractiveConsole::new();
            repl.run()?;
        }
        Some(Commands::Ps { filter }) => {
            let enumerator = default_enumerator();
            let mut procs = enumerator.list_processes()?;

            if let Some(ref q) = filter {
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
        }
        Some(Commands::Info { pid }) => {
            println!("Attaching to PID {pid}...");
            let mut pal = default_backend();
            pal.attach(pid)?;

            println!("Attached to process {pid}:");
            println!("  Backend:       {}", pal.backend_name());
            println!("  Architecture:  {:?}", pal.architecture());
            println!("  Stealth Level: {:?}", pal.stealth_level());

            let regions = pal.query_regions()?;
            println!("  Mapped Memory Regions: {}", regions.len());

            let modules = pal.enumerate_modules()?;
            println!("  Loaded Modules Count:  {}", modules.len());
            for m in modules.iter().take(10) {
                println!("    - {:<28} Base: {} (Size: 0x{:X})", m.name, m.base_address, m.size);
            }
            if modules.len() > 10 {
                println!("    ... and {} more modules", modules.len() - 10);
            }
        }
        Some(Commands::Scan { pid, value, val_type, alignment, limit }) => {
            let parsed_type = parse_cli_type(&val_type)?;
            let parsed_val = ScanValue::parse(&value, parsed_type)
                .map_err(|e| anyhow::anyhow!("Invalid value: {e}"))?;

            let mut pal = default_backend();
            pal.attach(pid)?;

            let mut config = ScanConfig::new(parsed_type);
            if let Some(align) = alignment {
                config.alignment = align;
            }

            println!("Scanning PID {} for {} ({:?}) [alignment={}]...", pid, parsed_val, parsed_type, config.alignment);
            let start = std::time::Instant::now();
            let mut scanner = MemoryScanner::new();
            let count = scanner.first_scan(&*pal, &config, &FirstScanMode::Exact(parsed_val))?;
            let elapsed = start.elapsed();

            println!("Found {count} results in {elapsed:.2?}.");
            if let Some(results) = scanner.current_results() {
                let page = results.page(0, limit);
                println!("\n{:<18} VALUE", "ADDRESS");
                println!("{:-<40}", "");
                for item in page {
                    println!("{:<18} {}", item.address, item.current_value);
                }
                if count > limit {
                    println!("... and {} more results", count - limit);
                }
            }
        }
        Some(Commands::Read { pid, address, val_type, size }) => {
            let addr = parse_hex_or_dec_val(&address)
                .ok_or_else(|| anyhow::anyhow!("Invalid address '{address}'"))?;

            let mut pal = default_backend();
            pal.attach(pid)?;

            let bytes = pal.read_raw(Address::new(addr), size)?;
            match val_type.to_lowercase().as_str() {
                "i32" if bytes.len() >= 4 => println!("{}: {}", address, i32::from_le_bytes(bytes[..4].try_into().unwrap())),
                "u32" if bytes.len() >= 4 => println!("{}: {}", address, u32::from_le_bytes(bytes[..4].try_into().unwrap())),
                "i64" if bytes.len() >= 8 => println!("{}: {}", address, i64::from_le_bytes(bytes[..8].try_into().unwrap())),
                "u64" if bytes.len() >= 8 => println!("{}: {}", address, u64::from_le_bytes(bytes[..8].try_into().unwrap())),
                "f32" if bytes.len() >= 4 => println!("{}: {}", address, f32::from_le_bytes(bytes[..4].try_into().unwrap())),
                "f64" if bytes.len() >= 8 => println!("{}: {}", address, f64::from_le_bytes(bytes[..8].try_into().unwrap())),
                "string" => println!("{}: \"{}\"", address, String::from_utf8_lossy(&bytes)),
                _ => {
                    let hex_str = bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                    println!("{}: [HEX] {}", address, hex_str);
                }
            }
        }
        Some(Commands::Write { pid, address, value, val_type }) => {
            let addr = parse_hex_or_dec_val(&address)
                .ok_or_else(|| anyhow::anyhow!("Invalid address '{address}'"))?;

            let bytes = match val_type.to_lowercase().as_str() {
                "i32" => value.parse::<i32>()?.to_le_bytes().to_vec(),
                "u32" => value.parse::<u32>()?.to_le_bytes().to_vec(),
                "f32" => value.parse::<f32>()?.to_le_bytes().to_vec(),
                "i64" => value.parse::<i64>()?.to_le_bytes().to_vec(),
                "u64" => value.parse::<u64>()?.to_le_bytes().to_vec(),
                "hex" => {
                    let mut b = Vec::new();
                    for t in value.split_whitespace() {
                        b.push(u8::from_str_radix(t, 16)?);
                    }
                    b
                }
                _ => anyhow::bail!("Unsupported write type '{val_type}'"),
            };

            let mut pal = default_backend();
            pal.attach(pid)?;
            pal.write_raw(Address::new(addr), &bytes)?;
            println!("Successfully wrote {} bytes to 0x{:X}", bytes.len(), addr);
        }
        Some(Commands::Disasm { pid, address, size, bitness }) => {
            let addr = parse_hex_or_dec_val(&address)
                .ok_or_else(|| anyhow::anyhow!("Invalid address '{address}'"))?;

            let mut pal = default_backend();
            pal.attach(pid)?;

            let bytes = pal.read_raw(Address::new(addr), size)?;
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
        }
        Some(Commands::Analyze { pid, address, size }) => {
            let addr = parse_hex_or_dec_val(&address)
                .ok_or_else(|| anyhow::anyhow!("Invalid address '{address}'"))?;

            let mut pal = default_backend();
            pal.attach(pid)?;

            let regions = pal.query_regions().unwrap_or_default();
            let bytes = pal.read_raw(Address::new(addr), size)?;
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
        }
        Some(Commands::Static { subcmd }) => match subcmd {
            StaticSubcommands::Info { path } => {
                let info = engine_mcp::static_analyzer::analyze_file(&path)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("Binary Analysis for {:?}:", path);
                println!("  Format:       {}", info.format);
                println!("  Architecture: {}", info.architecture);
                println!("  Entry Point:  {}", info.entry_point);
                println!("  File Size:    {} bytes", info.total_file_size);
                if !info.sections.is_empty() {
                    println!("  Sections ({}):", info.sections.len());
                    for s in &info.sections {
                        println!("    - {:<12} RVA: {:<10} Size: {:<8} Perms: {}", s.name, s.virtual_address, s.virtual_size, s.protection);
                    }
                }
            }
            StaticSubcommands::Strings { path, min_len, filter, limit } => {
                let strings = engine_mcp::static_analyzer::extract_strings_from_file(
                    &path,
                    min_len,
                    limit,
                    filter.as_deref(),
                ).map_err(|e| anyhow::anyhow!("{e}"))?;

                println!("Extracted {} strings from {:?}:", strings.len(), path);
                for s in strings {
                    println!("  [{}] ({} chars): \"{}\"", s.offset, s.length, s.text);
                }
            }
            StaticSubcommands::Disasm { path, offset, rva, size, bitness } => {
                let (rva_or_offset, is_rva) = if let Some(r) = rva {
                    (parse_hex_or_dec_val(&r).ok_or_else(|| anyhow::anyhow!("Invalid RVA '{r}'"))?, true)
                } else if let Some(o) = offset {
                    (parse_hex_or_dec_val(&o).ok_or_else(|| anyhow::anyhow!("Invalid offset '{o}'"))?, false)
                } else {
                    anyhow::bail!("Specify either --offset or --rva");
                };

                let asm = engine_mcp::static_analyzer::disassemble_file_code(
                    &path,
                    rva_or_offset,
                    is_rva,
                    size,
                    bitness,
                ).map_err(|e| anyhow::anyhow!("{e}"))?;

                println!("Disassembly of {:?}:", path);
                print!("{asm}");
            }
        },
        Some(Commands::Script { pid, code, file }) => {
            let script_code = match (code, file) {
                (Some(c), _) => c,
                (None, Some(f)) => std::fs::read_to_string(f)?,
                (None, None) => anyhow::bail!("Provide Lua code via -c <code> or script file via --file <path>"),
            };

            let mut pal = default_backend();
            if let Some(target_pid) = pid {
                pal.attach(target_pid)?;
            }
            let pal_arc: std::sync::Arc<std::sync::Mutex<Box<dyn engine_pal::ProcessAccessLayer>>> =
                std::sync::Arc::new(std::sync::Mutex::new(pal));
            let scanner_arc = std::sync::Arc::new(std::sync::Mutex::new(MemoryScanner::new()));
            let engine = engine_script::ScriptEngine::new(pal_arc, scanner_arc)
                .map_err(|e| anyhow::anyhow!("Failed to initialize ScriptEngine: {e}"))?;

            let val = engine.execute(&script_code)
                .map_err(|e| anyhow::anyhow!("Lua error: {e}"))?;
            let val_str = match val {
                engine_script::mlua::Value::Nil => "nil".to_string(),
                engine_script::mlua::Value::Boolean(b) => b.to_string(),
                engine_script::mlua::Value::Integer(i) => i.to_string(),
                engine_script::mlua::Value::Number(n) => n.to_string(),
                engine_script::mlua::Value::String(s) => s.to_str().unwrap_or("").to_string(),
                engine_script::mlua::Value::Table(_) => "[table]".to_string(),
                other => format!("{:?}", other),
            };
            println!("{val_str}");
        }
        Some(Commands::Aa { pid, script, file, disable }) => {
            let script_code = match (script, file) {
                (Some(s), _) => s.replace(';', "\n"),
                (None, Some(f)) => std::fs::read_to_string(f)?,
                (None, None) => anyhow::bail!("Provide AutoAssembler script via -s <script> or file via --file <path>"),
            };

            let mut pal = default_backend();
            pal.attach(pid)?;
            let mut allocs = std::collections::HashMap::new();

            let enable = !disable;
            let report = engine_script::AutoAssembler::execute(&script_code, enable, &mut *pal, &mut allocs)
                .map_err(|e| anyhow::anyhow!("AutoAssembler error: {e}"))?;

            println!("AutoAssembler executed successfully ({})", if enable { "ENABLED" } else { "DISABLED" });
            if !report.allocations.is_empty() {
                println!("  Allocations ({}):", report.allocations.len());
                for a in report.allocations {
                    println!("    - {}: 0x{:X} ({} bytes)", a.name, a.address.as_u64(), a.size);
                }
            }
        }
        Some(Commands::Assemble { code, ip, bitness }) => {
            let addr = parse_hex_or_dec_val(&ip)
                .ok_or_else(|| anyhow::anyhow!("Invalid ip address '{ip}'"))?;
            let normalized = code.replace(';', "\n");
            let bytes = engine_core::assemble_code(&normalized, bitness, addr)
                .map_err(|e| anyhow::anyhow!("Assembly error: {e}"))?;
            let hex_str = bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
            println!("Assembled {} bytes at 0x{:X}:", bytes.len(), addr);
            println!("  {}", hex_str);
        }
        Some(Commands::Patch { pid, address, code }) => {
            let addr = parse_hex_or_dec_val(&address)
                .ok_or_else(|| anyhow::anyhow!("Invalid address '{address}'"))?;
            let mut pal = default_backend();
            pal.attach(pid)?;
            let bitness = match pal.architecture() {
                engine_pal::CpuArchitecture::X86_32 => 32,
                engine_pal::CpuArchitecture::X86_64 => 64,
            };

            let bytes = if let Some(hex_part) = code.strip_prefix("hex:") {
                let mut b = Vec::new();
                for t in hex_part.split_whitespace() {
                    b.push(u8::from_str_radix(t.trim_start_matches("0x"), 16)?);
                }
                b
            } else {
                let normalized = code.replace(';', "\n");
                engine_core::assemble_code(&normalized, bitness, addr)
                    .map_err(|e| anyhow::anyhow!("Assembly error: {e}"))?
            };

            let orig = pal.read_raw(Address::new(addr), bytes.len()).unwrap_or_default();
            let orig_hex = orig.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
            pal.write_raw(Address::new(addr), &bytes)?;
            let patch_hex = bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");

            println!("Patched 0x{:X} ({} bytes):", addr, bytes.len());
            println!("  Original: {}", orig_hex);
            println!("  New:      {}", patch_hex);
        }
        Some(Commands::Hook { pid, target, cave, payload }) => {
            let target_addr = parse_hex_or_dec_val(&target)
                .ok_or_else(|| anyhow::anyhow!("Invalid target address '{target}'"))?;
            let cave_addr = parse_hex_or_dec_val(&cave)
                .ok_or_else(|| anyhow::anyhow!("Invalid cave address '{cave}'"))?;

            let mut pal = default_backend();
            pal.attach(pid)?;
            let bitness = match pal.architecture() {
                engine_pal::CpuArchitecture::X86_32 => 32,
                engine_pal::CpuArchitecture::X86_64 => 64,
            };

            let original_slice = pal.read_raw(Address::new(target_addr), 32)?;
            let payload_bytes = if let Some(p) = payload {
                let normalized = p.replace(';', "\n");
                engine_core::assemble_code(&normalized, bitness, cave_addr)
                    .map_err(|e| anyhow::anyhow!("Payload assembly error: {e}"))?
            } else {
                Vec::new()
            };

            let package = engine_core::build_detour_hook(
                &original_slice,
                target_addr,
                cave_addr,
                bitness,
                &payload_bytes,
            ).map_err(|e| anyhow::anyhow!("Hook generation error: {e}"))?;

            pal.write_raw(Address::new(cave_addr), &package.code_cave_bytes)?;
            pal.write_raw(Address::new(target_addr), &package.patch_bytes)?;

            println!("Detour hook installed successfully!");
            println!("  Target:       0x{:X}", target_addr);
            println!("  Code Cave:    0x{:X} ({} bytes)", cave_addr, package.code_cave_bytes.len());
            println!("  Stolen bytes: {} bytes", package.original_bytes.len());
            println!("  Return addr:  0x{:X}", package.return_address.as_u64());
        }
        Some(Commands::Pattern { pid, address, size }) => {
            let addr = parse_hex_or_dec_val(&address)
                .ok_or_else(|| anyhow::anyhow!("Invalid address '{address}'"))?;
            let mut pal = default_backend();
            pal.attach(pid)?;
            let bitness = match pal.architecture() {
                engine_pal::CpuArchitecture::X86_32 => 32,
                engine_pal::CpuArchitecture::X86_64 => 64,
            };

            let bytes = pal.read_raw(Address::new(addr), size)?;
            let pattern = engine_core::generate_pattern_from_bytes(&bytes, addr, bitness, size)
                .map_err(|e| anyhow::anyhow!("Pattern generation error: {e}"))?;
            let wildcards = pattern.split_whitespace().filter(|t| *t == "??").count();
            println!("Generated AOB Pattern ({} bytes, {} wildcards):", pattern.split_whitespace().count(), wildcards);
            println!("  {}", pattern);
        }
        Some(Commands::Xrefs { pid, target, start, size }) => {
            let target_addr = parse_hex_or_dec_val(&target)
                .ok_or_else(|| anyhow::anyhow!("Invalid target address '{target}'"))?;
            let start_addr = parse_hex_or_dec_val(&start)
                .ok_or_else(|| anyhow::anyhow!("Invalid start address '{start}'"))?;
            let mut pal = default_backend();
            pal.attach(pid)?;
            let bitness = match pal.architecture() {
                engine_pal::CpuArchitecture::X86_32 => 32,
                engine_pal::CpuArchitecture::X86_64 => 64,
            };

            let bytes = pal.read_raw(Address::new(start_addr), size)?;
            let xrefs = engine_core::find_xrefs_in_code(&bytes, start_addr, bitness, target_addr);
            println!("Found {} cross-references to 0x{:X}:", xrefs.len(), target_addr);
            for x in xrefs {
                println!("  0x{:X} [{:?}] {}", x.instruction_address.as_u64(), x.xref_type, x.instruction_text);
            }
        }
        Some(Commands::Alloc { pid, size, protection }) => {
            let mut pal = default_backend();
            pal.attach(pid)?;
            let prot = match protection.to_lowercase().as_str() {
                "rw" => ProtectionFlags::RW,
                "rx" => ProtectionFlags::RX,
                "rwx" => ProtectionFlags::RWX,
                _ => ProtectionFlags::RWX,
            };
            let addr = pal.allocate_memory(size, prot)?;
            println!("Successfully allocated {} bytes at 0x{:X} ({})", size, addr.as_u64(), protection);
        }
        Some(Commands::Free { pid, address }) => {
            let addr = parse_hex_or_dec_val(&address)
                .ok_or_else(|| anyhow::anyhow!("Invalid address '{address}'"))?;
            let mut pal = default_backend();
            pal.attach(pid)?;
            pal.free_memory(Address::new(addr))?;
            println!("Successfully freed memory at 0x{:X}", addr);
        }
        Some(Commands::Struct { pid, address, size, export, name }) => {
            let addr = parse_hex_or_dec_val(&address)
                .ok_or_else(|| anyhow::anyhow!("Invalid address '{address}'"))?;
            let mut pal = default_backend();
            pal.attach(pid)?;

            let bytes = pal.read_raw(Address::new(addr), size)?;
            let regions = pal.query_regions().unwrap_or_default();
            let structure = engine_core::ClassStructure::reconstruct(Address::new(addr), &bytes, &regions, Some(&name));

            if let Some(lang) = export {
                let code = match lang.to_lowercase().as_str() {
                    "rust" | "rs" => structure.to_rust(),
                    "cs" | "csharp" => structure.to_csharp(),
                    _ => structure.to_cpp(),
                };
                println!("{code}");
            } else {
                println!("\nReClass Node Analysis for {} at 0x{:X} (Size: 0x{:X} / {} bytes):", structure.name, addr, structure.total_size, structure.total_size);
                println!("{:<8} {:<16} {:<12} {:<24} COMMENT", "OFFSET", "NAME", "TYPE", "VALUE");
                println!("{:-<80}", "");
                for f in &structure.fields {
                    let comment = f.comment.as_deref().unwrap_or("");
                    println!("+0x{:04X}  {:<16} {:<12} {:<24} {}", f.offset, f.name, f.field_type.type_name(), f.display_value, comment);
                }
                println!();
            }
        }
    }

    Ok(())
}

fn parse_cli_type(s: &str) -> anyhow::Result<ScanValueType> {
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
        _ => anyhow::bail!("Unsupported value type: '{s}'"),
    }
}

fn parse_hex_or_dec_val(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}
