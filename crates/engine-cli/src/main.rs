mod repl;

use clap::{Parser, Subcommand};
use engine_core::{FirstScanMode, MemoryScanner, ScanConfig, ScanValue, ScanValueType};
use engine_pal::{default_backend, default_enumerator, Address, MemoryReader, ProcessId, ProtectionFlags};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use repl::InteractiveConsole;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "engine-plus")]
#[command(author = "Yarick <yarick@engine-plus.dev>")]
#[command(version)]
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

        /// Value type: i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, hex, string
        #[arg(short = 't', long, default_value = "i32")]
        val_type: String,

        /// Number of bytes to read (defaults automatically according to type)
        #[arg(short, long)]
        size: Option<usize>,
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

    /// Pause target process execution (freeze threads/SIGSTOP)
    Pause {
        #[arg(short, long)]
        pid: ProcessId,
    },

    /// Resume target process execution
    Resume {
        #[arg(short, long)]
        pid: ProcessId,
    },

    /// Read and dump CPU registers snapshot from target process
    Regs {
        #[arg(short, long)]
        pid: ProcessId,

        #[arg(short, long)]
        thread_id: Option<ProcessId>,
    },

    /// Set a software or hardware breakpoint/watchpoint on target address
    Bp {
        #[arg(short, long)]
        pid: ProcessId,

        #[arg(short, long)]
        address: String,

        /// Breakpoint type: software, write, access, execute
        #[arg(short = 't', long, default_value = "software")]
        bp_type: String,

        /// Watchpoint monitored size (1, 2, 4, 8 bytes)
        #[arg(short, long, default_value = "4")]
        size: usize,
    },

    /// Scan target process memory for multi-level static pointer chains
    PtrScan {
        #[arg(short, long)]
        pid: ProcessId,

        /// Target memory address to trace back (e.g. '0x7FFD1234')
        #[arg(short, long)]
        target: String,

        /// Max pointer chain depth (1..=5, default: 3)
        #[arg(short, long, default_value = "3")]
        depth: usize,

        /// Max offset from base pointer (default: 0x800)
        #[arg(short, long, default_value = "0x800")]
        max_offset: String,

        /// Maximum results to display
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },

    /// Resolve multi-level pointer path to actual target address
    PtrResolve {
        #[arg(short, long)]
        pid: ProcessId,

        /// Base module name (e.g. 'game.exe' or 'game.so')
        #[arg(short, long)]
        module: String,

        /// Base offset from module base (e.g. '0x1000')
        #[arg(short, long)]
        base_offset: String,

        /// Subsequent offsets in order (e.g. '0x20', '0xF8')
        #[arg(short, long, num_args = 1..)]
        offsets: Vec<String>,
    },

    /// Speed hack configuration or AutoAssembler injection script generator
    Speedhack {
        /// Speed multiplier (e.g. 2.0 for 2x speed, 0.5 for half speed)
        #[arg(short, long, default_value = "1.0")]
        multiplier: f64,

        /// Generate AutoAssembler injection script instead of displaying time dilation state
        #[arg(short, long)]
        script: bool,

        /// Target platform for script generation ('linux' or 'windows')
        #[arg(long)]
        platform: Option<String>,
    },

    /// Enumerate loaded modules and binaries in target process
    Modules {
        #[arg(short, long)]
        pid: ProcessId,

        /// Optional substring filter for module name or path
        #[arg(short, long)]
        filter: Option<String>,
    },

    /// Lookup functions and symbols via symbol tables and DWARF debug info
    Symbols {
        #[arg(short, long)]
        pid: ProcessId,

        /// Substring pattern to search for (e.g. 'player', 'health')
        #[arg(short = 's', long)]
        pattern: String,

        /// Optional module name or binary path (defaults to main executable)
        #[arg(short, long)]
        module: Option<String>,

        /// Maximum results to display
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// Inspect struct memory layout or list structs from DWARF debug info
    StructLayout {
        /// Process ID (inspects module in running process)
        #[arg(short, long)]
        pid: Option<ProcessId>,

        /// Direct binary path on disk (alternative to --pid)
        #[arg(long)]
        path: Option<PathBuf>,

        /// Structure name to inspect layout of (e.g. 'playerent')
        #[arg(short, long)]
        name: Option<String>,

        /// List all structure names found in DWARF debug symbols
        #[arg(short = 'l', long)]
        list_all: bool,

        /// Maximum structures to list
        #[arg(long, default_value = "100")]
        limit: usize,
    },

    /// Compare memory structure over time to identify changing fields
    Diff {
        #[arg(short, long)]
        pid: ProcessId,

        /// Memory address of structure to monitor (e.g. '0x6F7B630')
        #[arg(short, long)]
        address: String,

        /// Structure size in bytes
        #[arg(short, long, default_value = "128")]
        size: usize,

        /// Delay between memory samples in milliseconds
        #[arg(short, long, default_value = "500")]
        interval_ms: u64,
    },

    /// Batch read multiple addresses and pointer chains in a single pass
    Batch {
        #[arg(short, long)]
        pid: ProcessId,

        /// Address or pointer chain expressions (e.g. '0x5A3518:u64', 'linux_64_client+0x1A3518->+0x100:i32')
        #[arg(short, long, num_args = 1..)]
        items: Vec<String>,
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

            let read_size = size.unwrap_or_else(|| match val_type.to_lowercase().as_str() {
                "i8" | "u8" => 1,
                "i16" | "u16" => 2,
                "i64" | "u64" | "f64" => 8,
                "string" => 32,
                _ => 4,
            });

            let mut pal = default_backend();
            pal.attach(pid)?;

            let bytes = pal.read_raw(Address::new(addr), read_size)?;
            match val_type.to_lowercase().as_str() {
                "i8" if !bytes.is_empty() => println!("{}: {}", address, bytes[0] as i8),
                "u8" if !bytes.is_empty() => println!("{}: {} (0x{:02X})", address, bytes[0], bytes[0]),
                "i16" if bytes.len() >= 2 => println!("{}: {}", address, i16::from_le_bytes(bytes[..2].try_into().unwrap())),
                "u16" if bytes.len() >= 2 => println!("{}: {}", address, u16::from_le_bytes(bytes[..2].try_into().unwrap())),
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
                "i8" => vec![value.parse::<i8>()? as u8],
                "u8" => vec![value.parse::<u8>()?],
                "i16" => value.parse::<i16>()?.to_le_bytes().to_vec(),
                "u16" => value.parse::<u16>()?.to_le_bytes().to_vec(),
                "i32" => value.parse::<i32>()?.to_le_bytes().to_vec(),
                "u32" => value.parse::<u32>()?.to_le_bytes().to_vec(),
                "f32" => value.parse::<f32>()?.to_le_bytes().to_vec(),
                "i64" => value.parse::<i64>()?.to_le_bytes().to_vec(),
                "u64" => value.parse::<u64>()?.to_le_bytes().to_vec(),
                "f64" => value.parse::<f64>()?.to_le_bytes().to_vec(),
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
        Some(Commands::Pause { pid }) => {
            let mut pal = default_backend();
            pal.attach(pid)?;
            pal.suspend_process()?;
            println!("Process {pid} execution paused (frozen)");
        }
        Some(Commands::Resume { pid }) => {
            let mut pal = default_backend();
            pal.attach(pid)?;
            pal.resume_process()?;
            println!("Process {pid} execution resumed");
        }
        Some(Commands::Regs { pid, thread_id }) => {
            let mut pal = default_backend();
            pal.attach(pid)?;
            let regs = pal.get_registers(thread_id)?;
            println!("{}", regs.format_display());
        }
        Some(Commands::Bp { pid, address, bp_type, size }) => {
            let addr = parse_hex_or_dec_val(&address)
                .ok_or_else(|| anyhow::anyhow!("Invalid address '{address}'"))?;
            let mut pal = default_backend();
            pal.attach(pid)?;
            let mut bpm = engine_core::BreakpointManager::new();

            match bp_type.to_lowercase().as_str() {
                "software" | "sw" | "int3" => {
                    let id = bpm.set_software_breakpoint(&mut *pal, Address::new(addr))?;
                    println!("Software breakpoint #{} set at 0x{:X} (INT3 0xCC written)", id.0, addr);
                }
                "write" | "hw_write" => {
                    let slot = bpm.set_hardware_breakpoint(
                        Address::new(addr),
                        engine_pal::WatchpointCondition::Write,
                        engine_pal::WatchpointSize::from_bytes(size),
                    )?;
                    println!("Hardware watchpoint set in DR{slot} at 0x{:X} (Write, {} bytes)", addr, size);
                }
                "access" | "hw_access" | "rw" => {
                    let slot = bpm.set_hardware_breakpoint(
                        Address::new(addr),
                        engine_pal::WatchpointCondition::Access,
                        engine_pal::WatchpointSize::from_bytes(size),
                    )?;
                    println!("Hardware watchpoint set in DR{slot} at 0x{:X} (Read/Write, {} bytes)", addr, size);
                }
                "execute" | "exec" | "hw_exec" => {
                    let slot = bpm.set_hardware_breakpoint(
                        Address::new(addr),
                        engine_pal::WatchpointCondition::Execution,
                        engine_pal::WatchpointSize::from_bytes(size),
                    )?;
                    println!("Hardware execution breakpoint set in DR{slot} at 0x{:X}", addr);
                }
                other => anyhow::bail!("Unknown breakpoint type: '{other}'"),
            }
        }
        Some(Commands::PtrScan { pid, target, depth, max_offset, limit }) => {
            let target_addr = parse_hex_or_dec_val(&target)
                .ok_or_else(|| anyhow::anyhow!("Invalid target address '{target}'"))?;
            let max_off = parse_hex_or_dec_val(&max_offset)
                .ok_or_else(|| anyhow::anyhow!("Invalid max_offset '{max_offset}'"))? as usize;

            let mut pal = default_backend();
            pal.attach(pid)?;

            println!("Building pointer map of target process (PID: {pid})...");
            let regions = pal.query_regions()?;
            let ptr_size = pal.architecture().pointer_size();
            let pmap = engine_core::PointerMap::build_from_memory(&*pal, &regions, ptr_size, ptr_size, true)?;
            println!("Indexed {} pointers across writable regions", pmap.total_pointers());

            let modules = pal.enumerate_modules().unwrap_or_default();
            println!("Scanning for pointer chains to 0x{:X} (Depth: 1..={}, Max Offset: 0x{:X})...", target_addr, depth, max_off);

            let config = engine_core::PointerScannerConfig {
                max_depth: depth,
                max_offset: max_off,
                max_results: limit.max(50),
                writable_only: true,
            };
            let paths = engine_core::PointerScanner::scan(&pmap, &modules, Address::new(target_addr), &config);
            println!("Scan complete: Found {} pointer chain(s)", paths.len());

            let display_count = paths.len().min(limit);
            for (i, p) in paths.iter().take(display_count).enumerate() {
                println!("  [#{}] {}", i + 1, p);
            }
            if paths.len() > limit {
                println!("  ... and {} more path(s). Pass --limit to view more.", paths.len() - limit);
            }
        }
        Some(Commands::PtrResolve { pid, module, base_offset, offsets }) => {
            let base_off = parse_hex_or_dec_val(&base_offset)
                .ok_or_else(|| anyhow::anyhow!("Invalid base offset '{base_offset}'"))?;
            let mut parsed_offsets = Vec::new();
            for o in &offsets {
                let off = parse_hex_or_dec_val(o)
                    .ok_or_else(|| anyhow::anyhow!("Invalid offset '{o}'"))? as i64;
                parsed_offsets.push(off);
            }

            let mut pal = default_backend();
            pal.attach(pid)?;

            let modules = pal.enumerate_modules()?;
            let target_mod = modules
                .iter()
                .find(|m| m.name.eq_ignore_ascii_case(&module) || m.name.to_lowercase().contains(&module.to_lowercase()))
                .ok_or_else(|| anyhow::anyhow!("Module '{module}' not found in target process"))?;

            let path = engine_core::PointerPath {
                module_name: target_mod.name.clone(),
                base_offset: base_off,
                offsets: parsed_offsets,
            };
            let resolved = path.resolve(&*pal, target_mod.base_address, pal.architecture())?;
            println!("Pointer Path: {}", path);
            println!("  Module Base:      0x{:X}", target_mod.base_address.as_u64());
            println!("  Resolved Address: 0x{:X}", resolved.as_u64());

            if let Ok(bytes) = pal.read_raw(resolved, 8) {
                let u32_val = u32::from_le_bytes(bytes[0..4].try_into().unwrap_or_default());
                let i32_val = i32::from_le_bytes(bytes[0..4].try_into().unwrap_or_default());
                let f32_val = f32::from_le_bytes(bytes[0..4].try_into().unwrap_or_default());
                let u64_val = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or_default());
                println!("  Value at target: i32 = {}, u32 = {}, f32 = {:.4}, u64 = 0x{:X}", i32_val, u32_val, f32_val, u64_val);
            }
        }
        Some(Commands::Speedhack { multiplier, script, platform }) => {
            if script {
                let script_code = match platform.as_deref().map(|s| s.to_lowercase()) {
                    Some(ref p) if p == "windows" || p == "win" => {
                        engine_core::SpeedHackScriptGenerator::generate_windows_aa_script(multiplier)
                    }
                    _ => engine_core::SpeedHackScriptGenerator::generate_linux_aa_script(multiplier),
                };
                println!("Generated AutoAssembler Speed Hack Script (Multiplier: {:.2}x):", multiplier);
                println!("------------------------------------------------------------");
                println!("{script_code}");
                println!("------------------------------------------------------------");
            } else {
                let mut state = engine_core::TimeDilationState::new(multiplier);
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                state.set_multiplier(multiplier, now_ns);
                let virt_time = state.calculate_virtual_time(now_ns);
                println!("Speed Hack Time Dilation State:");
                println!("  Multiplier:   {:.2}x", state.multiplier);
                println!("  Real Time:    {:.3} s", now_ns as f64 / 1_000_000_000.0);
                println!("  Virtual Time: {:.3} s", virt_time as f64 / 1_000_000_000.0);
            }
        }
        Some(Commands::Modules { pid, filter }) => {
            let mut pal = default_backend();
            pal.attach(pid)?;
            let mut modules = pal.enumerate_modules()?;
            if let Some(ref f) = filter {
                let fl = f.to_lowercase();
                modules.retain(|m| m.name.to_lowercase().contains(&fl) || m.path.to_lowercase().contains(&fl));
            }
            println!("Loaded modules in process {pid} (Count: {}):", modules.len());
            println!("{:<32} | {:>18} | {:>10} | Path", "Module Name", "Base Address", "Size");
            println!("{:-<32}-+-{:-<18}-+-{:-<10}-+-{:-<40}", "", "", "", "");
            for m in &modules {
                println!("{:<32} | 0x{:016X} | 0x{:08X} | {}", m.name, m.base_address.as_u64(), m.size, m.path);
            }
        }
        Some(Commands::Symbols { pid, pattern, module, limit }) => {
            let mut pal = default_backend();
            pal.attach(pid)?;
            let modules = pal.enumerate_modules()?;
            let (mod_name, mod_path, mod_base) = if let Some(ref req) = module {
                if let Some(m) = modules.iter().find(|m| m.name.eq_ignore_ascii_case(req) || m.name.to_lowercase().contains(&req.to_lowercase())) {
                    (m.name.clone(), m.path.clone(), m.base_address)
                } else if std::path::Path::new(req).exists() {
                    (req.clone(), req.clone(), Address::NULL)
                } else {
                    anyhow::bail!("Module '{req}' not found");
                }
            } else if let Some(m) = modules.first() {
                (m.name.clone(), m.path.clone(), m.base_address)
            } else {
                anyhow::bail!("No modules found in target process");
            };

            let path_obj = std::path::Path::new(&mod_path);
            if !path_obj.exists() {
                anyhow::bail!("Binary file '{mod_path}' does not exist on disk for symbol reading");
            }

            let symbols = engine_core::lookup_symbols(path_obj, Some(mod_base), &pattern, limit)?;
            println!("Found {} symbol(s) matching '{pattern}' in {mod_name}:", symbols.len());
            println!("{:>18} | {:>10} | {:<8} | {:<8} | {:<12} | Name", "Runtime Addr", "Size", "Kind", "Binding", "Section");
            println!("{:-<18}-+-{:-<10}-+-{:-<8}-+-{:-<8}-+-{:-<12}-+-{:-<30}", "", "", "", "", "", "");
            for s in &symbols {
                let sec = s.section.as_deref().unwrap_or("-");
                println!("0x{:016X} | 0x{:08X} | {:<8} | {:<8} | {:<12} | {}", s.address.as_u64(), s.size, s.kind, s.binding, sec, s.name);
            }
        }
        Some(Commands::StructLayout { pid, path, name, list_all, limit }) => {
            let file_path = if let Some(p) = path {
                p
            } else if let Some(pid) = pid {
                let mut pal = default_backend();
                pal.attach(pid)?;
                let modules = pal.enumerate_modules()?;
                if let Some(m) = modules.first() {
                    PathBuf::from(&m.path)
                } else {
                    anyhow::bail!("No module path found for PID {pid}");
                }
            } else {
                anyhow::bail!("Please specify either --pid <PID> or --path <BINARY_PATH>");
            };

            if list_all {
                let names = engine_core::list_dwarf_structs(&file_path, limit)?;
                println!("Found {} structure(s) in DWARF debug info for '{}':", names.len(), file_path.display());
                for n in &names {
                    println!("  {n}");
                }
            } else if let Some(ref sname) = name {
                let layout = engine_core::inspect_dwarf_struct(&file_path, sname)?;
                println!("Structure '{}' (Total Size: {} bytes, {} members):", layout.name, layout.total_size, layout.members.len());
                println!("{:<10} | {:>6} | {:<24} | Field Name", "Offset", "Size", "Type");
                println!("{:-<10}-+-{:-<6}-+-{:-<24}-+-{:-<24}", "", "", "", "");
                for m in &layout.members {
                    println!("{:<10} | {:>6} | {:<24} | {}", m.offset_hex, m.size, m.type_name, m.name);
                }
                println!("\nC++ Struct Definition:\n{}", layout.format_cpp_definition());
            } else {
                anyhow::bail!("Please provide a structure name with -n/--name, or pass -l/--list-all");
            }
        }
        Some(Commands::Diff { pid, address, size, interval_ms }) => {
            let addr_val = parse_hex_or_dec_val(&address)
                .ok_or_else(|| anyhow::anyhow!("Invalid address '{address}'"))?;
            let addr = Address::new(addr_val);
            let mut pal = default_backend();
            pal.attach(pid)?;

            println!("Monitoring address {addr} (size: {size} bytes)...");
            let before = pal.read_raw(addr, size)?;
            println!("Captured baseline snapshot. Waiting {interval_ms} ms...");
            std::thread::sleep(std::time::Duration::from_millis(interval_ms));
            let after = pal.read_raw(addr, size)?;

            let diffs = engine_core::compute_struct_diff(addr, &before, &after);
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
        }
        Some(Commands::Batch { pid, items }) => {
            let mut pal = default_backend();
            pal.attach(pid)?;
            let modules = pal.enumerate_modules().unwrap_or_default();
            let arch = pal.architecture();

            println!("Executing batch read of {} item(s) on PID {pid}:", items.len());
            for (idx, item) in items.iter().enumerate() {
                let (expr, type_str) = if let Some((e, t)) = item.split_once(':') {
                    (e.trim(), t.trim())
                } else {
                    (item.trim(), "i32")
                };

                let resolved_addr: Result<Address, anyhow::Error> = if expr.contains("->") {
                    let parts: Vec<&str> = expr.split("->").map(|s| s.trim()).collect();
                    let base_part = parts[0];
                    let mut current_addr = if let Some((mod_name, off_str)) = base_part.split_once('+') {
                        let base_off = parse_hex_or_dec_val(off_str)
                            .ok_or_else(|| anyhow::anyhow!("Invalid offset '{off_str}'"))?;
                        let m = modules.iter().find(|m| m.name.eq_ignore_ascii_case(mod_name.trim()) || m.name.to_lowercase().contains(&mod_name.to_lowercase()))
                            .ok_or_else(|| anyhow::anyhow!("Module '{mod_name}' not found"))?;
                        m.base_address.add(base_off as usize)
                    } else {
                        let a = parse_hex_or_dec_val(base_part)
                            .ok_or_else(|| anyhow::anyhow!("Invalid base address '{base_part}'"))?;
                        Address::new(a)
                    };

                    current_addr = pal.read_pointer(current_addr, arch)?;
                    for (level, &off_str) in parts[1..].iter().enumerate() {
                        let off = if let Some(s) = off_str.strip_prefix('+') {
                            parse_hex_or_dec_val(s).ok_or_else(|| anyhow::anyhow!("Invalid offset '{off_str}'"))? as i64
                        } else if let Some(s) = off_str.strip_prefix('-') {
                            -(parse_hex_or_dec_val(s).ok_or_else(|| anyhow::anyhow!("Invalid offset '{off_str}'"))? as i64)
                        } else {
                            parse_hex_or_dec_val(off_str).ok_or_else(|| anyhow::anyhow!("Invalid offset '{off_str}'"))? as i64
                        };
                        let next = current_addr.offset(off);
                        if level == parts.len() - 2 {
                            current_addr = next;
                        } else {
                            current_addr = pal.read_pointer(next, arch)?;
                        }
                    }
                    Ok(current_addr)
                } else if let Some((mod_name, off_str)) = expr.split_once('+') {
                    let base_off = parse_hex_or_dec_val(off_str)
                        .ok_or_else(|| anyhow::anyhow!("Invalid offset '{off_str}'"))?;
                    let m = modules.iter().find(|m| m.name.eq_ignore_ascii_case(mod_name.trim()) || m.name.to_lowercase().contains(&mod_name.to_lowercase()))
                        .ok_or_else(|| anyhow::anyhow!("Module '{mod_name}' not found"))?;
                    Ok(m.base_address.add(base_off as usize))
                } else {
                    let a = parse_hex_or_dec_val(expr)
                        .ok_or_else(|| anyhow::anyhow!("Invalid address '{expr}'"))?;
                    Ok(Address::new(a))
                };

                match resolved_addr {
                    Ok(addr) => {
                        let val_str = match type_str.to_lowercase().as_str() {
                            "i8" => pal.read_i8(addr).map(|v| format!("{v}")),
                            "u8" => pal.read_u8(addr).map(|v| format!("{v} (0x{v:02X})")),
                            "i16" => pal.read_i16(addr).map(|v| format!("{v}")),
                            "u16" => pal.read_u16(addr).map(|v| format!("{v} (0x{v:04X})")),
                            "i32" => pal.read_i32(addr).map(|v| format!("{v}")),
                            "u32" => pal.read_u32(addr).map(|v| format!("{v} (0x{v:08X})")),
                            "i64" => pal.read_i64(addr).map(|v| format!("{v}")),
                            "u64" => pal.read_u64(addr).map(|v| format!("{v} (0x{v:016X})")),
                            "f32" => pal.read_f32(addr).map(|v| format!("{v:.4}")),
                            "f64" => pal.read_f64(addr).map(|v| format!("{v:.6}")),
                            "hex" => pal.read_raw(addr, 16).map(|b| b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")),
                            _ => pal.read_i32(addr).map(|v| format!("{v}")),
                        };
                        match val_str {
                            Ok(v) => println!("  [#{}] {} => {} [{}] = {}", idx + 1, expr, addr, type_str, v),
                            Err(e) => println!("  [#{}] {} => {} [{}] = Error: {}", idx + 1, expr, addr, type_str, e),
                        }
                    }
                    Err(e) => println!("  [#{}] {} => Error: {}", idx + 1, expr, e),
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing_subcommands() {
        assert!(Cli::try_parse_from(["engine-plus", "console"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "ps", "--filter", "game"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "script", "-c", "return 1"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "aa", "-p", "1234", "-s", "[ENABLE]"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "assemble", "-c", "xor eax, eax"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "pause", "-p", "1234"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "resume", "-p", "1234"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "regs", "-p", "1234"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "bp", "-p", "1234", "-a", "0x7FFF1000"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "ptr-scan", "-p", "1234", "-t", "0x7FFF1000"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "ptr-resolve", "-p", "1234", "-m", "game.exe", "-b", "0x1000", "-o", "0x20", "0xF8"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "speedhack", "-m", "2.5"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "speedhack", "-m", "1.5", "-s"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "modules", "-p", "1234"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "symbols", "-p", "1234", "-s", "player"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "struct-layout", "-p", "1234", "-n", "playerent"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "diff", "-p", "1234", "-a", "0x1000"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "batch", "-p", "1234", "-i", "0x1000:i32"]).is_ok());
        assert!(Cli::try_parse_from(["engine-plus", "--mcp"]).is_ok());
    }

    #[test]
    fn test_parse_cli_type() {
        assert_eq!(parse_cli_type("i32").unwrap(), ScanValueType::I32);
        assert_eq!(parse_cli_type("f32").unwrap(), ScanValueType::F32);
        assert_eq!(parse_cli_type("aob").unwrap(), ScanValueType::Aob);
        assert!(parse_cli_type("invalid").is_err());
    }

    #[test]
    fn test_parse_hex_or_dec_val() {
        assert_eq!(parse_hex_or_dec_val("0x1000"), Some(0x1000));
        assert_eq!(parse_hex_or_dec_val("4096"), Some(4096));
        assert_eq!(parse_hex_or_dec_val("bad"), None);
    }
}
