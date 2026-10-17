use clap::{Parser, Subcommand};
use engine_core::{FirstScanMode, MemoryScanner, ScanConfig, ScanValue, ScanValueType};
use engine_pal::{default_backend, default_enumerator, ProcessId};

#[derive(Parser, Debug)]
#[command(name = "engine-plus-cli")]
#[command(author = "Yarick <yarick@engine-plus.dev>")]
#[command(version = "0.1.0")]
#[command(about = "Modern Cheat Engine & Reverse Engineering CLI in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Run as standard Model Context Protocol (MCP) server over stdio
    #[arg(long)]
    mcp: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List active processes
    Ps {
        #[arg(short, long)]
        filter: Option<String>,
    },
    /// Attach to a target process by PID and print info
    Attach {
        #[arg(short, long)]
        pid: ProcessId,
    },
    /// Scan memory of a target process
    Scan {
        #[arg(short, long)]
        pid: ProcessId,

        /// Value to search for (number, float, or AOB hex pattern)
        #[arg(short, long)]
        value: String,

        /// Value type: i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, aob
        #[arg(short = 't', long, default_value = "i32")]
        val_type: String,

        /// Memory alignment (1, 2, 4, 8)
        #[arg(short, long)]
        alignment: Option<usize>,

        /// Max results to display
        #[arg(short, long, default_value = "20")]
        limit: usize,
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
        Some(Commands::Ps { filter }) => {
            let enumerator = default_enumerator();
            let mut processes = enumerator.list_processes()?;

            if let Some(ref query) = filter {
                let q_lower = query.to_lowercase();
                processes.retain(|p| {
                    p.name.to_lowercase().contains(&q_lower)
                        || p.cmdline
                            .as_ref()
                            .map_or(false, |c| c.to_lowercase().contains(&q_lower))
                });
            }

            println!(
                "{:<8} {:<8} {:<24} {}",
                "PID", "ARCH", "NAME", "CMDLINE"
            );
            println!("{:-<80}", "");

            for p in processes {
                let arch_str = match p.architecture {
                    engine_pal::CpuArchitecture::X86_32 => "x86",
                    engine_pal::CpuArchitecture::X86_64 => "x64",
                };
                let cmd = p.cmdline.unwrap_or_default();
                let short_cmd = if cmd.len() > 40 {
                    format!("{}...", &cmd[..37])
                } else {
                    cmd
                };
                println!("{:<8} {:<8} {:<24} {}", p.pid, arch_str, p.name, short_cmd);
            }
        }
        Some(Commands::Attach { pid }) => {
            println!("Attaching to PID {pid}...");
            let mut pal = default_backend();
            pal.attach(pid)?;

            let arch = pal.architecture();
            let arch_str = match arch {
                engine_pal::CpuArchitecture::X86_32 => "32-bit (x86)",
                engine_pal::CpuArchitecture::X86_64 => "64-bit (x64)",
            };
            println!("Successfully attached via backend: {}", pal.backend_name());
            println!("Architecture: {arch_str}");

            let regions = pal.query_regions()?;
            println!("Mapped regions count: {}", regions.len());

            let modules = pal.enumerate_modules()?;
            println!("Loaded modules count: {}", modules.len());
            for m in modules.iter().take(5) {
                println!(
                    "  [{}] Base: {} Size: 0x{:X}",
                    m.name, m.base_address, m.size
                );
            }
            if modules.len() > 5 {
                println!("  ... and {} more modules", modules.len() - 5);
            }
        }
        Some(Commands::Scan {
            pid,
            value,
            val_type,
            alignment,
            limit,
        }) => {
            let parsed_type = match val_type.to_lowercase().as_str() {
                "i8" => ScanValueType::I8,
                "u8" => ScanValueType::U8,
                "i16" => ScanValueType::I16,
                "u16" => ScanValueType::U16,
                "i32" => ScanValueType::I32,
                "u32" => ScanValueType::U32,
                "i64" => ScanValueType::I64,
                "u64" => ScanValueType::U64,
                "f32" => ScanValueType::F32,
                "f64" => ScanValueType::F64,
                "aob" => ScanValueType::Aob,
                _ => anyhow::bail!("Unsupported value type: '{val_type}'"),
            };

            let parsed_val = ScanValue::parse(&value, parsed_type)
                .map_err(|e| anyhow::anyhow!("Invalid value: {e}"))?;

            let mut pal = default_backend();
            pal.attach(pid)?;

            let mut config = ScanConfig::new(parsed_type);
            if let Some(align) = alignment {
                config.alignment = align;
            }

            println!(
                "Scanning PID {} for {} ({:?}) [alignment={}]...",
                pid, parsed_val, parsed_type, config.alignment
            );

            let start_time = std::time::Instant::now();
            let mut scanner = MemoryScanner::new();
            let count = scanner.first_scan(&*pal, &config, &FirstScanMode::Exact(parsed_val))?;
            let duration = start_time.elapsed();

            println!(
                "Found {} results in {:.2?} ({:.1} results/ms)",
                count,
                duration,
                if duration.as_millis() > 0 {
                    count as f64 / duration.as_millis() as f64
                } else {
                    count as f64
                }
            );

            if let Some(results) = scanner.current_results() {
                let display_items = results.page(0, limit);
                println!("\n{:<18} {}", "ADDRESS", "VALUE");
                println!("{:-<40}", "");
                for item in display_items {
                    println!("{:<18} {}", item.address, item.current_value);
                }
                if count > limit {
                    println!("... and {} more results", count - limit);
                }
            }
        }
        None => {
            println!("Engine+ CLI v0.1.0. Use --help for usage information.");
        }
    }

    Ok(())
}
