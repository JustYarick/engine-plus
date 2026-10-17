use clap::{Parser, Subcommand};
use engine_pal::{default_backend, default_enumerator, ProcessId};
use tracing::info;

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    if cli.mcp {
        info!("Starting Engine+ standard MCP server over stdio...");
        // MCP loop will be invoked here in Stage 5
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
        None => {
            println!("Engine+ CLI v0.1.0. Use --help for usage information.");
        }
    }

    Ok(())
}
