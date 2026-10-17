use tracing::info;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Engine+ IDE launching...");

    println!("Engine+ Desktop IDE v0.1.0");
    // eframe GUI loop will be invoked here in Stage 6

    Ok(())
}
