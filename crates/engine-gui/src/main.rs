use eframe::NativeOptions;
use egui::ViewportBuilder;
use engine_gui::EngineApp;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("Starting Engine+ IDE...");

    let options = NativeOptions {
        viewport: ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([850.0, 550.0])
            .with_title("Engine+ — Modern Reverse Engineering IDE"),
        ..Default::default()
    };

    eframe::run_native(
        "engine-plus",
        options,
        Box::new(|cc| Ok(Box::new(EngineApp::new(cc)))),
    )
}
