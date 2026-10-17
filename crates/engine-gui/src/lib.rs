pub mod app;
pub mod tabs;
pub mod theme;

pub use app::EngineApp;
pub use theme::apply_catppuccin_mocha;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_theme_application() {
        let ctx = egui::Context::default();
        apply_catppuccin_mocha(&ctx);
    }
}
