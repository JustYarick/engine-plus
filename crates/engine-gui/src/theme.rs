use egui::{
    epaint::Shadow,
    style::{Selection, WidgetVisuals, Widgets},
    Color32, Context, Rounding, Stroke, Visuals,
};

pub mod colors {
    use egui::Color32;

    pub const BASE: Color32 = Color32::from_rgb(0x1E, 0x1E, 0x2E);
    pub const MANTLE: Color32 = Color32::from_rgb(0x18, 0x18, 0x25);
    pub const CRUST: Color32 = Color32::from_rgb(0x11, 0x11, 0x1B);
    pub const SURFACE0: Color32 = Color32::from_rgb(0x31, 0x32, 0x44);
    pub const SURFACE1: Color32 = Color32::from_rgb(0x45, 0x47, 0x5A);
    pub const SURFACE2: Color32 = Color32::from_rgb(0x58, 0x5B, 0x70);
    pub const OVERLAY0: Color32 = Color32::from_rgb(0x6C, 0x70, 0x86);
    pub const TEXT: Color32 = Color32::from_rgb(0xCD, 0xD6, 0xF4);
    pub const SUBTEXT0: Color32 = Color32::from_rgb(0xA6, 0xAD, 0xC8);

    pub const BLUE: Color32 = Color32::from_rgb(0x89, 0xB4, 0xFA);
    pub const LAVENDER: Color32 = Color32::from_rgb(0xB4, 0xBE, 0xFE);
    pub const GREEN: Color32 = Color32::from_rgb(0xA6, 0xE3, 0xA1);
    pub const RED: Color32 = Color32::from_rgb(0xF3, 0x8B, 0xA8);
    pub const PEACH: Color32 = Color32::from_rgb(0xFA, 0xB3, 0x87);
    pub const MAUVE: Color32 = Color32::from_rgb(0xCB, 0xA6, 0xF7);
    pub const YELLOW: Color32 = Color32::from_rgb(0xF9, 0xE2, 0xAF);
}

/// Configure egui context with modern Catppuccin Mocha dark theme
pub fn apply_catppuccin_mocha(ctx: &Context) {
    let mut visuals = Visuals::dark();

    visuals.override_text_color = Some(colors::TEXT);
    visuals.panel_fill = colors::BASE;
    visuals.window_fill = colors::MANTLE;
    visuals.faint_bg_color = colors::MANTLE;
    visuals.extreme_bg_color = colors::CRUST;

    let rounding = Rounding::same(6.0_f32);

    visuals.widgets = Widgets {
        noninteractive: WidgetVisuals {
            bg_fill: colors::SURFACE0,
            weak_bg_fill: colors::BASE,
            bg_stroke: Stroke::new(1.0_f32, colors::SURFACE1),
            rounding,
            fg_stroke: Stroke::new(1.0_f32, colors::SUBTEXT0),
            expansion: 0.0_f32,
        },
        inactive: WidgetVisuals {
            bg_fill: colors::SURFACE0,
            weak_bg_fill: colors::SURFACE0,
            bg_stroke: Stroke::new(1.0_f32, colors::SURFACE1),
            rounding,
            fg_stroke: Stroke::new(1.0_f32, colors::TEXT),
            expansion: 0.0_f32,
        },
        hovered: WidgetVisuals {
            bg_fill: colors::SURFACE1,
            weak_bg_fill: colors::SURFACE1,
            bg_stroke: Stroke::new(1.0_f32, colors::BLUE),
            rounding,
            fg_stroke: Stroke::new(1.5_f32, colors::TEXT),
            expansion: 1.0_f32,
        },
        active: WidgetVisuals {
            bg_fill: colors::SURFACE2,
            weak_bg_fill: colors::SURFACE2,
            bg_stroke: Stroke::new(1.5_f32, colors::BLUE),
            rounding,
            fg_stroke: Stroke::new(2.0_f32, colors::BLUE),
            expansion: 1.0_f32,
        },
        open: WidgetVisuals {
            bg_fill: colors::SURFACE1,
            weak_bg_fill: colors::SURFACE1,
            bg_stroke: Stroke::new(1.0_f32, colors::BLUE),
            rounding,
            fg_stroke: Stroke::new(1.0_f32, colors::TEXT),
            expansion: 0.0_f32,
        },
    };

    visuals.selection = Selection {
        bg_fill: Color32::from_rgba_premultiplied(0x89, 0xB4, 0xFA, 0x55),
        stroke: Stroke::new(1.0_f32, colors::BLUE),
    };

    visuals.window_shadow = Shadow {
        offset: egui::Vec2::new(0.0_f32, 8.0_f32),
        blur: 16.0_f32,
        spread: 0.0_f32,
        color: Color32::from_rgba_premultiplied(0x00, 0x00, 0x00, 0x88),
    };

    ctx.set_visuals(visuals);
}
