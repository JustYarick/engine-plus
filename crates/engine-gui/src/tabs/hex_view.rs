use crate::app::EngineApp;
use crate::theme::colors;
use egui::{RichText, Ui};

pub fn render_hex_view_tab(app: &mut EngineApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label("Address:");
        let response = ui.add(
            egui::TextEdit::singleline(&mut app.hex_address_input)
                .hint_text("0x7FF...")
                .desired_width(160.0)
                .font(egui::TextStyle::Monospace),
        );

        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            app.refresh_hex_view();
        }

        if ui.button("Go").clicked() {
            app.refresh_hex_view();
        }

        if ui.button("⟵ Prev (256B)").clicked() {
            app.hex_navigate(-256);
        }

        if ui.button("Next (256B) ⟶").clicked() {
            app.hex_navigate(256);
        }
    });

    ui.separator();

    if !app.pal.is_attached() {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label(RichText::new("Attach to a process to inspect virtual memory.").color(colors::SUBTEXT0));
        });
        return;
    }

    if app.hex_bytes.is_empty() {
        ui.label(RichText::new("No memory data loaded for this address.").color(colors::SUBTEXT0));
        return;
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.horizontal(|ui| {
            // Hex view header
            ui.label(RichText::new(" Offset            00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII").monospace().color(colors::SUBTEXT0));
        });

        ui.separator();

        let base_addr = app.hex_view_base_address;
        for (line_idx, chunk) in app.hex_bytes.chunks(16).enumerate() {
            let row_addr = base_addr.wrapping_add((line_idx * 16) as u64);

            let mut hex_part = String::with_capacity(50);
            let mut ascii_part = String::with_capacity(16);

            for (byte_idx, &b) in chunk.iter().enumerate() {
                if byte_idx == 8 {
                    hex_part.push(' ');
                }
                hex_part.push_str(&format!("{:02X} ", b));

                if b.is_ascii_graphic() || b == b' ' {
                    ascii_part.push(b as char);
                } else {
                    ascii_part.push('.');
                }
            }

            // Pad remainder if chunk < 16
            while hex_part.len() < 49 {
                hex_part.push(' ');
            }

            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("0x{:016X} ", row_addr)).monospace().color(colors::BLUE));
                ui.label(RichText::new(hex_part).monospace().color(colors::TEXT));
                ui.label(RichText::new(ascii_part).monospace().color(colors::GREEN));
            });
        }
    });
}
