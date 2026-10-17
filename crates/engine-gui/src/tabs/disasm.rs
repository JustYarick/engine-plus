use crate::app::EngineApp;
use crate::theme::colors;
use egui::{RichText, Ui};

pub fn render_disasm_tab(app: &mut EngineApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label("Address:");
        let response = ui.add(
            egui::TextEdit::singleline(&mut app.disasm_address_input)
                .hint_text("0x7FF...")
                .desired_width(160.0)
                .font(egui::TextStyle::Monospace),
        );

        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            app.refresh_disassembly();
        }

        if ui.button("Disassemble").clicked() {
            app.refresh_disassembly();
        }

        ui.label("Arch:");
        egui::ComboBox::from_id_salt("disasm_bitness")
            .selected_text(format!("x{}-bit", app.disasm_bitness))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut app.disasm_bitness, 64, "x64 (64-bit)");
                ui.selectable_value(&mut app.disasm_bitness, 32, "x86 (32-bit)");
            });
    });

    ui.separator();

    if !app.pal.is_attached() {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label(RichText::new("Attach to a process to disassemble memory.").color(colors::SUBTEXT0));
        });
        return;
    }

    if app.disasm_lines.is_empty() {
        ui.label(RichText::new("No instructions disassembled. Enter an address above.").color(colors::SUBTEXT0));
        return;
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        for (addr_str, instr_str) in &app.disasm_lines {
            ui.horizontal(|ui| {
                ui.label(RichText::new(addr_str).monospace().color(colors::BLUE));
                ui.label(RichText::new(instr_str).monospace().color(colors::TEXT));
            });
        }
    });
}
