use crate::app::EngineApp;
use crate::theme::colors;
use egui::{Align, Layout, RichText, Ui};
use egui_extras::{Column, TableBuilder};
use engine_core::ScanValueType;

pub fn render_cheat_table_tab(app: &mut EngineApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        if ui.button("➕ Add Address Manually").clicked() {
            app.add_manual_cheat_entry();
        }

        if !app.cheat_entries.is_empty() && ui.button("🗑️ Clear Table").clicked() {
            app.cheat_entries.clear();
        }

        let total = app.cheat_entries.len();
        let active = app.cheat_entries.iter().filter(|e| e.active).count();
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(format!("Total: {total} | Active (Frozen): {active}")).color(colors::SUBTEXT0));
        });
    });

    ui.separator();

    if app.cheat_entries.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(30.0);
            ui.label(RichText::new("Cheat Table is empty.").color(colors::SUBTEXT0));
            ui.label("Add addresses from the Scanner results or click 'Add Address Manually'.");
        });
        return;
    }

    let mut to_remove = None;

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::initial(60.0).at_least(50.0)) // Active / Freeze
        .column(Column::initial(180.0).at_least(100.0)) // Description
        .column(Column::initial(150.0).at_least(120.0)) // Address
        .column(Column::initial(90.0).at_least(70.0)) // Type
        .column(Column::initial(140.0).at_least(100.0)) // Value
        .column(Column::remainder()) // Actions
        .header(22.0, |mut header| {
            header.col(|ui| {
                ui.strong("Freeze");
            });
            header.col(|ui| {
                ui.strong("Description");
            });
            header.col(|ui| {
                ui.strong("Address");
            });
            header.col(|ui| {
                ui.strong("Type");
            });
            header.col(|ui| {
                ui.strong("Value");
            });
            header.col(|ui| {
                ui.strong("Actions");
            });
        })
        .body(|body| {
            let entries_len = app.cheat_entries.len();
            body.rows(22.0, entries_len, |mut row| {
                let idx = row.index();
                let entry = &mut app.cheat_entries[idx];

                // 1. Active / Freeze
                row.col(|ui| {
                    if ui.checkbox(&mut entry.active, "").changed() {
                        if entry.active {
                            // If just activated freeze, record current value as freeze target
                            entry.freeze_val = entry.current_val.clone();
                        }
                    }
                });

                // 2. Description
                row.col(|ui| {
                    ui.text_edit_singleline(&mut entry.description);
                });

                // 3. Address
                row.col(|ui| {
                    ui.label(RichText::new(format!("0x{:016X}", entry.address.as_u64())).monospace());
                });

                // 4. Type
                row.col(|ui| {
                    egui::ComboBox::from_id_salt(format!("entry_type_{}", entry.id))
                        .selected_text(format!("{:?}", entry.val_type))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut entry.val_type, ScanValueType::I32, "i32");
                            ui.selectable_value(&mut entry.val_type, ScanValueType::U32, "u32");
                            ui.selectable_value(&mut entry.val_type, ScanValueType::F32, "f32");
                            ui.selectable_value(&mut entry.val_type, ScanValueType::F64, "f64");
                            ui.selectable_value(&mut entry.val_type, ScanValueType::I64, "i64");
                            ui.selectable_value(&mut entry.val_type, ScanValueType::U64, "u64");
                            ui.selectable_value(&mut entry.val_type, ScanValueType::I16, "i16");
                            ui.selectable_value(&mut entry.val_type, ScanValueType::I8, "i8");
                        });
                });

                // 5. Value
                row.col(|ui| {
                    let mut val_text = entry.current_val.clone();
                    let response = ui.add(
                        egui::TextEdit::singleline(&mut val_text)
                            .desired_width(100.0)
                            .font(egui::TextStyle::Monospace),
                    );

                    if response.lost_focus() && val_text != entry.current_val {
                        entry.current_val = val_text.clone();
                        entry.freeze_val = val_text.clone();
                        entry.pending_write = true;
                    }

                    if entry.active {
                        ui.colored_label(colors::BLUE, "❄️");
                    }
                });

                // 6. Actions
                row.col(|ui| {
                    if ui.button("❌").on_hover_text("Delete address").clicked() {
                        to_remove = Some(idx);
                    }
                });
            });
        });

    if let Some(idx) = to_remove {
        app.cheat_entries.remove(idx);
    }
}
