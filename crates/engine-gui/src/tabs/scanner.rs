use crate::app::EngineApp;
use crate::theme::colors;
use egui::{Align, Layout, RichText, Ui};
use egui_extras::{Column, TableBuilder};
use engine_core::ScanValueType;

pub fn render_scanner_tab(app: &mut EngineApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        if let Some(ref proc) = app.attached_process {
            ui.colored_label(
                colors::GREEN,
                format!("● Attached: {} (PID: {}) [{:?}]", proc.name, proc.pid, proc.architecture),
            );
            if ui.button("Detach").clicked() {
                app.detach_process();
            }
        } else {
            ui.colored_label(colors::RED, "○ No process attached");
            if ui.button("🎯 Select Process").clicked() {
                app.show_process_picker();
            }
        }
    });

    ui.separator();

    // Scan controls
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label("Value:");
            let value_response = ui.add(
                egui::TextEdit::singleline(&mut app.scan_value_input)
                    .hint_text("e.g. 100 or 48 8B 05 ??")
                    .desired_width(180.0),
            );

            // Pressing Enter in the value box triggers scan
            if value_response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                if app.scanner.current_results().is_some() {
                    app.perform_next_scan();
                } else {
                    app.perform_first_scan();
                }
            }

            ui.label("Type:");
            egui::ComboBox::from_id_salt("scan_val_type")
                .selected_text(format!("{:?}", app.scan_type))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut app.scan_type, ScanValueType::I32, "i32 (4 bytes)");
                    ui.selectable_value(&mut app.scan_type, ScanValueType::U32, "u32 (4 bytes)");
                    ui.selectable_value(&mut app.scan_type, ScanValueType::I64, "i64 (8 bytes)");
                    ui.selectable_value(&mut app.scan_type, ScanValueType::U64, "u64 (8 bytes)");
                    ui.selectable_value(&mut app.scan_type, ScanValueType::F32, "f32 (Float)");
                    ui.selectable_value(&mut app.scan_type, ScanValueType::F64, "f64 (Double)");
                    ui.selectable_value(&mut app.scan_type, ScanValueType::I16, "i16 (2 bytes)");
                    ui.selectable_value(&mut app.scan_type, ScanValueType::I8, "i8 (1 byte)");
                    ui.selectable_value(&mut app.scan_type, ScanValueType::Aob, "AOB (Hex pattern)");
                    ui.selectable_value(&mut app.scan_type, ScanValueType::StringUtf8, "String (UTF-8)");
                });

            ui.label("Scan Type:");
            egui::ComboBox::from_id_salt("scan_mode")
                .selected_text(&app.scan_mode_str)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut app.scan_mode_str, "Exact Value".to_string(), "Exact Value");
                    ui.selectable_value(&mut app.scan_mode_str, "Increased".to_string(), "Increased");
                    ui.selectable_value(&mut app.scan_mode_str, "Decreased".to_string(), "Decreased");
                    ui.selectable_value(&mut app.scan_mode_str, "Changed".to_string(), "Changed");
                    ui.selectable_value(&mut app.scan_mode_str, "Unchanged".to_string(), "Unchanged");
                });

            ui.label("Align:");
            egui::ComboBox::from_id_salt("scan_alignment")
                .selected_text(format!("{} bytes", app.alignment))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut app.alignment, 1, "1 byte (slow)");
                    ui.selectable_value(&mut app.alignment, 2, "2 bytes");
                    ui.selectable_value(&mut app.alignment, 4, "4 bytes (default)");
                    ui.selectable_value(&mut app.alignment, 8, "8 bytes (fast)");
                });
        });

        ui.add_space(4.0);

        ui.horizontal(|ui| {
            let is_attached = app.pal.is_attached();

            let first_scan_btn = ui.add_enabled(
                is_attached && !app.scan_value_input.is_empty(),
                egui::Button::new(RichText::new("🚀 First Scan").color(colors::CRUST).strong())
                    .fill(colors::BLUE),
            );
            if first_scan_btn.clicked() {
                app.perform_first_scan();
            }

            let has_results = app.scanner.current_results().is_some();
            let next_scan_btn = ui.add_enabled(
                is_attached && has_results,
                egui::Button::new(RichText::new("⚡ Next Scan").color(colors::CRUST).strong())
                    .fill(colors::GREEN),
            );
            if next_scan_btn.clicked() {
                app.perform_next_scan();
            }

            if ui.add_enabled(has_results, egui::Button::new("New Scan")).clicked() {
                app.reset_scan();
            }

            if ui.add_enabled(app.scanner.can_undo(), egui::Button::new("↶ Undo")).clicked() {
                app.scanner.undo_scan();
                app.log_message("Scan undone");
            }

            if ui.add_enabled(app.scanner.can_redo(), egui::Button::new("↷ Redo")).clicked() {
                app.scanner.redo_scan();
                app.log_message("Scan redone");
            }

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new(&app.scan_status).color(colors::SUBTEXT0));
            });
        });
    });

    ui.add_space(4.0);

    // Results virtual table
    let results_count = app
        .scanner
        .current_results()
        .map(|r| r.len())
        .unwrap_or(0);

    ui.horizontal(|ui| {
        ui.strong(format!("Found Addresses: {results_count}"));
        if results_count > 0 {
            ui.label("(Double-click row to add to Cheat Table)");
        }
    });

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::initial(50.0).at_least(40.0))
        .column(Column::initial(160.0).at_least(140.0))
        .column(Column::remainder())
        .header(22.0, |mut header| {
            header.col(|ui| {
                ui.strong("#");
            });
            header.col(|ui| {
                ui.strong("Address");
            });
            header.col(|ui| {
                ui.strong("Current Value");
            });
        })
        .body(|body| {
            body.rows(20.0, results_count, |mut row| {
                let index = row.index();
                if let Some(results) = app.scanner.current_results() {
                    let page = results.page(index, 1);
                    if let Some(entry) = page.first() {
                        let addr = entry.address;
                        let val_str = format!("{}", entry.current_value);

                        row.col(|ui| {
                            ui.label(format!("{}", index + 1));
                        });

                        row.col(|ui| {
                            let addr_label = ui.selectable_label(
                                app.selected_scan_address == Some(addr),
                                format!("0x{:016X}", addr.as_u64()),
                            );

                            if addr_label.clicked() {
                                app.selected_scan_address = Some(addr);
                            }

                            if addr_label.double_clicked() {
                                app.add_to_cheat_table(addr, app.scan_type, &val_str);
                            }

                            addr_label.context_menu(|ui| {
                                if ui.button("Add to Cheat Table").clicked() {
                                    app.add_to_cheat_table(addr, app.scan_type, &val_str);
                                    ui.close_menu();
                                }
                                if ui.button("Copy Address").clicked() {
                                    ui.output_mut(|o| o.copied_text = format!("0x{:X}", addr.as_u64()));
                                    ui.close_menu();
                                }
                                if ui.button("View in Hex Memory").clicked() {
                                    app.open_in_hex_view(addr);
                                    ui.close_menu();
                                }
                                if ui.button("Disassemble Address").clicked() {
                                    app.open_in_disasm(addr);
                                    ui.close_menu();
                                }
                            });
                        });

                        row.col(|ui| {
                            ui.colored_label(colors::YELLOW, val_str);
                        });
                    }
                }
            });
        });
}
