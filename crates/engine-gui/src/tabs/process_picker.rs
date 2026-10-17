use crate::app::EngineApp;
use crate::theme::colors;
use egui::{Align, Layout, RichText, Ui};
use egui_extras::{Column, TableBuilder};

pub fn render_process_picker_tab(app: &mut EngineApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label("🔍 Filter:");
        ui.text_edit_singleline(&mut app.process_filter);

        if ui.button("🔄 Refresh List").clicked() {
            app.refresh_process_list();
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(format!("Processes: {}", app.cached_processes.len())).color(colors::SUBTEXT0));
        });
    });

    ui.separator();

    let filter_lower = app.process_filter.to_lowercase();
    let filtered_indices: Vec<usize> = app
        .cached_processes
        .iter()
        .enumerate()
        .filter(|(_, p)| {
            if filter_lower.is_empty() {
                true
            } else {
                p.name.to_lowercase().contains(&filter_lower)
                    || format!("{}", p.pid).contains(&filter_lower)
                    || p.cmdline
                        .as_ref()
                        .map_or(false, |c| c.to_lowercase().contains(&filter_lower))
            }
        })
        .map(|(i, _)| i)
        .collect();

    let count = filtered_indices.len();
    let mut attach_to_pid = None;

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::initial(80.0).at_least(60.0)) // PID
        .column(Column::initial(220.0).at_least(150.0)) // Name
        .column(Column::initial(90.0).at_least(70.0)) // Architecture
        .column(Column::remainder()) // Actions / Cmdline
        .header(22.0, |mut header| {
            header.col(|ui| {
                ui.strong("PID");
            });
            header.col(|ui| {
                ui.strong("Process Name");
            });
            header.col(|ui| {
                ui.strong("Arch");
            });
            header.col(|ui| {
                ui.strong("Action / Command");
            });
        })
        .body(|body| {
            body.rows(22.0, count, |mut row| {
                let list_idx = filtered_indices[row.index()];
                let proc = &app.cached_processes[list_idx];
                let is_current = app
                    .attached_process
                    .as_ref()
                    .map_or(false, |p| p.pid == proc.pid);

                row.col(|ui| {
                    ui.label(RichText::new(format!("{}", proc.pid)).monospace());
                });

                row.col(|ui| {
                    let label = if is_current {
                        ui.colored_label(colors::GREEN, format!("● {}", proc.name))
                    } else {
                        ui.label(&proc.name)
                    };

                    if label.double_clicked() {
                        attach_to_pid = Some(proc.pid);
                    }
                });

                row.col(|ui| {
                    ui.label(format!("{:?}", proc.architecture));
                });

                row.col(|ui| {
                    if is_current {
                        ui.colored_label(colors::GREEN, "Attached");
                    } else if ui.button("Attach").clicked() {
                        attach_to_pid = Some(proc.pid);
                    }

                    if let Some(ref cmd) = proc.cmdline {
                        ui.add_space(8.0);
                        ui.label(RichText::new(cmd).color(colors::SUBTEXT0).italics());
                    }
                });
            });
        });

    if let Some(pid) = attach_to_pid {
        app.attach_process_by_pid(pid);
    }
}
