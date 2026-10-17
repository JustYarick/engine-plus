use crate::tabs::{
    cheat_table::render_cheat_table_tab, disasm::render_disasm_tab, hex_view::render_hex_view_tab,
    process_picker::render_process_picker_tab, scanner::render_scanner_tab, Tab,
};
use crate::theme::{apply_catppuccin_mocha, colors};
use egui::{RichText, Ui, WidgetText};
use egui_dock::{DockArea, DockState, NodeIndex, TabViewer};
use engine_core::{
    FirstScanMode, MemoryScanner, NextScanMode, ScanConfig, ScanValue, ScanValueType,
};
use engine_pal::{
    default_backend, default_enumerator, Address, ProcessAccessLayer, ProcessEntry,
    ProcessId,
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CheatEntry {
    pub id: u64,
    pub active: bool,
    pub description: String,
    pub address: Address,
    pub val_type: ScanValueType,
    pub current_val: String,
    pub freeze_val: String,
    pub pending_write: bool,
}

pub struct EngineApp {
    pub pal: Box<dyn ProcessAccessLayer>,
    pub scanner: MemoryScanner,
    pub attached_process: Option<ProcessEntry>,
    pub cached_processes: Vec<ProcessEntry>,
    pub process_filter: String,

    // Scanner state
    pub scan_value_input: String,
    pub scan_type: ScanValueType,
    pub scan_mode_str: String,
    pub alignment: usize,
    pub scan_status: String,
    pub selected_scan_address: Option<Address>,

    // Cheat table state
    pub cheat_entries: Vec<CheatEntry>,
    pub cheat_counter: u64,

    // Hex view state
    pub hex_address_input: String,
    pub hex_view_base_address: u64,
    pub hex_bytes: Vec<u8>,

    // Disasm state
    pub disasm_address_input: String,
    pub disasm_bitness: u32,
    pub disasm_lines: Vec<(String, String)>,

    // Logs
    pub log_lines: Vec<String>,

    // Docking layout
    pub dock_state: DockState<Tab>,

    // Ticks
    pub last_tick: Instant,
}

impl EngineApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_catppuccin_mocha(&cc.egui_ctx);

        let mut dock_state = DockState::new(vec![Tab::Scanner]);
        let surface = dock_state.main_surface_mut();

        // Split main surface: bottom for CheatTable, Processes, Logs
        let [top, _bottom] = surface.split_below(
            NodeIndex::root(),
            0.62,
            vec![Tab::CheatTable, Tab::ProcessPicker, Tab::LogConsole],
        );

        // Split top area: right side for MemoryViewer and Disassembly
        let _ = surface.split_right(top, 0.55, vec![Tab::MemoryViewer, Tab::Disassembly]);

        let mut app = EngineApp {
            pal: default_backend(),
            scanner: MemoryScanner::new(),
            attached_process: None,
            cached_processes: Vec::new(),
            process_filter: String::new(),

            scan_value_input: "100".to_string(),
            scan_type: ScanValueType::I32,
            scan_mode_str: "Exact Value".to_string(),
            alignment: 4,
            scan_status: "Ready".to_string(),
            selected_scan_address: None,

            cheat_entries: Vec::new(),
            cheat_counter: 0,

            hex_address_input: "0x00400000".to_string(),
            hex_view_base_address: 0x00400000,
            hex_bytes: Vec::new(),

            disasm_address_input: "0x00400000".to_string(),
            disasm_bitness: 64,
            disasm_lines: Vec::new(),

            log_lines: vec!["Welcome to Engine+ v0.1.0 (Cheat Engine & Reverse Engineering IDE)".to_string()],

            dock_state,
            last_tick: Instant::now(),
        };

        app.refresh_process_list();
        app
    }

    pub fn log_message(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        tracing::info!("{msg}");
        self.log_lines.push(msg);
        if self.log_lines.len() > 200 {
            self.log_lines.remove(0);
        }
    }

    pub fn refresh_process_list(&mut self) {
        let enumerator = default_enumerator();
        match enumerator.list_processes() {
            Ok(procs) => {
                self.cached_processes = procs;
                self.log_message(format!("Refreshed processes list ({} found)", self.cached_processes.len()));
            }
            Err(e) => {
                self.log_message(format!("Failed to list processes: {e}"));
            }
        }
    }

    pub fn attach_process_by_pid(&mut self, pid: ProcessId) {
        if let Err(e) = self.pal.attach(pid) {
            self.log_message(format!("Attach to PID {pid} failed: {e}"));
            return;
        }

        if let Some(proc) = self.cached_processes.iter().find(|p| p.pid == pid).cloned() {
            self.attached_process = Some(proc.clone());
            self.log_message(format!("Successfully attached to '{}' (PID: {})", proc.name, pid));
        } else {
            self.attached_process = Some(ProcessEntry {
                pid,
                name: format!("Process {pid}"),
                cmdline: None,
                architecture: engine_pal::CpuArchitecture::X86_64,
            });
            self.log_message(format!("Attached to process {pid}"));
        }

        self.reset_scan();
    }

    pub fn detach_process(&mut self) {
        if let Err(e) = self.pal.detach() {
            self.log_message(format!("Detach failed: {e}"));
        } else {
            self.log_message("Detached from process");
        }
        self.attached_process = None;
        self.reset_scan();
        self.hex_bytes.clear();
        self.disasm_lines.clear();
    }

    pub fn show_process_picker(&mut self) {
        self.refresh_process_list();
        // Focus or switch tab if needed
    }

    pub fn perform_first_scan(&mut self) {
        if !self.pal.is_attached() {
            self.scan_status = "Error: Not attached to any process".to_string();
            return;
        }

        let parsed_val = match ScanValue::parse(&self.scan_value_input, self.scan_type) {
            Ok(v) => v,
            Err(e) => {
                self.scan_status = format!("Invalid value: {e}");
                return;
            }
        };

        let mut config = ScanConfig::new(self.scan_type);
        config.alignment = self.alignment;

        let start = Instant::now();
        match self.scanner.first_scan(&*self.pal, &config, &FirstScanMode::Exact(parsed_val)) {
            Ok(count) => {
                let ms = start.elapsed().as_millis();
                self.scan_status = format!("Found: {count} addresses in {ms} ms");
                self.log_message(format!("First scan: {count} results in {ms} ms"));
            }
            Err(e) => {
                self.scan_status = format!("Scan error: {e}");
                self.log_message(format!("First scan failed: {e}"));
            }
        }
    }

    pub fn perform_next_scan(&mut self) {
        if !self.pal.is_attached() {
            self.scan_status = "Error: Not attached to any process".to_string();
            return;
        }

        let next_mode = match self.scan_mode_str.as_str() {
            "Exact Value" => {
                let parsed_val = match ScanValue::parse(&self.scan_value_input, self.scan_type) {
                    Ok(v) => v,
                    Err(e) => {
                        self.scan_status = format!("Invalid value: {e}");
                        return;
                    }
                };
                NextScanMode::Exact(parsed_val)
            }
            "Increased" => NextScanMode::Increased,
            "Decreased" => NextScanMode::Decreased,
            "Changed" => NextScanMode::Changed,
            "Unchanged" => NextScanMode::Unchanged,
            _ => NextScanMode::Changed,
        };

        let start = Instant::now();
        match self.scanner.next_scan(&*self.pal, &next_mode) {
            Ok(count) => {
                let ms = start.elapsed().as_millis();
                self.scan_status = format!("Filtered: {count} addresses in {ms} ms");
                self.log_message(format!("Next scan: {count} results left in {ms} ms"));
            }
            Err(e) => {
                self.scan_status = format!("Next scan error: {e}");
                self.log_message(format!("Next scan failed: {e}"));
            }
        }
    }

    pub fn reset_scan(&mut self) {
        self.scanner.reset();
        self.scan_status = "Scan reset".to_string();
    }

    pub fn add_to_cheat_table(&mut self, addr: Address, val_type: ScanValueType, initial_val: &str) {
        self.cheat_counter += 1;
        self.cheat_entries.push(CheatEntry {
            id: self.cheat_counter,
            active: false,
            description: format!("Address 0x{:X}", addr.as_u64()),
            address: addr,
            val_type,
            current_val: initial_val.to_string(),
            freeze_val: initial_val.to_string(),
            pending_write: false,
        });
        self.log_message(format!("Added 0x{:X} to Cheat Table", addr.as_u64()));
    }

    pub fn add_manual_cheat_entry(&mut self) {
        self.cheat_counter += 1;
        self.cheat_entries.push(CheatEntry {
            id: self.cheat_counter,
            active: false,
            description: format!("New Entry {}", self.cheat_counter),
            address: Address::new(0x00400000),
            val_type: ScanValueType::I32,
            current_val: "0".to_string(),
            freeze_val: "0".to_string(),
            pending_write: false,
        });
    }

    pub fn update_cheat_table(&mut self) {
        if !self.pal.is_attached() {
            return;
        }

        for entry in &mut self.cheat_entries {
            // If user edited value or freeze is active, write to memory
            if entry.pending_write || entry.active {
                let val_str = if entry.active {
                    &entry.freeze_val
                } else {
                    &entry.current_val
                };

                if let Ok(bytes) = encode_value_bytes(val_str, entry.val_type) {
                    let _ = self.pal.write_raw(entry.address, &bytes);
                }
                entry.pending_write = false;
            }

            // Read live value from memory if not frozen
            if !entry.active {
                let size = entry.val_type.size_in_bytes().unwrap_or(4).max(1);
                if let Ok(bytes) = self.pal.read_raw(entry.address, size) {
                    entry.current_val = decode_value_bytes(&bytes, entry.val_type);
                }
            }
        }
    }

    pub fn refresh_hex_view(&mut self) {
        if !self.pal.is_attached() {
            return;
        }

        let addr_u64 = parse_hex_or_dec(&self.hex_address_input).unwrap_or(0x00400000);
        self.hex_view_base_address = addr_u64;

        match self.pal.read_raw(Address::new(addr_u64), 256) {
            Ok(bytes) => {
                self.hex_bytes = bytes;
            }
            Err(e) => {
                self.log_message(format!("Failed to read memory at 0x{:X}: {e}", addr_u64));
                self.hex_bytes.clear();
            }
        }
    }

    pub fn hex_navigate(&mut self, delta: i64) {
        let new_base = if delta >= 0 {
            self.hex_view_base_address.saturating_add(delta as u64)
        } else {
            self.hex_view_base_address.saturating_sub((-delta) as u64)
        };
        self.hex_address_input = format!("0x{:X}", new_base);
        self.refresh_hex_view();
    }

    pub fn open_in_hex_view(&mut self, addr: Address) {
        self.hex_address_input = format!("0x{:X}", addr.as_u64());
        self.refresh_hex_view();
    }

    pub fn refresh_disassembly(&mut self) {
        if !self.pal.is_attached() {
            return;
        }

        let addr_u64 = parse_hex_or_dec(&self.disasm_address_input).unwrap_or(0x00400000);
        let read_size = 64;

        match self.pal.read_raw(Address::new(addr_u64), read_size) {
            Ok(bytes) => {
                use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

                let mut decoder = Decoder::with_ip(self.disasm_bitness, &bytes, addr_u64, DecoderOptions::NONE);
                let mut formatter = IntelFormatter::new();
                let mut lines = Vec::new();
                let mut instruction = Instruction::default();

                while decoder.can_decode() {
                    decoder.decode_out(&mut instruction);
                    let mut instr_str = String::new();
                    formatter.format(&instruction, &mut instr_str);
                    lines.push((format!("0x{:016X}", instruction.ip()), instr_str));
                }

                self.disasm_lines = lines;
            }
            Err(e) => {
                self.log_message(format!("Failed to read code for disassembly: {e}"));
                self.disasm_lines.clear();
            }
        }
    }

    pub fn open_in_disasm(&mut self, addr: Address) {
        self.disasm_address_input = format!("0x{:X}", addr.as_u64());
        self.refresh_disassembly();
    }
}

impl eframe::App for EngineApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Periodic cheat table freeze write and live value read (100ms)
        if self.last_tick.elapsed() >= Duration::from_millis(100) {
            self.update_cheat_table();
            self.last_tick = Instant::now();
        }

        // Top Menu Bar
        egui::TopBottomPanel::top("top_menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("🎯 Attach Process...").clicked() {
                        self.show_process_picker();
                        ui.close_menu();
                    }
                    if ui.button("❌ Detach Process").clicked() {
                        self.detach_process();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("View", |ui| {
                    if ui.button("Reset Layout").clicked() {
                        let mut dock = DockState::new(vec![Tab::Scanner]);
                        let surface = dock.main_surface_mut();
                        let [top, _bottom] = surface.split_below(
                            NodeIndex::root(),
                            0.62,
                            vec![Tab::CheatTable, Tab::ProcessPicker, Tab::LogConsole],
                        );
                        let _ = surface.split_right(top, 0.55, vec![Tab::MemoryViewer, Tab::Disassembly]);
                        self.dock_state = dock;
                        ui.close_menu();
                    }
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("About Engine+").clicked() {
                        self.log_message("Engine+ v0.1.0 — Modern Cheat Engine & Reverse Engineering IDE in Rust");
                        ui.close_menu();
                    }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(ref p) = self.attached_process {
                        ui.colored_label(colors::GREEN, format!("● [{}] {}", p.pid, p.name));
                    } else {
                        ui.colored_label(colors::SUBTEXT0, "○ Disconnected");
                    }
                });
            });
        });

        // Main DockArea
        let mut dock_state = std::mem::replace(&mut self.dock_state, DockState::new(vec![]));
        DockArea::new(&mut dock_state)
            .style(egui_dock::Style::from_egui(ctx.style().as_ref()))
            .show(ctx, &mut AppTabViewer { app: self });
        self.dock_state = dock_state;

        // Request repaint periodically if attached to ensure responsive live values
        if self.attached_process.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

struct AppTabViewer<'a> {
    app: &'a mut EngineApp,
}

impl TabViewer for AppTabViewer<'_> {
    type Tab = Tab;

    fn title(&mut self, tab: &mut Self::Tab) -> WidgetText {
        match tab {
            Tab::Scanner => "🔍 Memory Scanner".into(),
            Tab::CheatTable => "📋 Cheat Table".into(),
            Tab::MemoryViewer => "🔢 Memory View (Hex)".into(),
            Tab::Disassembly => "⚙️ Disassembly".into(),
            Tab::ProcessPicker => "🎯 Process Selector".into(),
            Tab::LogConsole => "📜 Logs & Events".into(),
        }
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut Self::Tab) {
        match tab {
            Tab::Scanner => render_scanner_tab(self.app, ui),
            Tab::CheatTable => render_cheat_table_tab(self.app, ui),
            Tab::MemoryViewer => render_hex_view_tab(self.app, ui),
            Tab::Disassembly => render_disasm_tab(self.app, ui),
            Tab::ProcessPicker => render_process_picker_tab(self.app, ui),
            Tab::LogConsole => {
                ui.horizontal(|ui| {
                    if ui.button("Clear Logs").clicked() {
                        self.app.log_lines.clear();
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                    for line in &self.app.log_lines {
                        ui.label(RichText::new(line).monospace().color(colors::SUBTEXT0));
                    }
                });
            }
        }
    }
}

fn parse_hex_or_dec(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex_part) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex_part, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn encode_value_bytes(val_str: &str, val_type: ScanValueType) -> Result<Vec<u8>, ()> {
    match val_type {
        ScanValueType::I8 => val_str.parse::<i8>().map(|v| vec![v as u8]).map_err(|_| ()),
        ScanValueType::U8 => val_str.parse::<u8>().map(|v| vec![v]).map_err(|_| ()),
        ScanValueType::I16 => val_str.parse::<i16>().map(|v| v.to_le_bytes().to_vec()).map_err(|_| ()),
        ScanValueType::U16 => val_str.parse::<u16>().map(|v| v.to_le_bytes().to_vec()).map_err(|_| ()),
        ScanValueType::I32 => val_str.parse::<i32>().map(|v| v.to_le_bytes().to_vec()).map_err(|_| ()),
        ScanValueType::U32 => val_str.parse::<u32>().map(|v| v.to_le_bytes().to_vec()).map_err(|_| ()),
        ScanValueType::I64 => val_str.parse::<i64>().map(|v| v.to_le_bytes().to_vec()).map_err(|_| ()),
        ScanValueType::U64 => val_str.parse::<u64>().map(|v| v.to_le_bytes().to_vec()).map_err(|_| ()),
        ScanValueType::F32 => val_str.parse::<f32>().map(|v| v.to_le_bytes().to_vec()).map_err(|_| ()),
        ScanValueType::F64 => val_str.parse::<f64>().map(|v| v.to_le_bytes().to_vec()).map_err(|_| ()),
        _ => Err(()),
    }
}

fn decode_value_bytes(bytes: &[u8], val_type: ScanValueType) -> String {
    match val_type {
        ScanValueType::I8 if !bytes.is_empty() => format!("{}", bytes[0] as i8),
        ScanValueType::U8 if !bytes.is_empty() => format!("{}", bytes[0]),
        ScanValueType::I16 if bytes.len() >= 2 => format!("{}", i16::from_le_bytes(bytes[..2].try_into().unwrap())),
        ScanValueType::U16 if bytes.len() >= 2 => format!("{}", u16::from_le_bytes(bytes[..2].try_into().unwrap())),
        ScanValueType::I32 if bytes.len() >= 4 => format!("{}", i32::from_le_bytes(bytes[..4].try_into().unwrap())),
        ScanValueType::U32 if bytes.len() >= 4 => format!("{}", u32::from_le_bytes(bytes[..4].try_into().unwrap())),
        ScanValueType::I64 if bytes.len() >= 8 => format!("{}", i64::from_le_bytes(bytes[..8].try_into().unwrap())),
        ScanValueType::U64 if bytes.len() >= 8 => format!("{}", u64::from_le_bytes(bytes[..8].try_into().unwrap())),
        ScanValueType::F32 if bytes.len() >= 4 => format!("{:.2}", f32::from_le_bytes(bytes[..4].try_into().unwrap())),
        ScanValueType::F64 if bytes.len() >= 8 => format!("{:.4}", f64::from_le_bytes(bytes[..8].try_into().unwrap())),
        _ => bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
    }
}
