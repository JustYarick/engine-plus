pub mod cheat_table;
pub mod disasm;
pub mod hex_view;
pub mod process_picker;
pub mod scanner;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tab {
    Scanner,
    CheatTable,
    MemoryViewer,
    Disassembly,
    ProcessPicker,
    LogConsole,
}
