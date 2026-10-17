pub mod assembler;
pub mod debugger;
pub mod error;
pub mod event;
pub mod hooks;
pub mod pattern;
pub mod pointer_scanner;
pub mod scanner;
pub mod speedhack;
pub mod structure;
pub mod dwarf;
pub mod struct_diff;
pub mod symbols;
pub mod xrefs;

pub use assembler::{assemble_code, create_absolute_jump, create_relative_jump, AssemblerError, AssemblerResult};
pub use debugger::{
    BreakpointManager, BreakpointSummary, Dr7Register, HardwareBreakpoint, HitTracer,
    SoftwareBreakpoint,
};
pub use dwarf::{inspect_dwarf_struct, list_dwarf_structs, DwarfMember, DwarfStructLayout};
pub use error::{CoreError, CoreResult};
pub use event::EngineEvent;
pub use hooks::{build_detour_hook, calculate_stolen_bytes, HookError, HookPackage, HookResult};
pub use pattern::{generate_pattern_from_bytes, PatternError, PatternResult};
pub use pointer_scanner::{
    PointerEntry, PointerMap, PointerPath, PointerScanner, PointerScannerConfig,
};
pub use scanner::{
    parse_aob_pattern, FirstScanMode, MemoryScanner, NextScanMode, ScanConfig, ScanMatch,
    ScanResults, ScanValue, ScanValueType,
};
pub use speedhack::{SpeedHackScriptGenerator, TimeDilationState};
pub use struct_diff::{compute_struct_diff, DiffEntry};
pub use structure::{ClassStructure, FieldType, StructureError, StructureField, StructureResult};
pub use symbols::{
    inspect_module, lookup_symbols, ModuleMetadata, SectionSummary, SymbolInfo,
};
pub use xrefs::{find_xrefs_in_code, XRefEntry, XRefType};
