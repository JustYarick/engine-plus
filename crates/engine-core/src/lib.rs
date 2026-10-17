pub mod assembler;
pub mod error;
pub mod event;
pub mod hooks;
pub mod pattern;
pub mod scanner;
pub mod xrefs;

pub use assembler::{assemble_code, create_absolute_jump, create_relative_jump, AssemblerError, AssemblerResult};
pub use error::{CoreError, CoreResult};
pub use event::EngineEvent;
pub use hooks::{build_detour_hook, calculate_stolen_bytes, HookError, HookPackage, HookResult};
pub use pattern::{generate_pattern_from_bytes, PatternError, PatternResult};
pub use scanner::{
    parse_aob_pattern, FirstScanMode, MemoryScanner, NextScanMode, ScanConfig, ScanMatch,
    ScanResults, ScanValue, ScanValueType,
};
pub use xrefs::{find_xrefs_in_code, XRefEntry, XRefType};
