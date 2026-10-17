use engine_pal::{Address, BreakpointId, ProcessId, ProtectionFlags};
use serde::{Deserialize, Serialize};

/// High-level engine events for UI updates, notifications, and logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EngineEvent {
    ProcessAttached {
        pid: ProcessId,
        name: String,
    },
    ProcessDetached {
        pid: ProcessId,
    },
    ScanStarted {
        scan_id: u64,
        description: String,
    },
    ScanProgress {
        scan_id: u64,
        percent: f32,
    },
    ScanCompleted {
        scan_id: u64,
        results_count: usize,
    },
    BreakpointHit {
        bp_id: BreakpointId,
        address: Address,
        thread_id: u32,
    },
    MemoryWritten {
        address: Address,
        bytes_count: usize,
    },
    ProtectionChanged {
        address: Address,
        protection: ProtectionFlags,
    },
}
