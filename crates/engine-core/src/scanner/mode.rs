use crate::scanner::value::{ScanValue, ScanValueType};
use serde::{Deserialize, Serialize};

/// Mode for the first memory scan
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FirstScanMode {
    /// Exact value match (e.g. 100)
    Exact(ScanValue),
    /// Value within range [min, max]
    Between(ScanValue, ScanValue),
    /// Store a full memory snapshot of all values
    UnknownInitial,
}

/// Mode for subsequent filtering scans
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NextScanMode {
    /// Exact value match
    Exact(ScanValue),
    /// Value within range [min, max]
    Between(ScanValue, ScanValue),
    /// Value has changed since last scan
    Changed,
    /// Value has not changed since last scan
    Unchanged,
    /// Value has increased since last scan
    Increased,
    /// Value has decreased since last scan
    Decreased,
    /// Value increased by an exact delta
    IncreasedBy(ScanValue),
    /// Value decreased by an exact delta
    DecreasedBy(ScanValue),
}

/// Configuration options for memory scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Target data type
    pub value_type: ScanValueType,
    /// Byte alignment in memory (1, 2, 4, 8)
    pub alignment: usize,
    /// Only scan writable memory pages
    pub writable_only: bool,
    /// Only scan executable memory pages (useful for finding code / instructions)
    pub executable_only: bool,
    /// Skip small pages or special buffers (fast scan)
    pub fast_scan: bool,
    /// Pause target process during scan to prevent race conditions
    pub pause_process: bool,
    /// Optional limit on maximum matches to collect
    pub max_results: Option<usize>,
}

impl ScanConfig {
    pub fn new(value_type: ScanValueType) -> Self {
        ScanConfig {
            value_type,
            alignment: value_type.default_alignment(),
            writable_only: true,
            executable_only: false,
            fast_scan: false,
            pause_process: false,
            max_results: None,
        }
    }

    pub fn with_alignment(mut self, alignment: usize) -> Self {
        self.alignment = alignment;
        self
    }

    pub fn with_writable_only(mut self, writable_only: bool) -> Self {
        self.writable_only = writable_only;
        self
    }
}
