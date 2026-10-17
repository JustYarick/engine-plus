use crate::scanner::value::ScanValue;
use engine_pal::Address;
use serde::{Deserialize, Serialize};

/// A single matched memory address with its current and previous values
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanMatch {
    pub address: Address,
    pub current_value: ScanValue,
    pub previous_value: Option<ScanValue>,
}

/// Collection of scan results with pagination support for UI rendering
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScanResults {
    pub matches: Vec<ScanMatch>,
}

impl ScanResults {
    pub fn new() -> Self {
        ScanResults {
            matches: Vec::new(),
        }
    }

    pub fn from_matches(matches: Vec<ScanMatch>) -> Self {
        ScanResults { matches }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.matches.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    /// Get a paginated view of results for virtual table scrolling in the GUI
    pub fn page(&self, offset: usize, limit: usize) -> &[ScanMatch] {
        if offset >= self.matches.len() {
            return &[];
        }
        let end = (offset + limit).min(self.matches.len());
        &self.matches[offset..end]
    }
}
