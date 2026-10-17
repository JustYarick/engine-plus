use crate::error::{CoreError, CoreResult};
use crate::scanner::mode::{FirstScanMode, NextScanMode, ScanConfig};
use crate::scanner::results::{ScanMatch, ScanResults};
use crate::scanner::value::{ScanValue, ScanValueType};
use engine_pal::{Address, MemoryRegion, ProcessAccessLayer};
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const CHUNK_SIZE: usize = 512 * 1024; // 512 KB chunks for reading large memory regions

/// High-performance multi-threaded memory scanner
pub struct MemoryScanner {
    history: Vec<ScanResults>,
    redo_stack: Vec<ScanResults>,
    active_config: Option<ScanConfig>,
}

impl MemoryScanner {
    pub fn new() -> Self {
        MemoryScanner {
            history: Vec::new(),
            redo_stack: Vec::new(),
            active_config: None,
        }
    }

    /// Current active scan results, if any
    pub fn current_results(&self) -> Option<&ScanResults> {
        self.history.last()
    }

    /// Check if undo is available
    pub fn can_undo(&self) -> bool {
        self.history.len() > 1
    }

    /// Check if redo is available
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Undo last scan step
    pub fn undo_scan(&mut self) -> Option<&ScanResults> {
        if self.history.len() > 1 {
            let popped = self.history.pop().unwrap();
            self.redo_stack.push(popped);
            self.history.last()
        } else {
            None
        }
    }

    /// Redo previously undone scan step
    pub fn redo_scan(&mut self) -> Option<&ScanResults> {
        if let Some(res) = self.redo_stack.pop() {
            self.history.push(res);
            self.history.last()
        } else {
            None
        }
    }

    /// Reset scanner state
    pub fn reset(&mut self) {
        self.history.clear();
        self.redo_stack.clear();
        self.active_config = None;
    }

    /// Execute first scan over target process memory
    pub fn first_scan<P: ProcessAccessLayer + ?Sized>(
        &mut self,
        pal: &P,
        config: &ScanConfig,
        mode: &FirstScanMode,
    ) -> CoreResult<usize> {
        let all_regions = pal.query_regions()?;
        let regions: Vec<MemoryRegion> = all_regions
            .into_iter()
            .filter(|r| {
                if !r.is_readable() {
                    return false;
                }
                if config.writable_only && !r.is_writable() {
                    return false;
                }
                if config.executable_only && !r.is_executable() {
                    return false;
                }
                true
            })
            .collect();

        let val_type = config.value_type;
        let alignment = config.alignment.max(1);
        let max_results = config.max_results;
        let total_found = AtomicUsize::new(0);

        // Parallel scan across filtered memory regions
        let matches: Vec<ScanMatch> = regions
            .par_iter()
            .flat_map(|region| {
                if let Some(max) = max_results {
                    if total_found.load(Ordering::Relaxed) >= max {
                        return Vec::new();
                    }
                }

                let mut local_matches = Vec::new();
                let region_size = region.size;
                let start_addr = region.start;

                let mut offset = 0;
                while offset < region_size {
                    let to_read = (region_size - offset).min(CHUNK_SIZE);
                    let chunk_addr = start_addr.add(offset);

                    if let Ok(bytes) = pal.read_raw(chunk_addr, to_read) {
                        scan_buffer_first(
                            &bytes,
                            chunk_addr,
                            val_type,
                            alignment,
                            mode,
                            &mut local_matches,
                        );
                    }

                    offset += to_read;
                }

                total_found.fetch_add(local_matches.len(), Ordering::Relaxed);
                local_matches
            })
            .collect();

        let count = matches.len();
        self.history.push(ScanResults::from_matches(matches));
        self.redo_stack.clear();
        self.active_config = Some(config.clone());

        Ok(count)
    }

    /// Filter existing results with next scan
    pub fn next_scan<P: ProcessAccessLayer + ?Sized>(
        &mut self,
        pal: &P,
        mode: &NextScanMode,
    ) -> CoreResult<usize> {
        let prev_results = self
            .current_results()
            .ok_or_else(|| CoreError::Scanner("No prior scan exists to filter".to_string()))?;

        let config = self
            .active_config
            .as_ref()
            .ok_or_else(|| CoreError::Scanner("Active scan configuration missing".to_string()))?;

        let val_type = config.value_type;
        let val_size = val_type.size_in_bytes().unwrap_or(4);

        // Parallel filter over previous matches
        let filtered: Vec<ScanMatch> = prev_results
            .matches
            .par_iter()
            .filter_map(|prev_match| {
                let addr = prev_match.address;
                let raw_bytes = pal.read_raw(addr, val_size).ok()?;
                let curr_val = ScanValue::read_from_slice(&raw_bytes, 0, val_type)?;

                let matched = match mode {
                    NextScanMode::Exact(target) => &curr_val == target,
                    NextScanMode::Between(min_val, max_val) => {
                        !curr_val.is_less_than(min_val) && !curr_val.is_greater_than(max_val)
                    }
                    NextScanMode::Changed => curr_val != prev_match.current_value,
                    NextScanMode::Unchanged => curr_val == prev_match.current_value,
                    NextScanMode::Increased => curr_val.is_greater_than(&prev_match.current_value),
                    NextScanMode::Decreased => curr_val.is_less_than(&prev_match.current_value),
                    NextScanMode::IncreasedBy(delta) => {
                        curr_val.is_increased_by(&prev_match.current_value, delta)
                    }
                    NextScanMode::DecreasedBy(delta) => {
                        curr_val.is_decreased_by(&prev_match.current_value, delta)
                    }
                };

                if matched {
                    Some(ScanMatch {
                        address: addr,
                        previous_value: Some(prev_match.current_value.clone()),
                        current_value: curr_val,
                    })
                } else {
                    None
                }
            })
            .collect();

        let count = filtered.len();
        self.history.push(ScanResults::from_matches(filtered));
        self.redo_stack.clear();

        Ok(count)
    }
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to scan a contiguous chunk buffer for first scan matches
fn scan_buffer_first(
    bytes: &[u8],
    base_address: Address,
    val_type: ScanValueType,
    alignment: usize,
    mode: &FirstScanMode,
    out: &mut Vec<ScanMatch>,
) {
    match mode {
        FirstScanMode::Exact(ScanValue::Aob(pattern)) => {
            let pat_len = pattern.len();
            if bytes.len() < pat_len {
                return;
            }

            for i in (0..=bytes.len() - pat_len).step_by(alignment) {
                let slice = &bytes[i..i + pat_len];
                let mut matches = true;

                for (idx, expected) in pattern.iter().enumerate() {
                    if let Some(expected_byte) = expected {
                        if slice[idx] != *expected_byte {
                            matches = false;
                            break;
                        }
                    }
                }

                if matches {
                    out.push(ScanMatch {
                        address: base_address.add(i),
                        current_value: ScanValue::Aob(pattern.clone()),
                        previous_value: None,
                    });
                }
            }
        }
        FirstScanMode::Exact(target) => {
            let val_size = val_type.size_in_bytes().unwrap_or(4);
            if bytes.len() < val_size {
                return;
            }

            for i in (0..=bytes.len() - val_size).step_by(alignment) {
                if let Some(val) = ScanValue::read_from_slice(bytes, i, val_type) {
                    if &val == target {
                        out.push(ScanMatch {
                            address: base_address.add(i),
                            current_value: val,
                            previous_value: None,
                        });
                    }
                }
            }
        }
        FirstScanMode::Between(min_val, max_val) => {
            let val_size = val_type.size_in_bytes().unwrap_or(4);
            if bytes.len() < val_size {
                return;
            }

            for i in (0..=bytes.len() - val_size).step_by(alignment) {
                if let Some(val) = ScanValue::read_from_slice(bytes, i, val_type) {
                    if !val.is_less_than(min_val) && !val.is_greater_than(max_val) {
                        out.push(ScanMatch {
                            address: base_address.add(i),
                            current_value: val,
                            previous_value: None,
                        });
                    }
                }
            }
        }
        FirstScanMode::UnknownInitial => {
            let val_size = val_type.size_in_bytes().unwrap_or(4);
            if bytes.len() < val_size {
                return;
            }

            for i in (0..=bytes.len() - val_size).step_by(alignment) {
                if let Some(val) = ScanValue::read_from_slice(bytes, i, val_type) {
                    out.push(ScanMatch {
                        address: base_address.add(i),
                        current_value: val,
                        previous_value: None,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::value::parse_aob_pattern;

    #[test]
    fn test_scan_buffer_exact_i32() {
        let mut buf = vec![0u8; 1024];
        // Write 100 (i32) at offset 0x40
        buf[0x40..0x44].copy_from_slice(&100i32.to_le_bytes());
        // Write 100 (i32) at offset 0x80
        buf[0x80..0x84].copy_from_slice(&100i32.to_le_bytes());

        let mut matches = Vec::new();
        scan_buffer_first(
            &buf,
            Address::new(0x1000),
            ScanValueType::I32,
            4,
            &FirstScanMode::Exact(ScanValue::I32(100)),
            &mut matches,
        );

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].address.as_u64(), 0x1040);
        assert_eq!(matches[1].address.as_u64(), 0x1080);
    }

    #[test]
    fn test_scan_buffer_aob_with_wildcards() {
        let mut buf = vec![0u8; 256];
        // Signature: 48 8B 05 [any 4 bytes] C3
        buf[0x20..0x27].copy_from_slice(&[0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xC3]);

        let pat = parse_aob_pattern("48 8B 05 ?? ?? ?? C3").unwrap();
        let mut matches = Vec::new();

        scan_buffer_first(
            &buf,
            Address::new(0x2000),
            ScanValueType::Aob,
            1,
            &FirstScanMode::Exact(ScanValue::Aob(pat)),
            &mut matches,
        );

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].address.as_u64(), 0x2020);
    }

    #[test]
    fn test_scanner_first_and_next_scan_on_self() {
        let mut pal = engine_pal::default_backend();
        pal.attach(std::process::id()).expect("Should attach to self");

        // Target integer variable on heap/stack
        let mut target_val: i32 = 424242;
        let target_addr = Address::new(&target_val as *const i32 as u64);

        let mut scanner = MemoryScanner::new();
        let config = ScanConfig::new(ScanValueType::I32).with_alignment(4);

        // 1. First scan for 424242
        let first_count = scanner
            .first_scan(&*pal, &config, &FirstScanMode::Exact(ScanValue::I32(424242)))
            .expect("First scan should succeed");
        assert!(first_count >= 1, "Must find at least our target_val");
        assert!(
            scanner
                .current_results()
                .unwrap()
                .matches
                .iter()
                .any(|m| m.address == target_addr),
            "Target address must be in results"
        );

        // 2. Change value
        target_val = std::hint::black_box(555555);
        assert_eq!(std::hint::black_box(target_val), 555555);

        // 3. Next scan for 555555
        let next_count = scanner
            .next_scan(&*pal, &NextScanMode::Exact(ScanValue::I32(555555)))
            .expect("Next scan should succeed");
        assert!(next_count >= 1);
        assert!(
            scanner
                .current_results()
                .unwrap()
                .matches
                .iter()
                .any(|m| m.address == target_addr),
            "Target address must survive next_scan"
        );

        // 4. Test Undo scan
        assert!(scanner.can_undo());
        let restored_results = scanner.undo_scan().expect("Undo should succeed");
        assert_eq!(restored_results.len(), first_count);

        // 5. Test Redo scan
        assert!(scanner.can_redo());
        let redone_results = scanner.redo_scan().expect("Redo should succeed");
        assert_eq!(redone_results.len(), next_count);
    }
}
