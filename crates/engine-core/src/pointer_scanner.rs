use crate::error::{CoreError, CoreResult};
use engine_pal::{Address, CpuArchitecture, MemoryReader, MemoryRegion, ModuleInfo, ProcessAccessLayer};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// An entry in the pointer map: a memory address `source` holding a pointer pointing to `target`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PointerEntry {
    pub target: Address,
    pub source: Address,
}

/// In-memory graph snapshot of all pointer-sized values for high-speed multi-level traversal
pub struct PointerMap {
    /// Pointers sorted by `target` address for logarithmic range queries
    pub entries: Vec<PointerEntry>,
    pub pointer_size: usize,
}

impl PointerMap {
    pub fn new(entries: Vec<PointerEntry>, pointer_size: usize) -> Self {
        let mut sorted_entries = entries;
        sorted_entries.sort_unstable();
        PointerMap {
            entries: sorted_entries,
            pointer_size,
        }
    }

    /// Build a pointer map by scanning memory regions.
    /// When `writable_only` is true (default for pointer scanning), only readable+writable
    /// regions (heap, .data, .bss) are scanned, filtering out code (.text) and constants (.rodata).
    pub fn build_from_memory(
        pal: &dyn ProcessAccessLayer,
        regions: &[MemoryRegion],
        pointer_size: usize,
        alignment: usize,
        writable_only: bool,
    ) -> CoreResult<Self> {
        let align = alignment.max(1);
        let mut entries = Vec::new();

        // Build quick lookup for valid target ranges (any readable memory)
        let valid_ranges: Vec<(u64, u64)> = regions
            .iter()
            .filter(|r| r.is_readable())
            .map(|r| (r.start.as_u64(), r.end.as_u64()))
            .collect();

        // Pointers to dynamic/heap data can only exist in writable memory
        let regions_to_scan = regions
            .iter()
            .filter(|r| r.is_readable() && (!writable_only || r.is_writable()));

        for r in regions_to_scan {
            // Read in blocks up to 512KB
            let chunk_size = 512 * 1024;
            let mut offset = 0;

            while offset < r.size {
                let current_size = (r.size - offset).min(chunk_size);
                let current_addr = r.start.add(offset);

                if let Ok(bytes) = pal.read_raw(current_addr, current_size) {
                    let mut i = 0;
                    while i + pointer_size <= bytes.len() {
                        let target_val = if pointer_size == 4 {
                            u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap_or([0; 4])) as u64
                        } else {
                            u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap_or([0; 8]))
                        };

                        // Check if pointer target falls into any valid readable region
                        if target_val != 0 {
                            let is_valid = valid_ranges
                                .iter()
                                .any(|&(start, end)| target_val >= start && target_val < end);

                            if is_valid {
                                entries.push(PointerEntry {
                                    source: current_addr.add(i),
                                    target: Address::new(target_val),
                                });
                            }
                        }

                        i += align;
                    }
                }

                offset += current_size;
            }
        }

        Ok(PointerMap::new(entries, pointer_size))
    }

    /// Find all pointers whose target falls within `[min_target, max_target]`
    pub fn find_pointers_in_range(
        &self,
        min_target: Address,
        max_target: Address,
    ) -> &[PointerEntry] {
        if self.entries.is_empty() || min_target > max_target {
            return &[];
        }

        let start_idx = self
            .entries
            .partition_point(|e| e.target < min_target);
        let end_idx = self
            .entries
            .partition_point(|e| e.target <= max_target);

        if start_idx < end_idx {
            &self.entries[start_idx..end_idx]
        } else {
            &[]
        }
    }

    pub fn total_pointers(&self) -> usize {
        self.entries.len()
    }
}

/// A complete pointer chain from a static base module to a target address
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerPath {
    pub module_name: String,
    pub base_offset: u64,
    pub offsets: Vec<i64>,
}

impl std::fmt::Display for PointerPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}+0x{:X}", self.module_name, self.base_offset)?;
        for offset in &self.offsets {
            if *offset >= 0 {
                write!(f, " -> +0x{:X}", offset)?;
            } else {
                write!(f, " -> -0x{:X}", offset.abs())?;
            }
        }
        Ok(())
    }
}

impl PointerPath {
    /// Resolve this pointer path at runtime in the target process
    pub fn resolve(
        &self,
        pal: &dyn ProcessAccessLayer,
        module_base: Address,
        arch: CpuArchitecture,
    ) -> CoreResult<Address> {
        let base_ptr_addr = module_base.add(self.base_offset as usize);
        let mut current_addr = pal
            .read_pointer(base_ptr_addr, arch)
            .map_err(|e| CoreError::Debugger(format!("Failed to read base pointer at {base_ptr_addr}: {e}")))?;

        for (idx, &offset) in self.offsets.iter().enumerate() {
            if current_addr.is_null() {
                return Err(CoreError::Debugger(format!(
                    "Pointer path broke at level {idx}: current address is NULL"
                )));
            }

            let next_ptr_addr = current_addr.offset(offset);
            if idx == self.offsets.len() - 1 {
                // Last offset directly points to target value
                return Ok(next_ptr_addr);
            }

            current_addr = pal.read_pointer(next_ptr_addr, arch).map_err(|e| {
                CoreError::Debugger(format!("Failed to read pointer at {next_ptr_addr}: {e}"))
            })?;
        }

        Ok(current_addr)
    }
}

/// Configuration settings for multi-level pointer scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerScannerConfig {
    /// Maximum pointer depth (levels of indirection: typically 1..=5)
    pub max_depth: usize,
    /// Maximum offset between pointer value and target (e.g. 4096 bytes)
    pub max_offset: usize,
    /// Maximum number of paths to collect
    pub max_results: usize,
    /// Only scan writable memory regions (default: true)
    #[serde(default = "default_writable_only")]
    pub writable_only: bool,
}

fn default_writable_only() -> bool {
    true
}

impl Default for PointerScannerConfig {
    fn default() -> Self {
        PointerScannerConfig {
            max_depth: 3,
            max_offset: 4096,
            max_results: 50,
            writable_only: true,
        }
    }
}

/// Helper to rank modules for pointer scanning:
/// 0 = Main executable binary (first module in list)
/// 1 = Game / application modules (not in system or driver path)
/// 2 = System / driver libraries (nvidia, mesa, glcore, gpucomp, vulkan, drm, libc, etc.)
pub fn module_rank(module_name: &str, is_first: bool) -> u8 {
    let lower = module_name.to_lowercase();

    let is_driver_or_system = lower.contains("nvidia")
        || lower.contains("glcore")
        || lower.contains("gpucomp")
        || lower.contains("mesa")
        || lower.contains("vulkan")
        || lower.contains("drm")
        || lower.contains("memfd")
        || lower.contains(".gl")
        || lower.contains("(deleted)")
        || lower.contains("libc.")
        || lower.contains("libc-")
        || lower.contains("libm.")
        || lower.contains("libpthread")
        || lower.contains("libdl")
        || lower.contains("ld-linux")
        || lower.contains("libstdc++")
        || lower.contains("system32")
        || lower.contains("syswow64");

    if is_driver_or_system {
        2
    } else if is_first {
        0
    } else {
        1
    }
}

/// High-performance multi-level pointer scanner
pub struct PointerScanner;

impl PointerScanner {
    /// Perform backward graph search from `target_address` to find static module-relative paths.
    /// Uses iterative deepening to guarantee shortest, direct static chains appear first.
    pub fn scan(
        map: &PointerMap,
        modules: &[ModuleInfo],
        target_address: Address,
        config: &PointerScannerConfig,
    ) -> Vec<PointerPath> {
        let mut results = Vec::new();
        let mut seen_paths = HashSet::new();

        let module_ranges: Vec<(&ModuleInfo, u64, u64, u8)> = modules
            .iter()
            .enumerate()
            .map(|(idx, m)| {
                let rank = module_rank(&m.name, idx == 0);
                (m, m.base_address.as_u64(), m.base_address.as_u64() + m.size as u64, rank)
            })
            .collect();

        // Iterative deepening: search depth 1 first, then 2, ..., up to max_depth
        for depth_limit in 1..=config.max_depth {
            if results.len() >= config.max_results {
                break;
            }

            let mut current_offsets = Vec::new();
            let mut visited = HashSet::new();
            Self::search_backward(
                map,
                &module_ranges,
                target_address,
                0,
                depth_limit,
                config.max_offset,
                config.max_results,
                &mut current_offsets,
                &mut visited,
                &mut seen_paths,
                &mut results,
            );
        }

        // Sort results:
        // 1. Shortest chains first (e.g. 1 offset before 2 offsets before 3 offsets)
        // 2. Main binary / game modules before system/driver libraries
        // 3. Lowest base offset
        // 4. Alphabetical module name
        results.sort_by(|a, b| {
            a.offsets
                .len()
                .cmp(&b.offsets.len())
                .then_with(|| {
                    let a_first = modules.first().is_some_and(|m| m.name == a.module_name);
                    let b_first = modules.first().is_some_and(|m| m.name == b.module_name);
                    let rank_a = module_rank(&a.module_name, a_first);
                    let rank_b = module_rank(&b.module_name, b_first);
                    rank_a.cmp(&rank_b)
                })
                .then_with(|| a.base_offset.cmp(&b.base_offset))
                .then_with(|| a.module_name.cmp(&b.module_name))
        });

        results
    }

    #[allow(clippy::too_many_arguments)]
    fn search_backward(
        map: &PointerMap,
        modules: &[(&ModuleInfo, u64, u64, u8)],
        current_target: Address,
        current_depth: usize,
        depth_limit: usize,
        max_offset: usize,
        max_results: usize,
        current_offsets: &mut Vec<i64>,
        visited: &mut HashSet<Address>,
        seen_paths: &mut HashSet<String>,
        results: &mut Vec<PointerPath>,
    ) {
        if results.len() >= max_results || current_depth >= depth_limit {
            return;
        }

        let min_target = current_target.sub(max_offset);
        let max_target = current_target;

        let mut candidates: Vec<&PointerEntry> = map
            .find_pointers_in_range(min_target, max_target)
            .iter()
            .collect();

        // Partition candidates so static module pointers are checked FIRST,
        // with higher-priority modules (main binary) prioritized over driver/system libraries
        candidates.sort_by_key(|entry| {
            let src = entry.source.as_u64();
            let rank = modules
                .iter()
                .find(|(_, start, end, _)| src >= *start && src < *end)
                .map(|(_, _, _, r)| *r)
                .unwrap_or(255);
            rank
        });

        for entry in candidates {
            if results.len() >= max_results {
                return;
            }

            let delta = current_target.as_u64().saturating_sub(entry.target.as_u64()) as i64;

            // Check if source address belongs to any static module
            let source_u64 = entry.source.as_u64();
            let static_module = modules
                .iter()
                .find(|(_, start, end, _)| source_u64 >= *start && source_u64 < *end);

            if let Some((module, start, _, _)) = static_module {
                let mut path_offsets = current_offsets.clone();
                path_offsets.push(delta);
                path_offsets.reverse();

                let path_key = format!("{}+{:#x}:{:?}", module.name, source_u64 - start, path_offsets);
                if seen_paths.insert(path_key) {
                    results.push(PointerPath {
                        module_name: module.name.clone(),
                        base_offset: source_u64 - start,
                        offsets: path_offsets,
                    });

                    if results.len() >= max_results {
                        return;
                    }
                }

                // A static module variable is a root; do not search deeper from this address
                continue;
            }

            // Continue searching one level deeper if not visited on this branch
            if current_depth + 1 < depth_limit && visited.insert(entry.source) {
                current_offsets.push(delta);
                Self::search_backward(
                    map,
                    modules,
                    entry.source,
                    current_depth + 1,
                    depth_limit,
                    max_offset,
                    max_results,
                    current_offsets,
                    visited,
                    seen_paths,
                    results,
                );
                current_offsets.pop();
                visited.remove(&entry.source);
            }
        }
    }

    /// Filter a set of previously discovered pointer paths against a new target address
    pub fn filter_paths(
        paths: &[PointerPath],
        pal: &dyn ProcessAccessLayer,
        modules: &[ModuleInfo],
        new_target: Address,
        arch: CpuArchitecture,
    ) -> Vec<PointerPath> {
        let module_map: HashMap<&str, Address> = modules
            .iter()
            .map(|m| (m.name.as_str(), m.base_address))
            .collect();

        paths
            .iter()
            .filter(|path| {
                if let Some(&base) = module_map.get(path.module_name.as_str()) {
                    if let Ok(resolved) = path.resolve(pal, base, arch) {
                        return resolved == new_target;
                    }
                }
                false
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPal {
        memory: HashMap<u64, u64>,
    }

    impl MockPal {
        fn new() -> Self {
            MockPal {
                memory: HashMap::new(),
            }
        }

        fn set_ptr(&mut self, addr: u64, target: u64) {
            self.memory.insert(addr, target);
        }
    }

    impl ProcessAccessLayer for MockPal {
        fn attach(&mut self, _pid: engine_pal::ProcessId) -> Result<(), engine_pal::PalError> { Ok(()) }
        fn detach(&mut self) -> Result<(), engine_pal::PalError> { Ok(()) }
        fn is_attached(&self) -> bool { true }
        fn attached_pid(&self) -> Option<engine_pal::ProcessId> { Some(100) }
        fn architecture(&self) -> CpuArchitecture { CpuArchitecture::X86_64 }
        fn read_raw(&self, address: Address, size: usize) -> Result<Vec<u8>, engine_pal::PalError> {
            let mut bytes = Vec::new();
            for i in 0..size {
                let base_word = address.as_u64() + (i / 8 * 8) as u64;
                let word = self.memory.get(&base_word).copied().unwrap_or(0);
                let byte = (word >> ((i % 8) * 8)) as u8;
                bytes.push(byte);
            }
            Ok(bytes)
        }
        fn write_raw(&self, _address: Address, _data: &[u8]) -> Result<(), engine_pal::PalError> { Ok(()) }
        fn query_regions(&self) -> Result<Vec<MemoryRegion>, engine_pal::PalError> { Ok(Vec::new()) }
        fn enumerate_modules(&self) -> Result<Vec<ModuleInfo>, engine_pal::PalError> { Ok(Vec::new()) }
        fn enumerate_threads(&self) -> Result<Vec<engine_pal::ThreadInfo>, engine_pal::PalError> { Ok(Vec::new()) }
        fn set_breakpoint(&mut self, _addr: Address, _bp: engine_pal::BreakpointType) -> Result<engine_pal::BreakpointId, engine_pal::PalError> { Ok(engine_pal::BreakpointId(1)) }
        fn remove_breakpoint(&mut self, _id: engine_pal::BreakpointId) -> Result<(), engine_pal::PalError> { Ok(()) }
        fn allocate_memory(&self, _size: usize, _protection: engine_pal::ProtectionFlags) -> Result<Address, engine_pal::PalError> { Ok(Address::new(0)) }
        fn free_memory(&self, _address: Address) -> Result<(), engine_pal::PalError> { Ok(()) }
        fn stealth_level(&self) -> engine_pal::StealthLevel { engine_pal::StealthLevel::None }
        fn backend_name(&self) -> &'static str { "MockPal" }
    }

    #[test]
    fn test_pointer_map_range_search() {
        let entries = vec![
            PointerEntry { source: Address::new(0x1000), target: Address::new(0x5000) },
            PointerEntry { source: Address::new(0x1008), target: Address::new(0x5020) },
            PointerEntry { source: Address::new(0x1010), target: Address::new(0x5040) },
            PointerEntry { source: Address::new(0x1018), target: Address::new(0x6000) },
        ];

        let map = PointerMap::new(entries, 8);
        let in_range = map.find_pointers_in_range(Address::new(0x5010), Address::new(0x5050));
        assert_eq!(in_range.len(), 2);
        assert_eq!(in_range[0].target.as_u64(), 0x5020);
        assert_eq!(in_range[1].target.as_u64(), 0x5040);
    }

    #[test]
    fn test_multi_level_pointer_scan_and_resolve() {
        // Module: ac_client.exe [0x400000..0x500000]
        // Static base: ac_client.exe + 0x1000 = 0x401000
        // Pointer chain:
        // [0x401000] -> points to 0x10000
        // (add offset 0x20) -> 0x10020
        // [0x10020] -> points to 0x20000
        // (add offset 0xF8) -> 0x200F8 (Health target address)
        let entries = vec![
            PointerEntry { source: Address::new(0x401000), target: Address::new(0x10000) },
            PointerEntry { source: Address::new(0x10020), target: Address::new(0x20000) },
        ];

        let map = PointerMap::new(entries, 8);

        let modules = vec![ModuleInfo {
            name: "ac_client.exe".to_string(),
            path: "/path/to/ac_client.exe".to_string(),
            base_address: Address::new(0x400000),
            size: 0x100000,
        }];

        let target = Address::new(0x200F8);
        let config = PointerScannerConfig {
            max_depth: 3,
            max_offset: 1024,
            max_results: 10,
            writable_only: true,
        };

        let paths = PointerScanner::scan(&map, &modules, target, &config);
        assert_eq!(paths.len(), 1);

        let path = &paths[0];
        assert_eq!(path.module_name, "ac_client.exe");
        assert_eq!(path.base_offset, 0x1000);
        assert_eq!(path.offsets, vec![0x20, 0xF8]);
        assert_eq!(format!("{path}"), "ac_client.exe+0x1000 -> +0x20 -> +0xF8");

        // Now test runtime resolution of this path
        let mut pal = MockPal::new();
        pal.set_ptr(0x401000, 0x10000);
        pal.set_ptr(0x10020, 0x20000);

        let resolved = path.resolve(&pal, Address::new(0x400000), CpuArchitecture::X86_64).unwrap();
        assert_eq!(resolved.as_u64(), 0x200F8);
    }

    #[test]
    fn test_shortest_static_chain_priority() {
        // Test that a direct 1-level static chain is prioritized over a deep multi-level chain
        // Static module: 0x400000..0x500000
        // Target: 0x286A780
        // Chain A (Direct 1-level): [ac_client + 0x1A3518] points to 0x286A680 (+ 0x100 -> 0x286A780)
        // Chain B (Deep 3-level): [ac_client + 0x500] -> [0x7FFF00] -> [0x7FFF50] -> 0x286A780
        let entries = vec![
            // Chain B entries
            PointerEntry { source: Address::new(0x400500), target: Address::new(0x7FFF00) },
            PointerEntry { source: Address::new(0x7FFF00), target: Address::new(0x7FFF50) },
            PointerEntry { source: Address::new(0x7FFF50), target: Address::new(0x286A780) },
            // Chain A entry (Direct static)
            PointerEntry { source: Address::new(0x400000 + 0x1A3518), target: Address::new(0x286A680) },
        ];

        let map = PointerMap::new(entries, 8);
        let modules = vec![ModuleInfo {
            name: "linux_64_client".to_string(),
            path: "/path/to/linux_64_client".to_string(),
            base_address: Address::new(0x400000),
            size: 0x200000,
        }];

        let target = Address::new(0x286A780);
        let config = PointerScannerConfig {
            max_depth: 3,
            max_offset: 1024,
            max_results: 10,
            writable_only: true,
        };

        let paths = PointerScanner::scan(&map, &modules, target, &config);
        assert!(!paths.is_empty(), "Should find at least 1 path");
        // Result #0 MUST be the direct 1-level static chain!
        assert_eq!(paths[0].offsets.len(), 1, "Shortest chain must come first");
        assert_eq!(paths[0].base_offset, 0x1A3518);
        assert_eq!(paths[0].offsets, vec![0x100]);
    }

    #[test]
    fn test_driver_deprioritization() {
        // Test that if both main binary and driver module (e.g. nvidia) have chains of equal depth,
        // main binary is prioritized over the driver library
        let entries = vec![
            // Driver chain: libnvidia-gpucomp.so + 0x100 -> +0x20
            PointerEntry { source: Address::new(0x7F000000 + 0x100), target: Address::new(0x286A760) },
            // Main binary chain: linux_64_client + 0x200 -> +0x20
            PointerEntry { source: Address::new(0x400000 + 0x200), target: Address::new(0x286A760) },
        ];

        let map = PointerMap::new(entries, 8);
        let modules = vec![
            ModuleInfo {
                name: "linux_64_client".to_string(),
                path: "/game/linux_64_client".to_string(),
                base_address: Address::new(0x400000),
                size: 0x200000,
            },
            ModuleInfo {
                name: "libnvidia-gpucomp.so".to_string(),
                path: "/usr/lib64/libnvidia-gpucomp.so".to_string(),
                base_address: Address::new(0x7F000000),
                size: 0x1000000,
            },
        ];

        let target = Address::new(0x286A780);
        let config = PointerScannerConfig {
            max_depth: 2,
            max_offset: 1024,
            max_results: 10,
            writable_only: true,
        };

        let paths = PointerScanner::scan(&map, &modules, target, &config);
        assert_eq!(paths.len(), 2);
        // linux_64_client must be first, despite having a larger base offset (0x200 > 0x100)
        assert_eq!(paths[0].module_name, "linux_64_client");
        assert_eq!(paths[1].module_name, "libnvidia-gpucomp.so");
    }
}

