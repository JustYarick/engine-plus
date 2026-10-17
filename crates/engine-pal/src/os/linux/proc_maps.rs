use crate::error::{PalError, PalResult};
use crate::types::{Address, MemoryRegion, ModuleInfo, ProcessId, ProtectionFlags};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Parse memory regions from /proc/<pid>/maps
pub fn parse_process_maps(pid: ProcessId) -> PalResult<Vec<MemoryRegion>> {
    let path = format!("/proc/{pid}/maps");
    let file = File::open(&path).map_err(|e| PalError::RegionQueryFailed(pid, e.to_string()))?;
    let reader = BufReader::new(file);

    let mut regions = Vec::new();

    for line_result in reader.lines() {
        let line =
            line_result.map_err(|e| PalError::RegionQueryFailed(pid, e.to_string()))?;
        if let Some(region) = parse_maps_line(&line) {
            regions.push(region);
        }
    }

    // Associate contiguous anonymous uninitialized data (.bss) with the preceding module
    let mut current_module_path: Option<String> = None;
    let mut current_module_end: u64 = 0;

    for r in &mut regions {
        let is_real_file = r.path.as_ref().is_some_and(|p| !p.is_empty() && !p.starts_with('['));
        if is_real_file {
            current_module_path = r.path.clone();
            current_module_end = r.end.as_u64();
        } else if let Some(ref mod_path) = current_module_path {
            // Check if contiguous anonymous writable segment immediately follows
            let is_anon = r.path.as_ref().is_none_or(|p| p.is_empty());
            let is_rw = r.protection.contains(ProtectionFlags::WRITE)
                && !r.protection.contains(ProtectionFlags::EXECUTE);
            if is_anon && is_rw && r.start.as_u64() == current_module_end {
                r.path = Some(mod_path.clone());
                current_module_end = r.end.as_u64();
            } else {
                current_module_path = None;
            }
        }
    }

    Ok(regions)
}

/// Enumerate loaded modules and binaries by aggregating regions mapped to executable files
pub fn parse_process_modules(pid: ProcessId) -> PalResult<Vec<ModuleInfo>> {
    let regions = parse_process_maps(pid)?;
    let mut module_map: HashMap<String, (u64, u64)> = HashMap::new();

    for region in regions {
        if let Some(ref path) = region.path {
            if path.is_empty()
                || path.starts_with('[')
                || path.starts_with("/memfd:")
                || path.contains("memfd:")
            {
                continue;
            }

            let entry = module_map
                .entry(path.clone())
                .or_insert((region.start.as_u64(), region.end.as_u64()));
            // Track base address as lowest start address
            if region.start.as_u64() < entry.0 {
                entry.0 = region.start.as_u64();
            }
            // Track highest end address to encompass full virtual memory span (including BSS)
            if region.end.as_u64() > entry.1 {
                entry.1 = region.end.as_u64();
            }
        }
    }

    let mut modules = Vec::new();
    for (path, (base_address, highest_end)) in module_map {
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());

        let size = (highest_end.saturating_sub(base_address)) as usize;

        modules.push(ModuleInfo {
            name,
            path,
            base_address: Address::new(base_address),
            size,
        });
    }

    // Sort modules by base address ascending
    modules.sort_by_key(|m| m.base_address);

    Ok(modules)
}

/// Parse a single line from /proc/<pid>/maps
/// Example: `00400000-00452000 r-xp 00000000 08:02 173521  /usr/bin/dbus-daemon`
pub fn parse_maps_line(line: &str) -> Option<MemoryRegion> {
    let mut parts = line.split_whitespace();

    // 1. Address range: 00400000-00452000
    let range_str = parts.next()?;
    let mut range_parts = range_str.split('-');
    let start = u64::from_str_radix(range_parts.next()?, 16).ok()?;
    let end = u64::from_str_radix(range_parts.next()?, 16).ok()?;

    // 2. Permissions: r-xp
    let perms_str = parts.next()?;
    let mut protection = ProtectionFlags::NONE;
    let mut chars = perms_str.chars();

    if chars.next()? == 'r' {
        protection |= ProtectionFlags::READ;
    }
    if chars.next()? == 'w' {
        protection |= ProtectionFlags::WRITE;
    }
    if chars.next()? == 'x' {
        protection |= ProtectionFlags::EXECUTE;
    }
    match chars.next()? {
        's' => protection |= ProtectionFlags::SHARED,
        'p' => protection |= ProtectionFlags::PRIVATE,
        _ => {}
    }

    // 3. Offset (skip)
    let _ = parts.next()?;
    // 4. Dev (skip)
    let _ = parts.next()?;
    // 5. Inode (skip)
    let _ = parts.next()?;

    // 6. Path (optional, remaining line)
    let path = parts.next().map(|p| p.to_string());

    Some(MemoryRegion::new(start, end, protection, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_maps_line() {
        let line = "00400000-00452000 r-xp 00000000 08:02 173521  /usr/bin/game";
        let region = parse_maps_line(line).expect("Should parse maps line");

        assert_eq!(region.start.as_u64(), 0x00400000);
        assert_eq!(region.end.as_u64(), 0x00452000);
        assert_eq!(region.size, 0x52000);
        assert!(region.is_readable());
        assert!(!region.is_writable());
        assert!(region.is_executable());
        assert_eq!(region.path.as_deref(), Some("/usr/bin/game"));
        assert!(!region.is_anonymous);
    }

    #[test]
    fn test_parse_anonymous_maps_line() {
        let line = "7ffd98b7e000-7ffd98b9f000 rw-p 00000000 00:00 0          [stack]";
        let region = parse_maps_line(line).expect("Should parse maps line");

        assert!(region.is_readable());
        assert!(region.is_writable());
        assert!(!region.is_executable());
        assert_eq!(region.path.as_deref(), Some("[stack]"));
        assert!(region.is_anonymous);
    }

    #[test]
    fn test_parse_module_with_contiguous_bss() {
        let raw_lines = vec![
            "00400000-00406000 r--p 00000000 08:01 1234  /game/client",
            "00406000-00500000 r-xp 00006000 08:01 1234  /game/client",
            "00500000-00504000 rw-p 00100000 08:01 1234  /game/client",
            "00504000-00540000 rw-p 00000000 00:00 0", // contiguous BSS!
            "00540000-00541000 r-xp 00000000 00:00 0", // anonymous executable (not BSS)
            "07000000-08000000 rw-p 00000000 00:00 0    [heap]",
        ];

        let mut regions: Vec<MemoryRegion> = raw_lines
            .into_iter()
            .filter_map(parse_maps_line)
            .collect();

        let mut current_module_path: Option<String> = None;
        let mut current_module_end: u64 = 0;

        for r in &mut regions {
            let is_real_file = r.path.as_ref().is_some_and(|p| !p.is_empty() && !p.starts_with('['));
            if is_real_file {
                current_module_path = r.path.clone();
                current_module_end = r.end.as_u64();
            } else if let Some(ref mod_path) = current_module_path {
                let is_anon = r.path.as_ref().is_none_or(|p| p.is_empty());
                let is_rw = r.protection.contains(ProtectionFlags::WRITE)
                    && !r.protection.contains(ProtectionFlags::EXECUTE);
                if is_anon && is_rw && r.start.as_u64() == current_module_end {
                    r.path = Some(mod_path.clone());
                    current_module_end = r.end.as_u64();
                } else {
                    current_module_path = None;
                }
            }
        }

        // BSS region at 0x504000 should be associated with /game/client
        assert_eq!(regions[3].path.as_deref(), Some("/game/client"));
        // Anonymous r-xp should NOT be associated
        assert!(regions[4].path.is_none() || regions[4].path.as_deref() == Some(""));

        // Check module size
        let mut min_start = u64::MAX;
        let mut max_end = 0;
        for r in &regions {
            if r.path.as_deref() == Some("/game/client") {
                min_start = min_start.min(r.start.as_u64());
                max_end = max_end.max(r.end.as_u64());
            }
        }
        assert_eq!(min_start, 0x00400000);
        assert_eq!(max_end, 0x00540000);
        assert_eq!(max_end - min_start, 0x140000);
    }
}
