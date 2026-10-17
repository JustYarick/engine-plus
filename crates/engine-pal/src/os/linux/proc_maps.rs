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

    Ok(regions)
}

/// Enumerate loaded modules and binaries by aggregating regions mapped to executable files
pub fn parse_process_modules(pid: ProcessId) -> PalResult<Vec<ModuleInfo>> {
    let regions = parse_process_maps(pid)?;
    let mut module_map: HashMap<String, (u64, usize)> = HashMap::new();

    for region in regions {
        if let Some(ref path) = region.path {
            if path.is_empty() || path.starts_with('[') {
                continue;
            }

            let entry = module_map
                .entry(path.clone())
                .or_insert((region.start.as_u64(), 0));
            // Track base address as lowest start address
            if region.start.as_u64() < entry.0 {
                entry.0 = region.start.as_u64();
            }
            // Aggregate size
            entry.1 += region.size;
        }
    }

    let mut modules = Vec::new();
    for (path, (base_address, size)) in module_map {
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());

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
}
