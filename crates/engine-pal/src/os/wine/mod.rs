pub mod pe;

pub use pe::{parse_pe_headers, PeHeaderInfo, PeParseError, PeSectionInfo};

use crate::types::{Address, MemoryRegion, ProcessEntry};
use std::path::{Path, PathBuf};

/// Check if a process is running under Proton or Wine on Linux
pub fn is_wine_process(entry: &ProcessEntry) -> bool {
    let name_lower = entry.name.to_lowercase();

    // Check process name
    if name_lower.contains("wine")
        || name_lower.contains("wineserver")
        || name_lower.ends_with(".exe")
    {
        return true;
    }

    // Check command line
    if let Some(cmd) = &entry.cmdline {
        let cmd_lower = cmd.to_lowercase();
        if cmd_lower.contains("wine")
            || cmd_lower.contains("proton")
            || cmd_lower.contains("steamapps/compatdata")
            || cmd_lower.ends_with(".exe")
        {
            return true;
        }
    }

    false
}

/// Find Proton/Wine prefix directory for a process if available
pub fn find_proton_prefix(entry: &ProcessEntry) -> Option<PathBuf> {
    if let Some(cmd) = &entry.cmdline {
        // Look for STEAM_COMPAT_DATA_PATH or WINEPREFIX pattern in cmdline
        for part in cmd.split_whitespace() {
            if part.contains("compatdata/") {
                if let Some(idx) = part.find("compatdata/") {
                    let sub = &part[idx..];
                    let segments: Vec<&str> = sub.split('/').collect();
                    if segments.len() >= 2 {
                        let p = PathBuf::from(&part[..idx])
                            .join(segments[0])
                            .join(segments[1])
                            .join("pfx");
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

/// Convert Windows DOS path (e.g. `C:\Program Files\Game\game.exe`) to Linux path inside Wine prefix
pub fn map_wine_dos_path(dos_path: &str, wine_prefix: &Path) -> Option<PathBuf> {
    let normalized = dos_path.replace('\\', "/");
    let trimmed = normalized.trim();

    if let Some(stripped) = trimmed.strip_prefix("C:/").or_else(|| trimmed.strip_prefix("c:/")) {
        Some(wine_prefix.join("drive_c").join(stripped))
    } else if let Some(stripped) = trimmed.strip_prefix("Z:/").or_else(|| trimmed.strip_prefix("z:/")) {
        // Z: is typically mapped to root "/" on Linux Wine
        Some(PathBuf::from("/").join(stripped))
    } else {
        None
    }
}

/// Helper to locate the main Windows executable or DLL base address from memory regions
pub fn find_wine_module_base(regions: &[MemoryRegion], module_name: &str) -> Option<Address> {
    let mod_lower = module_name.to_lowercase();

    for r in regions {
        if let Some(path) = &r.path {
            let p_lower = path.to_lowercase();
            if p_lower.ends_with(&mod_lower) {
                return Some(r.start);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CpuArchitecture;

    #[test]
    fn test_is_wine_process() {
        let wine_entry = ProcessEntry {
            pid: 1234,
            name: "Cyberpunk2077.exe".to_string(),
            cmdline: Some("C:\\Games\\Cyberpunk2077.exe".to_string()),
            architecture: CpuArchitecture::X86_64,
        };
        assert!(is_wine_process(&wine_entry));

        let native_entry = ProcessEntry {
            pid: 5678,
            name: "bash".to_string(),
            cmdline: Some("/bin/bash".to_string()),
            architecture: CpuArchitecture::X86_64,
        };
        assert!(!is_wine_process(&native_entry));
    }

    #[test]
    fn test_map_wine_dos_path() {
        let prefix = Path::new("/home/user/.steam/steam/steamapps/compatdata/1091500/pfx");
        let dos = r"C:\Games\Cyberpunk2077\bin\x64\Cyberpunk2077.exe";
        let mapped = map_wine_dos_path(dos, prefix).expect("Should map DOS path");
        assert_eq!(
            mapped,
            PathBuf::from("/home/user/.steam/steam/steamapps/compatdata/1091500/pfx/drive_c/Games/Cyberpunk2077/bin/x64/Cyberpunk2077.exe")
        );
    }
}
