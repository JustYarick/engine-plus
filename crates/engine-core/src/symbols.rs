use crate::error::{CoreError, CoreResult};
use engine_pal::Address;
use object::read::elf::FileHeader;
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub address: Address,
    pub file_address: u64,
    pub size: u64,
    pub kind: String,
    pub binding: String,
    pub section: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionSummary {
    pub name: String,
    pub address: Address,
    pub size: u64,
    pub is_executable: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMetadata {
    pub name: String,
    pub path: String,
    pub base_address: Address,
    pub size: u64,
    pub is_pie: bool,
    pub entry_point: Address,
    pub sections: Vec<SectionSummary>,
}

/// Inspect binary file on disk (ELF or PE) and extract module details, sections, and PIE flag
pub fn inspect_module(
    file_path: &Path,
    runtime_base: Option<Address>,
) -> CoreResult<ModuleMetadata> {
    let bytes = fs::read(file_path).map_err(|e| {
        CoreError::Analysis(format!("Failed to read binary file '{file_path:?}': {e}"))
    })?;

    let file = object::File::parse(bytes.as_slice()).map_err(|e| {
        CoreError::Analysis(format!("Failed to parse binary '{file_path:?}': {e}"))
    })?;

    let is_pie = check_is_pie(&file);
    let base = runtime_base.unwrap_or(Address::NULL);

    let mut sections = Vec::new();
    for sec in file.sections() {
        let sec_name = sec.name().unwrap_or("").to_string();
        if sec_name.is_empty() {
            continue;
        }

        let sec_addr = if is_pie {
            base.add(sec.address() as usize)
        } else {
            Address::new(sec.address())
        };

        let is_executable = sec.kind() == SectionKind::Text;
        let is_writable = matches!(sec.kind(), SectionKind::Data | SectionKind::UninitializedData);

        sections.push(SectionSummary {
            name: sec_name,
            address: sec_addr,
            size: sec.size(),
            is_executable,
            is_writable,
        });
    }

    let file_name = file_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let entry_addr = if is_pie {
        base.add(file.entry() as usize)
    } else {
        Address::new(file.entry())
    };

    Ok(ModuleMetadata {
        name: file_name,
        path: file_path.to_string_lossy().to_string(),
        base_address: base,
        size: bytes.len() as u64,
        is_pie,
        entry_point: entry_addr,
        sections,
    })
}

/// Lookup symbols in binary file (from .symtab and .dynsym) matching pattern
pub fn lookup_symbols(
    file_path: &Path,
    runtime_base: Option<Address>,
    pattern: &str,
    limit: usize,
) -> CoreResult<Vec<SymbolInfo>> {
    let bytes = fs::read(file_path).map_err(|e| {
        CoreError::Analysis(format!("Failed to read binary file '{file_path:?}': {e}"))
    })?;

    let file = object::File::parse(bytes.as_slice()).map_err(|e| {
        CoreError::Analysis(format!("Failed to parse binary '{file_path:?}': {e}"))
    })?;

    let is_pie = check_is_pie(&file);
    let base = runtime_base.unwrap_or(Address::NULL);
    let pattern_lower = pattern.to_lowercase();

    let mut matches = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    let parse_sym = |sym: &dyn ObjectSymbol| -> Option<SymbolInfo> {
        let raw_name = sym.name().ok()?;
        if raw_name.is_empty() {
            return None;
        }

        if !pattern_lower.is_empty() && !raw_name.to_lowercase().contains(&pattern_lower) {
            return None;
        }

        let file_addr = sym.address();
        let runtime_addr = if is_pie {
            base.add(file_addr as usize)
        } else {
            Address::new(file_addr)
        };

        let kind_str = match sym.kind() {
            SymbolKind::Text => "Function",
            SymbolKind::Data => "Data",
            SymbolKind::Section => "Section",
            SymbolKind::File => "File",
            SymbolKind::Label => "Label",
            _ => "Unknown",
        };

        let binding_str = if sym.is_global() {
            "Global"
        } else if sym.is_weak() {
            "Weak"
        } else {
            "Local"
        };

        let sec_name = sym
            .section_index()
            .and_then(|idx| file.section_by_index(idx).ok())
            .and_then(|s| s.name().ok())
            .map(|n| n.to_string());

        Some(SymbolInfo {
            name: raw_name.to_string(),
            address: runtime_addr,
            file_address: file_addr,
            size: sym.size(),
            kind: kind_str.to_string(),
            binding: binding_str.to_string(),
            section: sec_name,
        })
    };

    // Iterate over regular symbols (.symtab)
    for sym in file.symbols() {
        if matches.len() >= limit {
            break;
        }
        if let Some(info) = parse_sym(&sym) {
            let sym_key = format!("{}_{}", info.name, info.file_address);
            if seen_names.insert(sym_key) {
                matches.push(info);
            }
        }
    }

    // Iterate over dynamic symbols (.dynsym)
    if matches.len() < limit {
        for sym in file.dynamic_symbols() {
            if matches.len() >= limit {
                break;
            }
            if let Some(info) = parse_sym(&sym) {
                let sym_key = format!("{}_{}", info.name, info.file_address);
                if seen_names.insert(sym_key) {
                    matches.push(info);
                }
            }
        }
    }

    // Sort: exact matches first, then functions, then alphabetically
    matches.sort_by(|a, b| {
        let a_exact = a.name.eq_ignore_ascii_case(pattern);
        let b_exact = b.name.eq_ignore_ascii_case(pattern);
        b_exact
            .cmp(&a_exact)
            .then_with(|| (a.kind == "Function").cmp(&(b.kind == "Function")).reverse())
            .then_with(|| a.name.cmp(&b.name))
    });

    Ok(matches)
}

fn check_is_pie(file: &object::File) -> bool {
    match file {
        object::File::Elf32(e) => e.elf_header().e_type(e.endian()) == object::elf::ET_DYN,
        object::File::Elf64(e) => e.elf_header().e_type(e.endian()) == object::elf::ET_DYN,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_lookup_on_current_exe() {
        if let Ok(exe_path) = std::env::current_exe() {
            let res = lookup_symbols(&exe_path, None, "test", 20);
            if let Ok(syms) = res {
                assert!(!syms.is_empty(), "Should find symbols in test binary");
            }
        }
    }
}
