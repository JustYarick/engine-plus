use crate::error::{CoreError, CoreResult};
use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::fs;
use std::path::Path;

type SliceReader<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwarfMember {
    pub name: String,
    pub offset: u64,
    pub offset_hex: String,
    pub type_name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwarfStructLayout {
    pub name: String,
    pub total_size: u64,
    pub members: Vec<DwarfMember>,
}

impl DwarfStructLayout {
    pub fn format_cpp_definition(&self) -> String {
        let mut out = format!("struct {} {{\n", self.name);
        for m in &self.members {
            out.push_str(&format!("    /* 0x{:04X} */ {} {};\n", m.offset, m.type_name, m.name));
        }
        out.push_str(&format!("}}; // Size: 0x{:X} ({} bytes)\n", self.total_size, self.total_size));
        out
    }
}

/// Extract struct or class layout from DWARF debug information in binary file
pub fn inspect_dwarf_struct(file_path: &Path, target_struct: &str) -> CoreResult<DwarfStructLayout> {
    let file_bytes = fs::read(file_path).map_err(|e| {
        CoreError::Analysis(format!("Failed to read file '{file_path:?}': {e}"))
    })?;

    let file = object::File::parse(file_bytes.as_slice()).map_err(|e| {
        CoreError::Analysis(format!("Failed to parse object file: {e}"))
    })?;

    let endian = if file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let load_section = |id: gimli::SectionId| -> Result<SliceReader<'_>, Infallible> {
        let data = match file.section_by_name(id.name()) {
            Some(ref section) => section.data().unwrap_or(&[]),
            None => &[],
        };
        Ok(gimli::EndianSlice::new(data, endian))
    };

    let dwarf = match gimli::Dwarf::load(&load_section) {
        Ok(d) => d,
        Err(e) => return Err(CoreError::Analysis(format!("Failed to load DWARF sections: {e}"))),
    };

    let mut iter = dwarf.units();
    while let Ok(Some(header)) = iter.next() {
        let unit = match dwarf.unit(header) {
            Ok(u) => u,
            Err(_) => continue,
        };

        let mut entries = unit.entries();
        while let Ok(Some(entry)) = entries.next_dfs() {
            if entry.tag() == gimli::DW_TAG_structure_type || entry.tag() == gimli::DW_TAG_class_type {
                let name = match entry.attr_value(gimli::DW_AT_name) {
                    Some(attr) => match dwarf.attr_string(&unit, attr) {
                        Ok(s) => s.to_string_lossy().into_owned(),
                        Err(_) => continue,
                    },
                    None => continue,
                };

                if name.eq_ignore_ascii_case(target_struct) {
                    let total_size = match entry.attr_value(gimli::DW_AT_byte_size) {
                        Some(attr) => attr.udata_value().unwrap_or(0),
                        None => 0,
                    };

                    let mut members = Vec::new();

                    // Search children for members
                    if let Ok(mut tree) = unit.entries_tree(Some(entry.offset())) {
                        if let Ok(root) = tree.root() {
                            let mut children = root.children();
                            while let Ok(Some(child)) = children.next() {
                                let c_entry = child.entry();
                                if c_entry.tag() == gimli::DW_TAG_member {
                                    let member_name = match c_entry.attr_value(gimli::DW_AT_name) {
                                        Some(attr) => match dwarf.attr_string(&unit, attr) {
                                            Ok(s) => s.to_string_lossy().into_owned(),
                                            Err(_) => "unnamed".to_string(),
                                        },
                                        None => "unnamed".to_string(),
                                    };

                                    let member_offset = match c_entry.attr_value(gimli::DW_AT_data_member_location) {
                                        Some(attr) => attr.udata_value().unwrap_or(0),
                                        None => 0,
                                    };

                                    let (type_name, type_size) = resolve_type_info(&dwarf, &unit, c_entry);

                                    members.push(DwarfMember {
                                        name: member_name,
                                        offset: member_offset,
                                        offset_hex: format!("+0x{member_offset:X}"),
                                        type_name,
                                        size: type_size,
                                    });
                                }
                            }
                        }
                    }

                    members.sort_by_key(|m| m.offset);

                    return Ok(DwarfStructLayout {
                        name,
                        total_size,
                        members,
                    });
                }
            }
        }
    }

    Err(CoreError::NotFound(format!(
        "Struct/class '{target_struct}' not found in DWARF debug symbols"
    )))
}

fn resolve_type_info(
    dwarf: &gimli::Dwarf<SliceReader<'_>>,
    unit: &gimli::Unit<SliceReader<'_>>,
    entry: &gimli::DebuggingInformationEntry<SliceReader<'_>>,
) -> (String, u64) {
    if let Some(gimli::AttributeValue::UnitRef(offset)) = entry.attr_value(gimli::DW_AT_type) {
        if let Ok(type_entry) = unit.entry(offset) {
            let type_name = match type_entry.attr_value(gimli::DW_AT_name) {
                Some(attr) => match dwarf.attr_string(unit, attr) {
                    Ok(s) => s.to_string_lossy().into_owned(),
                    Err(_) => "unknown".to_string(),
                },
                None => match type_entry.tag() {
                    gimli::DW_TAG_pointer_type => "pointer*".to_string(),
                    gimli::DW_TAG_array_type => "array[]".to_string(),
                    gimli::DW_TAG_const_type => "const".to_string(),
                    _ => "unknown".to_string(),
                },
            };

            let size = match type_entry.attr_value(gimli::DW_AT_byte_size) {
                Some(attr) => attr.udata_value().unwrap_or(0),
                None => 0,
            };

            return (type_name, size);
        }
    }

    ("unknown".to_string(), 0)
}

/// List all structure and class names present in binary DWARF debug info
pub fn list_dwarf_structs(file_path: &Path, limit: usize) -> CoreResult<Vec<String>> {
    let file_bytes = fs::read(file_path).map_err(|e| {
        CoreError::Analysis(format!("Failed to read file '{file_path:?}': {e}"))
    })?;

    let file = object::File::parse(file_bytes.as_slice()).map_err(|e| {
        CoreError::Analysis(format!("Failed to parse object file: {e}"))
    })?;

    let endian = if file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let load_section = |id: gimli::SectionId| -> Result<SliceReader<'_>, Infallible> {
        let data = match file.section_by_name(id.name()) {
            Some(ref section) => section.data().unwrap_or(&[]),
            None => &[],
        };
        Ok(gimli::EndianSlice::new(data, endian))
    };

    let dwarf = match gimli::Dwarf::load(&load_section) {
        Ok(d) => d,
        Err(e) => return Err(CoreError::Analysis(format!("Failed to load DWARF sections: {e}"))),
    };

    let mut structs = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut iter = dwarf.units();
    while let Ok(Some(header)) = iter.next() {
        if structs.len() >= limit {
            break;
        }

        let unit = match dwarf.unit(header) {
            Ok(u) => u,
            Err(_) => continue,
        };

        let mut entries = unit.entries();
        while let Ok(Some(entry)) = entries.next_dfs() {
            if entry.tag() == gimli::DW_TAG_structure_type || entry.tag() == gimli::DW_TAG_class_type {
                if let Some(attr) = entry.attr_value(gimli::DW_AT_name) {
                    if let Ok(s) = dwarf.attr_string(&unit, attr) {
                        let name_str = s.to_string_lossy().into_owned();
                        if !name_str.is_empty() && seen.insert(name_str.clone()) {
                            structs.push(name_str);
                            if structs.len() >= limit {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    structs.sort();
    Ok(structs)
}
