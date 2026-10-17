use engine_pal::{Address, MemoryRegion};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StructureError {
    #[error("Field at offset 0x{offset:X} not found")]
    FieldNotFound { offset: usize },
    #[error("Invalid field size: {0}")]
    InvalidSize(usize),
}

pub type StructureResult<T> = Result<T, StructureError>;

/// Supported field types in ReClass-style node memory representation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FieldType {
    Hex8,
    Hex16,
    Hex32,
    Hex64,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Float,
    Double,
    Bool,
    Vector2([f32; 2]),
    Vector3([f32; 3]),
    Vector4([f32; 4]),
    Pointer {
        target: Address,
        region_type: Option<String>,
    },
    VTable {
        address: Address,
        method_count: usize,
    },
    InlineString {
        text: String,
        length: usize,
    },
    Padding {
        size: usize,
    },
}

impl FieldType {
    /// Byte size of this field type
    pub fn size(&self) -> usize {
        match self {
            FieldType::Hex8 | FieldType::Int8 | FieldType::UInt8 | FieldType::Bool => 1,
            FieldType::Hex16 | FieldType::Int16 | FieldType::UInt16 => 2,
            FieldType::Hex32 | FieldType::Int32 | FieldType::UInt32 | FieldType::Float => 4,
            FieldType::Hex64 | FieldType::Int64 | FieldType::UInt64 | FieldType::Double => 8,
            FieldType::Vector2(_) => 8,
            FieldType::Vector3(_) => 12,
            FieldType::Vector4(_) => 16,
            FieldType::Pointer { .. } | FieldType::VTable { .. } => 8, // 64-bit default
            FieldType::InlineString { length, .. } => *length,
            FieldType::Padding { size } => *size,
        }
    }

    /// Short type name for display and serialization
    pub fn type_name(&self) -> &'static str {
        match self {
            FieldType::Hex8 => "hex8",
            FieldType::Hex16 => "hex16",
            FieldType::Hex32 => "hex32",
            FieldType::Hex64 => "hex64",
            FieldType::Int8 => "int8",
            FieldType::Int16 => "int16",
            FieldType::Int32 => "int32",
            FieldType::Int64 => "int64",
            FieldType::UInt8 => "uint8",
            FieldType::UInt16 => "uint16",
            FieldType::UInt32 => "uint32",
            FieldType::UInt64 => "uint64",
            FieldType::Float => "float",
            FieldType::Double => "double",
            FieldType::Bool => "bool",
            FieldType::Vector2(_) => "Vector2",
            FieldType::Vector3(_) => "Vector3",
            FieldType::Vector4(_) => "Vector4",
            FieldType::Pointer { .. } => "Pointer",
            FieldType::VTable { .. } => "VTable",
            FieldType::InlineString { .. } => "String",
            FieldType::Padding { .. } => "Padding",
        }
    }
}

/// A single field in a reconstructed class structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructureField {
    pub offset: usize,
    pub name: String,
    pub field_type: FieldType,
    pub size: usize,
    pub display_value: String,
    pub comment: Option<String>,
}

/// Complete representation of an analyzed class or entity structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassStructure {
    pub name: String,
    pub base_address: Option<Address>,
    pub total_size: usize,
    pub fields: Vec<StructureField>,
}

impl ClassStructure {
    /// Create a new empty structure
    pub fn new(name: impl Into<String>, base_address: Option<Address>, total_size: usize) -> Self {
        Self {
            name: name.into(),
            base_address,
            total_size,
            fields: Vec::new(),
        }
    }

    /// Rename a field at specific offset
    pub fn rename_field(&mut self, offset: usize, new_name: &str) -> StructureResult<()> {
        if let Some(f) = self.fields.iter_mut().find(|f| f.offset == offset) {
            f.name = new_name.to_string();
            Ok(())
        } else {
            Err(StructureError::FieldNotFound { offset })
        }
    }

    /// Automatically reconstruct class structure from raw memory bytes using heuristics
    pub fn reconstruct(
        base: Address,
        bytes: &[u8],
        mapped_regions: &[MemoryRegion],
        class_name: Option<&str>,
    ) -> Self {
        let name = class_name.unwrap_or("ReconstructedClass").to_string();
        let total_size = bytes.len();
        let mut fields = Vec::new();
        let mut offset = 0;

        while offset < total_size {
            let remaining = total_size - offset;

            // 1. Detect VTable at offset 0 (or aligned 8)
            if offset % 8 == 0 && remaining >= 8 {
                let ptr_val = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                if is_valid_user_pointer(ptr_val) {
                    let target_addr = Address::new(ptr_val);
                    if let Some(reg) = mapped_regions.iter().find(|r| r.contains(target_addr)) {
                        if !reg.is_writable() || offset == 0 {
                            fields.push(StructureField {
                                offset,
                                name: if offset == 0 { "vtable".to_string() } else { format!("vtable_{offset:X}") },
                                field_type: FieldType::VTable { address: target_addr, method_count: 0 },
                                size: 8,
                                display_value: format!("0x{ptr_val:X}"),
                                comment: Some(format!("Virtual Method Table ({})", reg.path.as_deref().unwrap_or("module"))),
                            });
                            offset += 8;
                            continue;
                        }
                    }
                }
            }

            // 2. Detect 3D Coordinates / Vector3 (3 contiguous valid floats)
            if offset % 4 == 0 && remaining >= 12 {
                let f1 = f32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                let f2 = f32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
                let f3 = f32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap());

                if is_valid_coordinate(f1) && is_valid_coordinate(f2) && is_valid_coordinate(f3) {
                    let non_zero_count = (f1 != 0.0) as usize + (f2 != 0.0) as usize + (f3 != 0.0) as usize;
                    if non_zero_count >= 2 {
                        fields.push(StructureField {
                            offset,
                            name: format!("vec3_{offset:X}"),
                            field_type: FieldType::Vector3([f1, f2, f3]),
                            size: 12,
                            display_value: format!("({f1:.3}, {f2:.3}, {f3:.3})"),
                            comment: Some("3D World / Local Vector (X, Y, Z)".to_string()),
                        });
                        offset += 12;
                        continue;
                    }
                }
            }

            // 3. Detect 64-bit Pointers to mapped memory
            if offset % 8 == 0 && remaining >= 8 {
                let ptr_val = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                if is_valid_user_pointer(ptr_val) {
                    let target_addr = Address::new(ptr_val);
                    if let Some(reg) = mapped_regions.iter().find(|r| r.contains(target_addr)) {
                        let region_desc = if reg.is_executable() {
                            "Code / Function".to_string()
                        } else if reg.is_writable() {
                            "Heap / RW Object".to_string()
                        } else {
                            "ROData / Constant".to_string()
                        };

                        fields.push(StructureField {
                            offset,
                            name: format!("ptr_{offset:X}"),
                            field_type: FieldType::Pointer {
                                target: target_addr,
                                region_type: Some(region_desc.clone()),
                            },
                            size: 8,
                            display_value: format!("0x{ptr_val:X}"),
                            comment: Some(format!("Pointer -> {region_desc} [{}]", reg.path.as_deref().unwrap_or("anon"))),
                        });
                        offset += 8;
                        continue;
                    }
                }
            }

            // 4. Detect Padding sequences of zeros (checking lookahead at 4-byte boundaries)
            if bytes[offset] == 0 {
                let mut zero_len = 0;
                while offset + zero_len < total_size && bytes[offset + zero_len] == 0 {
                    let check_off = offset + zero_len;
                    if zero_len > 0 && check_off % 4 == 0 && check_off < total_size {
                        if check_off + 12 <= total_size {
                            let f1 = f32::from_le_bytes(bytes[check_off..check_off + 4].try_into().unwrap());
                            let f2 = f32::from_le_bytes(bytes[check_off + 4..check_off + 8].try_into().unwrap());
                            let f3 = f32::from_le_bytes(bytes[check_off + 8..check_off + 12].try_into().unwrap());
                            if is_valid_coordinate(f1) && is_valid_coordinate(f2) && is_valid_coordinate(f3) {
                                let non_zeros = (f1 != 0.0) as usize + (f2 != 0.0) as usize + (f3 != 0.0) as usize;
                                if non_zeros >= 2 {
                                    break;
                                }
                            }
                        }
                        if check_off + 4 <= total_size {
                            let f = f32::from_le_bytes(bytes[check_off..check_off + 4].try_into().unwrap());
                            if f != 0.0 && is_typical_game_float(f) {
                                break;
                            }
                        }
                    }
                    zero_len += 1;
                }
                if zero_len >= 8 || (zero_len >= 4 && offset + zero_len == total_size) || (zero_len >= 4 && (offset + zero_len) % 4 == 0) {
                    fields.push(StructureField {
                        offset,
                        name: format!("_pad_{offset:X}"),
                        field_type: FieldType::Padding { size: zero_len },
                        size: zero_len,
                        display_value: format!("0x00 x {zero_len}"),
                        comment: Some("Unused / Padding bytes".to_string()),
                    });
                    offset += zero_len;
                    continue;
                }
            }

            // 5. Detect Inline ASCII / UTF-8 Strings
            if (32..=126).contains(&bytes[offset]) {
                let mut str_len = 0;
                while offset + str_len < total_size && (32..=126).contains(&bytes[offset + str_len]) {
                    str_len += 1;
                }
                // If terminated by 0x00 and at least 4 characters long
                if str_len >= 4 && (offset + str_len == total_size || bytes[offset + str_len] == 0) {
                    let text = String::from_utf8_lossy(&bytes[offset..offset + str_len]).to_string();
                    let total_str_bytes = if offset + str_len < total_size && bytes[offset + str_len] == 0 {
                        str_len + 1
                    } else {
                        str_len
                    };

                    fields.push(StructureField {
                        offset,
                        name: format!("str_{offset:X}"),
                        field_type: FieldType::InlineString { text: text.clone(), length: total_str_bytes },
                        size: total_str_bytes,
                        display_value: format!("\"{text}\""),
                        comment: Some(format!("ASCII string (len {str_len})")),
                    });
                    offset += total_str_bytes;
                    continue;
                }
            }

            // 6. Detect Single Float
            if offset % 4 == 0 && remaining >= 4 {
                let f = f32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                if is_typical_game_float(f) {
                    fields.push(StructureField {
                        offset,
                        name: format!("fl_{offset:X}"),
                        field_type: FieldType::Float,
                        size: 4,
                        display_value: format!("{f:.4}"),
                        comment: Some(format!("Float32 (approx {f:.2})")),
                    });
                    offset += 4;
                    continue;
                }
            }

            // 7. Detect Integer (i32 / u32)
            if offset % 4 == 0 && remaining >= 4 {
                let i = i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                if i != 0 && ((-100_000)..=10_000_000).contains(&i) {
                    fields.push(StructureField {
                        offset,
                        name: format!("n_{offset:X}"),
                        field_type: FieldType::Int32,
                        size: 4,
                        display_value: format!("{i}"),
                        comment: Some(format!("Int32 (hex: 0x{i:X})")),
                    });
                    offset += 4;
                    continue;
                }
            }

            // 8. Fallback to raw hex byte
            let b = bytes[offset];
            fields.push(StructureField {
                offset,
                name: format!("byte_{offset:X}"),
                field_type: FieldType::Hex8,
                size: 1,
                display_value: format!("0x{b:02X}"),
                comment: None,
            });
            offset += 1;
        }

        Self {
            name,
            base_address: Some(base),
            total_size,
            fields,
        }
    }

    /// Export structure to clean C++ struct header definition
    pub fn to_cpp(&self) -> String {
        let mut out = String::new();
        out.push_str("#pragma once\n#include <cstdint>\n\n");
        out.push_str("struct Vector2 { float x, y; };\n");
        out.push_str("struct Vector3 { float x, y, z; };\n");
        out.push_str("struct Vector4 { float x, y, z, w; };\n\n");

        out.push_str(&format!("// Reconstructed structure: {}\n", self.name));
        if let Some(base) = self.base_address {
            out.push_str(&format!("// Base Address: 0x{:X}\n", base.as_u64()));
        }
        out.push_str(&format!("struct {} {{\n", self.name));

        for f in &self.fields {
            let type_str = match &f.field_type {
                FieldType::Hex8 => "uint8_t".to_string(),
                FieldType::Hex16 => "uint16_t".to_string(),
                FieldType::Hex32 => "uint32_t".to_string(),
                FieldType::Hex64 => "uint64_t".to_string(),
                FieldType::Int8 => "int8_t".to_string(),
                FieldType::Int16 => "int16_t".to_string(),
                FieldType::Int32 => "int32_t".to_string(),
                FieldType::Int64 => "int64_t".to_string(),
                FieldType::UInt8 => "uint8_t".to_string(),
                FieldType::UInt16 => "uint16_t".to_string(),
                FieldType::UInt32 => "uint32_t".to_string(),
                FieldType::UInt64 => "uint64_t".to_string(),
                FieldType::Float => "float".to_string(),
                FieldType::Double => "double".to_string(),
                FieldType::Bool => "bool".to_string(),
                FieldType::Vector2(_) => "Vector2".to_string(),
                FieldType::Vector3(_) => "Vector3".to_string(),
                FieldType::Vector4(_) => "Vector4".to_string(),
                FieldType::Pointer { .. } => "void*".to_string(),
                FieldType::VTable { .. } => "void**".to_string(),
                FieldType::InlineString { length, .. } => format!("char[{length}]"),
                FieldType::Padding { size } => format!("uint8_t[{size}]"),
            };

            let comment_part = if let Some(ref c) = f.comment {
                format!(" // 0x{:04X}: {} ({})", f.offset, c, f.display_value)
            } else {
                format!(" // 0x{:04X}: {}", f.offset, f.display_value)
            };

            if type_str.contains('[') {
                let (base_type, arr_part) = type_str.split_once('[').unwrap();
                out.push_str(&format!("    {:<12} {}{:<20};{}\n", base_type, f.name, format!("[{}", arr_part), comment_part));
            } else {
                out.push_str(&format!("    {:<12} {:<20};{}\n", type_str, f.name, comment_part));
            }
        }

        out.push_str("};\n");
        out.push_str(&format!("static_assert(sizeof({}) == 0x{:X}, \"Size mismatch\");\n", self.name, self.total_size));
        out
    }

    /// Export structure to Rust `#[repr(C)]` struct definition
    pub fn to_rust(&self) -> String {
        let mut out = String::new();
        out.push_str("#[repr(C)]\n");
        out.push_str("#[derive(Debug, Clone, Copy, PartialEq)]\n");
        out.push_str("pub struct Vector3 { pub x: f32, pub y: f32, pub z: f32 }\n\n");

        out.push_str("#[repr(C)]\n");
        out.push_str(&format!("pub struct {} {{\n", self.name));

        for f in &self.fields {
            let type_str = match &f.field_type {
                FieldType::Hex8 | FieldType::UInt8 => "u8".to_string(),
                FieldType::Hex16 | FieldType::UInt16 => "u16".to_string(),
                FieldType::Hex32 | FieldType::UInt32 => "u32".to_string(),
                FieldType::Hex64 | FieldType::UInt64 => "u64".to_string(),
                FieldType::Int8 => "i8".to_string(),
                FieldType::Int16 => "i16".to_string(),
                FieldType::Int32 => "i32".to_string(),
                FieldType::Int64 => "i64".to_string(),
                FieldType::Float => "f32".to_string(),
                FieldType::Double => "f64".to_string(),
                FieldType::Bool => "bool".to_string(),
                FieldType::Vector2(_) => "[f32; 2]".to_string(),
                FieldType::Vector3(_) => "Vector3".to_string(),
                FieldType::Vector4(_) => "[f32; 4]".to_string(),
                FieldType::Pointer { .. } => "*const ()".to_string(),
                FieldType::VTable { .. } => "*const usize".to_string(),
                FieldType::InlineString { length, .. } => format!("[u8; {length}]"),
                FieldType::Padding { size } => format!("[u8; {size}]"),
            };

            let comment_part = if let Some(ref c) = f.comment {
                format!(" // 0x{:04X}: {} ({})", f.offset, c, f.display_value)
            } else {
                format!(" // 0x{:04X}: {}", f.offset, f.display_value)
            };

            out.push_str(&format!("    pub {:<16}: {:<16}, {}\n", f.name, type_str, comment_part));
        }

        out.push_str("}\n");
        out
    }

    /// Export structure to C# `[StructLayout(LayoutKind.Explicit)]` definition
    pub fn to_csharp(&self) -> String {
        let mut out = String::new();
        out.push_str("using System;\nusing System.Runtime.InteropServices;\n\n");
        out.push_str(&format!("[StructLayout(LayoutKind.Explicit, Size = 0x{:X})]\n", self.total_size));
        out.push_str(&format!("public struct {} {{\n", self.name));

        for f in &self.fields {
            if matches!(f.field_type, FieldType::Padding { .. }) {
                continue; // Explicit layout handles padding via FieldOffset
            }

            let type_str = match &f.field_type {
                FieldType::Hex8 | FieldType::UInt8 => "byte",
                FieldType::Hex16 | FieldType::UInt16 => "ushort",
                FieldType::Hex32 | FieldType::UInt32 => "uint",
                FieldType::Hex64 | FieldType::UInt64 => "ulong",
                FieldType::Int8 => "sbyte",
                FieldType::Int16 => "short",
                FieldType::Int32 => "int",
                FieldType::Int64 => "long",
                FieldType::Float => "float",
                FieldType::Double => "double",
                FieldType::Bool => "bool",
                FieldType::Vector2(_) | FieldType::Vector3(_) | FieldType::Vector4(_) => "System.Numerics.Vector3",
                FieldType::Pointer { .. } | FieldType::VTable { .. } => "IntPtr",
                _ => "byte",
            };

            out.push_str(&format!(
                "    [FieldOffset(0x{:X})] public {} {}; // {}\n",
                f.offset, type_str, f.name, f.display_value
            ));
        }

        out.push_str("}\n");
        out
    }
}

fn is_valid_user_pointer(val: u64) -> bool {
    val > 0x10000 && val < 0x7FFFFFFF_FFFFFFFF
}

fn is_valid_coordinate(f: f32) -> bool {
    f.is_finite() && !f.is_subnormal() && f.abs() < 1_000_000.0 && (f == 0.0 || f.abs() > 0.0001)
}

fn is_typical_game_float(f: f32) -> bool {
    f.is_finite() && !f.is_subnormal() && f.abs() > 0.01 && f.abs() <= 50_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_pal::ProtectionFlags;

    #[test]
    fn test_structure_reconstruction_with_vtable_and_vector3() {
        let mut buffer = vec![0u8; 64];

        // 0x00: VTable pointer (points to 0x7FFF0000)
        let vtable_addr = 0x7FFF_0000u64;
        buffer[0..8].copy_from_slice(&vtable_addr.to_le_bytes());

        // 0x08..0x14: Padding (zeros)
        // 0x14..0x20: Vector3 (10.0, 20.0, 30.0)
        let x: f32 = 10.0;
        let y: f32 = 20.0;
        let z: f32 = 30.0;
        buffer[20..24].copy_from_slice(&x.to_le_bytes());
        buffer[24..28].copy_from_slice(&y.to_le_bytes());
        buffer[28..32].copy_from_slice(&z.to_le_bytes());

        // 0x20: Health (i32: 100)
        buffer[32..36].copy_from_slice(&100i32.to_le_bytes());

        let fake_region = MemoryRegion {
            start: Address::new(0x7FFE_0000),
            end: Address::new(0x7FFF_FFFF),
            size: 0x20000,
            protection: ProtectionFlags::RX,
            path: Some("/game/game_client.so".to_string()),
            is_anonymous: false,
        };

        let structure = ClassStructure::reconstruct(
            Address::new(0x1000),
            &buffer,
            &[fake_region],
            Some("EntityPlayer"),
        );

        assert_eq!(structure.name, "EntityPlayer");
        assert!(structure.fields.iter().any(|f| matches!(f.field_type, FieldType::VTable { .. })));
        assert!(structure.fields.iter().any(|f| matches!(f.field_type, FieldType::Vector3(_))));
        assert!(structure.fields.iter().any(|f| matches!(f.field_type, FieldType::Int32)));

        let cpp = structure.to_cpp();
        assert!(cpp.contains("struct EntityPlayer"));
        assert!(cpp.contains("Vector3"));
        assert!(cpp.contains("static_assert(sizeof(EntityPlayer) == 0x40"));

        let rust = structure.to_rust();
        assert!(rust.contains("pub struct EntityPlayer"));
        assert!(rust.contains("pub vtable"));

        let cs = structure.to_csharp();
        assert!(cs.contains("public struct EntityPlayer"));
        assert!(cs.contains("[FieldOffset("));
    }

    #[test]
    fn test_structure_rename_field() {
        let mut buffer = vec![0u8; 16];
        buffer[0..4].copy_from_slice(&100i32.to_le_bytes());
        let mut structure = ClassStructure::reconstruct(Address::new(0x1000), &buffer, &[], None);
        assert!(structure.rename_field(0, "m_iHealth").is_ok());
        assert_eq!(structure.fields[0].name, "m_iHealth");
        assert!(structure.rename_field(999, "invalid").is_err());
    }

    #[test]
    fn test_structure_inline_string_detection() {
        let mut buffer = vec![0u8; 32];
        let name = b"JohnDoe\0";
        buffer[4..4 + name.len()].copy_from_slice(name);
        let structure = ClassStructure::reconstruct(Address::new(0x1000), &buffer, &[], None);
        assert!(structure.fields.iter().any(|f| matches!(&f.field_type, FieldType::InlineString { text, .. } if text == "JohnDoe")));
    }
}
