use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported types of data that can be searched in memory
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScanValueType {
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
    Aob,
    StringUtf8,
    StringUtf16,
}

impl ScanValueType {
    /// Default byte alignment in memory for this data type
    pub fn default_alignment(&self) -> usize {
        match self {
            ScanValueType::I8 | ScanValueType::U8 | ScanValueType::Aob | ScanValueType::StringUtf8 => 1,
            ScanValueType::I16 | ScanValueType::U16 | ScanValueType::StringUtf16 => 2,
            ScanValueType::I32 | ScanValueType::U32 | ScanValueType::F32 => 4,
            ScanValueType::I64 | ScanValueType::U64 | ScanValueType::F64 => 8,
        }
    }

    /// Size in bytes for fixed-size scalar types
    pub fn size_in_bytes(&self) -> Option<usize> {
        match self {
            ScanValueType::I8 | ScanValueType::U8 => Some(1),
            ScanValueType::I16 | ScanValueType::U16 => Some(2),
            ScanValueType::I32 | ScanValueType::U32 | ScanValueType::F32 => Some(4),
            ScanValueType::I64 | ScanValueType::U64 | ScanValueType::F64 => Some(8),
            ScanValueType::Aob | ScanValueType::StringUtf8 | ScanValueType::StringUtf16 => None,
        }
    }
}

/// A concrete typed value searched or stored in memory scan
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScanValue {
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    F32(f32),
    F64(f64),
    Aob(Vec<Option<u8>>),
    StringUtf8(String),
    StringUtf16(String),
}

impl ScanValue {
    /// Get the value type
    pub fn value_type(&self) -> ScanValueType {
        match self {
            ScanValue::I8(_) => ScanValueType::I8,
            ScanValue::U8(_) => ScanValueType::U8,
            ScanValue::I16(_) => ScanValueType::I16,
            ScanValue::U16(_) => ScanValueType::U16,
            ScanValue::I32(_) => ScanValueType::I32,
            ScanValue::U32(_) => ScanValueType::U32,
            ScanValue::I64(_) => ScanValueType::I64,
            ScanValue::U64(_) => ScanValueType::U64,
            ScanValue::F32(_) => ScanValueType::F32,
            ScanValue::F64(_) => ScanValueType::F64,
            ScanValue::Aob(_) => ScanValueType::Aob,
            ScanValue::StringUtf8(_) => ScanValueType::StringUtf8,
            ScanValue::StringUtf16(_) => ScanValueType::StringUtf16,
        }
    }

    /// Parse a string into a ScanValue according to the target type
    pub fn parse(input: &str, val_type: ScanValueType) -> Result<Self, String> {
        let input = input.trim();
        match val_type {
            ScanValueType::I8 => input
                .parse::<i8>()
                .map(ScanValue::I8)
                .map_err(|e| e.to_string()),
            ScanValueType::U8 => input
                .parse::<u8>()
                .map(ScanValue::U8)
                .map_err(|e| e.to_string()),
            ScanValueType::I16 => input
                .parse::<i16>()
                .map(ScanValue::I16)
                .map_err(|e| e.to_string()),
            ScanValueType::U16 => input
                .parse::<u16>()
                .map(ScanValue::U16)
                .map_err(|e| e.to_string()),
            ScanValueType::I32 => input
                .parse::<i32>()
                .map(ScanValue::I32)
                .map_err(|e| e.to_string()),
            ScanValueType::U32 => input
                .parse::<u32>()
                .map(ScanValue::U32)
                .map_err(|e| e.to_string()),
            ScanValueType::I64 => input
                .parse::<i64>()
                .map(ScanValue::I64)
                .map_err(|e| e.to_string()),
            ScanValueType::U64 => input
                .parse::<u64>()
                .map(ScanValue::U64)
                .map_err(|e| e.to_string()),
            ScanValueType::F32 => input
                .parse::<f32>()
                .map(ScanValue::F32)
                .map_err(|e| e.to_string()),
            ScanValueType::F64 => input
                .parse::<f64>()
                .map(ScanValue::F64)
                .map_err(|e| e.to_string()),
            ScanValueType::Aob => parse_aob_pattern(input).map(ScanValue::Aob),
            ScanValueType::StringUtf8 => Ok(ScanValue::StringUtf8(input.to_string())),
            ScanValueType::StringUtf16 => Ok(ScanValue::StringUtf16(input.to_string())),
        }
    }

    /// Read a value of the given type from a byte slice at offset
    #[inline]
    pub fn read_from_slice(bytes: &[u8], offset: usize, val_type: ScanValueType) -> Option<Self> {
        let slice = bytes.get(offset..)?;
        match val_type {
            ScanValueType::I8 => slice.first().map(|&b| ScanValue::I8(b as i8)),
            ScanValueType::U8 => slice.first().map(|&b| ScanValue::U8(b)),
            ScanValueType::I16 if slice.len() >= 2 => {
                Some(ScanValue::I16(LittleEndian::read_i16(slice)))
            }
            ScanValueType::U16 if slice.len() >= 2 => {
                Some(ScanValue::U16(LittleEndian::read_u16(slice)))
            }
            ScanValueType::I32 if slice.len() >= 4 => {
                Some(ScanValue::I32(LittleEndian::read_i32(slice)))
            }
            ScanValueType::U32 if slice.len() >= 4 => {
                Some(ScanValue::U32(LittleEndian::read_u32(slice)))
            }
            ScanValueType::I64 if slice.len() >= 8 => {
                Some(ScanValue::I64(LittleEndian::read_i64(slice)))
            }
            ScanValueType::U64 if slice.len() >= 8 => {
                Some(ScanValue::U64(LittleEndian::read_u64(slice)))
            }
            ScanValueType::F32 if slice.len() >= 4 => {
                Some(ScanValue::F32(LittleEndian::read_f32(slice)))
            }
            ScanValueType::F64 if slice.len() >= 8 => {
                Some(ScanValue::F64(LittleEndian::read_f64(slice)))
            }
            _ => None,
        }
    }

    /// Check if this value is strictly greater than another value
    pub fn is_greater_than(&self, other: &Self) -> bool {
        match (self, other) {
            (ScanValue::I8(a), ScanValue::I8(b)) => a > b,
            (ScanValue::U8(a), ScanValue::U8(b)) => a > b,
            (ScanValue::I16(a), ScanValue::I16(b)) => a > b,
            (ScanValue::U16(a), ScanValue::U16(b)) => a > b,
            (ScanValue::I32(a), ScanValue::I32(b)) => a > b,
            (ScanValue::U32(a), ScanValue::U32(b)) => a > b,
            (ScanValue::I64(a), ScanValue::I64(b)) => a > b,
            (ScanValue::U64(a), ScanValue::U64(b)) => a > b,
            (ScanValue::F32(a), ScanValue::F32(b)) => a > b,
            (ScanValue::F64(a), ScanValue::F64(b)) => a > b,
            _ => false,
        }
    }

    /// Check if this value is strictly less than another value
    pub fn is_less_than(&self, other: &Self) -> bool {
        match (self, other) {
            (ScanValue::I8(a), ScanValue::I8(b)) => a < b,
            (ScanValue::U8(a), ScanValue::U8(b)) => a < b,
            (ScanValue::I16(a), ScanValue::I16(b)) => a < b,
            (ScanValue::U16(a), ScanValue::U16(b)) => a < b,
            (ScanValue::I32(a), ScanValue::I32(b)) => a < b,
            (ScanValue::U32(a), ScanValue::U32(b)) => a < b,
            (ScanValue::I64(a), ScanValue::I64(b)) => a < b,
            (ScanValue::U64(a), ScanValue::U64(b)) => a < b,
            (ScanValue::F32(a), ScanValue::F32(b)) => a < b,
            (ScanValue::F64(a), ScanValue::F64(b)) => a < b,
            _ => false,
        }
    }

    /// Check if this value increased by a specific delta compared to previous
    pub fn is_increased_by(&self, prev: &Self, delta: &Self) -> bool {
        match (self, prev, delta) {
            (ScanValue::I8(curr), ScanValue::I8(p), ScanValue::I8(d)) => curr.wrapping_sub(*p) == *d,
            (ScanValue::U8(curr), ScanValue::U8(p), ScanValue::U8(d)) => curr.wrapping_sub(*p) == *d,
            (ScanValue::I16(curr), ScanValue::I16(p), ScanValue::I16(d)) => curr.wrapping_sub(*p) == *d,
            (ScanValue::U16(curr), ScanValue::U16(p), ScanValue::U16(d)) => curr.wrapping_sub(*p) == *d,
            (ScanValue::I32(curr), ScanValue::I32(p), ScanValue::I32(d)) => curr.wrapping_sub(*p) == *d,
            (ScanValue::U32(curr), ScanValue::U32(p), ScanValue::U32(d)) => curr.wrapping_sub(*p) == *d,
            (ScanValue::I64(curr), ScanValue::I64(p), ScanValue::I64(d)) => curr.wrapping_sub(*p) == *d,
            (ScanValue::U64(curr), ScanValue::U64(p), ScanValue::U64(d)) => curr.wrapping_sub(*p) == *d,
            (ScanValue::F32(curr), ScanValue::F32(p), ScanValue::F32(d)) => (curr - p - d).abs() < 0.0001,
            (ScanValue::F64(curr), ScanValue::F64(p), ScanValue::F64(d)) => (curr - p - d).abs() < 0.0000001,
            _ => false,
        }
    }

    /// Check if this value decreased by a specific delta compared to previous
    pub fn is_decreased_by(&self, prev: &Self, delta: &Self) -> bool {
        match (self, prev, delta) {
            (ScanValue::I8(curr), ScanValue::I8(p), ScanValue::I8(d)) => p.wrapping_sub(*curr) == *d,
            (ScanValue::U8(curr), ScanValue::U8(p), ScanValue::U8(d)) => p.wrapping_sub(*curr) == *d,
            (ScanValue::I16(curr), ScanValue::I16(p), ScanValue::I16(d)) => p.wrapping_sub(*curr) == *d,
            (ScanValue::U16(curr), ScanValue::U16(p), ScanValue::U16(d)) => p.wrapping_sub(*curr) == *d,
            (ScanValue::I32(curr), ScanValue::I32(p), ScanValue::I32(d)) => p.wrapping_sub(*curr) == *d,
            (ScanValue::U32(curr), ScanValue::U32(p), ScanValue::U32(d)) => p.wrapping_sub(*curr) == *d,
            (ScanValue::I64(curr), ScanValue::I64(p), ScanValue::I64(d)) => p.wrapping_sub(*curr) == *d,
            (ScanValue::U64(curr), ScanValue::U64(p), ScanValue::U64(d)) => p.wrapping_sub(*curr) == *d,
            (ScanValue::F32(curr), ScanValue::F32(p), ScanValue::F32(d)) => (p - curr - d).abs() < 0.0001,
            (ScanValue::F64(curr), ScanValue::F64(p), ScanValue::F64(d)) => (p - curr - d).abs() < 0.0000001,
            _ => false,
        }
    }
}

impl fmt::Display for ScanValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanValue::I8(v) => write!(f, "{v}"),
            ScanValue::U8(v) => write!(f, "{v}"),
            ScanValue::I16(v) => write!(f, "{v}"),
            ScanValue::U16(v) => write!(f, "{v}"),
            ScanValue::I32(v) => write!(f, "{v}"),
            ScanValue::U32(v) => write!(f, "{v}"),
            ScanValue::I64(v) => write!(f, "{v}"),
            ScanValue::U64(v) => write!(f, "{v}"),
            ScanValue::F32(v) => write!(f, "{v:.3}"),
            ScanValue::F64(v) => write!(f, "{v:.6}"),
            ScanValue::Aob(pat) => {
                let parts: Vec<String> = pat
                    .iter()
                    .map(|b| match b {
                        Some(val) => format!("{:02X}", val),
                        None => "??".to_string(),
                    })
                    .collect();
                write!(f, "{}", parts.join(" "))
            }
            ScanValue::StringUtf8(s) => write!(f, "\"{s}\""),
            ScanValue::StringUtf16(s) => write!(f, "L\"{s}\""),
        }
    }
}

/// Parse an Array of Bytes (AOB) string with wildcards (e.g. "48 8B 05 ?? ?? ?? ?? 48 89")
pub fn parse_aob_pattern(input: &str) -> Result<Vec<Option<u8>>, String> {
    let mut pattern = Vec::new();

    for token in input.split_whitespace() {
        if token == "?" || token == "??" {
            pattern.push(None);
        } else {
            match u8::from_str_radix(token, 16) {
                Ok(byte) => pattern.push(Some(byte)),
                Err(_) => return Err(format!("Invalid hex byte in AOB: '{token}'")),
            }
        }
    }

    if pattern.is_empty() {
        return Err("AOB pattern cannot be empty".to_string());
    }

    Ok(pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_aob_pattern() {
        let pattern = parse_aob_pattern("48 8B ?? ?? C3").expect("Should parse valid AOB");
        assert_eq!(pattern.len(), 5);
        assert_eq!(pattern[0], Some(0x48));
        assert_eq!(pattern[1], Some(0x8B));
        assert_eq!(pattern[2], None);
        assert_eq!(pattern[3], None);
        assert_eq!(pattern[4], Some(0xC3));
    }

    #[test]
    fn test_scan_value_read_from_slice() {
        let bytes = [0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3F];
        let val_i32 = ScanValue::read_from_slice(&bytes, 0, ScanValueType::I32).unwrap();
        assert_eq!(val_i32, ScanValue::I32(100));

        let val_f32 = ScanValue::read_from_slice(&bytes, 4, ScanValueType::F32).unwrap();
        assert_eq!(val_f32, ScanValue::F32(1.0));
    }
}
