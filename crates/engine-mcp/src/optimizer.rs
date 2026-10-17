use engine_pal::{Address, MemoryRegion};
use serde::{Deserialize, Serialize};

/// Compact semantic summary of a memory block optimized for LLM token efficiency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStructureSummary {
    pub base_address: String,
    pub total_size: usize,
    pub zero_ranges: Vec<[usize; 2]>,
    pub strings: Vec<StringEntry>,
    pub pointers: Vec<PointerEntry>,
    pub floats: Vec<FloatEntry>,
    pub integers: Vec<IntegerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    pub offset: String,
    pub text: String,
    pub encoding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerEntry {
    pub offset: String,
    pub target_address: String,
    pub region_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FloatEntry {
    pub offset: String,
    pub value: f32,
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegerEntry {
    pub offset: String,
    pub as_i32: i32,
    pub as_u32: u32,
}

/// Analyze raw bytes with heuristics to produce a token-efficient semantic structure
pub fn analyze_memory_block(
    base: Address,
    bytes: &[u8],
    mapped_regions: &[MemoryRegion],
) -> MemoryStructureSummary {
    let mut zero_ranges = Vec::new();
    let mut strings = Vec::new();
    let mut pointers = Vec::new();
    let mut floats = Vec::new();
    let mut integers = Vec::new();

    // 1. Detect zero ranges to omit redundant zeros
    let mut in_zero = false;
    let mut zero_start = 0;

    for (i, &b) in bytes.iter().enumerate() {
        if b == 0 {
            if !in_zero {
                in_zero = true;
                zero_start = i;
            }
        } else if in_zero {
            in_zero = false;
            if i - zero_start >= 16 {
                zero_ranges.push([zero_start, i]);
            }
        }
    }
    if in_zero && bytes.len() - zero_start >= 16 {
        zero_ranges.push([zero_start, bytes.len()]);
    }

    // 2. Detect 64-bit pointers (aligned to 8 bytes)
    for offset in (0..bytes.len().saturating_sub(7)).step_by(8) {
        let val = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        if val > 0x10000 && val < 0x7FFFFFFF_FFFFFFFF {
            let target_addr = Address::new(val);
            if let Some(reg) = mapped_regions.iter().find(|r| r.contains(target_addr)) {
                let info = reg.path.clone().unwrap_or_else(|| {
                    if reg.is_executable() {
                        "executable code".to_string()
                    } else if reg.is_writable() {
                        "heap / rw data".to_string()
                    } else {
                        "rodata".to_string()
                    }
                });

                pointers.push(PointerEntry {
                    offset: format!("+0x{:X}", offset),
                    target_address: format!("0x{:X}", val),
                    region_info: Some(info),
                });
            }
        }
    }

    // 3. Detect 32-bit floats (aligned to 4 bytes)
    for offset in (0..bytes.len().saturating_sub(3)).step_by(4) {
        let val = f32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        if val.is_finite() && !val.is_nan() && val.abs() >= 0.001 && val.abs() <= 1_000_000.0 {
            // Check if looks like a coordinate, health, or percent
            let hint = if (0.0..=100.0).contains(&val) {
                Some("health / percent / ratio?".to_string())
            } else if val.abs() > 10.0 {
                Some("coordinate / velocity / distance?".to_string())
            } else {
                None
            };

            floats.push(FloatEntry {
                offset: format!("+0x{:X}", offset),
                value: (val * 1000.0).round() / 1000.0,
                hint,
            });
        }
    }

    // 4. Detect non-trivial integers (aligned to 4 bytes)
    for offset in (0..bytes.len().saturating_sub(3)).step_by(4) {
        let val_i32 = i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let val_u32 = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        if val_i32 > 0 && val_i32 < 100_000_000 {
            integers.push(IntegerEntry {
                offset: format!("+0x{:X}", offset),
                as_i32: val_i32,
                as_u32: val_u32,
            });
        }
    }

    // 5. Detect printable ASCII strings (>= 4 chars)
    let mut current_ascii = Vec::new();
    let mut ascii_start = 0;

    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' {
            if current_ascii.is_empty() {
                ascii_start = i;
            }
            current_ascii.push(b);
        } else {
            if current_ascii.len() >= 4 {
                if let Ok(s) = String::from_utf8(current_ascii.clone()) {
                    strings.push(StringEntry {
                        offset: format!("+0x{:X}", ascii_start),
                        text: s,
                        encoding: "ascii/utf8".to_string(),
                    });
                }
            }
            current_ascii.clear();
        }
    }

    MemoryStructureSummary {
        base_address: format!("0x{:X}", base.as_u64()),
        total_size: bytes.len(),
        zero_ranges,
        strings,
        pointers,
        floats,
        integers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimizer_finds_floats_integers_strings_zeros() {
        let mut buffer = vec![0u8; 64];

        // Put a string at offset 0
        let s = b"PlayerOne";
        buffer[..s.len()].copy_from_slice(s);

        // Put a float at offset 16 (aligned to 4)
        let hp: f32 = 99.5;
        buffer[16..20].copy_from_slice(&hp.to_le_bytes());

        // Put an integer at offset 24
        let score: i32 = 42000;
        buffer[24..28].copy_from_slice(&score.to_le_bytes());

        // Leave 32..64 all zeros (32 consecutive zeros)

        let summary = analyze_memory_block(Address::new(0x1000), &buffer, &[]);

        assert_eq!(summary.base_address, "0x1000");
        assert_eq!(summary.total_size, 64);

        // Check string
        assert!(summary.strings.iter().any(|st| st.text == "PlayerOne"));

        // Check float
        assert!(summary.floats.iter().any(|f| (f.value - 99.5).abs() < 0.01));

        // Check integer
        assert!(summary.integers.iter().any(|it| it.as_i32 == 42000));

        // Check zero range
        assert!(summary.zero_ranges.iter().any(|r| r[0] <= 28 && r[1] == 64));
    }
}
