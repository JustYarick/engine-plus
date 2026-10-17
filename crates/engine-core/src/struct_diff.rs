use engine_pal::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub offset: usize,
    pub offset_hex: String,
    pub size: usize,
    pub old_bytes_hex: String,
    pub new_bytes_hex: String,
    pub old_i32: Option<i32>,
    pub new_i32: Option<i32>,
    pub old_f32: Option<f32>,
    pub new_f32: Option<f32>,
    pub old_u64: Option<u64>,
    pub new_u64: Option<u64>,
    pub summary: String,
}

/// Compute differences between two memory snapshots of an object/struct
pub fn compute_struct_diff(
    _base_address: Address,
    old_bytes: &[u8],
    new_bytes: &[u8],
) -> Vec<DiffEntry> {
    let min_len = old_bytes.len().min(new_bytes.len());
    let mut diffs = Vec::new();
    let mut i = 0;

    while i < min_len {
        if old_bytes[i] != new_bytes[i] {
            let start_offset = i;

            // Expand to natural field boundaries if possible (e.g. 4-byte or 8-byte aligned)
            // Find end of contiguous difference
            while i < min_len && old_bytes[i] != new_bytes[i] {
                i += 1;
            }

            // Align start and end to 4 bytes if change is within a 4-byte slot and in bounds
            let aligned_start = (start_offset / 4) * 4;
            let aligned_end = i.div_ceil(4) * 4;
            let (chunk_start, chunk_end) = if aligned_end <= min_len && (aligned_end - aligned_start) <= 8 {
                (aligned_start, aligned_end)
            } else {
                (start_offset, i)
            };

            let chunk_size = chunk_end - chunk_start;
            let old_slice = &old_bytes[chunk_start..chunk_end];
            let new_slice = &new_bytes[chunk_start..chunk_end];

            let old_hex = old_slice.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
            let new_hex = new_slice.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");

            let mut old_i32 = None;
            let mut new_i32 = None;
            let mut old_f32 = None;
            let mut new_f32 = None;
            let mut old_u64 = None;
            let mut new_u64 = None;
            let mut summary_parts = Vec::new();

            if chunk_size == 4 {
                let o_i32 = i32::from_le_bytes(old_slice.try_into().unwrap_or([0; 4]));
                let n_i32 = i32::from_le_bytes(new_slice.try_into().unwrap_or([0; 4]));
                let o_f32 = f32::from_le_bytes(old_slice.try_into().unwrap_or([0; 4]));
                let n_f32 = f32::from_le_bytes(new_slice.try_into().unwrap_or([0; 4]));
                old_i32 = Some(o_i32);
                new_i32 = Some(n_i32);
                old_f32 = Some(o_f32);
                new_f32 = Some(n_f32);

                if o_f32.is_finite() && n_f32.is_finite() && (o_f32.abs() > 0.001 || n_f32.abs() > 0.001) && o_f32.abs() < 100000.0 && n_f32.abs() < 100000.0 {
                    summary_parts.push(format!("f32: {o_f32:.2} -> {n_f32:.2}"));
                }
                summary_parts.push(format!("i32: {o_i32} -> {n_i32}"));
            } else if chunk_size == 8 {
                let o_u64 = u64::from_le_bytes(old_slice.try_into().unwrap_or([0; 8]));
                let n_u64 = u64::from_le_bytes(new_slice.try_into().unwrap_or([0; 8]));
                old_u64 = Some(o_u64);
                new_u64 = Some(n_u64);
                summary_parts.push(format!("u64/ptr: 0x{o_u64:X} -> 0x{n_u64:X}"));
            } else {
                summary_parts.push(format!("hex: [{old_hex}] -> [{new_hex}]"));
            }

            diffs.push(DiffEntry {
                offset: chunk_start,
                offset_hex: format!("+0x{chunk_start:X}"),
                size: chunk_size,
                old_bytes_hex: old_hex,
                new_bytes_hex: new_hex,
                old_i32,
                new_i32,
                old_f32,
                new_f32,
                old_u64,
                new_u64,
                summary: summary_parts.join(", "),
            });

            i = chunk_end;
        } else {
            i += 1;
        }
    }

    diffs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_struct_diff_i32_and_float() {
        let mut old = vec![0u8; 32];
        let mut new = vec![0u8; 32];

        // Offset 0: Health changed from 100 to 95
        old[0..4].copy_from_slice(&100i32.to_le_bytes());
        new[0..4].copy_from_slice(&95i32.to_le_bytes());

        // Offset 16: Position Y changed from 12.5f to 15.0f
        old[16..20].copy_from_slice(&12.5f32.to_le_bytes());
        new[16..20].copy_from_slice(&15.0f32.to_le_bytes());

        let diffs = compute_struct_diff(Address::new(0x1000), &old, &new);
        assert_eq!(diffs.len(), 2);
        assert_eq!(diffs[0].offset, 0);
        assert_eq!(diffs[0].offset_hex, "+0x0");
        assert_eq!(diffs[0].old_i32, Some(100));
        assert_eq!(diffs[0].new_i32, Some(95));

        assert_eq!(diffs[1].offset, 16);
        assert_eq!(diffs[1].offset_hex, "+0x10");
        assert_eq!(diffs[1].old_f32, Some(12.5));
        assert_eq!(diffs[1].new_f32, Some(15.0));
    }
}
