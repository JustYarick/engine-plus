use engine_pal::os::wine::pe::{parse_pe_headers, PeHeaderInfo};
use engine_pal::ProtectionFlags;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionSummary {
    pub name: String,
    pub virtual_address: String,
    pub virtual_size: usize,
    pub raw_data_offset: String,
    pub raw_data_size: usize,
    pub protection: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryAnalysisResult {
    pub format: String,
    pub architecture: String,
    pub image_base: Option<String>,
    pub entry_point: String,
    pub total_file_size: u64,
    pub sections: Vec<SectionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub offset: String,
    pub text: String,
    pub length: usize,
    pub encoding: &'static str,
}

/// Analyze executable or library headers (PE or ELF)
pub fn analyze_file(path: &Path) -> Result<BinaryAnalysisResult, String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {e}"))?;
    let file_size = file
        .metadata()
        .map_err(|e| format!("Failed to get metadata: {e}"))?
        .len();

    // Read header chunk (first 64 KB is typically enough for all headers and section tables)
    let header_read_size = (file_size.min(65536)) as usize;
    let mut header_buf = vec![0u8; header_read_size];
    file.read_exact(&mut header_buf)
        .map_err(|e| format!("Failed to read header: {e}"))?;

    // Check for PE format (starts with "MZ")
    if header_buf.len() >= 2 && header_buf[0] == b'M' && header_buf[1] == b'Z' {
        return analyze_pe(&header_buf, file_size);
    }

    // Check for ELF format (starts with "\x7fELF")
    if header_buf.len() >= 4 && &header_buf[..4] == b"\x7fELF" {
        return analyze_elf(&header_buf, file_size);
    }

    Err("Unknown or unsupported binary format (neither PE nor ELF)".to_string())
}

fn analyze_pe(header_buf: &[u8], file_size: u64) -> Result<BinaryAnalysisResult, String> {
    let pe_info: PeHeaderInfo =
        parse_pe_headers(header_buf).map_err(|e| format!("PE parsing failed: {e}"))?;

    let sections = pe_info
        .sections
        .into_iter()
        .map(|s| {
            let mut prot_str = Vec::new();
            if s.protection.contains(ProtectionFlags::READ) {
                prot_str.push("R");
            }
            if s.protection.contains(ProtectionFlags::WRITE) {
                prot_str.push("W");
            }
            if s.protection.contains(ProtectionFlags::EXECUTE) {
                prot_str.push("X");
            }

            SectionSummary {
                name: s.name,
                virtual_address: format!("0x{:X}", s.virtual_address),
                virtual_size: s.virtual_size as usize,
                raw_data_offset: format!("0x{:X}", s.raw_data_offset),
                raw_data_size: s.raw_data_size as usize,
                protection: prot_str.join(""),
            }
        })
        .collect();

    Ok(BinaryAnalysisResult {
        format: "Windows PE (Portable Executable)".to_string(),
        architecture: format!("{:?}", pe_info.architecture),
        image_base: Some(format!("0x{:X}", pe_info.image_base.as_u64())),
        entry_point: format!("0x{:X}", pe_info.entry_point_rva),
        total_file_size: file_size,
        sections,
    })
}

fn analyze_elf(header_buf: &[u8], file_size: u64) -> Result<BinaryAnalysisResult, String> {
    if header_buf.len() < 52 {
        return Err("ELF header buffer too small".to_string());
    }

    let is_64 = header_buf[4] == 2;
    let arch = if is_64 {
        let machine = u16::from_le_bytes(header_buf[18..20].try_into().unwrap());
        match machine {
            0x3E => "X86_64",
            0xB7 => "AArch64",
            _ => "Unknown",
        }
    } else {
        "X86_32"
    };

    let entry_point = if is_64 && header_buf.len() >= 32 {
        let entry = u64::from_le_bytes(header_buf[24..32].try_into().unwrap());
        format!("0x{:X}", entry)
    } else {
        let entry = u32::from_le_bytes(header_buf[24..28].try_into().unwrap());
        format!("0x{:X}", entry)
    };

    Ok(BinaryAnalysisResult {
        format: if is_64 { "ELF64" } else { "ELF32" }.to_string(),
        architecture: arch.to_string(),
        image_base: None,
        entry_point,
        total_file_size: file_size,
        sections: Vec::new(),
    })
}

/// Extract printable strings from static binary file
pub fn extract_strings_from_file(
    path: &Path,
    min_len: usize,
    max_results: usize,
    filter: Option<&str>,
) -> Result<Vec<ExtractedString>, String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {e}"))?;
    let mut results = Vec::new();
    let filter_lower = filter.map(|f| f.to_lowercase());

    // Stream through file in 64 KB blocks to maintain small memory footprint
    let mut buffer = vec![0u8; 65536];
    let mut total_offset: u64 = 0;
    let mut current_string = Vec::new();
    let mut str_start_offset: u64 = 0;

    loop {
        let read_bytes = file
            .read(&mut buffer)
            .map_err(|e| format!("Read error: {e}"))?;
        if read_bytes == 0 {
            break;
        }

        for (i, &b) in buffer[..read_bytes].iter().enumerate() {
            let file_offset = total_offset + i as u64;

            if b.is_ascii_graphic() || b == b' ' {
                if current_string.is_empty() {
                    str_start_offset = file_offset;
                }
                current_string.push(b);
            } else {
                if current_string.len() >= min_len {
                    if let Ok(s) = String::from_utf8(current_string.clone()) {
                        let matches_filter = match &filter_lower {
                            Some(f) => s.to_lowercase().contains(f),
                            None => true,
                        };

                        if matches_filter {
                            results.push(ExtractedString {
                                offset: format!("0x{:X}", str_start_offset),
                                text: s,
                                length: current_string.len(),
                                encoding: "ASCII/UTF-8",
                            });

                            if results.len() >= max_results {
                                return Ok(results);
                            }
                        }
                    }
                }
                current_string.clear();
            }
        }

        total_offset += read_bytes as u64;
    }

    Ok(results)
}

/// Disassemble machine code bytes from file by RVA or raw offset
pub fn disassemble_file_code(
    path: &Path,
    rva_or_offset: u64,
    is_rva: bool,
    size: usize,
    bitness: u32,
) -> Result<String, String> {
    let size = size.clamp(1, 512);
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {e}"))?;

    let file_offset = if is_rva {
        // Parse PE section headers to convert RVA to raw file offset
        let mut header_buf = vec![0u8; 65536];
        let n = file
            .read(&mut header_buf)
            .map_err(|e| format!("Failed to read header: {e}"))?;
        header_buf.truncate(n);

        let pe_info = parse_pe_headers(&header_buf)
            .map_err(|e| format!("Failed to parse PE for RVA resolution: {e}"))?;

        let mut resolved_offset = None;
        for s in pe_info.sections {
            if rva_or_offset >= s.virtual_address && rva_or_offset < s.virtual_address + s.virtual_size {
                let delta = rva_or_offset - s.virtual_address;
                resolved_offset = Some(s.raw_data_offset + delta);
                break;
            }
        }

        resolved_offset.ok_or_else(|| {
            format!("RVA 0x{:X} does not fall within any PE section", rva_or_offset)
        })?
    } else {
        rva_or_offset
    };

    file.seek(SeekFrom::Start(file_offset))
        .map_err(|e| format!("Seek failed to offset 0x{:X}: {e}", file_offset))?;

    let mut code_buf = vec![0u8; size];
    let n = file
        .read(&mut code_buf)
        .map_err(|e| format!("Read code bytes failed: {e}"))?;
    code_buf.truncate(n);

    if code_buf.is_empty() {
        return Err("No code bytes could be read at offset".to_string());
    }

    let mut decoder = Decoder::with_ip(bitness, &code_buf, rva_or_offset, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut output = String::new();
    let mut instruction = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        let mut instr_str = String::new();
        formatter.format(&instruction, &mut instr_str);
        output.push_str(&format!("0x{:016X}: {}\n", instruction.ip(), instr_str));
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_extract_strings_from_temp_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("engine_mcp_test_strings.bin");

        {
            let mut f = File::create(&test_file).unwrap();
            f.write_all(b"\x00\x00\x00PlayerHealth\x00\x00GameAssembly.dll\x00\x00").unwrap();
        }

        let strings = extract_strings_from_file(&test_file, 4, 10, None).unwrap();
        assert!(strings.iter().any(|s| s.text == "PlayerHealth"));
        assert!(strings.iter().any(|s| s.text == "GameAssembly.dll"));

        let filtered = extract_strings_from_file(&test_file, 4, 10, Some("player")).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].text, "PlayerHealth");

        let _ = std::fs::remove_file(test_file);
    }
}
