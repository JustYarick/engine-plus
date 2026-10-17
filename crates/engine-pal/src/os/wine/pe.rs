use crate::types::{Address, CpuArchitecture, ProtectionFlags};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_data_offset: u64,
    pub raw_data_size: u64,
    pub protection: ProtectionFlags,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeHeaderInfo {
    pub architecture: CpuArchitecture,
    pub image_base: Address,
    pub entry_point_rva: u64,
    pub size_of_image: u64,
    pub sections: Vec<PeSectionInfo>,
}

#[derive(Debug, thiserror::Error)]
pub enum PeParseError {
    #[error("Buffer too small for DOS header")]
    BufferTooSmall,
    #[error("Invalid DOS signature (expected 'MZ')")]
    InvalidDosSignature,
    #[error("Invalid PE offset in DOS header")]
    InvalidPeOffset,
    #[error("Invalid PE signature (expected 'PE\\0\\0')")]
    InvalidPeSignature,
    #[error("Unsupported COFF machine type: 0x{0:04X}")]
    UnsupportedMachine(u16),
    #[error("Invalid Optional Header magic: 0x{0:04X}")]
    InvalidOptionalHeader(u16),
}

/// Parse Windows PE (Portable Executable 32-bit / 64-bit) header and sections from byte slice
pub fn parse_pe_headers(bytes: &[u8]) -> Result<PeHeaderInfo, PeParseError> {
    if bytes.len() < 0x40 {
        return Err(PeParseError::BufferTooSmall);
    }

    // 1. Verify DOS Header "MZ" (0x5A4D)
    if bytes[0] != b'M' || bytes[1] != b'Z' {
        return Err(PeParseError::InvalidDosSignature);
    }

    // Offset to PE Header is at 0x3C (e_lfanew)
    let pe_offset = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    if pe_offset + 24 > bytes.len() {
        return Err(PeParseError::InvalidPeOffset);
    }

    // 2. Verify PE signature "PE\0\0"
    if &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(PeParseError::InvalidPeSignature);
    }

    // 3. COFF File Header (20 bytes after signature)
    let coff_offset = pe_offset + 4;
    let machine = u16::from_le_bytes(bytes[coff_offset..coff_offset + 2].try_into().unwrap());
    let num_sections = u16::from_le_bytes(bytes[coff_offset + 2..coff_offset + 4].try_into().unwrap()) as usize;
    let size_of_opt_header = u16::from_le_bytes(bytes[coff_offset + 16..coff_offset + 18].try_into().unwrap()) as usize;

    let architecture = match machine {
        0x8664 => CpuArchitecture::X86_64,
        0x014C => CpuArchitecture::X86_32,
        _ => return Err(PeParseError::UnsupportedMachine(machine)),
    };

    // 4. Optional Header
    let opt_offset = coff_offset + 20;
    if opt_offset + size_of_opt_header > bytes.len() {
        return Err(PeParseError::BufferTooSmall);
    }

    let opt_magic = u16::from_le_bytes(bytes[opt_offset..opt_offset + 2].try_into().unwrap());
    let is_pe32_plus = match opt_magic {
        0x010B => false, // PE32
        0x020B => true,  // PE32+ (64-bit)
        _ => return Err(PeParseError::InvalidOptionalHeader(opt_magic)),
    };

    let entry_point_rva = u32::from_le_bytes(bytes[opt_offset + 16..opt_offset + 20].try_into().unwrap()) as u64;

    let (image_base, size_of_image) = if is_pe32_plus {
        let base = u64::from_le_bytes(bytes[opt_offset + 24..opt_offset + 32].try_into().unwrap());
        let size = u32::from_le_bytes(bytes[opt_offset + 56..opt_offset + 60].try_into().unwrap()) as u64;
        (Address::new(base), size)
    } else {
        let base = u32::from_le_bytes(bytes[opt_offset + 28..opt_offset + 32].try_into().unwrap()) as u64;
        let size = u32::from_le_bytes(bytes[opt_offset + 56..opt_offset + 60].try_into().unwrap()) as u64;
        (Address::new(base), size)
    };

    // 5. Section Headers (follow Optional Header, 40 bytes each)
    let section_headers_offset = opt_offset + size_of_opt_header;
    let mut sections = Vec::with_capacity(num_sections);

    for i in 0..num_sections {
        let s_offset = section_headers_offset + (i * 40);
        if s_offset + 40 > bytes.len() {
            break;
        }

        // Section name: 8-byte null-padded ASCII
        let name_bytes = &bytes[s_offset..s_offset + 8];
        let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_len]).to_string();

        let virtual_size = u32::from_le_bytes(bytes[s_offset + 8..s_offset + 12].try_into().unwrap()) as u64;
        let virtual_address = u32::from_le_bytes(bytes[s_offset + 12..s_offset + 16].try_into().unwrap()) as u64;
        let raw_data_size = u32::from_le_bytes(bytes[s_offset + 16..s_offset + 20].try_into().unwrap()) as u64;
        let raw_data_offset = u32::from_le_bytes(bytes[s_offset + 20..s_offset + 24].try_into().unwrap()) as u64;
        let characteristics = u32::from_le_bytes(bytes[s_offset + 36..s_offset + 40].try_into().unwrap());

        // Characteristics bit flags:
        // IMAGE_SCN_MEM_EXECUTE = 0x20000000
        // IMAGE_SCN_MEM_READ    = 0x40000000
        // IMAGE_SCN_MEM_WRITE   = 0x80000000
        let mut protection = ProtectionFlags::NONE;
        if (characteristics & 0x4000_0000) != 0 {
            protection |= ProtectionFlags::READ;
        }
        if (characteristics & 0x8000_0000) != 0 {
            protection |= ProtectionFlags::WRITE;
        }
        if (characteristics & 0x2000_0000) != 0 {
            protection |= ProtectionFlags::EXECUTE;
        }

        sections.push(PeSectionInfo {
            name,
            virtual_address,
            virtual_size,
            raw_data_offset,
            raw_data_size,
            protection,
        });
    }

    Ok(PeHeaderInfo {
        architecture,
        image_base,
        entry_point_rva,
        size_of_image,
        sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_synthetic_pe64() {
        let mut buffer = vec![0u8; 512];

        // DOS Header
        buffer[0] = b'M';
        buffer[1] = b'Z';
        let pe_offset: u32 = 0x80;
        buffer[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());

        // PE Header signature
        let p = pe_offset as usize;
        buffer[p..p + 4].copy_from_slice(b"PE\0\0");

        // COFF Header (20 bytes)
        let coff = p + 4;
        let machine: u16 = 0x8664; // x86_64
        let num_sections: u16 = 2;
        let opt_size: u16 = 0xF0;
        buffer[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
        buffer[coff + 2..coff + 4].copy_from_slice(&num_sections.to_le_bytes());
        buffer[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());

        // Optional Header (PE32+)
        let opt = coff + 20;
        let magic: u16 = 0x020B; // PE32+
        let entry_point: u32 = 0x1500;
        let image_base: u64 = 0x140000000;
        let size_of_image: u32 = 0x10000;
        buffer[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
        buffer[opt + 16..opt + 20].copy_from_slice(&entry_point.to_le_bytes());
        buffer[opt + 24..opt + 32].copy_from_slice(&image_base.to_le_bytes());
        buffer[opt + 56..opt + 60].copy_from_slice(&size_of_image.to_le_bytes());

        // Section 1: .text
        let sec1 = opt + opt_size as usize;
        buffer[sec1..sec1 + 5].copy_from_slice(b".text");
        let virt_size: u32 = 0x2000;
        let virt_addr: u32 = 0x1000;
        let raw_size: u32 = 0x2000;
        let raw_offset: u32 = 0x400;
        let chars: u32 = 0x60000020; // EXECUTE | READ
        buffer[sec1 + 8..sec1 + 12].copy_from_slice(&virt_size.to_le_bytes());
        buffer[sec1 + 12..sec1 + 16].copy_from_slice(&virt_addr.to_le_bytes());
        buffer[sec1 + 16..sec1 + 20].copy_from_slice(&raw_size.to_le_bytes());
        buffer[sec1 + 20..sec1 + 24].copy_from_slice(&raw_offset.to_le_bytes());
        buffer[sec1 + 36..sec1 + 40].copy_from_slice(&chars.to_le_bytes());

        let info = parse_pe_headers(&buffer).expect("Should parse PE64 headers");
        assert_eq!(info.architecture, CpuArchitecture::X86_64);
        assert_eq!(info.image_base, Address::new(0x140000000));
        assert_eq!(info.entry_point_rva, 0x1500);
        assert_eq!(info.sections.len(), 2);
        assert_eq!(info.sections[0].name, ".text");
        assert!(info.sections[0].protection.contains(ProtectionFlags::EXECUTE));
        assert!(info.sections[0].protection.contains(ProtectionFlags::READ));
    }
}
