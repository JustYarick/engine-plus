//! Minimal PE (Portable Executable) parser sufficient for manual mapping,
//! reflective loading, header erasure and export resolution.
//!
//! This is intentionally hand-rolled (rather than pulling the `object` crate's
//! higher-level PE reader) so that manual mapping has full control over raw
//! data directories, relocation blocks and import thunks.

use crate::error::{InjectError, InjectResult};
use engine_pal::types::CpuArchitecture;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;

const IMAGE_FILE_DLL: u16 = 0x2000;

// Section characteristics
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// Data directory indices
pub const DD_EXPORT: usize = 0;
pub const DD_IMPORT: usize = 1;
pub const DD_BASERELOC: usize = 5;
pub const DD_TLS: usize = 9;

// Relocation types
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;

/// A single section header from the image.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    /// Compute the section's page-aligned size in memory.
    pub fn mapped_size(&self) -> usize {
        align_up(self.virtual_size.max(self.raw_size) as usize, 0x1000)
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }
    pub fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }
}

/// One imported DLL and the thunks that must be resolved against it.
#[derive(Debug, Clone)]
pub struct ImportDescriptor {
    /// DLL name as it appears in the image (e.g. "KERNEL32.dll").
    pub name: String,
    /// RVA of the Import Address Table (filled after relocation).
    pub first_thunk: u32,
    /// RVA of the OriginalFirstThunk (name/ordinal table); may be 0.
    pub original_first_thunk: u32,
}

/// A relocation block: page RVA plus a list of (offset, type) entries.
#[derive(Debug, Clone)]
pub struct RelocBlock {
    pub page_rva: u32,
    /// (offset within page, relocation type)
    pub entries: Vec<(u16, u16)>,
}

/// Fully-parsed view of a PE image kept in a local buffer.
pub struct PeImage {
    pub data: Vec<u8>,
    pub architecture: CpuArchitecture,
    pub is_dll: bool,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub entry_point_rva: u32,
    pub sections: Vec<Section>,
    pub imports: Vec<ImportDescriptor>,
    pub relocs: Vec<RelocBlock>,
    pub export_dir_rva: u32,
    pub export_dir_size: u32,
}

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

impl PeImage {
    /// Parse a PE image from a raw file buffer.
    pub fn parse(data: Vec<u8>) -> InjectResult<PeImage> {
        if data.len() < 0x40 {
            return Err(InjectError::InvalidImage("buffer smaller than DOS header".into()));
        }
        let dos_magic = read_u16(&data, 0).ok_or_else(|| {
            InjectError::InvalidImage("cannot read DOS magic".into())
        })?;
        if dos_magic != IMAGE_DOS_SIGNATURE {
            return Err(InjectError::InvalidImage("missing MZ signature".into()));
        }

        let pe_offset = read_u32(&data, 0x3C)
            .ok_or_else(|| InjectError::InvalidImage("cannot read e_lfanew".into()))? as usize;

        let nt_sig = read_u32(&data, pe_offset)
            .ok_or_else(|| InjectError::InvalidImage("cannot read NT signature".into()))?;
        if nt_sig != IMAGE_NT_SIGNATURE {
            return Err(InjectError::InvalidImage("missing PE signature".into()));
        }

        let coff = pe_offset + 4;
        let machine = read_u16(&data, coff)
            .ok_or_else(|| InjectError::Malformed("COFF machine".into()))?;
        let num_sections = read_u16(&data, coff + 2)
            .ok_or_else(|| InjectError::Malformed("COFF num sections".into()))? as usize;
        let size_of_opt_header = read_u16(&data, coff + 16)
            .ok_or_else(|| InjectError::Malformed("COFF optional header size".into()))? as usize;
        let characteristics = read_u16(&data, coff + 18)
            .ok_or_else(|| InjectError::Malformed("COFF characteristics".into()))?;

        let architecture = match machine {
            0x8664 => CpuArchitecture::X86_64,
            0x014C => CpuArchitecture::X86_32,
            other => {
                return Err(InjectError::InvalidImage(format!(
                    "unsupported machine 0x{other:04X}"
                )))
            }
        };
        let is_dll = characteristics & IMAGE_FILE_DLL != 0;

        let opt = coff + 20;
        let opt_magic = read_u16(&data, opt)
            .ok_or_else(|| InjectError::Malformed("optional header magic".into()))?;
        let pe32_plus = match opt_magic {
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => true,
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => false,
            other => {
                return Err(InjectError::InvalidImage(format!(
                    "unsupported optional header magic 0x{other:04X}"
                )))
            }
        };

        let entry_point_rva = read_u32(&data, opt + 16)
            .ok_or_else(|| InjectError::Malformed("AddressOfEntryPoint".into()))?;
        let (image_base, size_of_image, size_of_headers) = if pe32_plus {
            let base = read_u64(&data, opt + 24)
                .ok_or_else(|| InjectError::Malformed("ImageBase".into()))?;
            let image = read_u32(&data, opt + 56)
                .ok_or_else(|| InjectError::Malformed("SizeOfImage".into()))?;
            let headers = read_u32(&data, opt + 60)
                .ok_or_else(|| InjectError::Malformed("SizeOfHeaders".into()))?;
            (base, image, headers)
        } else {
            let base = read_u32(&data, opt + 28)
                .ok_or_else(|| InjectError::Malformed("ImageBase".into()))? as u64;
            let image = read_u32(&data, opt + 56)
                .ok_or_else(|| InjectError::Malformed("SizeOfImage".into()))?;
            let headers = read_u32(&data, opt + 60)
                .ok_or_else(|| InjectError::Malformed("SizeOfHeaders".into()))?;
            (base, image, headers)
        };

        // Data directories start after the standard optional header fields.
        // PE32+: 112 bytes in; PE32: 96 bytes in.
        let (dd_offset, num_rva_and_sizes) = if pe32_plus {
            (
                opt + 112,
                read_u32(&data, opt + 108)
                    .ok_or_else(|| InjectError::Malformed("NumberOfRvaAndSizes".into()))?
                    as usize,
            )
        } else {
            (
                opt + 96,
                read_u32(&data, opt + 92)
                    .ok_or_else(|| InjectError::Malformed("NumberOfRvaAndSizes".into()))?
                    as usize,
            )
        };

        let read_dd = |index: usize| -> (u32, u32) {
            if index >= num_rva_and_sizes {
                return (0, 0);
            }
            let off = dd_offset + index * 8;
            let rva = read_u32(&data, off).unwrap_or(0);
            let size = read_u32(&data, off + 4).unwrap_or(0);
            (rva, size)
        };

        let (export_dir_rva, export_dir_size) = read_dd(DD_EXPORT);
        let (import_rva, import_size) = read_dd(DD_IMPORT);
        let (reloc_rva, reloc_size) = read_dd(DD_BASERELOC);
        let _ = import_size;

        // Section headers follow the optional header.
        let section_offset = opt + size_of_opt_header;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = section_offset + i * 40;
            if s + 40 > data.len() {
                return Err(InjectError::Malformed("section header out of bounds".into()));
            }
            let name_bytes = &data[s..s + 8];
            let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_len]).into_owned();

            sections.push(Section {
                name,
                virtual_size: read_u32(&data, s + 8).unwrap_or(0),
                virtual_address: read_u32(&data, s + 12).unwrap_or(0),
                raw_size: read_u32(&data, s + 16).unwrap_or(0),
                raw_offset: read_u32(&data, s + 20).unwrap_or(0),
                characteristics: read_u32(&data, s + 36).unwrap_or(0),
            });
        }

        let imports = if import_rva != 0 {
            parse_imports(&data, import_rva, &sections)?
        } else {
            Vec::new()
        };

        let relocs = if reloc_rva != 0 {
            parse_relocs(&data, reloc_rva, reloc_size, &sections)?
        } else {
            Vec::new()
        };

        Ok(PeImage {
            data,
            architecture,
            is_dll,
            image_base,
            size_of_image,
            size_of_headers,
            entry_point_rva,
            sections,
            imports,
            relocs,
            export_dir_rva,
            export_dir_size,
        })
    }

    /// Resolve an exported function's RVA by name using the local image copy.
    pub fn find_export_rva(&self, name: &str) -> Option<u32> {
        if self.export_dir_rva == 0 {
            return None;
        }
        let data = &self.data;
        let dir = rva_to_offset(self.export_dir_rva, &self.sections)?;
        let number_of_names = read_u32(data, dir + 24)? as usize;
        let addr_of_funcs = read_u32(data, dir + 28)?;
        let addr_of_names = read_u32(data, dir + 32)?;
        let addr_of_ords = read_u32(data, dir + 36)?;

        let names_offset = rva_to_offset(addr_of_names, &self.sections)?;
        let ords_offset = rva_to_offset(addr_of_ords, &self.sections)?;
        let funcs_offset = rva_to_offset(addr_of_funcs, &self.sections)?;

        for i in 0..number_of_names {
            let name_rva = read_u32(data, names_offset + i * 4)?;
            let name_offset = rva_to_offset(name_rva, &self.sections)?;
            let export_name = read_ascii_string(data, name_offset)?;
            if export_name == name {
                let ord = read_u16(data, ords_offset + i * 2)? as usize;
                let func_rva = read_u32(data, funcs_offset + ord * 4)?;
                return Some(func_rva);
            }
        }
        None
    }

    /// Apply base relocations to a local buffer laid out as it will appear in
    /// memory (`image` is `size_of_image` bytes, sections copied to their
    /// virtual addresses). `delta` is `remote_base - image_base`.
    pub fn apply_relocations(&self, image: &mut [u8], delta: i64) -> InjectResult<usize> {
        let mut applied = 0usize;
        for block in &self.relocs {
            for &(offset, rel_type) in &block.entries {
                let rva = block.page_rva.wrapping_add(offset as u32) as usize;
                match rel_type {
                    IMAGE_REL_BASED_ABSOLUTE => {}
                    IMAGE_REL_BASED_DIR64 => {
                        let slot = rva;
                        if slot + 8 > image.len() {
                            continue;
                        }
                        let value = read_u64(image, slot).unwrap_or(0);
                        let new = (value as i64).wrapping_add(delta) as u64;
                        image[slot..slot + 8].copy_from_slice(&new.to_le_bytes());
                        applied += 1;
                    }
                    IMAGE_REL_BASED_HIGHLOW => {
                        let slot = rva;
                        if slot + 4 > image.len() {
                            continue;
                        }
                        let value = read_u32(image, slot).unwrap_or(0);
                        let new = (value as i64).wrapping_add(delta) as u32;
                        image[slot..slot + 4].copy_from_slice(&new.to_le_bytes());
                        applied += 1;
                    }
                    _ => {}
                }
            }
        }
        Ok(applied)
    }

    /// Copy section raw data into a `size_of_image`-sized local image buffer.
    /// Headers are copied up to `size_of_headers`; the remainder is zeroed.
    pub fn build_local_image(&self, include_headers: bool) -> Vec<u8> {
        let mut image = vec![0u8; self.size_of_image as usize];
        if include_headers {
            let header_len = (self.size_of_headers as usize).min(image.len());
            let src_len = header_len.min(self.data.len());
            image[..header_len].copy_from_slice(&self.data[..src_len]);
        }
        for section in &self.sections {
            if section.raw_size == 0 || section.raw_offset == 0 {
                continue;
            }
            let src_start = section.raw_offset as usize;
            let src_end = (src_start + section.raw_size as usize).min(self.data.len());
            if src_start >= self.data.len() {
                continue;
            }
            let dst_start = section.virtual_address as usize;
            let copy_len = (src_end - src_start).min(image.len().saturating_sub(dst_start));
            image[dst_start..dst_start + copy_len]
                .copy_from_slice(&self.data[src_start..src_start + copy_len]);
        }
        image
    }
}

fn parse_imports(
    data: &[u8],
    import_rva: u32,
    sections: &[Section],
) -> InjectResult<Vec<ImportDescriptor>> {
    let mut out = Vec::new();
    let mut desc_rva = import_rva;
    loop {
        let offset = rva_to_offset(desc_rva, sections)
            .ok_or_else(|| InjectError::Malformed("import descriptor RVA".into()))?;
        if offset + 20 > data.len() {
            break;
        }
        let original_first_thunk = read_u32(data, offset).unwrap_or(0);
        let name_rva = read_u32(data, offset + 12).unwrap_or(0);
        let first_thunk = read_u32(data, offset + 16).unwrap_or(0);

        // All-zero descriptor terminates the array.
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let name = if name_rva != 0 {
            let name_off = rva_to_offset(name_rva, sections).unwrap_or(0);
            read_ascii_string(data, name_off).unwrap_or_default()
        } else {
            String::new()
        };

        out.push(ImportDescriptor {
            name,
            first_thunk,
            original_first_thunk,
        });
        desc_rva = desc_rva.wrapping_add(20);
    }
    Ok(out)
}

fn parse_relocs(
    data: &[u8],
    reloc_rva: u32,
    reloc_size: u32,
    sections: &[Section],
) -> InjectResult<Vec<RelocBlock>> {
    let start = match rva_to_offset(reloc_rva, sections) {
        Some(s) => s,
        None => return Ok(Vec::new()),
    };
    let end = (start + reloc_size as usize).min(data.len());
    let mut blocks = Vec::new();
    let mut cursor = start;

    while cursor + 8 <= end {
        let page_rva = read_u32(data, cursor).unwrap_or(0);
        let block_size = read_u32(data, cursor + 4).unwrap_or(0) as usize;
        if block_size == 0 || cursor + block_size > end {
            break;
        }
        let mut entries = Vec::new();
        let mut entry_cursor = cursor + 8;
        let block_end = cursor + block_size;
        while entry_cursor + 2 <= block_end {
            let entry = read_u16(data, entry_cursor).unwrap_or(0);
            let rel_type = entry >> 12;
            let offset = entry & 0x0FFF;
            entries.push((offset, rel_type));
            entry_cursor += 2;
        }
        blocks.push(RelocBlock { page_rva, entries });
        cursor += block_size;
    }
    Ok(blocks)
}

/// Translate an RVA to a file offset using the section table.
pub fn rva_to_offset(rva: u32, sections: &[Section]) -> Option<usize> {
    for section in sections {
        let va = section.virtual_address;
        let size = section.virtual_size.max(section.raw_size);
        if rva >= va && rva < va + size {
            return Some((rva - va + section.raw_offset) as usize);
        }
    }
    if sections.is_empty() || sections.iter().all(|s| rva < s.virtual_address) {
        return Some(rva as usize);
    }
    None
}

fn read_ascii_string(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..].iter().position(|&b| b == 0)? + offset;
    Some(String::from_utf8_lossy(&data[offset..end]).into_owned())
}

/// Section layout of an image that is already laid out in memory (a mapped
/// view), as opposed to a raw on-disk file.
///
/// Used by [`crate::unhook`] to compare a live module against its clean
/// `\KnownDlls` counterpart.
#[derive(Debug, Clone)]
pub struct MappedSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub characteristics: u32,
}

impl MappedSection {
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
}

/// Header-only description of a module mapped in memory.
#[derive(Debug, Clone)]
pub struct MappedImage {
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub sections: Vec<MappedSection>,
}

impl MappedImage {
    /// Parse the headers of a mapped image from a buffer that starts at the
    /// image base (i.e. `data[VirtualAddress]` holds the section body).
    pub fn parse(data: &[u8]) -> InjectResult<MappedImage> {
        if data.len() < 0x40 {
            return Err(InjectError::InvalidImage("mapped header smaller than DOS header".into()));
        }
        let dos_magic = read_u16(data, 0).ok_or_else(|| {
            InjectError::InvalidImage("cannot read mapped DOS magic".into())
        })?;
        if dos_magic != IMAGE_DOS_SIGNATURE {
            return Err(InjectError::InvalidImage("mapped image missing MZ".into()));
        }
        let pe_offset = read_u32(data, 0x3C)
            .ok_or_else(|| InjectError::InvalidImage("mapped e_lfanew".into()))? as usize;
        let nt_sig = read_u32(data, pe_offset)
            .ok_or_else(|| InjectError::InvalidImage("mapped NT signature".into()))?;
        if nt_sig != IMAGE_NT_SIGNATURE {
            return Err(InjectError::InvalidImage("mapped image missing PE signature".into()));
        }

        let coff = pe_offset + 4;
        let num_sections = read_u16(data, coff + 2)
            .ok_or_else(|| InjectError::Malformed("mapped COFF num sections".into()))?
            as usize;
        let size_of_opt_header = read_u16(data, coff + 16)
            .ok_or_else(|| InjectError::Malformed("mapped optional header size".into()))?
            as usize;

        let opt = coff + 20;
        let opt_magic = read_u16(data, opt)
            .ok_or_else(|| InjectError::Malformed("mapped optional magic".into()))?;
        let pe32_plus = match opt_magic {
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => true,
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => false,
            other => {
                return Err(InjectError::InvalidImage(format!(
                    "mapped unsupported optional magic 0x{other:04X}"
                )))
            }
        };
        let _ = pe32_plus;
        let size_of_image = read_u32(data, opt + 56)
            .ok_or_else(|| InjectError::Malformed("mapped SizeOfImage".into()))?;
        let size_of_headers = read_u32(data, opt + 60)
            .ok_or_else(|| InjectError::Malformed("mapped SizeOfHeaders".into()))?;

        let section_offset = opt + size_of_opt_header;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = section_offset + i * 40;
            if s + 40 > data.len() {
                return Err(InjectError::Malformed("mapped section header OOB".into()));
            }
            let name_bytes = &data[s..s + 8];
            let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            sections.push(MappedSection {
                name: String::from_utf8_lossy(&name_bytes[..name_len]).into_owned(),
                virtual_size: read_u32(data, s + 8).unwrap_or(0),
                virtual_address: read_u32(data, s + 12).unwrap_or(0),
                characteristics: read_u32(data, s + 36).unwrap_or(0),
            });
        }

        Ok(MappedImage {
            size_of_image,
            size_of_headers,
            sections,
        })
    }
}

/// The outcome of resolving an export in a mapped module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportResolution {
    /// Direct function address inside the target process.
    Address(u64),
    /// Forwarder string (e.g. "NTDLL.RtlAllocateHeap" or "KERNELBASE.VirtualAlloc").
    Forwarder(String),
}

/// Resolve an exported function's absolute address from a module mapped at
/// `module_base` inside a target process.
///
/// Memory is fetched through the `read_at` closure so this works identically
/// against a live process (`pal.read_raw`), a local buffer, or an in-memory
/// test fixture. The closure returns bytes at the given absolute address.
pub fn resolve_export_at(
    read_at: &dyn Fn(u64, usize) -> InjectResult<Vec<u8>>,
    module_base: u64,
    name: &str,
) -> InjectResult<ExportResolution> {
    // DOS header: e_lfanew at 0x3C.
    let dos = read_at(module_base, 0x40)?;
    let pe_off = read_u32(&dos, 0x3C)
        .ok_or_else(|| InjectError::Malformed("e_lfanew unreadable".into()))? as u64;

    // NT headers: signature(4) + COFF(20) + optional header.
    let nt = read_at(module_base + pe_off, 0x108)?;
    let opt_magic = read_u16(&nt, 24)
        .ok_or_else(|| InjectError::Malformed("optional header magic".into()))?;
    let pe32_plus = match opt_magic {
        IMAGE_NT_OPTIONAL_HDR64_MAGIC => true,
        IMAGE_NT_OPTIONAL_HDR32_MAGIC => false,
        other => {
            return Err(InjectError::InvalidImage(format!(
                "unexpected optional header magic 0x{other:04X}"
            )))
        }
    };

    // Export data directory index 0 offset within NT headers:
    // PE32+: 24 (opt start) + 112 = 136; PE32: 24 + 96 = 120.
    let dd = if pe32_plus { 136 } else { 120 };
    let export_rva = read_u32(&nt, dd)
        .ok_or_else(|| InjectError::Malformed("export directory RVA".into()))? as u64;
    let export_size = read_u32(&nt, dd + 4).unwrap_or(0) as u64;
    if export_rva == 0 || export_size == 0 {
        return Err(InjectError::SymbolResolution {
            symbol: name.to_string(),
            reason: "module has no export directory".into(),
        });
    }

    let export = read_at(module_base + export_rva, 40)?;
    let num_names = read_u32(&export, 24).unwrap_or(0) as u64;
    let addr_of_funcs = read_u32(&export, 28).unwrap_or(0) as u64;
    let addr_of_names = read_u32(&export, 32).unwrap_or(0) as u64;
    let addr_of_ords = read_u32(&export, 36).unwrap_or(0) as u64;

    let names = read_at(module_base + addr_of_names, (num_names * 4) as usize)?;
    let ords = read_at(module_base + addr_of_ords, (num_names * 2) as usize)?;

    for i in 0..num_names {
        let name_rva = read_u32(&names, (i * 4) as usize).unwrap_or(0) as u64;
        let remote = read_c_string_at(read_at, module_base + name_rva, 256)?;
        if remote == name {
            let ord_index = read_u16(&ords, (i * 2) as usize).unwrap_or(0) as u64;
            let func_bytes = read_at(module_base + addr_of_funcs + ord_index * 4, 4)?;
            let func_rva = read_u32(&func_bytes, 0).unwrap_or(0) as u64;

            if func_rva >= export_rva && func_rva < export_rva + export_size {
                let forwarder = read_c_string_at(read_at, module_base + func_rva, 256)?;
                return Ok(ExportResolution::Forwarder(forwarder));
            }

            return Ok(ExportResolution::Address(module_base + func_rva));
        }
    }

    Err(InjectError::SymbolResolution {
        symbol: name.to_string(),
        reason: "export not found".into(),
    })
}

/// Read a NUL-terminated ASCII string at `address` via `read_at`.
fn read_c_string_at(
    read_at: &dyn Fn(u64, usize) -> InjectResult<Vec<u8>>,
    address: u64,
    max_len: usize,
) -> InjectResult<String> {
    let bytes = read_at(address, max_len)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

pub(crate) fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

pub(crate) fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

pub(crate) fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_synthetic_pe64() -> Vec<u8> {
        let mut buf = vec![0u8; 0x1000];
        // DOS header
        buf[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 0x80

        // NT signature
        buf[0x80..0x84].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());
        // COFF header
        buf[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // X86_64
        buf[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
        buf[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // opt header size = 240
        buf[0x96..0x98].copy_from_slice(&IMAGE_FILE_DLL.to_le_bytes());

        // Optional header (starts at 0x98)
        let opt = 0x98;
        buf[opt..opt + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        buf[opt + 24..opt + 32].copy_from_slice(&0x180000000u64.to_le_bytes()); // ImageBase
        buf[opt + 56..opt + 60].copy_from_slice(&0x5000u32.to_le_bytes()); // SizeOfImage
        buf[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        // Data directories at opt + 112 = 0x108
        // Export dir (DD 0): RVA 0x2000, size 0x200
        buf[opt + 112..opt + 116].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[opt + 116..opt + 120].copy_from_slice(&0x200u32.to_le_bytes());
        // Relocs dir (DD 5): RVA 0x3000, size 0x100 (DD index 5 is opt + 112 + 5*8 = opt + 152)
        buf[opt + 152..opt + 156].copy_from_slice(&0x3000u32.to_le_bytes());
        buf[opt + 156..opt + 160].copy_from_slice(&0x100u32.to_le_bytes());

        // Section table starts at opt + 0xF0 = 0x188
        let sec0 = opt + 0xF0;
        // Section 0: .text (VA 0x1000, Raw 0x400, RawSize 0x200)
        buf[sec0..sec0 + 5].copy_from_slice(b".text");
        buf[sec0 + 8..sec0 + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual_size
        buf[sec0 + 12..sec0 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual_address
        buf[sec0 + 16..sec0 + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw_size
        buf[sec0 + 20..sec0 + 24].copy_from_slice(&0x400u32.to_le_bytes()); // raw_offset
        buf[sec0 + 36..sec0 + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // RX

        // Section 1: .edata (VA 0x2000, Raw 0x600, RawSize 0x400)
        let sec1 = sec0 + 40;
        buf[sec1..sec1 + 6].copy_from_slice(b".edata");
        buf[sec1 + 8..sec1 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec1 + 12..sec1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[sec1 + 16..sec1 + 20].copy_from_slice(&0x400u32.to_le_bytes());
        buf[sec1 + 20..sec1 + 24].copy_from_slice(&0x600u32.to_le_bytes());
        buf[sec1 + 36..sec1 + 40].copy_from_slice(&0x40000040u32.to_le_bytes()); // Read

        // Export directory data in .edata section (file offset 0x600, RVA 0x2000)
        let edata_off = 0x600;
        // NumberOfFunctions at +20
        buf[edata_off + 20..edata_off + 24].copy_from_slice(&1u32.to_le_bytes());
        // NumberOfNames at +24
        buf[edata_off + 24..edata_off + 28].copy_from_slice(&1u32.to_le_bytes());
        // AddressOfFunctions at +28 -> RVA 0x2028 (file offset 0x628)
        buf[edata_off + 28..edata_off + 32].copy_from_slice(&0x2028u32.to_le_bytes());
        // AddressOfNames at +32 -> RVA 0x2030 (file offset 0x630)
        buf[edata_off + 32..edata_off + 36].copy_from_slice(&0x2030u32.to_le_bytes());
        // AddressOfNameOrdinals at +36 -> RVA 0x2038 (file offset 0x638)
        buf[edata_off + 36..edata_off + 40].copy_from_slice(&0x2038u32.to_le_bytes());

        // Func 0 RVA = 0x1020 (at 0x628)
        buf[0x628..0x62C].copy_from_slice(&0x1020u32.to_le_bytes());
        // Name 0 RVA = 0x2040 (at 0x630)
        buf[0x630..0x634].copy_from_slice(&0x2040u32.to_le_bytes());
        // Ordinal 0 = 0 (at 0x638)
        buf[0x638..0x63A].copy_from_slice(&0u16.to_le_bytes());
        // Name string at 0x640: "ReflectiveLoader\0"
        let name_str = b"ReflectiveLoader\0";
        buf[0x640..0x640 + name_str.len()].copy_from_slice(name_str);

        buf
    }

    #[test]
    fn test_parse_pe64_and_find_export() {
        let pe_bytes = build_synthetic_pe64();
        let pe = PeImage::parse(pe_bytes).expect("synthetic PE64 must parse");
        assert_eq!(pe.architecture, CpuArchitecture::X86_64);
        assert!(pe.is_dll);
        assert_eq!(pe.sections.len(), 2);

        let export_rva = pe.find_export_rva("ReflectiveLoader");
        assert_eq!(export_rva, Some(0x1020));
        assert_eq!(pe.find_export_rva("NonExistent"), None);
    }

    #[test]
    fn test_resolve_export_at_direct_and_forwarder() {
        // Mock a mapped module in memory (where RVA == offset from module_base)
        let mut mapped = vec![0u8; 0x4000];
        // DOS + NT headers
        mapped[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
        mapped[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe_off = 0x80;
        mapped[pe_off..pe_off + 4].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());
        let opt = pe_off + 24;
        mapped[opt..opt + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes());
        // Export directory at RVA 0x1000, size 0x200
        let dd0 = opt + 112;
        mapped[dd0..dd0 + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        mapped[dd0 + 4..dd0 + 8].copy_from_slice(&0x200u32.to_le_bytes());

        // Export directory at 0x1000
        let exp = 0x1000;
        mapped[exp + 20..exp + 24].copy_from_slice(&2u32.to_le_bytes()); // NumberOfFunctions = 2
        mapped[exp + 24..exp + 28].copy_from_slice(&2u32.to_le_bytes()); // NumberOfNames = 2
        mapped[exp + 28..exp + 32].copy_from_slice(&0x1030u32.to_le_bytes()); // AddressOfFunctions
        mapped[exp + 32..exp + 36].copy_from_slice(&0x1040u32.to_le_bytes()); // AddressOfNames
        mapped[exp + 36..exp + 40].copy_from_slice(&0x1050u32.to_le_bytes()); // AddressOfNameOrdinals

        // Functions: [0x2500 (direct), 0x1100 (forwarder in [0x1000..0x1200])]
        mapped[0x1030..0x1034].copy_from_slice(&0x2500u32.to_le_bytes());
        mapped[0x1034..0x1038].copy_from_slice(&0x1100u32.to_le_bytes());

        // Names: [0x1060 ("DirectFunc"), 0x1070 ("ForwardFunc")]
        mapped[0x1040..0x1044].copy_from_slice(&0x1060u32.to_le_bytes());
        mapped[0x1044..0x1048].copy_from_slice(&0x1070u32.to_le_bytes());

        // Ordinals: [0, 1]
        mapped[0x1050..0x1052].copy_from_slice(&0u16.to_le_bytes());
        mapped[0x1052..0x1054].copy_from_slice(&1u16.to_le_bytes());

        // Name strings
        mapped[0x1060..0x106B].copy_from_slice(b"DirectFunc\0");
        mapped[0x1070..0x107C].copy_from_slice(b"ForwardFunc\0");

        // Forwarder string at 0x1100: "NTDLL.RtlAllocateHeap\0"
        mapped[0x1100..0x1116].copy_from_slice(b"NTDLL.RtlAllocateHeap\0");

        let read_at = |addr: u64, size: usize| -> InjectResult<Vec<u8>> {
            let start = addr as usize;
            let end = (start + size).min(mapped.len());
            if start >= mapped.len() {
                Ok(vec![0u8; size])
            } else {
                let mut out = mapped[start..end].to_vec();
                out.resize(size, 0);
                Ok(out)
            }
        };

        // Resolve DirectFunc
        let res_direct = resolve_export_at(&read_at, 0, "DirectFunc").unwrap();
        assert_eq!(res_direct, ExportResolution::Address(0x2500));

        // Resolve ForwardFunc
        let res_fwd = resolve_export_at(&read_at, 0, "ForwardFunc").unwrap();
        assert_eq!(
            res_fwd,
            ExportResolution::Forwarder("NTDLL.RtlAllocateHeap".to_string())
        );
    }
}

