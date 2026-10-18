//! High-level, file-oriented injection entry point.
//!
//! The CLI, the MCP server and the sandboxed Lua runtime all need the same
//! operation: read a DLL/`.so` from disk and inject it into the attached
//! process with a chosen strategy. Keeping that dispatch here avoids three
//! copies of the same platform `cfg` logic in the facade crates.
//!
//! On Windows the caller chooses between manual mapping and reflective
//! loading; on Linux the object is always loaded with a remote `dlopen`.

use crate::error::{InjectError, InjectResult};
use engine_pal::types::Address;
use engine_pal::ProcessAccessLayer;

/// Strategy used to place a Windows DLL into the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectMethod {
    /// Pick reflective loading when the DLL exports `ReflectiveLoader`,
    /// otherwise fall back to manual mapping.
    Auto,
    /// Map sections, apply relocations and resolve imports by hand.
    ManualMap,
    /// Use the DLL's own `ReflectiveLoader` export (Stephen Fewer RDI).
    ReflectiveRdi,
    /// Append a runtime-assembled position-independent loader stub.
    ReflectiveStub,
}

impl InjectMethod {
    /// Parse a method name as accepted on the command line / in JSON.
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "manual_map" | "manual" | "map" => Some(Self::ManualMap),
            "reflective_rdi" | "rdi" | "reflective" => Some(Self::ReflectiveRdi),
            "reflective_stub" | "stub" => Some(Self::ReflectiveStub),
            _ => None,
        }
    }

    /// Stable, lower-case identifier used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::ManualMap => "manual_map",
            Self::ReflectiveRdi => "reflective_rdi",
            Self::ReflectiveStub => "reflective_stub",
        }
    }
}

/// Options controlling an injection.
#[derive(Debug, Clone, Copy)]
pub struct InjectOptions {
    /// Placement strategy (ignored on Linux).
    pub method: InjectMethod,
    /// Zero the PE headers after manual mapping.
    pub erase_headers: bool,
    /// Run the entry point (`DllMain`) in a remote thread after manual mapping.
    pub call_entry_point: bool,
}

impl Default for InjectOptions {
    fn default() -> Self {
        InjectOptions {
            method: InjectMethod::Auto,
            erase_headers: true,
            call_entry_point: true,
        }
    }
}

/// Result of a successful injection, normalised across strategies.
#[derive(Debug, Clone, Default)]
pub struct InjectOutcome {
    /// Strategy actually used (e.g. `"manual_map"`, `"remote_dlopen"`).
    pub method: &'static str,
    /// Base address of the image (mapped base, or raw image base for
    /// reflective loading, or the `dlopen` handle on Linux).
    pub base: Address,
    /// RDI mode: RVA of the `ReflectiveLoader` export.
    pub loader_rva: Option<u32>,
    /// Stub mode: size of the appended PIC stub.
    pub stub_len: Option<usize>,
    /// Manual map: size of the mapped image.
    pub size_of_image: Option<usize>,
    /// Manual map: resolved entry point.
    pub entry_point: Option<Address>,
    /// Manual map: number of relocations applied.
    pub relocations_applied: Option<usize>,
    /// Manual map: number of imports resolved.
    pub imports_resolved: Option<usize>,
    /// Manual map: number of dependency DLLs loaded.
    pub dependencies_loaded: Option<usize>,
    /// Linux: whether the object was a temporary file removed after mapping.
    pub temporary: bool,
}

/// Read `path` from disk and inject it into the target behind `pal`.
pub fn inject_file(
    pal: &dyn ProcessAccessLayer,
    path: &str,
    options: InjectOptions,
) -> InjectResult<InjectOutcome> {
    let bytes = std::fs::read(path).map_err(|e| {
        InjectError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to read '{path}': {e}"),
        ))
    })?;
    inject_bytes(pal, &bytes, options)
}

/// Inject an in-memory image into the target behind `pal`.
pub fn inject_bytes(
    pal: &dyn ProcessAccessLayer,
    bytes: &[u8],
    options: InjectOptions,
) -> InjectResult<InjectOutcome> {
    #[cfg(target_os = "linux")]
    let result = {
        if bytes.len() >= 2 && &bytes[..2] == b"MZ" {
            Err(InjectError::InvalidImage(
                "input is a Windows PE DLL (MZ); Linux native injection only supports ELF shared objects (.so) via remote dlopen".to_string(),
            ))
        } else {
            let _ = options;
            let rep = crate::linux::LinuxInjector::new(pal).inject_bytes(bytes)?;
            Ok(InjectOutcome {
                method: "remote_dlopen",
                base: rep.base,
                temporary: rep.temporary,
                ..InjectOutcome::default()
            })
        }
    };

    #[cfg(target_os = "windows")]
    let result = windows_inject(pal, bytes, options);

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let result: InjectResult<InjectOutcome> = {
        let _ = (pal, bytes, options);
        Err(InjectError::NotSupported {
            backend: "unknown",
            feature: "dll/shared-object injection".to_string(),
        })
    };

    result
}

/// Windows-specific dispatch between manual mapping and reflective loading.
#[cfg(target_os = "windows")]
fn windows_inject(
    pal: &dyn ProcessAccessLayer,
    bytes: &[u8],
    options: InjectOptions,
) -> InjectResult<InjectOutcome> {
    use crate::manual_map::{ManualMapInjector, ManualMapOptions};
    use crate::pe::PeImage;
    use crate::reflective::{ReflectiveLoader, ReflectiveMode, RDI_EXPORT_NAME};

    let method = if options.method == InjectMethod::Auto {
        match PeImage::parse(bytes.to_vec()) {
            Ok(pe) if pe.find_export_rva(RDI_EXPORT_NAME).is_some() => InjectMethod::ReflectiveRdi,
            _ => InjectMethod::ManualMap,
        }
    } else {
        options.method
    };

    match method {
        InjectMethod::ReflectiveRdi => {
            let r = ReflectiveLoader::new(pal, ReflectiveMode::Rdi).inject(bytes)?;
            Ok(InjectOutcome {
                method: "reflective_rdi",
                base: r.raw_base,
                loader_rva: r.loader_rva,
                ..InjectOutcome::default()
            })
        }
        InjectMethod::ReflectiveStub => {
            let r = ReflectiveLoader::new(pal, ReflectiveMode::Stub).inject(bytes)?;
            Ok(InjectOutcome {
                method: "reflective_stub",
                base: r.raw_base,
                stub_len: r.stub_len,
                ..InjectOutcome::default()
            })
        }
        InjectMethod::Auto | InjectMethod::ManualMap => {
            let map_options = ManualMapOptions {
                erase_headers: options.erase_headers,
                call_entry_point: options.call_entry_point,
                ..ManualMapOptions::default()
            };
            let r = ManualMapInjector::new(pal, map_options).inject(bytes)?;
            Ok(InjectOutcome {
                method: "manual_map",
                base: r.base,
                size_of_image: Some(r.size_of_image),
                entry_point: r.entry_point,
                relocations_applied: Some(r.relocations_applied),
                imports_resolved: Some(r.imports_resolved),
                dependencies_loaded: Some(r.dependencies_loaded),
                ..InjectOutcome::default()
            })
        }
    }
}
