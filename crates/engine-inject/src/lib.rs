//! # engine-inject
//!
//! DLL / shared-library injection, manual mapping, reflective loading,
//! PE header erasure, unhooking and stealth primitives for Engine+.
//!
//! ## Design
//!
//! * [`pe`] — hand-rolled PE parser (sections, imports, exports, relocations)
//!   used by manual mapping, reflective loading and export resolution.
//! * [`manual_map`] — classic in-memory manual map: allocate, copy sections,
//!   apply relocations, resolve imports, set per-section protections and call
//!   the entry point, optionally erasing headers afterwards.
//! * [`reflective`] — two reflective-loading modes: the Stephen Fewer RDI
//!   `ReflectiveLoader` export, and a self-contained PIC stub assembled at
//!   runtime with `iced-x86`.
//! * [`stealth`] — PE header erasure over a mapped image.
//! * [`unhook`] — restores `ntdll` (and other system modules) `.text` from the
//!   clean `\KnownDlls\ntdll.dll` section mapping.
//! * [`hiding`] — hiding of threads, memory regions and handles (handle hiding
//!   uses a helper "stash" process; see module docs for the security notes).
//! * [`linux`] — Linux `.so` injection via `ptrace` + remote `dlopen`, and
//!   ELF manual mapping.
//! * [`facade`] — file-oriented injection entry point shared by the CLI, MCP
//!   server and Lua API.
//!
//! All OS-level syscalls live in `engine-pal`; this crate only orchestrates
//! them and owns the PE/ELF image logic.
//!
//! ## Security / scope
//!
//! Techniques here are generic, publicly documented reverse-engineering and
//! debugging primitives. There is no targeting of any specific anti-cheat or
//! EDR product, and kernel-level (VAD / DKOM) hiding is explicitly out of
//! scope.

pub mod error;
pub mod facade;
pub mod hiding;
pub mod manual_map;
pub mod pe;
pub mod reflective;
pub mod stealth;
pub mod unhook;

#[cfg(target_os = "linux")]
pub mod linux;

pub use error::{InjectError, InjectResult};
pub use facade::{inject_bytes, inject_file, InjectMethod, InjectOptions, InjectOutcome};
pub use hiding::{HandleStash, StealthHider};
pub use manual_map::{ManualMapInjector, ManualMapOptions, ManualMapResult};
pub use pe::{ExportResolution, PeImage};
pub use reflective::{ReflectiveLoader, ReflectiveMode};
pub use stealth::StealthOps;
pub use unhook::Unhooker;

#[cfg(target_os = "linux")]
pub use linux::LinuxInjector;
