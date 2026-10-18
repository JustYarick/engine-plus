use engine_pal::{Address, PalError, ProcessId};
use thiserror::Error;

/// Strongly-typed error enum for all injection and stealth operations.
#[derive(Debug, Error)]
pub enum InjectError {
    /// Underlying process-access-layer failure.
    #[error("process access layer error: {0}")]
    Pal(#[from] PalError),

    /// The provided image is not a valid PE / ELF binary.
    #[error("invalid image format: {0}")]
    InvalidImage(String),

    /// The image architecture does not match the target process.
    #[error("architecture mismatch: image is {image}, target process {pid} is {target}")]
    ArchitectureMismatch {
        image: String,
        target: String,
        pid: ProcessId,
    },

    /// A required PE/ELF structure could not be located or read.
    #[error("malformed structure: {0}")]
    Malformed(String),

    /// Failure while resolving an import or export symbol.
    #[error("symbol resolution failed for '{symbol}': {reason}")]
    SymbolResolution { symbol: String, reason: String },

    /// Failure allocating or writing memory in the target.
    #[error("remote memory operation failed: {0}")]
    RemoteMemory(String),

    /// Failure creating or waiting on a remote thread.
    #[error("remote thread operation failed: {0}")]
    RemoteThread(String),

    /// The requested stealth feature is not supported on this platform/backend.
    #[error("not supported by backend '{backend}': {feature}")]
    NotSupported {
        backend: &'static str,
        feature: String,
    },

    /// Failure during an unhooking or protection-restore step.
    #[error("protection/restore failure at {address}: {reason}")]
    Protection {
        address: Address,
        reason: String,
    },

    /// I/O failure (reading an image from disk, etc).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type InjectResult<T> = Result<T, InjectError>;
