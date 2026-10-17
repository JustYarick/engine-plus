use crate::types::{Address, ProcessId};
use thiserror::Error;

/// Strongly-typed error enum for all Process Access Layer operations
#[derive(Debug, Error)]
pub enum PalError {
    #[error("Process {0} was not found")]
    ProcessNotFound(ProcessId),

    #[error("Access denied to process {0}: {1}")]
    AccessDenied(ProcessId, String),

    #[error("Failed to attach to process {0}: {1}")]
    AttachFailed(ProcessId, String),

    #[error("Failed to detach from process {0}: {1}")]
    DetachFailed(ProcessId, String),

    #[error("Not attached to any process")]
    NotAttached,

    #[error("Already attached to process {0}")]
    AlreadyAttached(ProcessId),

    #[error("Memory read failed at {address} (size {size} bytes): {reason}")]
    ReadFailed {
        address: Address,
        size: usize,
        reason: String,
    },

    #[error("Memory write failed at {address} (size {size} bytes): {reason}")]
    WriteFailed {
        address: Address,
        size: usize,
        reason: String,
    },

    #[error("Failed to query memory regions for process {0}: {1}")]
    RegionQueryFailed(ProcessId, String),

    #[error("Failed to enumerate modules for process {0}: {1}")]
    ModuleEnumFailed(ProcessId, String),

    #[error("Failed to enumerate threads for process {0}: {1}")]
    ThreadEnumFailed(ProcessId, String),

    #[error("Breakpoint error at {address}: {reason}")]
    BreakpointFailed {
        address: Address,
        reason: String,
    },

    #[error("Memory allocation failed (size {size} bytes): {reason}")]
    AllocationFailed {
        size: usize,
        reason: String,
    },

    #[error("Operation not supported by backend '{backend}': {feature}")]
    NotSupported {
        backend: &'static str,
        feature: String,
    },

    #[error("OS I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal PAL error: {0}")]
    Internal(String),
}

pub type PalResult<T> = Result<T, PalError>;
