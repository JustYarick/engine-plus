use engine_pal::PalError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("PAL error: {0}")]
    Pal(#[from] PalError),

    #[error("Scanner error: {0}")]
    Scanner(String),

    #[error("Cheat table error: {0}")]
    Table(String),

    #[error("Disassembly error: {0}")]
    Disassembly(String),

    #[error("Debugger error: {0}")]
    Debugger(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type CoreResult<T> = Result<T, CoreError>;
