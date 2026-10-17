use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("Lua error: {0}")]
    Lua(#[from] mlua::Error),

    #[error("Core engine error: {0}")]
    Core(#[from] engine_core::CoreError),

    #[error("PAL error: {0}")]
    Pal(#[from] engine_pal::PalError),

    #[error("AutoAssembler error: {0}")]
    AutoAssemble(#[from] crate::auto_assembler::AutoAssembleError),

    #[error("Security violation: {0}")]
    Security(String),

    #[error("Script execution timeout ({0} seconds)")]
    Timeout(u64),
}

pub type ScriptResult<T> = Result<T, ScriptError>;
