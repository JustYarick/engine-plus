use thiserror::Error;

#[derive(Debug, Error)]
pub enum McpError {
    #[error("JSON-RPC Protocol error ({code}): {message}")]
    JsonRpc { code: i32, message: String },

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Engine core error: {0}")]
    Core(#[from] engine_core::CoreError),

    #[error("Tool execution failed for '{name}': {reason}")]
    ToolExecution { name: String, reason: String },
}

pub type McpResult<T> = Result<T, McpError>;
