pub mod error;
pub mod optimizer;
pub mod protocol;
pub mod server;
pub mod static_analyzer;
pub mod tools;

pub use error::{McpError, McpResult};
pub use optimizer::{analyze_memory_block, MemoryStructureSummary};
pub use protocol::{CallToolResult, JsonRpcRequest, JsonRpcResponse, Tool};
pub use server::McpServer;
pub use tools::{dispatch_tool_call, list_tools, EngineSession};
