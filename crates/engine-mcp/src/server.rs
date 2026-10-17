use crate::error::McpResult;
use crate::protocol::{
    CallToolResult, Implementation, InitializeResult, JsonRpcRequest, JsonRpcResponse,
    ServerCapabilities, ToolsCapability,
};
use crate::tools::{dispatch_tool_call, list_tools, EngineSession};
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{error, info};

/// Standard Model Context Protocol (MCP) Server operating over stdio
pub struct McpServer {
    session: Arc<Mutex<EngineSession>>,
}

impl McpServer {
    pub fn new() -> Self {
        McpServer {
            session: Arc::new(Mutex::new(EngineSession::new())),
        }
    }

    /// Run the server loop, reading line-delimited JSON-RPC from stdin and replying on stdout
    pub async fn run_stdio(&self) -> McpResult<()> {
        info!("Engine+ MCP server listening on stdio (JSON-RPC 2.0)...");

        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();

        while reader.read_line(&mut line).await? > 0 {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                line.clear();
                continue;
            }

            match serde_json::from_str::<JsonRpcRequest>(trimmed) {
                Ok(req) => {
                    if let Some(resp) = self.handle_request(req) {
                        let resp_json = serde_json::to_string(&resp)?;
                        stdout.write_all(resp_json.as_bytes()).await?;
                        stdout.write_all(b"\n").await?;
                        stdout.flush().await?;
                    }
                }
                Err(e) => {
                    error!("Invalid JSON-RPC request: {e}");
                    let err_resp = JsonRpcResponse::error(None, -32700, format!("Parse error: {e}"));
                    if let Ok(resp_json) = serde_json::to_string(&err_resp) {
                        stdout.write_all(resp_json.as_bytes()).await?;
                        stdout.write_all(b"\n").await?;
                        stdout.flush().await?;
                    }
                }
            }

            line.clear();
        }

        info!("MCP stdio connection closed.");
        Ok(())
    }

    /// Handle a single JSON-RPC request
    pub fn handle_request(&self, req: JsonRpcRequest) -> Option<JsonRpcResponse> {
        let id = req.id;

        match req.method.as_str() {
            "initialize" => {
                let init_result = InitializeResult {
                    protocol_version: "2024-11-05".to_string(),
                    capabilities: ServerCapabilities {
                        tools: Some(ToolsCapability {
                            list_changed: false,
                        }),
                    },
                    server_info: Implementation {
                        name: "engine-plus-mcp".to_string(),
                        version: "0.1.0".to_string(),
                    },
                };
                Some(JsonRpcResponse::success(id, json!(init_result)))
            }
            "notifications/initialized" => {
                // Client confirmed initialization. No response needed for notifications.
                None
            }
            "ping" => Some(JsonRpcResponse::success(id, json!({}))),
            "tools/list" => {
                let tools = list_tools();
                Some(JsonRpcResponse::success(id, json!({ "tools": tools })))
            }
            "tools/call" => {
                let params = match req.params {
                    Some(p) => p,
                    None => {
                        return Some(JsonRpcResponse::error(
                            id,
                            -32602,
                            "Missing 'params' for tools/call",
                        ));
                    }
                };

                let tool_name = match params.get("name").and_then(|v| v.as_str()) {
                    Some(n) => n,
                    None => {
                        return Some(JsonRpcResponse::error(
                            id,
                            -32602,
                            "Missing 'name' in tools/call params",
                        ));
                    }
                };

                let tool_args = params.get("arguments").cloned();
                let result: CallToolResult =
                    dispatch_tool_call(&self.session, tool_name, tool_args);

                Some(JsonRpcResponse::success(id, json!(result)))
            }
            _ => {
                // Unknown method
                Some(JsonRpcResponse::error(
                    id,
                    -32601,
                    format!("Method not found: '{}'", req.method),
                ))
            }
        }
    }
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_mcp_initialize() {
        let server = McpServer::new();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: None,
        };

        let resp = server.handle_request(req).expect("should return response");
        assert_eq!(resp.id, Some(json!(1)));
        assert!(resp.error.is_none());

        let result = resp.result.expect("should have result");
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert_eq!(result["serverInfo"]["name"], "engine-plus-mcp");
    }

    #[test]
    fn test_mcp_tools_list() {
        let server = McpServer::new();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(2)),
            method: "tools/list".to_string(),
            params: None,
        };

        let resp = server.handle_request(req).expect("should return response");
        let result = resp.result.expect("should have result");
        let tools = result["tools"].as_array().expect("tools array");
        assert!(tools.len() >= 15);
        assert!(tools.iter().any(|t| t["name"] == "process_list"));
        assert!(tools.iter().any(|t| t["name"] == "memory_scan"));
        assert!(tools.iter().any(|t| t["name"] == "disassemble"));
        assert!(tools.iter().any(|t| t["name"] == "script_execute"));
        assert!(tools.iter().any(|t| t["name"] == "assemble"));
        assert!(tools.iter().any(|t| t["name"] == "code_patch"));
        assert!(tools.iter().any(|t| t["name"] == "hook_install"));
        assert!(tools.iter().any(|t| t["name"] == "pattern_generate"));
        assert!(tools.iter().any(|t| t["name"] == "find_xrefs"));
    }

    #[test]
    fn test_mcp_tool_call_disassemble() {
        let server = McpServer::new();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(3)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "disassemble",
                "arguments": {
                    "hex": "90 CC"
                }
            })),
        };

        let resp = server.handle_request(req).expect("should return response");
        let result = resp.result.expect("should have result");
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().expect("text string");
        assert!(text.contains("nop"));
        assert!(text.contains("int3"));
    }

    #[test]
    fn test_mcp_tool_call_script_execute() {
        let server = McpServer::new();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(4)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "script_execute",
                "arguments": {
                    "code": "return 50 * 4"
                }
            })),
        };

        let resp = server.handle_request(req).expect("should return response");
        let result = resp.result.expect("should have result");
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().expect("text string");
        assert!(text.contains("200"));
    }

    #[test]
    fn test_mcp_tool_call_assemble() {
        let server = McpServer::new();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(6)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "assemble",
                "arguments": {
                    "code": "xor eax, eax\nret",
                    "ip": "0x1000",
                    "bitness": 64
                }
            })),
        };

        let resp = server.handle_request(req).expect("should return response");
        let result = resp.result.expect("should have result");
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().expect("text string");
        assert!(text.contains("hex"));
        assert!(text.contains("C3"));
    }

    #[test]
    fn test_mcp_unknown_method() {
        let server = McpServer::new();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(5)),
            method: "non_existent_method".to_string(),
            params: None,
        };

        let resp = server.handle_request(req).expect("should return response");
        assert!(resp.result.is_none());
        let err = resp.error.expect("should return error");
        assert_eq!(err.code, -32601);
    }
}
