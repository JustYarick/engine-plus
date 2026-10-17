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
        assert!(tools.len() >= 19);
        assert!(tools.iter().any(|t| t["name"] == "process_list"));
        assert!(tools.iter().any(|t| t["name"] == "memory_scan"));
        assert!(tools.iter().any(|t| t["name"] == "disassemble"));
        assert!(tools.iter().any(|t| t["name"] == "script_execute"));
        assert!(tools.iter().any(|t| t["name"] == "auto_assemble"));
        assert!(tools.iter().any(|t| t["name"] == "assemble"));
        assert!(tools.iter().any(|t| t["name"] == "code_patch"));
        assert!(tools.iter().any(|t| t["name"] == "hook_install"));
        assert!(tools.iter().any(|t| t["name"] == "pattern_generate"));
        assert!(tools.iter().any(|t| t["name"] == "find_xrefs"));
        assert!(tools.iter().any(|t| t["name"] == "struct_reconstruct"));
        assert!(tools.iter().any(|t| t["name"] == "struct_export"));
        assert!(tools.iter().any(|t| t["name"] == "struct_rename_field"));
        assert!(tools.iter().any(|t| t["name"] == "debug_breakpoint_set"));
        assert!(tools.iter().any(|t| t["name"] == "debug_breakpoint_remove"));
        assert!(tools.iter().any(|t| t["name"] == "debug_breakpoint_list"));
        assert!(tools.iter().any(|t| t["name"] == "debug_find_what_writes"));
        assert!(tools.iter().any(|t| t["name"] == "debug_get_registers"));
        assert!(tools.iter().any(|t| t["name"] == "debug_pause"));
        assert!(tools.iter().any(|t| t["name"] == "debug_resume"));
        assert!(tools.iter().any(|t| t["name"] == "debug_step"));
        assert!(tools.iter().any(|t| t["name"] == "pointer_scan"));
        assert!(tools.iter().any(|t| t["name"] == "pointer_resolve"));
        assert!(tools.iter().any(|t| t["name"] == "speedhack_set"));
        assert!(tools.iter().any(|t| t["name"] == "speedhack_generate_script"));
    }

    #[test]
    fn test_mcp_tool_call_debug_breakpoints_and_what_writes() {
        let server = McpServer::new();

        // 1. Set a hardware write breakpoint
        let set_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(10)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "debug_breakpoint_set",
                "arguments": {
                    "address": "0x7FFF1000",
                    "bp_type": "hardware_write",
                    "size": 4
                }
            })),
        };
        let set_resp = server.handle_request(set_req).expect("should succeed");
        let set_res = set_resp.result.expect("result");
        assert_eq!(set_res["isError"], false);
        let set_text = set_res["content"][0]["text"].as_str().unwrap();
        assert!(set_text.contains("DR0"));

        // 2. List breakpoints
        let list_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(11)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "debug_breakpoint_list",
                "arguments": {}
            })),
        };
        let list_resp = server.handle_request(list_req).expect("should succeed");
        let list_res = list_resp.result.expect("result");
        assert_eq!(list_res["isError"], false);
        let list_text = list_res["content"][0]["text"].as_str().unwrap();
        assert!(list_text.contains("Hardware DR0"));

        // 3. Remove breakpoint
        let rem_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(12)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "debug_breakpoint_remove",
                "arguments": {
                    "id": 1000
                }
            })),
        };
        let rem_resp = server.handle_request(rem_req).expect("should succeed");
        let rem_res = rem_resp.result.expect("result");
        assert_eq!(rem_res["isError"], false);

        // 4. Test find_what_writes
        let ww_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(13)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "debug_find_what_writes",
                "arguments": {
                    "address": "0x7FFF123450",
                    "size": 4
                }
            })),
        };
        let ww_resp = server.handle_request(ww_req).expect("should succeed");
        let ww_res = ww_resp.result.expect("result");
        assert_eq!(ww_res["isError"], false);
        let ww_text = ww_res["content"][0]["text"].as_str().unwrap();
        assert!(ww_text.contains("target_address"));
        assert!(ww_text.contains("table_view"));
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
                    "code": "return type(memory) .. ' ' .. type(scanner) .. ' ' .. type(assembler) .. ' ' .. type(auto_assemble)"
                }
            })),
        };

        let resp = server.handle_request(req).expect("should return response");
        let result = resp.result.expect("should have result");
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().expect("text string");
        assert_eq!(text, "table table table function");
    }

    #[test]
    fn test_mcp_tool_call_auto_assemble_unattached() {
        let server = McpServer::new();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(7)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "auto_assemble",
                "arguments": {
                    "script": "[ENABLE]\n0x1000:\nnop\n"
                }
            })),
        };

        let resp = server.handle_request(req).expect("should return response");
        let result = resp.result.expect("should have result");
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().expect("text string");
        assert!(text.contains("Not attached to any process"));
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

    #[test]
    fn test_mcp_tool_call_speedhack_and_script() {
        let server = McpServer::new();

        // 1. Set speedhack multiplier
        let sh_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(20)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "speedhack_set",
                "arguments": {
                    "multiplier": 2.5
                }
            })),
        };
        let sh_resp = server.handle_request(sh_req).expect("should return response");
        let sh_res = sh_resp.result.expect("result");
        assert_eq!(sh_res["isError"], false);
        let sh_text = sh_res["content"][0]["text"].as_str().unwrap();
        assert!(sh_text.contains("2.50x"));

        // 2. Generate speedhack AutoAssembler script for Linux
        let gen_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(21)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "speedhack_generate_script",
                "arguments": {
                    "multiplier": 1.5,
                    "target_platform": "linux"
                }
            })),
        };
        let gen_resp = server.handle_request(gen_req).expect("should return response");
        let gen_res = gen_resp.result.expect("result");
        assert_eq!(gen_res["isError"], false);
        let gen_text = gen_res["content"][0]["text"].as_str().unwrap();
        assert!(gen_text.contains("clock_gettime"));
        assert!(gen_text.contains("[ENABLE]"));
        assert!(gen_text.contains("[DISABLE]"));
    }

    #[test]
    fn test_mcp_tool_call_pointer_tools_unattached() {
        let server = McpServer::new();

        // pointer_scan when unattached
        let scan_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(22)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "pointer_scan",
                "arguments": {
                    "target_address": "0x123450"
                }
            })),
        };
        let scan_resp = server.handle_request(scan_req).expect("should return response");
        let scan_res = scan_resp.result.expect("result");
        assert_eq!(scan_res["isError"], true);

        // pointer_resolve when unattached
        let res_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(23)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "pointer_resolve",
                "arguments": {
                    "module": "game.exe",
                    "base_offset": "0x1000",
                    "offsets": ["0x20", "0xF8"]
                }
            })),
        };
        let res_resp = server.handle_request(res_req).expect("should return response");
        let res_res = res_resp.result.expect("result");
        assert_eq!(res_res["isError"], true);
    }

    #[test]
    fn test_mcp_new_tools_registration_and_execution() {
        let server = McpServer::new();

        // 1. Check tools/list contains all 5 new tools
        let list_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(30)),
            method: "tools/list".to_string(),
            params: None,
        };
        let list_resp = server.handle_request(list_req).expect("should return response");
        let list_res = list_resp.result.expect("result");
        let tools = list_res["tools"].as_array().expect("tools array");
        let tool_names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();

        assert!(tool_names.contains(&"memory_read_batch"));
        assert!(tool_names.contains(&"module_list"));
        assert!(tool_names.contains(&"symbol_lookup"));
        assert!(tool_names.contains(&"struct_layout"));
        assert!(tool_names.contains(&"struct_diff"));

        // 2. Attach to self
        let my_pid = std::process::id();
        let attach_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(31)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "process_attach",
                "arguments": { "pid": my_pid }
            })),
        };
        let attach_resp = server.handle_request(attach_req).expect("attach response");
        assert_eq!(attach_resp.result.unwrap()["isError"], false);

        // 3. Test memory_read_batch on self
        let var1: i32 = 0x12345678;
        let var2: f32 = 13.37;
        let addr1 = format!("0x{:X}", &var1 as *const i32 as u64);
        let addr2 = format!("0x{:X}", &var2 as *const f32 as u64);

        let batch_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(32)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "memory_read_batch",
                "arguments": {
                    "reads": [
                        { "address": addr1, "val_type": "i32", "tag": "test_int" },
                        { "address": addr2, "val_type": "f32", "tag": "test_float" }
                    ]
                }
            })),
        };
        let batch_resp = server.handle_request(batch_req).expect("batch response");
        let batch_res = batch_resp.result.unwrap();
        assert_eq!(batch_res["isError"], false);
        let batch_text = batch_res["content"][0]["text"].as_str().unwrap();
        let batch_json: serde_json::Value = serde_json::from_str(batch_text).expect("valid json");
        assert_eq!(batch_json["count"], 2);
        assert_eq!(batch_json["results"][0]["value"], 0x12345678);
        assert_eq!(batch_json["results"][0]["tag"], "test_int");

        // 4. Test struct_diff with snapshot_id on self
        let mut buffer = vec![0x10u8, 0x20, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00];
        let buf_addr = format!("0x{:X}", buffer.as_ptr() as u64);

        let diff_req1 = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(33)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "struct_diff",
                "arguments": {
                    "address": buf_addr,
                    "size": 8,
                    "snapshot_id": "test_snap"
                }
            })),
        };
        let diff_resp1 = server.handle_request(diff_req1).expect("diff response 1");
        let diff_res1 = diff_resp1.result.unwrap();
        assert_eq!(diff_res1["isError"], false);
        let diff_text1 = diff_res1["content"][0]["text"].as_str().unwrap();
        assert!(diff_text1.contains("baseline_saved"));

        // Modify buffer
        buffer[0] = 0x99;

        let diff_req2 = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(34)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "struct_diff",
                "arguments": {
                    "address": buf_addr,
                    "size": 8,
                    "snapshot_id": "test_snap"
                }
            })),
        };
        let diff_resp2 = server.handle_request(diff_req2).expect("diff response 2");
        let diff_res2 = diff_resp2.result.unwrap();
        assert_eq!(diff_res2["isError"], false);
        let diff_text2 = diff_res2["content"][0]["text"].as_str().unwrap();
        assert!(diff_text2.contains("compared_with_previous"));
        assert!(diff_text2.contains("99") || diff_text2.contains("changed_fields"));

        // 5. Test module_list
        let mod_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(35)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "module_list",
                "arguments": {}
            })),
        };
        let mod_resp = server.handle_request(mod_req).expect("module list response");
        let mod_res = mod_resp.result.unwrap();
        assert_eq!(mod_res["isError"], false);
    }
}
