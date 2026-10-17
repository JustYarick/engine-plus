use crate::optimizer::analyze_memory_block;
use crate::protocol::{CallToolResult, Tool};
use engine_core::{FirstScanMode, MemoryScanner, NextScanMode, ScanConfig, ScanValue, ScanValueType};
use engine_pal::{default_backend, default_enumerator, Address, ProcessAccessLayer, ProcessId};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// Global state session for active process and scanning operations in MCP
pub struct EngineSession {
    pub pal: Box<dyn ProcessAccessLayer>,
    pub scanner: MemoryScanner,
}

impl EngineSession {
    pub fn new() -> Self {
        EngineSession {
            pal: default_backend(),
            scanner: MemoryScanner::new(),
        }
    }
}

impl Default for EngineSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Register all standard MCP tools for reverse engineering and memory operations
pub fn list_tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "process_list".to_string(),
            description: "Get list of active running processes with optional name filtering".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "filter": { "type": "string", "description": "Optional substring filter for process name or cmdline" }
                }
            }),
        },
        Tool {
            name: "process_attach".to_string(),
            description: "Attach to a target process by PID to start memory analysis or scanning".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "Target Process ID (PID)" }
                },
                "required": ["pid"]
            }),
        },
        Tool {
            name: "process_info".to_string(),
            description: "Get detailed information about currently attached process (architecture, memory regions, loaded modules)".to_string(),
            input_schema: json!({ "type": "object" }),
        },
        Tool {
            name: "memory_scan".to_string(),
            description: "Scan target process memory for an exact value, range, changed/unchanged, or AOB hex pattern with wildcards".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "value": { "type": "string", "description": "Value to search for (e.g. '100', '3.14', or AOB hex pattern '48 8B 05 ?? ?? C3')" },
                    "val_type": {
                        "type": "string",
                        "enum": ["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64", "aob", "string"],
                        "default": "i32",
                        "description": "Data type"
                    },
                    "scan_mode": {
                        "type": "string",
                        "enum": ["first_exact", "next_exact", "next_changed", "next_unchanged", "next_increased", "next_decreased"],
                        "default": "first_exact",
                        "description": "Scan type mode"
                    },
                    "alignment": { "type": "integer", "description": "Byte alignment (1, 2, 4, 8). Defaults to type size" },
                    "max_results": { "type": "integer", "default": 20, "description": "Max results to return in response" }
                },
                "required": ["value"]
            }),
        },
        Tool {
            name: "memory_read".to_string(),
            description: "Read typed memory values or raw bytes from an address in the target process".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Hex address (e.g. '0x7FFC968E1360')" },
                    "val_type": {
                        "type": "string",
                        "enum": ["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64", "hex", "string"],
                        "default": "i32"
                    },
                    "size": { "type": "integer", "default": 4, "description": "Number of bytes to read (for hex/string)" }
                },
                "required": ["address"]
            }),
        },
        Tool {
            name: "memory_write".to_string(),
            description: "Write typed value or raw bytes into target process memory at an address".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Hex address (e.g. '0x7FFC968E1360')" },
                    "value": { "type": "string", "description": "Value to write (e.g. '9999' or '48 89 E5')" },
                    "val_type": {
                        "type": "string",
                        "enum": ["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64", "hex"],
                        "default": "i32"
                    }
                },
                "required": ["address", "value"]
            }),
        },
        Tool {
            name: "process_detach".to_string(),
            description: "Detach from the currently attached target process".to_string(),
            input_schema: json!({ "type": "object" }),
        },
        Tool {
            name: "memory_regions".to_string(),
            description: "Query and list virtual memory map regions of the attached process".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "writable_only": { "type": "boolean", "default": false, "description": "Filter only writable memory regions" }
                }
            }),
        },
        Tool {
            name: "analyze_structure".to_string(),
            description: "Heuristically analyze a memory block to automatically identify object fields (pointers, floats, strings, vtables) with minimal token overhead".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Starting hex address of object (e.g. '0x7FFC968E1360')" },
                    "size": { "type": "integer", "default": 256, "description": "Estimated object size in bytes" }
                },
                "required": ["address"]
            }),
        },
        Tool {
            name: "disassemble".to_string(),
            description: "Disassemble raw machine code bytes (x86/x64) into assembly instructions".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hex": { "type": "string", "description": "Space-separated hex machine code bytes (e.g. '48 89 E5' or '90 CC')" },
                    "ip": { "type": "string", "default": "0x1000", "description": "Base instruction pointer hex address" },
                    "bitness": { "type": "integer", "enum": [32, 64], "default": 64, "description": "Architecture bitness" }
                },
                "required": ["hex"]
            }),
        },
        Tool {
            name: "script_execute".to_string(),
            description: "Execute safe sandboxed Lua 5.4 script for automation, reverse engineering, or math".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "code": { "type": "string", "description": "Lua script code to execute" }
                },
                "required": ["code"]
            }),
        },
        Tool {
            name: "file_analyze_binary".to_string(),
            description: "Statically analyze an executable or library file on disk (.exe, .dll, ELF) without running it. Extracts headers, architecture, entry point, ImageBase, and section map with protections.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute or relative file path to the binary" }
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "file_extract_strings".to_string(),
            description: "Extract ASCII/UTF-8 strings from a static binary file with offset tracking and token-budget filtering (great for finding class names, URLs, error logs, and function names).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to binary file" },
                    "min_len": { "type": "integer", "default": 5, "description": "Minimum string length" },
                    "max_results": { "type": "integer", "default": 100, "description": "Maximum number of strings to return" },
                    "filter": { "type": "string", "description": "Optional substring filter" }
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "file_disassemble_rva".to_string(),
            description: "Disassemble machine code directly from a static binary file on disk given an RVA (Relative Virtual Address) or raw file offset.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to binary file" },
                    "rva": { "type": "string", "description": "Hex RVA address (e.g. '0x1500') to disassemble" },
                    "offset": { "type": "string", "description": "Alternative raw file hex offset (e.g. '0x400')" },
                    "size": { "type": "integer", "default": 64, "description": "Number of bytes to disassemble (default: 64, max: 512)" },
                    "bitness": { "type": "integer", "enum": [32, 64], "default": 64, "description": "Architecture bitness" }
                },
                "required": ["path"]
            }),
        },
    ]
}

/// Execute an MCP tool by name with arguments
pub fn dispatch_tool_call(
    session_arc: &Arc<Mutex<EngineSession>>,
    name: &str,
    args: Option<Value>,
) -> CallToolResult {
    let args = args.unwrap_or(json!({}));

    match name {
        "process_list" => {
            let filter = args.get("filter").and_then(|v| v.as_str());
            let enumerator = default_enumerator();
            match enumerator.list_processes() {
                Ok(mut procs) => {
                    if let Some(f) = filter {
                        let f_lower = f.to_lowercase();
                        procs.retain(|p| {
                            p.name.to_lowercase().contains(&f_lower)
                                || p.cmdline
                                    .as_ref()
                                    .map_or(false, |c| c.to_lowercase().contains(&f_lower))
                        });
                    }
                    CallToolResult::json(&procs).unwrap_or_else(|e| CallToolResult::error(e.to_string()))
                }
                Err(e) => CallToolResult::error(format!("Failed to list processes: {e}")),
            }
        }
        "process_attach" => {
            let pid = match args.get("pid").and_then(|v| v.as_u64()) {
                Some(p) => p as ProcessId,
                None => return CallToolResult::error("Missing required parameter 'pid'"),
            };

            let mut session = session_arc.lock().unwrap();
            match session.pal.attach(pid) {
                Ok(()) => {
                    session.scanner.reset();
                    let arch = match session.pal.architecture() {
                        engine_pal::CpuArchitecture::X86_32 => "32-bit (x86)",
                        engine_pal::CpuArchitecture::X86_64 => "64-bit (x64)",
                    };
                    CallToolResult::text(format!(
                        "Successfully attached to process {pid} ({arch}) via backend '{}'",
                        session.pal.backend_name()
                    ))
                }
                Err(e) => CallToolResult::error(format!("Failed to attach to process {pid}: {e}")),
            }
        }
        "process_info" => {
            let session = session_arc.lock().unwrap();
            let pid = match session.pal.attached_pid() {
                Some(p) => p,
                None => return CallToolResult::error("Not attached to any process. Call process_attach first."),
            };

            let regions_count = session.pal.query_regions().map(|r| r.len()).unwrap_or(0);
            let modules = session.pal.enumerate_modules().unwrap_or_default();
            let threads_count = session.pal.enumerate_threads().map(|t| t.len()).unwrap_or(0);

            let info = json!({
                "pid": pid,
                "backend": session.pal.backend_name(),
                "architecture": format!("{:?}", session.pal.architecture()),
                "stealth_level": format!("{:?}", session.pal.stealth_level()),
                "mapped_regions_count": regions_count,
                "threads_count": threads_count,
                "loaded_modules_count": modules.len(),
                "main_modules": modules.iter().take(10).collect::<Vec<_>>()
            });

            CallToolResult::json(&info).unwrap_or_else(|e| CallToolResult::error(e.to_string()))
        }
        "memory_scan" => {
            let val_str = match args.get("value").and_then(|v| v.as_str()) {
                Some(v) => v,
                None => return CallToolResult::error("Missing required parameter 'value'"),
            };

            let type_str = args.get("val_type").and_then(|v| v.as_str()).unwrap_or("i32");
            let mode_str = args.get("scan_mode").and_then(|v| v.as_str()).unwrap_or("first_exact");
            let max_res = args.get("max_results").and_then(|v| v.as_u64()).unwrap_or(20) as usize;

            let parsed_type = match type_str.to_lowercase().as_str() {
                "i8" => ScanValueType::I8,
                "u8" => ScanValueType::U8,
                "i16" => ScanValueType::I16,
                "u16" => ScanValueType::U16,
                "i32" => ScanValueType::I32,
                "u32" => ScanValueType::U32,
                "i64" => ScanValueType::I64,
                "u64" => ScanValueType::U64,
                "f32" => ScanValueType::F32,
                "f64" => ScanValueType::F64,
                "aob" => ScanValueType::Aob,
                "string" => ScanValueType::StringUtf8,
                _ => return CallToolResult::error(format!("Unsupported val_type '{type_str}'")),
            };

            let parsed_val = match ScanValue::parse(val_str, parsed_type) {
                Ok(v) => v,
                Err(e) => return CallToolResult::error(format!("Failed to parse value: {e}")),
            };

            let session = &mut *session_arc.lock().unwrap();
            if !session.pal.is_attached() {
                return CallToolResult::error("Not attached to any process. Call process_attach first.");
            }

            let pal = &*session.pal;
            let scanner = &mut session.scanner;

            let start = std::time::Instant::now();
            let count_res = if mode_str == "first_exact" {
                let mut config = ScanConfig::new(parsed_type);
                if let Some(a) = args.get("alignment").and_then(|v| v.as_u64()) {
                    config.alignment = a as usize;
                }
                scanner.first_scan(pal, &config, &FirstScanMode::Exact(parsed_val))
            } else {
                let next_mode = match mode_str {
                    "next_exact" => NextScanMode::Exact(parsed_val),
                    "next_changed" => NextScanMode::Changed,
                    "next_unchanged" => NextScanMode::Unchanged,
                    "next_increased" => NextScanMode::Increased,
                    "next_decreased" => NextScanMode::Decreased,
                    _ => return CallToolResult::error(format!("Unsupported scan_mode '{mode_str}'")),
                };
                scanner.next_scan(pal, &next_mode)
            };

            let duration = start.elapsed();
            match count_res {
                Ok(total_found) => {
                    let results_page = scanner
                        .current_results()
                        .map(|r| r.page(0, max_res).to_vec())
                        .unwrap_or_default();

                    let res_json = json!({
                        "total_found": total_found,
                        "scan_duration_ms": duration.as_millis(),
                        "results": results_page
                    });
                    CallToolResult::json(&res_json).unwrap_or_else(|e| CallToolResult::error(e.to_string()))
                }
                Err(e) => CallToolResult::error(format!("Scan error: {e}")),
            }
        }
        "memory_read" => {
            let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                Some(a) => a,
                None => return CallToolResult::error("Missing parameter 'address'"),
            };
            let addr = match parse_hex_or_dec_address(addr_str) {
                Some(a) => a,
                None => return CallToolResult::error(format!("Invalid address: '{addr_str}'")),
            };

            let type_str = args.get("val_type").and_then(|v| v.as_str()).unwrap_or("i32");
            let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(4) as usize;

            let session = session_arc.lock().unwrap();
            if !session.pal.is_attached() {
                return CallToolResult::error("Not attached to any process. Call process_attach first.");
            }

            match session.pal.read_raw(addr, size) {
                Ok(bytes) => {
                    let val = match type_str {
                        "i32" if bytes.len() >= 4 => json!(i32::from_le_bytes(bytes[..4].try_into().unwrap())),
                        "u32" if bytes.len() >= 4 => json!(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
                        "f32" if bytes.len() >= 4 => json!(f32::from_le_bytes(bytes[..4].try_into().unwrap())),
                        "i64" if bytes.len() >= 8 => json!(i64::from_le_bytes(bytes[..8].try_into().unwrap())),
                        "u64" if bytes.len() >= 8 => json!(u64::from_le_bytes(bytes[..8].try_into().unwrap())),
                        "f64" if bytes.len() >= 8 => json!(f64::from_le_bytes(bytes[..8].try_into().unwrap())),
                        "string" => json!(String::from_utf8_lossy(&bytes)),
                        _ => {
                            let hex_str = bytes
                                .iter()
                                .map(|b| format!("{:02X}", b))
                                .collect::<Vec<_>>()
                                .join(" ");
                            json!(hex_str)
                        }
                    };

                    CallToolResult::json(&json!({
                        "address": format!("0x{:X}", addr.as_u64()),
                        "value": val,
                        "raw_hex": bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
                    }))
                    .unwrap_or_else(|e| CallToolResult::error(e.to_string()))
                }
                Err(e) => CallToolResult::error(format!("Failed to read memory: {e}")),
            }
        }
        "memory_write" => {
            let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                Some(a) => a,
                None => return CallToolResult::error("Missing parameter 'address'"),
            };
            let addr = match parse_hex_or_dec_address(addr_str) {
                Some(a) => a,
                None => return CallToolResult::error(format!("Invalid address: '{addr_str}'")),
            };

            let val_str = match args.get("value").and_then(|v| v.as_str()) {
                Some(v) => v,
                None => return CallToolResult::error("Missing parameter 'value'"),
            };

            let type_str = args.get("val_type").and_then(|v| v.as_str()).unwrap_or("i32");
            let bytes_to_write = match type_str {
                "i32" => match val_str.parse::<i32>() {
                    Ok(n) => n.to_le_bytes().to_vec(),
                    Err(e) => return CallToolResult::error(format!("Invalid i32: {e}")),
                },
                "f32" => match val_str.parse::<f32>() {
                    Ok(f) => f.to_le_bytes().to_vec(),
                    Err(e) => return CallToolResult::error(format!("Invalid f32: {e}")),
                },
                "hex" => {
                    let mut b = Vec::new();
                    for t in val_str.split_whitespace() {
                        match u8::from_str_radix(t, 16) {
                            Ok(byte) => b.push(byte),
                            Err(e) => return CallToolResult::error(format!("Invalid hex byte '{t}': {e}")),
                        }
                    }
                    b
                }
                _ => return CallToolResult::error(format!("Unsupported type '{type_str}' for write")),
            };

            let session = session_arc.lock().unwrap();
            if !session.pal.is_attached() {
                return CallToolResult::error("Not attached to any process. Call process_attach first.");
            }

            match session.pal.write_raw(addr, &bytes_to_write) {
                Ok(()) => CallToolResult::text(format!(
                    "Successfully wrote {} bytes to address 0x{:X}",
                    bytes_to_write.len(),
                    addr.as_u64()
                )),
                Err(e) => CallToolResult::error(format!("Failed to write memory: {e}")),
            }
        }
        "analyze_structure" => {
            let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                Some(a) => a,
                None => return CallToolResult::error("Missing parameter 'address'"),
            };
            let addr = match parse_hex_or_dec_address(addr_str) {
                Some(a) => a,
                None => return CallToolResult::error(format!("Invalid address: '{addr_str}'")),
            };
            let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(256) as usize;

            let session = session_arc.lock().unwrap();
            if !session.pal.is_attached() {
                return CallToolResult::error("Not attached to any process. Call process_attach first.");
            }

            let regions = session.pal.query_regions().unwrap_or_default();
            match session.pal.read_raw(addr, size) {
                Ok(bytes) => {
                    let summary = analyze_memory_block(addr, &bytes, &regions);
                    CallToolResult::json(&summary).unwrap_or_else(|e| CallToolResult::error(e.to_string()))
                }
                Err(e) => CallToolResult::error(format!("Failed to read memory for structure analysis: {e}")),
            }
        }
        "process_detach" => {
            let mut session = session_arc.lock().unwrap();
            match session.pal.detach() {
                Ok(()) => CallToolResult::text("Successfully detached from process"),
                Err(e) => CallToolResult::error(format!("Failed to detach: {e}")),
            }
        }
        "memory_regions" => {
            let session = session_arc.lock().unwrap();
            if !session.pal.is_attached() {
                return CallToolResult::error("Not attached to any process. Call process_attach first.");
            }
            let writable_only = args.get("writable_only").and_then(|v| v.as_bool()).unwrap_or(false);
            match session.pal.query_regions() {
                Ok(mut regs) => {
                    if writable_only {
                        regs.retain(|r| r.is_writable());
                    }
                    CallToolResult::json(&regs).unwrap_or_else(|e| CallToolResult::error(e.to_string()))
                }
                Err(e) => CallToolResult::error(format!("Failed to query regions: {e}")),
            }
        }
        "disassemble" => {
            let hex_str = match args.get("hex").and_then(|v| v.as_str()) {
                Some(h) => h,
                None => return CallToolResult::error("Missing parameter 'hex'"),
            };
            let bitness = args.get("bitness").and_then(|v| v.as_u64()).unwrap_or(64) as u32;
            let ip = args
                .get("ip")
                .and_then(|v| v.as_str())
                .and_then(parse_hex_or_dec_address)
                .map(|a| a.as_u64())
                .unwrap_or(0x1000);

            let mut bytes = Vec::new();
            for b_str in hex_str.split_whitespace() {
                match u8::from_str_radix(b_str, 16) {
                    Ok(b) => bytes.push(b),
                    Err(e) => return CallToolResult::error(format!("Invalid hex byte '{b_str}': {e}")),
                }
            }

            if bytes.is_empty() {
                return CallToolResult::error("No valid hex bytes provided for disassembly");
            }

            let mut decoder = Decoder::with_ip(bitness, &bytes, ip, DecoderOptions::NONE);
            let mut formatter = IntelFormatter::new();
            let mut output = String::new();
            let mut instruction = Instruction::default();

            while decoder.can_decode() {
                decoder.decode_out(&mut instruction);
                let mut instr_str = String::new();
                formatter.format(&instruction, &mut instr_str);
                output.push_str(&format!("0x{:016X}: {}\n", instruction.ip(), instr_str));
            }

            CallToolResult::text(output)
        }
        "script_execute" => {
            let code = match args.get("code").and_then(|v| v.as_str()) {
                Some(c) => c,
                None => return CallToolResult::error("Missing parameter 'code'"),
            };

            match engine_script::sandbox::create_sandboxed_lua() {
                Ok(lua) => {
                    match lua.load(code).eval::<engine_script::mlua::Value>() {
                        Ok(val) => {
                            let val_str = match val {
                                engine_script::mlua::Value::Nil => "nil".to_string(),
                                engine_script::mlua::Value::Boolean(b) => b.to_string(),
                                engine_script::mlua::Value::Integer(i) => i.to_string(),
                                engine_script::mlua::Value::Number(n) => n.to_string(),
                                engine_script::mlua::Value::String(s) => s.to_str().unwrap_or("").to_string(),
                                engine_script::mlua::Value::Table(_) => "[table]".to_string(),
                                other => format!("{:?}", other),
                            };
                            CallToolResult::text(val_str)
                        }
                        Err(e) => CallToolResult::error(format!("Lua execution error: {e}")),
                    }
                }
                Err(e) => CallToolResult::error(format!("Failed to initialize Lua sandbox: {e}")),
            }
        }
        "file_analyze_binary" => {
            let path_str = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return CallToolResult::error("Missing parameter 'path'"),
            };
            match crate::static_analyzer::analyze_file(std::path::Path::new(path_str)) {
                Ok(result) => {
                    CallToolResult::json(&result).unwrap_or_else(|e| CallToolResult::error(e.to_string()))
                }
                Err(e) => CallToolResult::error(e),
            }
        }
        "file_extract_strings" => {
            let path_str = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return CallToolResult::error("Missing parameter 'path'"),
            };
            let min_len = args.get("min_len").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
            let max_results = args.get("max_results").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
            let filter = args.get("filter").and_then(|v| v.as_str());

            match crate::static_analyzer::extract_strings_from_file(
                std::path::Path::new(path_str),
                min_len,
                max_results,
                filter,
            ) {
                Ok(strings) => CallToolResult::json(&json!({
                    "count": strings.len(),
                    "strings": strings
                }))
                .unwrap_or_else(|e| CallToolResult::error(e.to_string())),
                Err(e) => CallToolResult::error(e),
            }
        }
        "file_disassemble_rva" => {
            let path_str = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return CallToolResult::error("Missing parameter 'path'"),
            };
            let bitness = args.get("bitness").and_then(|v| v.as_u64()).unwrap_or(64) as u32;
            let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(64) as usize;

            let (rva_or_offset, is_rva) = if let Some(rva_s) = args.get("rva").and_then(|v| v.as_str()) {
                match parse_hex_or_dec_address(rva_s) {
                    Some(a) => (a.as_u64(), true),
                    None => return CallToolResult::error(format!("Invalid RVA address: '{rva_s}'")),
                }
            } else if let Some(off_s) = args.get("offset").and_then(|v| v.as_str()) {
                match parse_hex_or_dec_address(off_s) {
                    Some(a) => (a.as_u64(), false),
                    None => return CallToolResult::error(format!("Invalid offset: '{off_s}'")),
                }
            } else {
                return CallToolResult::error("Either 'rva' or 'offset' parameter must be provided");
            };

            match crate::static_analyzer::disassemble_file_code(
                std::path::Path::new(path_str),
                rva_or_offset,
                is_rva,
                size,
                bitness,
            ) {
                Ok(asm_text) => CallToolResult::text(asm_text),
                Err(e) => CallToolResult::error(e),
            }
        }
        _ => CallToolResult::error(format!("Unknown tool: '{name}'")),
    }
}

fn parse_hex_or_dec_address(s: &str) -> Option<Address> {
    let s = s.trim();
    if let Some(hex_part) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex_part, 16).ok().map(Address::new)
    } else {
        s.parse::<u64>().ok().map(Address::new)
    }
}
