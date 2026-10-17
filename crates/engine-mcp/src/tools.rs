use crate::optimizer::analyze_memory_block;
use crate::protocol::{CallToolResult, Tool};
use engine_core::{
    assemble_code, build_detour_hook, find_xrefs_in_code, generate_pattern_from_bytes,
    ClassStructure, FirstScanMode, MemoryScanner, NextScanMode, ScanConfig, ScanValue, ScanValueType,
};
use engine_pal::{
    default_backend, default_enumerator, Address, ProcessAccessLayer, ProcessId, ProtectionFlags,
};
use engine_script::{AutoAssembler, ScriptEngine};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Global state session for active process and scanning operations in MCP
pub struct EngineSession {
    pub pal: Arc<Mutex<Box<dyn ProcessAccessLayer>>>,
    pub scanner: Arc<Mutex<MemoryScanner>>,
    pub script_engine: Arc<Mutex<ScriptEngine>>,
    pub aa_allocations: Arc<Mutex<HashMap<String, Address>>>,
}

impl EngineSession {
    pub fn new() -> Self {
        let pal: Arc<Mutex<Box<dyn ProcessAccessLayer>>> = Arc::new(Mutex::new(default_backend()));
        let scanner = Arc::new(Mutex::new(MemoryScanner::new()));
        let aa_allocations = Arc::new(Mutex::new(HashMap::new()));
        let script_engine = Arc::new(Mutex::new(
            ScriptEngine::with_allocations(
                Arc::clone(&pal),
                Arc::clone(&scanner),
                Arc::clone(&aa_allocations),
            )
            .expect("Failed to initialize ScriptEngine"),
        ));

        EngineSession {
            pal,
            scanner,
            script_engine,
            aa_allocations,
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
            description: "Execute safe sandboxed Lua 5.4 script for automation, reverse engineering, or math. Has access to 'memory', 'scanner', and 'assembler' modules, and 'auto_assemble' function.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "code": { "type": "string", "description": "Lua script code to execute" }
                },
                "required": ["code"]
            }),
        },
        Tool {
            name: "auto_assemble".to_string(),
            description: "Execute a Cheat Engine style AutoAssembler script with [ENABLE] / [DISABLE] sections, alloc(name, size), dealloc(name), labels, and assembly instructions/patches".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "script": { "type": "string", "description": "AutoAssembler script content" },
                    "enable": { "type": "boolean", "default": true, "description": "Execute [ENABLE] section (true) or [DISABLE] section (false)" }
                },
                "required": ["script"]
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
        Tool {
            name: "assemble".to_string(),
            description: "Assemble x86/x64 assembly instructions into machine code bytes. Supports instructions (mov, push, pop, add, sub, xor, jmp, call, ret, nop, etc.) and 'db'/'hex:' directives.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "code": { "type": "string", "description": "Assembly code instructions separated by newlines (e.g. 'xor eax, eax\\nret')" },
                    "ip": { "type": "string", "default": "0x1000", "description": "Base instruction pointer hex address" },
                    "bitness": { "type": "integer", "enum": [32, 64], "default": 64, "description": "Target architecture bitness" }
                },
                "required": ["code"]
            }),
        },
        Tool {
            name: "code_patch".to_string(),
            description: "Patch executable code at a specific memory address with assembly instructions or hex bytes. Automatically saves original bytes for rollback safety and supports NOP padding.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Target hex memory address (e.g. '0x7FFC968E1360')" },
                    "asm": { "type": "string", "description": "Assembly instructions to compile and write (e.g. 'nop\\nnop' or 'xor eax, eax')" },
                    "hex": { "type": "string", "description": "Alternative raw hex bytes to write (e.g. '90 90 90' or '31 C0 C3')" },
                    "nop_pad_to": { "type": "integer", "description": "Optional minimum total byte length to pad with NOPs (0x90)" }
                },
                "required": ["address"]
            }),
        },
        Tool {
            name: "hook_install".to_string(),
            description: "Install an inline detour/trampoline hook. Disassembles target site to calculate safe stolen byte boundaries, writes jump to code cave containing payload + stolen instructions, and jumps back to normal flow.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_address": { "type": "string", "description": "Address of instruction/function to hook (e.g. '0x7FFC968E1360')" },
                    "cave_address": { "type": "string", "description": "Address of allocated executable memory for trampoline/code cave (e.g. '0x7FFD00000000')" },
                    "payload_asm": { "type": "string", "description": "Optional assembly payload to execute before original instructions" },
                    "payload_hex": { "type": "string", "description": "Optional raw hex machine code payload to execute before original instructions" }
                },
                "required": ["target_address", "cave_address"]
            }),
        },
        Tool {
            name: "pattern_generate".to_string(),
            description: "Generate an AOB byte signature pattern with wildcards ('??') automatically masking relative call/jump offsets and RIP-relative displacements. Creates signatures resilient across game updates.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Start address of function or code block" },
                    "size": { "type": "integer", "default": 32, "description": "Number of bytes to analyze (default: 32, max: 128)" },
                    "bitness": { "type": "integer", "enum": [32, 64], "description": "Optional bitness override (defaults to attached process arch)" }
                },
                "required": ["address"]
            }),
        },
        Tool {
            name: "find_xrefs".to_string(),
            description: "Scan code memory for cross-references (calls, jumps, and RIP-relative data loads) pointing to a target address.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_address": { "type": "string", "description": "Address of target function or data to find references to" },
                    "search_start": { "type": "string", "description": "Starting address of memory region/module to scan" },
                    "search_size": { "type": "integer", "description": "Number of bytes to scan (e.g. 65536 or module size)" },
                    "bitness": { "type": "integer", "enum": [32, 64], "description": "Optional bitness override" }
                },
                "required": ["target_address", "search_start", "search_size"]
            }),
        },
        Tool {
            name: "memory_allocate".to_string(),
            description: "Allocate virtual memory in target process (e.g. for code caves, injected payload, or detour trampolines).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "size": { "type": "integer", "default": 4096, "description": "Number of bytes to allocate (e.g. 4096)" },
                    "protection": {
                        "type": "string",
                        "enum": ["rw", "rx", "rwx"],
                        "default": "rwx",
                        "description": "Memory protection flags"
                    }
                }
            }),
        },
        Tool {
            name: "memory_free".to_string(),
            description: "Free previously allocated virtual memory in target process.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Hex address of allocated memory to free" }
                },
                "required": ["address"]
            }),
        },
        Tool {
            name: "struct_reconstruct".to_string(),
            description: "Reconstruct a C/C++ game object class layout from memory (ReClass style). Heuristically classifies VTable pointers, 3D Vector3 coordinates, pointers to heap/code, inline strings, floats, ints, and padding.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Base hex address of object (e.g. '0x7FFC968E1360')" },
                    "size": { "type": "integer", "default": 128, "description": "Number of bytes to inspect (default: 128, max: 1024)" },
                    "class_name": { "type": "string", "description": "Optional name for class (e.g. 'PlayerEntity')" }
                },
                "required": ["address"]
            }),
        },
        Tool {
            name: "struct_export".to_string(),
            description: "Export reconstructed object structure layout directly into clean C++, Rust, or C# code definitions with correct field offsets, padding, and static asserts.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Base hex address of object" },
                    "size": { "type": "integer", "default": 128, "description": "Number of bytes to inspect" },
                    "language": {
                        "type": "string",
                        "enum": ["cpp", "rust", "csharp"],
                        "default": "cpp",
                        "description": "Target programming language"
                    },
                    "class_name": { "type": "string", "default": "ReconstructedClass", "description": "Class name" }
                },
                "required": ["address"]
            }),
        },
        Tool {
            name: "struct_rename_field".to_string(),
            description: "Rename a field in a reconstructed structure by offset (useful for AI agents labeling game variables like 'health', 'position', 'vtable') and return updated definition.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Base hex address of object" },
                    "size": { "type": "integer", "default": 128, "description": "Number of bytes" },
                    "class_name": { "type": "string", "default": "ReconstructedClass", "description": "Class name" },
                    "field_offset": { "type": "string", "description": "Hex or decimal field offset (e.g. '0x10' or '16')" },
                    "new_name": { "type": "string", "description": "New variable name (e.g. 'm_vecPosition')" }
                },
                "required": ["address", "field_offset", "new_name"]
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
    let (pal_arc, scanner_arc, script_engine_arc, aa_allocs_arc) = {
        let s = session_arc.lock().unwrap();
        (
            Arc::clone(&s.pal),
            Arc::clone(&s.scanner),
            Arc::clone(&s.script_engine),
            Arc::clone(&s.aa_allocations),
        )
    };

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
                                    .is_some_and(|c| c.to_lowercase().contains(&f_lower))
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

            let mut pal = pal_arc.lock().unwrap();
            match pal.attach(pid) {
                Ok(()) => {
                    scanner_arc.lock().unwrap().reset();
                    let arch = match pal.architecture() {
                        engine_pal::CpuArchitecture::X86_32 => "32-bit (x86)",
                        engine_pal::CpuArchitecture::X86_64 => "64-bit (x64)",
                    };
                    CallToolResult::text(format!(
                        "Successfully attached to process {pid} ({arch}) via backend '{}'",
                        pal.backend_name()
                    ))
                }
                Err(e) => CallToolResult::error(format!("Failed to attach to process {pid}: {e}")),
            }
        }
        "process_info" => {
            let pal = pal_arc.lock().unwrap();
            let pid = match pal.attached_pid() {
                Some(p) => p,
                None => return CallToolResult::error("Not attached to any process. Call process_attach first."),
            };

            let regions_count = pal.query_regions().map(|r| r.len()).unwrap_or(0);
            let modules = pal.enumerate_modules().unwrap_or_default();
            let threads_count = pal.enumerate_threads().map(|t| t.len()).unwrap_or(0);

            let info = json!({
                "pid": pid,
                "backend": pal.backend_name(),
                "architecture": format!("{:?}", pal.architecture()),
                "stealth_level": format!("{:?}", pal.stealth_level()),
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

            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("Not attached to any process. Call process_attach first.");
            }

            let pal_ref = &**pal;
            let mut scanner = scanner_arc.lock().unwrap();

            let start = std::time::Instant::now();
            let count_res = if mode_str == "first_exact" {
                let mut config = ScanConfig::new(parsed_type);
                if let Some(a) = args.get("alignment").and_then(|v| v.as_u64()) {
                    config.alignment = a as usize;
                }
                scanner.first_scan(pal_ref, &config, &FirstScanMode::Exact(parsed_val))
            } else {
                let next_mode = match mode_str {
                    "next_exact" => NextScanMode::Exact(parsed_val),
                    "next_changed" => NextScanMode::Changed,
                    "next_unchanged" => NextScanMode::Unchanged,
                    "next_increased" => NextScanMode::Increased,
                    "next_decreased" => NextScanMode::Decreased,
                    _ => return CallToolResult::error(format!("Unsupported scan_mode '{mode_str}'")),
                };
                scanner.next_scan(pal_ref, &next_mode)
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

            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("Not attached to any process. Call process_attach first.");
            }

            match pal.read_raw(addr, size) {
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

            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("Not attached to any process. Call process_attach first.");
            }

            match pal.write_raw(addr, &bytes_to_write) {
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

            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("Not attached to any process. Call process_attach first.");
            }

            let regions = pal.query_regions().unwrap_or_default();
            match pal.read_raw(addr, size) {
                Ok(bytes) => {
                    let summary = analyze_memory_block(addr, &bytes, &regions);
                    CallToolResult::json(&summary).unwrap_or_else(|e| CallToolResult::error(e.to_string()))
                }
                Err(e) => CallToolResult::error(format!("Failed to read memory for structure analysis: {e}")),
            }
        }
        "process_detach" => {
            let mut pal = pal_arc.lock().unwrap();
            match pal.detach() {
                Ok(()) => CallToolResult::text("Successfully detached from process"),
                Err(e) => CallToolResult::error(format!("Failed to detach: {e}")),
            }
        }
        "memory_regions" => {
            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("Not attached to any process. Call process_attach first.");
            }
            let writable_only = args.get("writable_only").and_then(|v| v.as_bool()).unwrap_or(false);
            match pal.query_regions() {
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

            let script_engine = script_engine_arc.lock().unwrap();
            let result = match script_engine.execute(code) {
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
            };
            result
        }
        "auto_assemble" => {
            let script = match args.get("script").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return CallToolResult::error("Missing parameter 'script'"),
            };
            let enable = args.get("enable").and_then(|v| v.as_bool()).unwrap_or(true);

            let mut pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("Not attached to any process. Call process_attach first.");
            }

            let mut allocs = aa_allocs_arc.lock().unwrap();
            match AutoAssembler::execute(script, enable, &mut **pal, &mut allocs) {
                Ok(report) => {
                    let resp = json!({
                        "status": if enable { "enabled" } else { "disabled" },
                        "allocations": report.allocations.iter().map(|a| json!({
                            "name": a.name,
                            "address": format!("0x{:X}", a.address.as_u64()),
                            "size": a.size
                        })).collect::<Vec<_>>(),
                        "total_allocations": allocs.len(),
                    });
                    CallToolResult::json(&resp).unwrap_or_else(|e| CallToolResult::error(e.to_string()))
                }
                Err(e) => CallToolResult::error(format!("AutoAssembler error: {e}")),
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
        "assemble" => {
            let code = match args.get("code").and_then(|v| v.as_str()) {
                Some(c) => c,
                None => return CallToolResult::error("Missing parameter 'code'"),
            };
            let ip = match args.get("ip").and_then(|v| v.as_str()) {
                Some(s) => match parse_hex_or_dec_address(s) {
                    Some(a) => a.as_u64(),
                    None => return CallToolResult::error(format!("Invalid ip hex address: '{s}'")),
                },
                None => 0x1000,
            };
            let bitness = args.get("bitness").and_then(|v| v.as_u64()).unwrap_or(64) as u32;

            match assemble_code(code, bitness, ip) {
                Ok(bytes) => {
                    let hex_str = bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
                    CallToolResult::json(&json!({
                        "hex": hex_str,
                        "bytes": bytes,
                        "length": bytes.len(),
                        "ip": format!("0x{ip:X}")
                    }))
                    .unwrap_or_else(|e| CallToolResult::error(e.to_string()))
                }
                Err(e) => CallToolResult::error(format!("Assembly error: {e}")),
            }
        }
        "code_patch" => {
            let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                Some(a) => a,
                None => return CallToolResult::error("Missing parameter 'address'"),
            };
            let address = match parse_hex_or_dec_address(addr_str) {
                Some(a) => a,
                None => return CallToolResult::error(format!("Invalid address: '{addr_str}'")),
            };

            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("No process attached. Use 'process_attach' first.");
            }
            let bitness = match pal.architecture() {
                engine_pal::CpuArchitecture::X86_32 => 32,
                engine_pal::CpuArchitecture::X86_64 => 64,
            };

            let mut patch_bytes = if let Some(asm) = args.get("asm").and_then(|v| v.as_str()) {
                match assemble_code(asm, bitness, address.as_u64()) {
                    Ok(b) => b,
                    Err(e) => return CallToolResult::error(format!("Assembly error: {e}")),
                }
            } else if let Some(hex_str) = args.get("hex").and_then(|v| v.as_str()) {
                match parse_hex_bytes(hex_str) {
                    Ok(b) => b,
                    Err(e) => return CallToolResult::error(format!("Invalid hex bytes: {e}")),
                }
            } else {
                return CallToolResult::error("Either 'asm' or 'hex' parameter must be provided");
            };

            if let Some(pad_len) = args.get("nop_pad_to").and_then(|v| v.as_u64()) {
                let pad_len = pad_len as usize;
                while patch_bytes.len() < pad_len {
                    patch_bytes.push(0x90);
                }
            }

            if patch_bytes.is_empty() {
                return CallToolResult::error("Patch bytes are empty");
            }

            let original_bytes = match pal.read_raw(address, patch_bytes.len()) {
                Ok(b) => b,
                Err(e) => return CallToolResult::error(format!("Failed to read original bytes: {e}")),
            };

            match pal.write_raw(address, &patch_bytes) {
                Ok(()) => {
                    let orig_hex = original_bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
                    let patch_hex = patch_bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
                    CallToolResult::json(&json!({
                        "status": "success",
                        "address": format!("0x{:X}", address.as_u64()),
                        "original_bytes_hex": orig_hex,
                        "patched_bytes_hex": patch_hex,
                        "length": patch_bytes.len()
                    }))
                    .unwrap_or_else(|e| CallToolResult::error(e.to_string()))
                }
                Err(e) => CallToolResult::error(format!("Failed to write patch to memory: {e}")),
            }
        }
        "hook_install" => {
            let target_str = match args.get("target_address").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return CallToolResult::error("Missing parameter 'target_address'"),
            };
            let target_addr = match parse_hex_or_dec_address(target_str) {
                Some(a) => a,
                None => return CallToolResult::error(format!("Invalid target_address: '{target_str}'")),
            };

            let cave_str = match args.get("cave_address").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return CallToolResult::error("Missing parameter 'cave_address'"),
            };
            let cave_addr = match parse_hex_or_dec_address(cave_str) {
                Some(a) => a,
                None => return CallToolResult::error(format!("Invalid cave_address: '{cave_str}'")),
            };

            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("No process attached. Use 'process_attach' first.");
            }
            let bitness = match pal.architecture() {
                engine_pal::CpuArchitecture::X86_32 => 32,
                engine_pal::CpuArchitecture::X86_64 => 64,
            };

            let original_slice = match pal.read_raw(target_addr, 32) {
                Ok(b) => b,
                Err(e) => return CallToolResult::error(format!("Failed to read target instructions: {e}")),
            };

            let mut payload = Vec::new();
            if let Some(asm) = args.get("payload_asm").and_then(|v| v.as_str()) {
                match assemble_code(asm, bitness, cave_addr.as_u64()) {
                    Ok(b) => payload = b,
                    Err(e) => return CallToolResult::error(format!("Payload assembly error: {e}")),
                }
            } else if let Some(hex_str) = args.get("payload_hex").and_then(|v| v.as_str()) {
                match parse_hex_bytes(hex_str) {
                    Ok(b) => payload = b,
                    Err(e) => return CallToolResult::error(format!("Payload hex error: {e}")),
                }
            }

            match build_detour_hook(
                &original_slice,
                target_addr.as_u64(),
                cave_addr.as_u64(),
                bitness,
                &payload,
            ) {
                Ok(package) => {
                    if let Err(e) = pal.write_raw(cave_addr, &package.code_cave_bytes) {
                        return CallToolResult::error(format!("Failed to write code cave bytes: {e}"));
                    }
                    if let Err(e) = pal.write_raw(target_addr, &package.patch_bytes) {
                        return CallToolResult::error(format!("Failed to write detour patch: {e}"));
                    }

                    let orig_hex = package.original_bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
                    let patch_hex = package.patch_bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
                    let cave_hex = package.code_cave_bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");

                    CallToolResult::json(&json!({
                        "status": "hook_installed",
                        "target_address": format!("0x{:X}", target_addr.as_u64()),
                        "cave_address": format!("0x{:X}", cave_addr.as_u64()),
                        "stolen_bytes_count": package.original_bytes.len(),
                        "return_address": format!("0x{:X}", package.return_address.as_u64()),
                        "target_patch_hex": patch_hex,
                        "original_bytes_hex": orig_hex,
                        "code_cave_hex": cave_hex
                    }))
                    .unwrap_or_else(|e| CallToolResult::error(e.to_string()))
                }
                Err(e) => CallToolResult::error(format!("Failed to build detour hook: {e}")),
            }
        }
        "pattern_generate" => {
            let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                Some(a) => a,
                None => return CallToolResult::error("Missing parameter 'address'"),
            };
            let address = match parse_hex_or_dec_address(addr_str) {
                Some(a) => a,
                None => return CallToolResult::error(format!("Invalid address: '{addr_str}'")),
            };
            let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(32).min(128) as usize;

            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("No process attached. Use 'process_attach' first.");
            }
            let bitness = args.get("bitness").and_then(|v| v.as_u64()).map(|b| b as u32).unwrap_or_else(|| {
                match pal.architecture() {
                    engine_pal::CpuArchitecture::X86_32 => 32,
                    engine_pal::CpuArchitecture::X86_64 => 64,
                }
            });

            let code_bytes = match pal.read_raw(address, size) {
                Ok(b) => b,
                Err(e) => return CallToolResult::error(format!("Failed to read memory: {e}")),
            };

            match generate_pattern_from_bytes(&code_bytes, address.as_u64(), bitness, size) {
                Ok(pattern) => {
                    let wildcard_count = pattern.split_whitespace().filter(|t| *t == "??").count();
                    let total_tokens = pattern.split_whitespace().count();
                    CallToolResult::json(&json!({
                        "address": format!("0x{:X}", address.as_u64()),
                        "pattern": pattern,
                        "total_bytes": total_tokens,
                        "wildcards": wildcard_count
                    }))
                    .unwrap_or_else(|e| CallToolResult::error(e.to_string()))
                }
                Err(e) => CallToolResult::error(format!("Pattern generation error: {e}")),
            }
        }
        "find_xrefs" => {
            let target_str = match args.get("target_address").and_then(|v| v.as_str()) {
                Some(t) => t,
                None => return CallToolResult::error("Missing parameter 'target_address'"),
            };
            let target_addr = match parse_hex_or_dec_address(target_str) {
                Some(a) => a,
                None => return CallToolResult::error(format!("Invalid target_address: '{target_str}'")),
            };

            let start_str = match args.get("search_start").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return CallToolResult::error("Missing parameter 'search_start'"),
            };
            let start_addr = match parse_hex_or_dec_address(start_str) {
                Some(a) => a,
                None => return CallToolResult::error(format!("Invalid search_start: '{start_str}'")),
            };

            let search_size = match args.get("search_size").and_then(|v| v.as_u64()) {
                Some(s) => (s as usize).min(10 * 1024 * 1024),
                None => return CallToolResult::error("Missing parameter 'search_size'"),
            };

            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("No process attached. Use 'process_attach' first.");
            }
            let bitness = args.get("bitness").and_then(|v| v.as_u64()).map(|b| b as u32).unwrap_or_else(|| {
                match pal.architecture() {
                    engine_pal::CpuArchitecture::X86_32 => 32,
                    engine_pal::CpuArchitecture::X86_64 => 64,
                }
            });

            let code_bytes = match pal.read_raw(start_addr, search_size) {
                Ok(b) => b,
                Err(e) => return CallToolResult::error(format!("Failed to read memory at search_start: {e}")),
            };

            let xrefs = find_xrefs_in_code(&code_bytes, start_addr.as_u64(), bitness, target_addr.as_u64());
            CallToolResult::json(&json!({
                "target_address": format!("0x{:X}", target_addr.as_u64()),
                "search_range": format!("0x{:X} - 0x{:X}", start_addr.as_u64(), start_addr.as_u64() + search_size as u64),
                "count": xrefs.len(),
                "xrefs": xrefs
            }))
            .unwrap_or_else(|e| CallToolResult::error(e.to_string()))
        }
        "memory_allocate" => {
            let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(4096) as usize;
            let prot_str = args.get("protection").and_then(|v| v.as_str()).unwrap_or("rwx");
            let protection = match prot_str.to_lowercase().as_str() {
                "rw" => ProtectionFlags::RW,
                "rx" => ProtectionFlags::RX,
                "rwx" => ProtectionFlags::RWX,
                _ => ProtectionFlags::RWX,
            };

            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("No process attached. Use 'process_attach' first.");
            }

            match pal.allocate_memory(size, protection) {
                Ok(addr) => CallToolResult::json(&json!({
                    "status": "success",
                    "address": format!("0x{:X}", addr.as_u64()),
                    "size": size,
                    "protection": prot_str
                }))
                .unwrap_or_else(|e| CallToolResult::error(e.to_string())),
                Err(e) => CallToolResult::error(format!("Memory allocation failed: {e}")),
            }
        }
        "memory_free" => {
            let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                Some(a) => a,
                None => return CallToolResult::error("Missing parameter 'address'"),
            };
            let address = match parse_hex_or_dec_address(addr_str) {
                Some(a) => a,
                None => return CallToolResult::error(format!("Invalid address: '{addr_str}'")),
            };

            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("No process attached. Use 'process_attach' first.");
            }

            match pal.free_memory(address) {
                Ok(()) => CallToolResult::json(&json!({
                    "status": "freed",
                    "address": format!("0x{:X}", address.as_u64())
                }))
                .unwrap_or_else(|e| CallToolResult::error(e.to_string())),
                Err(e) => CallToolResult::error(format!("Failed to free memory: {e}")),
            }
        }
        "struct_reconstruct" => {
            let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                Some(a) => a,
                None => return CallToolResult::error("Missing parameter 'address'"),
            };
            let address = match parse_hex_or_dec_address(addr_str) {
                Some(a) => a,
                None => return CallToolResult::error(format!("Invalid address: '{addr_str}'")),
            };
            let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(128).min(1024) as usize;
            let class_name = args.get("class_name").and_then(|v| v.as_str()).unwrap_or("ReconstructedClass");

            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("No process attached. Use 'process_attach' first.");
            }

            let bytes = match pal.read_raw(address, size) {
                Ok(b) => b,
                Err(e) => return CallToolResult::error(format!("Failed to read memory: {e}")),
            };
            let regions = pal.query_regions().unwrap_or_default();
            let structure = ClassStructure::reconstruct(address, &bytes, &regions, Some(class_name));

            CallToolResult::json(&structure).unwrap_or_else(|e| CallToolResult::error(e.to_string()))
        }
        "struct_export" => {
            let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                Some(a) => a,
                None => return CallToolResult::error("Missing parameter 'address'"),
            };
            let address = match parse_hex_or_dec_address(addr_str) {
                Some(a) => a,
                None => return CallToolResult::error(format!("Invalid address: '{addr_str}'")),
            };
            let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(128).min(1024) as usize;
            let lang = args.get("language").and_then(|v| v.as_str()).unwrap_or("cpp");
            let class_name = args.get("class_name").and_then(|v| v.as_str()).unwrap_or("ReconstructedClass");

            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("No process attached. Use 'process_attach' first.");
            }

            let bytes = match pal.read_raw(address, size) {
                Ok(b) => b,
                Err(e) => return CallToolResult::error(format!("Failed to read memory: {e}")),
            };
            let regions = pal.query_regions().unwrap_or_default();
            let structure = ClassStructure::reconstruct(address, &bytes, &regions, Some(class_name));

            let code = match lang.to_lowercase().as_str() {
                "rust" | "rs" => structure.to_rust(),
                "cs" | "csharp" => structure.to_csharp(),
                _ => structure.to_cpp(),
            };

            CallToolResult::text(code)
        }
        "struct_rename_field" => {
            let addr_str = match args.get("address").and_then(|v| v.as_str()) {
                Some(a) => a,
                None => return CallToolResult::error("Missing parameter 'address'"),
            };
            let address = match parse_hex_or_dec_address(addr_str) {
                Some(a) => a,
                None => return CallToolResult::error(format!("Invalid address: '{addr_str}'")),
            };
            let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(128).min(1024) as usize;
            let class_name = args.get("class_name").and_then(|v| v.as_str()).unwrap_or("ReconstructedClass");

            let offset_str = match args.get("field_offset").and_then(|v| v.as_str()) {
                Some(o) => o,
                None => return CallToolResult::error("Missing parameter 'field_offset'"),
            };
            let offset = match parse_hex_or_dec_address(offset_str) {
                Some(a) => a.as_u64() as usize,
                None => return CallToolResult::error(format!("Invalid field_offset: '{offset_str}'")),
            };

            let new_name = match args.get("new_name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => return CallToolResult::error("Missing parameter 'new_name'"),
            };

            let pal = pal_arc.lock().unwrap();
            if !pal.is_attached() {
                return CallToolResult::error("No process attached. Use 'process_attach' first.");
            }

            let bytes = match pal.read_raw(address, size) {
                Ok(b) => b,
                Err(e) => return CallToolResult::error(format!("Failed to read memory: {e}")),
            };
            let regions = pal.query_regions().unwrap_or_default();
            let mut structure = ClassStructure::reconstruct(address, &bytes, &regions, Some(class_name));

            match structure.rename_field(offset, new_name) {
                Ok(()) => CallToolResult::json(&structure).unwrap_or_else(|e| CallToolResult::error(e.to_string())),
                Err(e) => CallToolResult::error(format!("Failed to rename field: {e}")),
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

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for token in s.split_whitespace() {
        let clean = token.trim_start_matches("0x").trim_start_matches("0X");
        let b = u8::from_str_radix(clean, 16)
            .map_err(|e| format!("Invalid hex byte '{token}': {e}"))?;
        bytes.push(b);
    }
    Ok(bytes)
}
