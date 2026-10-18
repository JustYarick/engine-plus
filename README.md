# Engine+

High-Performance Reverse Engineering Suite, Memory Scanner, Scripting Sandbox and AI Model Context Protocol (MCP) Server in Rust.

[![Build and Test](https://img.shields.io/badge/tests-88%2F88%20passing-brightgreen)](#)
[![License](https://img.shields.io/badge/license-MIT-blue)](#)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20Wine%2FProton-lightgrey)](#)
[![MCP Spec](https://img.shields.io/badge/MCP-2024--11--05-orange)](#)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-purple)](#)

Engine+ is a modern, modular, memory-safe reverse engineering toolkit and Cheat Engine alternative built from scratch in Rust. It combines a high-speed multithreaded memory scanner, position-independent code injection, position-independent reflective loading, unhooking, debugger and hit tracing with a fully sandboxed Lua 5.4 scripting environment and a native Model Context Protocol (MCP) server for autonomous AI reverse engineering (Claude, Cursor, Antigravity, GPT, Ollama).

---

## Key Features

* **Parallel Memory Scanner (Rayon):** Fast first and next scans for all numeric primitives (`i8`..`u64`, `f32`, `f64`), strings (UTF-8, UTF-16, ASCII) and Array-of-Bytes (AOB) with wildcards (`48 8B ?? C3`). 512 KiB chunk-buffered paging scans gigabytes in milliseconds.
* **AI-Native MCP Server (27 Tools):** Fully compliant with MCP specification `2024-11-05` over stdio transport. Features a Token Optimizer that converts raw memory dumps into structured JSON definitions (detecting pointers, floats, strings, zero-sequences) with pagination.
* **Structure Dissector (ReClass Style):** Automatic discovery of virtual method tables (VTables), 3D vectors (`Vector3`), nested pointers and inline strings. Exports generated class definitions to C++, Rust, and C#.
* **Debugger & Hit Tracer:**
  * Hardware breakpoints DR0-DR3 (execution, memory write, memory read/write) with DR6/DR7 bitfield management.
  * Software INT3 breakpoints (0xCC) with automatic restoration of original instruction bytes.
  * Real-time "What writes to this address?" analyzer with CPU register capture and instruction disassembly via `iced-x86`.
* **Disassembler, Inline Assembler & Detour Hooks:**
  * Full Intel-syntax assembly and disassembly powered by `iced-x86`.
  * Automatic boundary calculation for stolen bytes, 5-byte relative branch trampolines (`jmp rel32`) and NOP-padding.
  * AOB signature generator with automatic wildcard masking of relative jump and call displacements.
* **DLL / Shared-Object Injection & Stealth (`engine-inject`):**
  * **Manual Mapping:** Allocates virtual memory, copies PE sections, applies base relocations, resolves imports (including missing dependency autoloading and recursive export forwarder resolution), sets per-section protections, optionally erases headers, and executes `DllMain` in a remote thread.
  * **Reflective DLL Injection:** Two modes supported:
    * Classic Stephen Fewer RDI convention (starts remote execution at the DLL's exported `ReflectiveLoader`).
    * Custom position-independent x64 loader stub assembled at runtime via `iced-x86`, which allocates, relocates and initializes the DLL in-process.
  * **PE Header Erasure:** Overwrites DOS and NT headers of mapped modules with zeroes, using temporary protection transitions to defeat in-memory PE scanners.
  * **System Module Unhooking:** Restores modified `.text` sections of hooked modules (e.g., `ntdll.dll`) by diffing and patching against clean memory views from `\KnownDlls`.
  * **Stealth Primitives:** Thread hiding (`ThreadHideFromDebugger`), memory remapping to pagefile-backed sections (`MEM_MAPPED` instead of `MEM_PRIVATE`), and handle stashing in dedicated helper processes via `DuplicateHandle`.
  * **Linux Injection:** ELF validation and remote `dlopen` execution over `ptrace` with automatic unlinking of temporary in-memory objects.
* **Sandboxed Lua 5.4 Scripting & Cheat Engine AutoAssembler:**
  * Strictly isolated Lua 5.4 environment: dangerous system APIs (`os`, `io`, `debug`, `package`, `dofile`, `loadfile`, `require`) are stripped from the environment.
  * Core bindings for reading/writing memory, assembling code, managing allocations, and invoking injection primitives.
  * Compatibility parser for Cheat Engine AutoAssembler scripts (`[ENABLE]` / `[DISABLE]`, `alloc`, `dealloc`, `labels`).
* **Multi-Level Pointer Scanner:** Traverses pointer graphs across loaded modules and heaps to discover stable static pointer chains (`module.exe + 0x1000 -> +0x20 -> +0xF8`) with live resolution.
* **Continuous Speedhack:** State-machine-driven time scaling with continuous mathematical continuity, generating injection stubs for `clock_gettime` (Linux) and `QueryPerformanceCounter` (Windows).

---

## Workspace Architecture

```
crates/
├── engine-pal       # Process Access Layer: OS abstractions (Linux, Windows, Wine/Proton)
├── engine-core      # Core: Parallel Rayon scanner, disassembler, ReClass, pointer scanner
├── engine-inject    # DLL injection, manual mapping, reflective loading, stealth & unhooking
├── engine-script    # Sandboxed Lua 5.4 runtime and Cheat Engine AutoAssembler
├── engine-mcp       # Standard Model Context Protocol (MCP) server for AI integration
└── engine-cli       # Primary binary ('engine-plus'): Interactive REPL, subcommands & MCP server
```

### Supported Platforms

* **Linux:** Native 64-bit and 32-bit (via `process_vm_readv`, `/proc/<pid>/mem`, `ptrace`), Steam Deck and Proton/Wine game emulation. Requires appropriate permissions or `sudo` for full access to remote address spaces.
* **Windows:** 64-bit and 32-bit WOW64 (`OpenProcess`, `VirtualAllocEx`, `VirtualProtectEx`, `CreateRemoteThread`, `NtCreateSection`, `NtMapViewOfSection`, Toolhelp32). Requires Administrator privileges.
* **macOS:** Strictly excluded.

---

## Installation

### Prerequisites

* Rust 1.75+ (stable toolchain)
* C compiler and CMake (for vendored Lua build on Linux)
* Linux: `build-essential`, `pkg-config`
* Windows: MSVC or MinGW-w64 toolchain

### Building from Source

```bash
# Clone the repository
git clone git@github.com:JustYarick/engine-plus.git
cd engine-plus

# Build in release mode
cargo build --release --bin engine-plus

# The compiled binary is located at:
# target/release/engine-plus
```

### System Installation

```bash
# Automatic installation into ~/.local/bin (Linux):
./install.sh

# Or install globally via cargo:
cargo install --path crates/engine-cli --bin engine-plus
```

---

## Usage

### 1. Interactive Console (REPL)

Start the interactive console:

```bash
engine-plus console
```

Available REPL commands:

```text
Process Management:
  ps [filter]                 - List processes matching filter
  attach <pid>                - Attach to target process
  detach                      - Detach from target process
  info                        - Display attached process information
  modules                     - List loaded modules and base addresses
  threads                     - List process threads

Memory Scanning:
  scan <val> <type> [align]   - Start first scan (types: i8, i16, i32, i64, u8, u16, u32, u64, f32, f64, str, aob)
  next <val|mode>             - Filter scan (modes: exact, changed, unchanged, increased, decreased)
  results [limit]             - Show scan results (default: 20)
  read <addr> <type>          - Read typed value from address
  write <addr> <type> <val>   - Write typed value to address
  dump <addr> <size>          - Hexadecimal memory dump

Disassembly and Inspection:
  disasm <addr> [count]       - Disassemble instructions via iced-x86
  whatwrites <addr> [size]    - Hit tracer: identify instructions writing to address
  reclass <addr> [size]       - Analyze and reconstruct data structures (VTables, floats, strings)
  export <addr> [size] <lang> - Export structure code to cpp, rust, or csharp
  ptrscan <addr> [depth] [off]- Search for static pointer chains
  ptrresolve <mod> <off...>   - Resolve pointer chain to target address
  speedhack <factor>          - Apply time dilation (e.g., speedhack 2.0)

Injection and Stealth:
  inject <path> [method]      - Inject library (methods: auto, manual_map, reflective_rdi, reflective_stub)
  unhook [module]             - Restore module .text from \KnownDlls (default: ntdll.dll)
  hidethread <tid|all>        - Hide thread from debuggers (ThreadHideFromDebugger)
  hidemem <addr> <size>       - Remap private region as section-backed (MEM_MAPPED)
  hidehandle <handle> [exe]   - Relocate handle to helper process (handle stashing)

Scripting:
  aa <script_file>            - Execute Cheat Engine AutoAssembler script
  lua <script_file>           - Execute sandboxed Lua 5.4 script
```

### 2. AI Model Context Protocol (MCP) Server

Engine+ functions as a standard MCP server over stdio for AI assistants (Cursor, Claude Desktop, Antigravity, Windsurf).

Start the server:

```bash
engine-plus --mcp
```

Configuration example for Claude Desktop (`claude_desktop_config.json`) or Cursor (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "engine-plus": {
      "command": "engine-plus",
      "args": ["--mcp"]
    }
  }
}
```

Registered MCP tools (27 tools total):
* Process: `process_list`, `process_attach`, `process_detach`, `process_info`, `memory_regions`, `module_list`
* Memory: `memory_scan`, `memory_read`, `memory_write`, `memory_allocate`, `memory_free`
* Structure & Analysis: `analyze_structure`, `generate_signature`, `find_xrefs`, `static_analyze_file`
* Assembly: `assemble`, `disassemble`, `auto_assemble`
* Debugger: `debug_set_breakpoint`, `debug_remove_breakpoint`, `debug_what_writes`, `debug_registers`
* Injection & Stealth: `inject_dll`, `unhook_ntdll`, `hide_thread`, `hide_memory`, `hide_handle`
* Scripting: `script_execute`, `speedhack_set`

---

## Documentation

* [Architecture Overview](docs/ARCHITECTURE.md) - System layers, PAL traits, and concurrency design
* [Project Roadmap](docs/ROADMAP.md) - Completed milestones and development progress
* [Model Context Protocol Integration](docs/MCP_INTEGRATION.md) - MCP tools specification and AI prompts
* [AI Reversing Guide](docs/AI_REVERSING_GUIDE.md) - Step-by-step game reversing tutorial for AI agents
* [Lua Scripting Sandbox](docs/SCRIPTING_LUA.md) - Sandboxed Lua 5.4 runtime and API reference
* [Cross-Platform Architecture](docs/CROSS_PLATFORM.md) - Linux, Windows and Wine/Proton implementation details
* [Code Injection & Detour Hooks](docs/CODE_INJECTION.md) - Low-level trampoline allocation and hooking details

---

## Verification and Testing

Engine+ enforces a strict Zero Warnings and Safe Error Handling policy:

```bash
# 1. Run workspace unit and integration tests (88 tests)
cargo test --workspace

# 2. Windows cross-compilation check
cargo check --target x86_64-pc-windows-gnu -p engine-pal -p engine-core -p engine-inject

# 3. Static analysis and linter check (0 warnings)
cargo clippy --all-targets -- -D warnings
cargo clippy --target x86_64-pc-windows-gnu -p engine-pal -p engine-core -p engine-inject --all-targets -- -D warnings
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
