# AGENTS.md — Developer & AI Agent Guidelines for Engine+

> **CRITICAL DIRECTIVE FOR ALL AI AGENTS AND CONTRIBUTORS:**
> This repository is a high-performance, security-conscious, modern reverse engineering suite and Cheat Engine alternative built in Rust.
> You MUST adhere strictly to the architectural standards, code quality rules, and safety constraints defined in this document.
> **DO NOT** write sloppy code ("говнокод"), duplicate logic, introduce compiler warnings, or bypass sandboxing constraints.

---

## 1. Project Vision & Architecture

Engine+ is designed as a modular workspace of dedicated Rust crates:

```
crates/
├── engine-pal       # Process Access Layer: OS abstractions (Linux, Windows, Wine/Proton, Kernel Driver stubs)
├── engine-core      # High-performance parallel memory scanning engine (Rayon, AOB, ScanValue, pagination)
├── engine-script    # Sandboxed scripting environment (Pure Lua 5.4, zero OS/IO access)
├── engine-mcp       # Standard Model Context Protocol (MCP) server for AI reverse-engineering
├── engine-gui       # VS Code/IDE-style desktop GUI (egui, egui_dock, Catppuccin Mocha theme)
└── engine-cli       # Headless CLI & MCP stdio launcher
```

### Supported Platforms
* **Linux:** Native 64-bit & 32-bit (via `process_vm_readv`, `/proc/<pid>/mem`, `ptrace_scope`), Steam Deck & Proton/Wine Windows game emulation. Requires `sudo` for full memory access.
* **Windows:** 64-bit & 32-bit WOW64 (`OpenProcess`, `ReadProcessMemory`, `WriteProcessMemory`, `VirtualQueryEx`, Toolhelp32). Requires "Run as Administrator".
* **macOS:** ⚠️ **STRICTLY EXCLUDED / POSTPONED.** Do not add macOS code or dependencies.

---

## 2. Non-Negotiable Coding Standards

### 2.1. SOLID, DRY, KISS
* **Single Responsibility:** Keep crates and modules strictly focused. Never leak OS-specific syscalls outside of `engine-pal`.
* **Don't Repeat Yourself (DRY):** Reuse types and helper functions. Common types live in `engine_pal::types` and `engine_core::scanner`.
* **Keep It Simple, Stupid (KISS):** Prefer standard library primitives over heavy third-party dependencies (e.g. use `u32::from_le_bytes` instead of extra binary conversion crates).

### 2.2. Zero Warnings Policy
* Every build must produce **0 warnings and 0 errors**.
* Unused imports, unused variables, and dead code must be removed immediately.
* Do not suppress warnings with `#![allow(unused)]` or `#![allow(warnings)]` at the crate level. Address the root cause.

### 2.3. Safe Error Handling
* **NO `unwrap()` or `expect()` in production library code:**
  * All public methods must return `Result<T, PalError>`, `McpResult<T>`, or `ScriptResult<T>`.
  * Strongly typed errors are defined using `thiserror`.
  * `unwrap()` is strictly reserved for unit tests (`#[cfg(test)]`) and compile-time guaranteed invariants.
* Use `?` operator for clean error propagation.

### 2.4. Concurrency & RAII
* All shared state in engine services and PAL backends must implement `Send + Sync`.
* Wrap raw OS handles (e.g., Win32 `HANDLE`, Linux file descriptors) in RAII structs (`AutoHandle`, `OwnedFd`) that call `CloseHandle` or `close` in `Drop`. Never leak OS descriptors.

### 2.5. Scripting Constraints
* **Pure Lua 5.4 only (`mlua`).**
* Python scripting was **explicitly rejected** by architectural decision due to sandbox vulnerabilities, binary bloat, and GIL lock overhead.
* The Lua environment **must remain strictly sandboxed**: `os`, `io`, `package`, `debug`, `dofile`, `loadfile`, and `require` are permanently stripped from the environment.

---

## 3. Verification Workflow (Run Before Committing)

Before submitting any code change or claiming a task is done, run the following verification steps:

```bash
# 1. Workspace Unit & Integration Tests (must pass 100%)
cargo test

# 2. Cross-Platform Windows Compilation Check
cargo check --target x86_64-pc-windows-gnu -p engine-pal -p engine-core

# 3. Lint & Formatting
cargo clippy --all-targets -- -D warnings
```

If any check fails, resolve it before proceeding.

---

## 4. MCP Server & AI Integration Guidelines

* The MCP server in `crates/engine-mcp` adheres to the **Model Context Protocol specification `2024-11-05`**.
* All tools must have a detailed `description` and a complete JSON Schema for arguments (`input_schema`).
* **Token Optimization is Mandatory:**
  * Do not return mega-byte raw hex memory dumps to the AI.
  * Use [`analyze_structure`](file:///home/yarick/my/myproject/engine_plus/crates/engine-mcp/src/optimizer.rs) to return structured JSON summaries (identifying pointers, floats, strings, and folding zero sequences).
  * Paginate scan results (default 20 items per page).

---

## 5. Git Commit Protocol

Follow Conventional Commits:
* `feat(pal): ...` — New platform abstraction or driver feature.
* `feat(core): ...` — Scanner improvements or data types.
* `feat(mcp): ...` — New MCP tool or protocol feature.
* `feat(gui): ...` — UI widgets, panels, docking, themes.
* `fix(...): ...` — Bug fix.
* `refactor(...): ...` — Architectural refactoring without changing behavior.
* `docs(...): ...` — Documentation updates.

Keep `docs/ROADMAP.md` updated as milestones are completed.
