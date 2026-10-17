# 🔩 Tech Stack — Технологический стек Engine+

## Языки

| Язык | Где используется |
|------|-----------------|
| **Rust** | Core engine, PAL, GUI, CLI, MCP server, scripting bindings |
| **C** | Kernel driver (LKM), некоторые FFI bindings |
| **Lua** | Пользовательские скрипты и чит-таблицы |

---

## Основные зависимости (Rust crates)

### Core

| Crate | Версия | Назначение |
|-------|--------|-----------|
| `tokio` | 1.x | Async runtime |
| `serde` / `serde_json` | 1.x | Сериализация |
| `thiserror` | 2.x | Типизированные ошибки |
| `anyhow` | 1.x | Контекстные ошибки |
| `tracing` | 0.1 | Structured logging |
| `crossbeam` | 0.8 | Lock-free structures, channels |
| `rayon` | 1.x | Параллелизм (для scanner) |
| `dashmap` | 6.x | Concurrent HashMap |
| `bitflags` | 2.x | Битовые флаги |

### Memory / Process

| Crate | Назначение |
|-------|-----------|
| `nix` | Unix API wrappers (ptrace, mmap, signals) |
| `libc` | Raw libc bindings |
| `proc-maps` | Парсинг /proc/pid/maps |
| `memchr` | Быстрый поиск байтов |
| `byteorder` | Endian conversions |
| `zerocopy` | Zero-copy parsing |

### Disassembler / Assembler

| Crate | Назначение |
|-------|-----------|
| `iced-x86` | x86/x64 disassembler & assembler (НЕ путать с UI iced!) |
| `capstone` | Multi-arch disassembler (fallback) |
| `keystone` | Multi-arch assembler |
| `goblin` | PE/ELF/Mach-O parser |
| `object` | Object file parser |

### GUI

| Crate | Назначение |
|-------|-----------|
| `eframe` / `egui` | Immediate mode GUI |
| `egui_extras` | Дополнительные виджеты |
| `egui-dock` | Docking layout (VS Code-like) |
| `egui_code_editor` | Code editor widget |
| `syntect` | Syntax highlighting |
| `rfd` | Native file dialogs |
| `image` | Image loading (icons) |

### MCP

| Crate | Назначение |
|-------|-----------|
| `mcp-sdk` или custom | MCP protocol implementation |
| `jsonrpc-core` | JSON-RPC 2.0 |
| `tower` | Service middleware (rate limiting, etc.) |
| `axum` | HTTP server (для SSE transport) |
| `tokio-tungstenite` | WebSocket (для WS transport) |

### Scripting

| Crate | Назначение |
|-------|-----------|
| `mlua` | Встроенный рантайм Lua 5.4 (`vendored` + `async`) |
| `wasmtime` | WASM runtime (для плагинов) |

### CLI

| Crate | Назначение |
|-------|-----------|
| `clap` | Argument parser |
| `ratatui` | TUI framework |
| `indicatif` | Progress bars |
| `colored` | Colored terminal output |
| `rustyline` | Readline (REPL) |

### Утилиты

| Crate | Назначение |
|-------|-----------|
| `uuid` | Уникальные идентификаторы |
| `chrono` | Дата/время |
| `directories` | XDG directories |
| `toml` | Config files |
| `rmp-serde` | MessagePack (для таблиц) |
| `flate2` | Compression |

---

## Системные требования

### Минимальные

- **OS**: Linux 5.10+ (kernel с CONFIG_PROCESS_VM_READV=y)
- **CPU**: x86_64 (AMD64)
- **RAM**: 512 MB
- **GPU**: OpenGL 3.3+ или Vulkan (для egui)
- **Rust**: 1.75+ (nightly для некоторых features)

### Рекомендуемые

- **OS**: Linux 6.x
- **RAM**: 4 GB+ (для больших сканирований)
- **GPU**: Vulkan support (wgpu backend)
- **Для driver**: root access, kernel headers

### Платформы

- **Linux**: Linux 5.10+ (нативная поддержка, чтение `/proc/pid/mem`, `process_vm_readv`, ptrace, LKM)
- **Windows**: Windows 10/11 (x64 / WOW64, `ReadProcessMemory`, прямые NT сисколлы, KMDF драйвер)
- **Wine / Proton**: Полная поддержка запуска и отладки Windows-игр на Linux / Steam Deck

---

## Сборка

### Development

```bash
# Полная сборка
cargo build

# Только core (без GUI)
cargo build -p engine-core

# С оптимизациями (для scanner)
cargo build --release

# С ASAN
RUSTFLAGS="-Z sanitizer=address" cargo +nightly build

# Kernel driver
cd crates/engine-driver/kernel
make
```

### Release

```bash
# Optimized build
RUSTFLAGS="-C target-cpu=native -C lto=fat" cargo build --release

# Strip debug info
strip target/release/engine-plus

# Package
tar czf engine-plus-v0.1.0-linux-x86_64.tar.gz \
    target/release/engine-plus \
    target/release/engine-plus-cli \
    README.md themes/ scripts/
```

---

## Структура feature flags

```toml
[features]
default = ["gui", "lua-scripting"]

# UI
gui = ["dep:eframe", "dep:egui", "dep:egui-dock"]
tui = ["dep:ratatui"]

# Scripting
lua-scripting = ["dep:mlua"]
wasm-plugins = ["dep:wasmtime"]

# Backends
driver-backend = []      # Kernel driver support
hypervisor = []          # KVM/Hypervisor backend

# MCP
mcp-server = ["dep:axum", "dep:tower"]
mcp-stdio = []
mcp-sse = ["mcp-server"]
mcp-websocket = ["dep:tokio-tungstenite"]

# Analysis
advanced-disasm = ["dep:capstone"]
file-analysis = ["dep:goblin"]

# Debug
verbose-logging = []
```
