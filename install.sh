#!/usr/bin/env bash
# ==============================================================================
# Engine+ — Automated Installer and Environment Setup Script
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
TARGET_BIN="${BIN_DIR}/engine-plus"

echo "=================================================================="
echo "  🚀 Installing Engine+ (High-Performance Reverse Engineering Suite)"
echo "=================================================================="

# 1. Build release binary
echo "[1/4] Compiling Engine+ in release mode with Cargo..."
cd "${SCRIPT_DIR}"
cargo build --release --bin engine-plus

# 2. Install binary to ~/.local/bin
echo "[2/4] Installing binary to ${TARGET_BIN}..."
mkdir -p "${BIN_DIR}"
install -m 755 "${SCRIPT_DIR}/target/release/engine-plus" "${TARGET_BIN}"

# 3. Check PATH
echo "[3/4] Checking PATH configuration..."
if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    echo "  ⚠️ Notice: ${BIN_DIR} is not in your PATH."
    echo "  Add it by running:"
    echo "    echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
else
    echo "  ✅ ${BIN_DIR} is already in PATH!"
fi

# 4. Memory access & PTRACE permissions check
echo "[4/4] Verifying Linux memory access permissions..."
if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    PTRACE_SCOPE=$(cat /proc/sys/kernel/yama/ptrace_scope)
    if [ "$PTRACE_SCOPE" -ne 0 ]; then
        echo "  ℹ️  Current ptrace_scope is $PTRACE_SCOPE."
        echo "  To allow Engine+ to inspect and modify any process without typing sudo every time:"
        echo "    sudo sysctl -w kernel.yama.ptrace_scope=0"
        echo "  Or grant capability directly to binary:"
        echo "    sudo setcap cap_sys_ptrace=eip ${TARGET_BIN}"
    else
        echo "  ✅ ptrace_scope is 0 (full process access allowed)."
    fi
fi

echo ""
echo "=================================================================="
echo "  🎉 Engine+ v0.2.0 successfully installed!"
echo "=================================================================="
echo "  Executable: ${TARGET_BIN}"
echo "  Interactive REPL:  engine-plus console"
echo "  List Processes:    engine-plus ps"
echo "  Start MCP Server:  engine-plus --mcp"
echo ""
echo "  MCP Server Configuration (Claude Desktop, Cursor, Antigravity):"
echo "  ----------------------------------------------------------------"
cat << 'EOF'
  {
    "mcpServers": {
      "engine-plus": {
        "command": "engine-plus",
        "args": ["--mcp"]
      }
    }
  }
EOF
echo "=================================================================="
