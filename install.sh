#!/usr/bin/env bash
set -e

REPO_URL="https://github.com/Lakey31/anon-scan.git"
INSTALL_DIR="$HOME/anon-scan"

echo "╔══════════════════════════════════════════════════════╗"
echo "║   🛰  ANON SCANNER - One-Line Auto Installer         ║"
echo "╚══════════════════════════════════════════════════════╝"

if [ -n "$PREFIX" ] && [ -d "$PREFIX/bin" ]; then
    IS_TERMUX=1
    BIN_DIR="$PREFIX/bin"
    echo "[*] Environment: Termux (Android)"
    for pkg_name in git golang clang; do
        if ! command -v "$pkg_name" >/dev/null 2>&1; then
            echo "[*] Installing $pkg_name..."
            pkg update -y && pkg install -y "$pkg_name"
        fi
    done
else
    IS_TERMUX=0
    BIN_DIR="/usr/local/bin"
    echo "[*] Environment: Linux"
    if ! command -v git >/dev/null 2>&1 || ! command -v go >/dev/null 2>&1; then
        echo "[!] Please install 'git' and 'golang' first, then re-run."
        exit 1
    fi
fi

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "[*] Updating existing repository in $INSTALL_DIR..."
    cd "$INSTALL_DIR"
    git pull origin main
else
    echo "[*] Cloning $REPO_URL into $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo "[*] Building anon-scan..."
if [ "$IS_TERMUX" -eq 1 ] && command -v clang >/dev/null 2>&1; then
    go build -ldflags="-s -w" -o anon-scan ./cmd/cli
else
    CGO_ENABLED=0 go build -ldflags="-s -w" -o anon-scan ./cmd/cli
fi

pkill -9 anon-scan 2>/dev/null || true
if [ "$IS_TERMUX" -eq 1 ]; then
    rm -f "$BIN_DIR/anon-scan"
    cp anon-scan "$BIN_DIR/anon-scan"
    chmod +x "$BIN_DIR/anon-scan"
else
    sudo rm -f "$BIN_DIR/anon-scan" 2>/dev/null || rm -f "$BIN_DIR/anon-scan"
    sudo cp anon-scan "$BIN_DIR/anon-scan" 2>/dev/null || cp anon-scan "$BIN_DIR/anon-scan"
    sudo chmod +x "$BIN_DIR/anon-scan" 2>/dev/null || chmod +x "$BIN_DIR/anon-scan"
fi

echo ""
echo "[✓] ANON SCANNER installed successfully!"
echo "    Run: anon-scan"
