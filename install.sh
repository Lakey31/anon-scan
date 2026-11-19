#!/usr/bin/env bash
set -e

REPO_URL="https://github.com/Lakey31/anon-scan.git"
INSTALL_DIR="$HOME/anon-scan"

echo "╔══════════════════════════════════════════════════════╗"
echo "║   🛰  ANON SCANNER - One-Line Auto Installer         ║"
echo "╚══════════════════════════════════════════════════════╝"

# Optional: ./install.sh --prebuilt downloads the latest release binary and
# verifies its SHA256 instead of compiling. Falls back to a source build on any failure.
PREBUILT=0
for arg in "$@"; do
    [ "$arg" = "--prebuilt" ] && PREBUILT=1
done

install_prebuilt() {
    command -v curl >/dev/null 2>&1 || { echo "[!] curl not found"; return 1; }
    command -v sha256sum >/dev/null 2>&1 || { echo "[!] sha256sum not found"; return 1; }

    local arch asset bin_dir base tmp
    case "$(uname -m)" in
        aarch64|arm64) arch="arm64" ;;
        x86_64|amd64)  arch="amd64" ;;
        *) echo "[!] No prebuilt binary for $(uname -m)"; return 1 ;;
    esac

    if [ -n "$PREFIX" ] && [ -d "$PREFIX/bin" ]; then
        bin_dir="$PREFIX/bin"
        if [ "$arch" = "arm64" ]; then asset="anon-scan-android-arm64"; else asset="anon-scan-linux-$arch"; fi
    else
        bin_dir="/usr/local/bin"
        asset="anon-scan-linux-$arch"
    fi

    base="https://github.com/Lakey31/anon-scan/releases/latest/download"
    tmp="$(mktemp -d)"

    echo "[*] Downloading $asset..."
    if ! curl -fsSL "$base/$asset" -o "$tmp/$asset" || ! curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"; then
        echo "[!] Download failed (no release published yet?)"
        rm -rf "$tmp"; return 1
    fi

    if ! ( cd "$tmp" && grep " $asset\$" SHA256SUMS | sha256sum -c - >/dev/null 2>&1 ); then
        echo "[!] Checksum verification FAILED - not installing"
        rm -rf "$tmp"; return 1
    fi
    echo "[✓] Checksum OK"

    chmod +x "$tmp/$asset"
    pkill -9 anon-scan 2>/dev/null || true
    if [ "$bin_dir" = "/usr/local/bin" ]; then
        sudo cp "$tmp/$asset" "$bin_dir/anon-scan" 2>/dev/null || cp "$tmp/$asset" "$bin_dir/anon-scan" || { rm -rf "$tmp"; return 1; }
    else
        cp "$tmp/$asset" "$bin_dir/anon-scan" || { rm -rf "$tmp"; return 1; }
    fi
    rm -rf "$tmp"
    echo "[✓] Installed prebuilt anon-scan to $bin_dir/anon-scan"
    return 0
}

if [ "$PREBUILT" -eq 1 ]; then
    if install_prebuilt; then
        exit 0
    fi
    echo "[*] Falling back to building from source..."
fi

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
