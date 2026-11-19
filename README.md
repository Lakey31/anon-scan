# 🛰 ANON SCANNER (`anon-scan`)

Termux (ARM64 / Android) සහ Linux සඳහා root අවශ්‍ය නොවී වේගවත්ව වැඩ කරන Go-based Network Diagnostics, Recon & Host Scanner CLI tool එකකි.

## ✨ Key Features

- **Interactive Arrow-Key TUI (`anon-scan`):** `↑`/`↓` arrows සහ `Space` bar එකෙන් multi-method HTTP scanning, file picker, සහ presets තේරීම.
- **Social Package Mode (`-pkg-mode`):** Normal data නැති වෙලාවට external APIs bypass කර Android native `netd` ISP DNS හරහා scan කිරීම.
- **Local Proxy Support (`-proxy`):** SOCKS5 / HTTP CONNECT (`127.0.0.1:10808`) හරහා scanning සහ recon modules (`crt.sh`, `ASN`, `RDAP`, `Reverse IP`) route කිරීම.
- **Multi-Source Recon:** `crt.sh`, HackerTarget, සහ AlienVault OTX හරහා Subdomain discovery, RIPEstat `-asn-cidr`, RDAP expiry, සහ Dangling CNAME audit.
- **Protocol & Speed Probes:** Non-root TCP latency, Jitter benchmark (`-bench`), TLS 1.0–1.3 audit (`-tls-audit`), HTTP/3 `Alt-Svc`, WebSocket `101`, සහ 128KB speed test (`-speed`).
- **Exports & Automation:** Dark-mode HTML dashboard (`-html`), CSV (`-csv`), JSONL (`-json`), Scan Diff (`diff`), Auto-Resume (`--resume`), Watch mode (`watch`), Clipboard (`--copy`), සහ Termux Notification (`--notify`).

## 📱 Termux Installation

```bash
pkg update -y && pkg install -y golang clang termux-api
git clone https://github.com/Lakey31/anon-scan.git
cd anon-scan
make install-termux
```

## 🚀 Usage Examples

```bash
# Interactive TUI Menu (File Picker & Multi-Method)
anon-scan

# Single Domain Full Diagnostic + Speed + TLS Audit
anon-scan -t cloudflare.com -doh -dns-all -tls-audit -speed -6

# Social Media Package Mode (No normal data required)
anon-scan -cidr 104.16.0.0/29 -sni m.facebook.com -pkg-mode -only-alive

# Bulk Scan via Local Proxy with HTML Dashboard & Clipboard Copy
anon-scan -f hosts.txt -proxy 127.0.0.1:10808 -html report.html --copy --notify

# Utilities & Monitoring
anon-scan dedup -f hosts.txt -o clean.txt
anon-scan split -f hosts.txt -n 500
anon-scan diff old.jsonl new.jsonl
anon-scan watch -t cloudflare.com -interval 30 -notify
anon-scan history cloudflare.com
```
