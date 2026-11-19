# 🛰 ANON SCANNER (anon-scan)

Termux (ARM64 / Android) සහ Linux සඳහා root අවශ්‍ය නොවී වේගවත්ව වැඩ කරන Go-based Network Diagnostics, Recon & Host Scanner CLI tool එකකි.

## ⚡ One-Line Install (Termux & Linux)

    curl -sSL https://raw.githubusercontent.com/Lakey31/anon-scan/main/install.sh | bash

## ✨ Key Features

- **Interactive Arrow-Key TUI (anon-scan):** Arrow keys, Space bar multi-method selection (GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE, PATCH), සහ .txt File Picker.
- **Social Package Mode (-pkg-mode):** Normal data නැති වෙලාවට Android native netd ISP DNS හරහා scan කිරීම.
- **Local Proxy Support (-proxy):** SOCKS5 / HTTP CONNECT (127.0.0.1:10808) හරහා scanning සහ recon modules (crt.sh, ASN, RDAP, Reverse IP) route කිරීම.
- **Multi-Source Recon & DNS:** crt.sh + HackerTarget + AlienVault OTX Subfinder, Reverse IP (OTX fallback), RIPEstat -asn-cidr, RDAP expiry, -dns-all (NS/MX/TXT), -dns-compare (1.1.1.1 vs 8.8.8.8 vs 9.9.9.9), සහ Dangling CNAME audit.
- **Protocol, Tech & Speed Probes:** Non-root TCP latency, Jitter benchmark (-bench), TLS 1.0–1.3 audit (-tls-audit), HTTP/3 Alt-Svc, WebSocket 101, Tech Stack fingerprinter, සහ 128KB speed test (-speed).
- **Exports & Automation:** Dark-mode HTML dashboard (-html), CSV (-csv), JSONL (-json), Scan Diff (diff), Auto-Resume (--resume), Watch mode (watch), Clipboard (--copy), Notification (--notify), History (history), සහ Self-Update (anon-scan update).

## 🚀 Quick Usage

    anon-scan
    anon-scan -t cloudflare.com -doh -dns-all -dns-compare -tls-audit -speed -6
    anon-scan -cidr 104.16.0.0/29 -sni m.facebook.com -pkg-mode -only-alive
    anon-scan -f hosts.txt -proxy 127.0.0.1:10808 -html report.html --copy --notify
    anon-scan dedup -f hosts.txt -o clean.txt
    anon-scan split -f hosts.txt -n 500
    anon-scan diff old.jsonl new.jsonl
    anon-scan watch -t cloudflare.com -interval 30 -notify
    anon-scan history cloudflare.com
    anon-scan update

## 🛠 Manual Build & Tests

    make test
    make install-termux
