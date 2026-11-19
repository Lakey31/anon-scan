# 🛰 ANON SCANNER (`anon-scan`)

Termux (ARM64 / Android) සහ Linux සඳහා root අවශ්‍ය නොවී වේගවත්ව වැඩ කරන Go-based Network Diagnostics, Recon & Host Scanner CLI tool එකකි.

## ✨ Key Features

- **Interactive Arrow-Key TUI (`anon-scan`):** `↑`/`↓` arrows, `Space` bar multi-method selection, සහ `.txt` File Picker.
- **Social Package Mode (`-pkg-mode`):** Normal data නැති වෙලාවට Android native `netd` ISP DNS හරහා scan කිරීම.
- **Local Proxy Support (`-proxy`):** SOCKS5 / HTTP CONNECT (`127.0.0.1:10808`) හරහා scanning සහ recon modules (`crt.sh`, `ASN`, `RDAP`, `Reverse IP`) route කිරීම.
- **Protocol & Speed Probes:** TCP latency, Jitter benchmark (`-bench`), TLS 1.0–1.3 audit (`-tls-audit`), HTTP/3 `Alt-Svc`, WebSocket `101`, සහ 128KB speed test (`-speed`).
- **Exports & Automation:** Dark-mode HTML dashboard (`-html`), CSV (`-csv`), Scan Diff (`diff`), Auto-Resume (`--resume`), Watch mode (`watch`), Clipboard (`--copy`), සහ History (`history`).

## 📱 Build on Termux

```bash
make install-termux
```
