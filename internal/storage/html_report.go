package storage

import (
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
	"time"

	"anon-scan/internal/models"
)

func WriteHTMLReport(outPath string, results []models.ScanResult) error {
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create HTML report %s: %w", outPath, err)
	}
	defer f.Close()

	sorted := make([]models.ScanResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Alive != sorted[j].Alive {
			return sorted[i].Alive
		}
		return sorted[i].BestLatency < sorted[j].BestLatency
	})

	total := len(sorted)
	aliveCount := 0
	wsCount := 0
	h3Count := 0
	for _, r := range sorted {
		if r.Alive {
			aliveCount++
		}
		if r.HTTP.WebSocket101 {
			wsCount++
		}
		if r.HTTP.HTTP3Quic {
			h3Count++
		}
	}

	nowStr := time.Now().Format("2006-01-02 15:04:05")

	var rows strings.Builder
	for idx, r := range sorted {
		statusBadge := `<span class="badge down">DOWN</span>`
		rowClass := "row-down"
		if r.Alive {
			statusBadge = `<span class="badge alive">ALIVE</span>`
			rowClass = "row-alive"
		}

		wsBadge := `<span class="badge muted">NO</span>`
		if r.HTTP.WebSocket101 {
			wsBadge = `<span class="badge ws">101 WS</span>`
			rowClass += " row-ws"
		}

		h3Badge := `<span class="badge muted">NO</span>`
		if r.HTTP.HTTP3Quic {
			h3Badge = `<span class="badge h3">H3 QUIC</span>`
			rowClass += " row-h3"
		}

		cdn := r.HTTP.DetectedCDN
		if cdn == "" {
			cdn = r.CDNHint
		}
		if cdn == "" {
			cdn = "-"
		}

		var openPorts []string
		for _, p := range r.Ports {
			if p.Open {
				openPorts = append(openPorts, fmt.Sprintf("%d", p.Port))
			}
		}
		portsStr := strings.Join(openPorts, ", ")
		if portsStr == "" {
			portsStr = "-"
		}

		tlsStr := "-"
		if r.TLS.Supported {
			tlsStr = fmt.Sprintf("%s (%s)", r.TLS.Version, r.TLS.NegotiatedALPN)
		}

		secStr := fmt.Sprintf("%d/%d", r.HTTP.SecurityHeaders.Score, r.HTTP.SecurityHeaders.Total)

		rows.WriteString(fmt.Sprintf(`
      <tr class="%s">
        <td>%d</td>
        <td class="mono">%s</td>
        <td class="mono">%s</td>
        <td>%s</td>
        <td><strong>%dms</strong></td>
        <td class="mono">%s</td>
        <td>%d</td>
        <td>%s</td>
        <td>%s</td>
        <td>%s</td>
        <td class="mono">%s</td>
        <td>%s</td>
      </tr>`,
			rowClass,
			idx+1,
			html.EscapeString(r.Target),
			html.EscapeString(r.BestIP),
			statusBadge,
			r.BestLatency,
			html.EscapeString(portsStr),
			r.HTTP.StatusCode,
			wsBadge,
			h3Badge,
			html.EscapeString(cdn),
			html.EscapeString(tlsStr),
			html.EscapeString(secStr),
		))
	}

	page := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ANON SCANNER Report - %s</title>
<style>
  :root {
    --bg: #0b0f19;
    --card: #111827;
    --border: #1f2937;
    --text: #e5e7eb;
    --muted: #9ca3af;
    --accent: #38bdf8;
    --green: #10b981;
    --red: #ef4444;
    --purple: #a855f7;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    padding: 20px;
  }
  .header {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    margin-bottom: 20px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }
  .header h1 { font-size: 1.35rem; color: var(--accent); }
  .header .meta { font-size: 0.85rem; color: var(--muted); }
  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
  }
  .stat-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px;
  }
  .stat-card .label { font-size: 0.78rem; color: var(--muted); text-transform: uppercase; }
  .stat-card .val { font-size: 1.5rem; font-weight: 700; margin-top: 4px; }
  .controls {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 16px;
  }
  .search-input {
    flex: 1;
    min-width: 200px;
    background: var(--card);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 10px 14px;
    border-radius: 8px;
    outline: none;
  }
  .btn {
    background: var(--card);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 9px 14px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.85rem;
  }
  .btn.active { border-color: var(--accent); color: var(--accent); }
  .table-wrap {
    overflow-x: auto;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
  }
  table { width: 100%%; border-collapse: collapse; font-size: 0.88rem; }
  th, td { padding: 11px 12px; text-align: left; border-bottom: 1px solid var(--border); white-space: nowrap; }
  th { background: #161f33; color: var(--muted); font-weight: 600; font-size: 0.78rem; text-transform: uppercase; }
  tr:hover { background: rgba(56, 189, 248, 0.05); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
  .badge { padding: 3px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; }
  .badge.alive { background: rgba(16, 185, 129, 0.15); color: var(--green); }
  .badge.down { background: rgba(239, 68, 68, 0.15); color: var(--red); }
  .badge.ws { background: rgba(56, 189, 248, 0.15); color: var(--accent); }
  .badge.h3 { background: rgba(168, 85, 247, 0.18); color: var(--purple); }
  .badge.muted { background: rgba(156, 163, 175, 0.12); color: var(--muted); }
</style>
</head>
<body>
  <div class="header">
    <div>
      <h1>🛰 ANON SCANNER Dashboard</h1>
      <div class="meta">Generated on %s • Termux ARM64 Engine</div>
    </div>
  </div>

  <div class="stats">
    <div class="stat-card"><div class="label">Total Targets</div><div class="val">%d</div></div>
    <div class="stat-card"><div class="label">Alive Hosts</div><div class="val" style="color:var(--green)">%d</div></div>
    <div class="stat-card"><div class="label">WebSocket 101</div><div class="val" style="color:var(--accent)">%d</div></div>
    <div class="stat-card"><div class="label">HTTP/3 QUIC</div><div class="val" style="color:var(--purple)">%d</div></div>
  </div>

  <div class="controls">
    <input type="text" id="searchBox" class="search-input" placeholder="Search domain, IP, CDN, TLS..." oninput="filterRows()">
    <button class="btn active" onclick="setFilter('all', this)">All</button>
    <button class="btn" onclick="setFilter('alive', this)">Alive Only</button>
    <button class="btn" onclick="setFilter('ws', this)">WebSocket 101</button>
    <button class="btn" onclick="setFilter('h3', this)">HTTP/3 QUIC</button>
  </div>

  <div class="table-wrap">
    <table id="scanTable">
      <thead>
        <tr>
          <th>#</th>
          <th>Target</th>
          <th>Best IP</th>
          <th>Status</th>
          <th>Latency</th>
          <th>Open Ports</th>
          <th>HTTP</th>
          <th>WebSocket</th>
          <th>HTTP/3</th>
          <th>CDN / Edge</th>
          <th>TLS / ALPN</th>
          <th>SecHeaders</th>
        </tr>
      </thead>
      <tbody>%s
      </tbody>
    </table>
  </div>

<script>
let currentMode = 'all';
function setFilter(mode, btn) {
  currentMode = mode;
  document.querySelectorAll('.controls .btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterRows();
}
function filterRows() {
  const q = document.getElementById('searchBox').value.toLowerCase();
  const rows = document.querySelectorAll('#scanTable tbody tr');
  rows.forEach(r => {
    const textMatch = r.innerText.toLowerCase().includes(q);
    let modeMatch = true;
    if (currentMode === 'alive') modeMatch = r.classList.contains('row-alive');
    if (currentMode === 'ws') modeMatch = r.classList.contains('row-ws');
    if (currentMode === 'h3') modeMatch = r.classList.contains('row-h3');
    r.style.display = (textMatch && modeMatch) ? '' : 'none';
  });
}
</script>
</body>
</html>`, nowStr, nowStr, total, aliveCount, wsCount, h3Count, rows.String())

	_, err = f.WriteString(page)
	return err
}
