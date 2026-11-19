package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"anon-scan/internal/models"
)

func HistoryPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".anon_scan_history.jsonl"
	}
	return filepath.Join(home, ".anon_scan_history.jsonl")
}

func AppendHistory(r models.ScanResult) {
	f, err := os.OpenFile(HistoryPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	if b, err := json.Marshal(r); err == nil {
		_, _ = f.WriteString(string(b) + "\n")
	}
}

func SearchHistory(query string, limit int) ([]models.ScanResult, error) {
	f, err := os.Open(HistoryPath())
	if err != nil {
		return nil, err
	}
	defer f.Close()

	q := strings.ToLower(strings.TrimSpace(query))
	var matches []models.ScanResult

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r models.ScanResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		if q == "" || strings.Contains(strings.ToLower(r.Target), q) || strings.Contains(r.BestIP, q) {
			matches = append(matches, r)
		}
	}

	if limit > 0 && len(matches) > limit {
		matches = matches[len(matches)-limit:]
	}
	return matches, sc.Err()
}

func PrintHistory(query string, limit int) {
	items, err := SearchHistory(query, limit)
	if err != nil {
		fmt.Printf("[!] No scan history found yet (%s).\n", HistoryPath())
		return
	}
	if len(items) == 0 {
		fmt.Printf("[!] No history entries matched %q.\n", query)
		return
	}
	fmt.Printf("[*] Showing last %d history entries:\n\n", len(items))
	for _, r := range items {
		status := "DOWN"
		if r.Alive {
			status = "ALIVE"
		}
		fmt.Printf("  %s | %-24s | %-15s | %-5s | %4dms | HTTP %-3d | WS101:%v\n",
			r.Timestamp, r.Target, r.BestIP, status, r.BestLatency, r.HTTP.StatusCode, r.HTTP.WebSocket101)
	}
	fmt.Println()
}
