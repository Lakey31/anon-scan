package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"anon-scan/internal/models"
)

type DiffSummary struct {
	NewlyAlive []models.ScanResult
	NewlyDown  []models.ScanResult
	NewWS101   []models.ScanResult
	ChangedIPs []string
	TotalOld   int
	TotalNew   int
}

func CompareJSONLFiles(oldPath, newPath string) (DiffSummary, error) {
	var summary DiffSummary

	oldMap, err := loadJSONLMap(oldPath)
	if err != nil {
		return summary, fmt.Errorf("failed to read old JSONL %s: %w", oldPath, err)
	}
	newMap, err := loadJSONLMap(newPath)
	if err != nil {
		return summary, fmt.Errorf("failed to read new JSONL %s: %w", newPath, err)
	}

	summary.TotalOld = len(oldMap)
	summary.TotalNew = len(newMap)

	var targets []string
	seen := make(map[string]bool)
	for k := range newMap {
		seen[k] = true
		targets = append(targets, k)
	}
	for k := range oldMap {
		if !seen[k] {
			targets = append(targets, k)
		}
	}
	sort.Strings(targets)

	for _, t := range targets {
		oldRes, inOld := oldMap[t]
		newRes, inNew := newMap[t]

		if inNew && !inOld {
			if newRes.Alive {
				summary.NewlyAlive = append(summary.NewlyAlive, newRes)
			}
			if newRes.HTTP.WebSocket101 {
				summary.NewWS101 = append(summary.NewWS101, newRes)
			}
			continue
		}

		if inOld && inNew {
			if !oldRes.Alive && newRes.Alive {
				summary.NewlyAlive = append(summary.NewlyAlive, newRes)
			} else if oldRes.Alive && !newRes.Alive {
				summary.NewlyDown = append(summary.NewlyDown, newRes)
			}

			if !oldRes.HTTP.WebSocket101 && newRes.HTTP.WebSocket101 {
				summary.NewWS101 = append(summary.NewWS101, newRes)
			}

			if oldRes.BestIP != "" && newRes.BestIP != "" && oldRes.BestIP != newRes.BestIP {
				summary.ChangedIPs = append(summary.ChangedIPs,
					fmt.Sprintf("%s : %s -> %s (%s)", t, oldRes.BestIP, newRes.BestIP, newRes.CDNHint))
			}
		}
	}

	return summary, nil
}

func loadJSONLMap(path string) (map[string]models.ScanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := make(map[string]models.ScanResult)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var r models.ScanResult
		if err := json.Unmarshal([]byte(line), &r); err == nil && r.Target != "" {
			m[strings.ToLower(r.Target)] = r
		}
	}
	return m, sc.Err()
}
