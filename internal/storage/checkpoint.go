package storage

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

type CheckpointTracker struct {
	path string
	mu   sync.Mutex
	file *os.File
	done map[string]bool
}

func NewCheckpointTracker(path string) (*CheckpointTracker, error) {
	if path == "" {
		path = ".anon_scan_resume.log"
	}

	done := make(map[string]bool)
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				done[strings.ToLower(line)] = true
			}
		}
		_ = f.Close()
	}

	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	return &CheckpointTracker{
		path: path,
		file: out,
		done: done,
	}, nil
}

func (c *CheckpointTracker) FilterRemaining(targets []string) ([]string, int) {
	var remaining []string
	skipped := 0
	for _, t := range targets {
		if c.done[strings.ToLower(t)] {
			skipped++
			continue
		}
		remaining = append(remaining, t)
	}
	return remaining, skipped
}

func (c *CheckpointTracker) MarkDone(target string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == nil {
		return
	}
	_, _ = c.file.WriteString(strings.ToLower(target) + "\n")
}

func (c *CheckpointTracker) Close(removeFile bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file != nil {
		_ = c.file.Sync()
		_ = c.file.Close()
		c.file = nil
	}
	if removeFile && c.path != "" {
		_ = os.Remove(c.path)
	}
}
