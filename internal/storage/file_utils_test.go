package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDedupAndSplitHostsFile(t *testing.T) {
	tmpDir := t.TempDir()
	inFile := filepath.Join(tmpDir, "hosts.txt")
	content := strings.Join([]string{
		"https://Example.com/login",
		"example.com:443",
		"# comment line",
		"cloudflare.com",
		"CLOUDFLARE.COM",
		"google.com",
	}, "\n")

	if err := os.WriteFile(inFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp input: %v", err)
	}

	outFile := filepath.Join(tmpDir, "clean.txt")
	total, unique, err := DedupHostsFile(inFile, outFile)
	if err != nil {
		t.Fatalf("DedupHostsFile failed: %v", err)
	}
	if total != 5 || unique != 3 {
		t.Fatalf("expected total=5 unique=3, got total=%d unique=%d", total, unique)
	}

	files, splitTotal, err := SplitHostsFile(outFile, 2, filepath.Join(tmpDir, "chunk"))
	if err != nil {
		t.Fatalf("SplitHostsFile failed: %v", err)
	}
	if splitTotal != 3 || len(files) != 2 {
		t.Fatalf("expected 3 lines across 2 files, got %d lines in %d files", splitTotal, len(files))
	}
}
