package storage

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func DedupHostsFile(inputPath, outputPath string) (int, int, error) {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to open %s: %w", inputPath, err)
	}
	defer inFile.Close()

	if outputPath == "" {
		ext := filepath.Ext(inputPath)
		base := strings.TrimSuffix(inputPath, ext)
		if ext == "" {
			ext = ".txt"
		}
		outputPath = base + "_dedup" + ext
	}

	seen := make(map[string]bool)
	totalLines := 0

	sc := bufio.NewScanner(inFile)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		totalLines++
		h := normalizeHostLine(raw)
		if h != "" {
			seen[h] = true
		}
	}
	if err := sc.Err(); err != nil {
		return totalLines, 0, err
	}

	unique := make([]string, 0, len(seen))
	for h := range seen {
		unique = append(unique, h)
	}
	sort.Strings(unique)

	outFile, err := os.Create(outputPath)
	if err != nil {
		return totalLines, 0, fmt.Errorf("failed to create %s: %w", outputPath, err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	for _, h := range unique {
		_, _ = writer.WriteString(h + "\n")
	}
	if err := writer.Flush(); err != nil {
		return totalLines, 0, err
	}

	return totalLines, len(unique), nil
}

func SplitHostsFile(inputPath string, chunkSize int, outPrefix string) ([]string, int, error) {
	if chunkSize <= 0 {
		chunkSize = 500
	}

	inFile, err := os.Open(inputPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open %s: %w", inputPath, err)
	}
	defer inFile.Close()

	if outPrefix == "" {
		ext := filepath.Ext(inputPath)
		outPrefix = strings.TrimSuffix(inputPath, ext)
	}

	var createdFiles []string
	totalLines := 0
	partNum := 1
	countInPart := 0

	var currentFile *os.File
	var writer *bufio.Writer

	openNextPart := func() error {
		if writer != nil {
			_ = writer.Flush()
		}
		if currentFile != nil {
			_ = currentFile.Close()
		}
		partPath := fmt.Sprintf("%s_part_%03d.txt", outPrefix, partNum)
		f, err := os.Create(partPath)
		if err != nil {
			return err
		}
		currentFile = f
		writer = bufio.NewWriter(f)
		createdFiles = append(createdFiles, partPath)
		partNum++
		countInPart = 0
		return nil
	}

	sc := bufio.NewScanner(inFile)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if currentFile == nil || countInPart >= chunkSize {
			if err := openNextPart(); err != nil {
				return createdFiles, totalLines, err
			}
		}
		_, _ = writer.WriteString(line + "\n")
		countInPart++
		totalLines++
	}

	if writer != nil {
		_ = writer.Flush()
	}
	if currentFile != nil {
		_ = currentFile.Close()
	}

	if err := sc.Err(); err != nil {
		return createdFiles, totalLines, err
	}

	return createdFiles, totalLines, nil
}

func normalizeHostLine(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	input = strings.Split(input, "/")[0]
	input = strings.Split(input, ":")[0]
	return strings.ToLower(strings.TrimSpace(input))
}
