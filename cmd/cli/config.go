package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// configSkip lists flags that make no sense in a config file.
var configSkip = map[string]bool{
	"config":  true,
	"version": true,
	"i":       true,
}

// defaultConfigPath returns $ANON_SCAN_CONFIG, or ~/.anon-scan.conf.
func defaultConfigPath() string {
	if p := strings.TrimSpace(os.Getenv("ANON_SCAN_CONFIG")); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".anon-scan.conf")
}

// applyConfigFile reads simple "key = value" lines (flag names without the
// leading dash; '#' starts a comment) and applies them to fs for every flag
// the user did NOT set on the command line, so CLI flags always win.
// A missing file is not an error. It returns warnings for lines it ignored.
func applyConfigFile(fs *flag.FlagSet, path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	setOnCLI := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { setOnCLI[fl.Name] = true })

	var warnings []string
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			warnings = append(warnings, fmt.Sprintf("%s:%d: expected key = value", path, lineNo))
			continue
		}
		key = strings.TrimLeft(strings.TrimSpace(key), "-")
		val = strings.Trim(strings.TrimSpace(val), `"'`)

		if configSkip[key] {
			warnings = append(warnings, fmt.Sprintf("%s:%d: %q is not allowed in a config file", path, lineNo, key))
			continue
		}
		if fs.Lookup(key) == nil {
			warnings = append(warnings, fmt.Sprintf("%s:%d: unknown option %q", path, lineNo, key))
			continue
		}
		if setOnCLI[key] {
			continue
		}
		// flag's Set can zero the value on a parse error, so keep the old one to restore.
		fl := fs.Lookup(key)
		prev := fl.Value.String()
		if err := fs.Set(key, val); err != nil {
			_ = fl.Value.Set(prev)
			warnings = append(warnings, fmt.Sprintf("%s:%d: invalid value for %q: %v", path, lineNo, key, err))
		}
	}
	return warnings, sc.Err()
}
