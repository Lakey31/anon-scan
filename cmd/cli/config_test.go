package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func newTestFlags() (*flag.FlagSet, *int, *float64, *bool, *string) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	w := fs.Int("w", 25, "")
	rate := fs.Float64("rate", 0, "")
	alive := fs.Bool("only-alive", false, "")
	proxy := fs.String("proxy", "", "")
	fs.Bool("version", false, "")
	return fs, w, rate, alive, proxy
}

func writeConf(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.conf")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApplyConfigFileDefaults(t *testing.T) {
	fs, w, rate, alive, proxy := newTestFlags()
	_ = fs.Parse(nil)
	p := writeConf(t, "# comment\nw = 10\n-rate=5.5  # inline\nonly-alive = true\nproxy = \"127.0.0.1:10808\"\n")

	warns, err := applyConfigFile(fs, p)
	if err != nil || len(warns) != 0 {
		t.Fatalf("err=%v warns=%v", err, warns)
	}
	if *w != 10 || *rate != 5.5 || !*alive || *proxy != "127.0.0.1:10808" {
		t.Fatalf("got w=%d rate=%v alive=%v proxy=%q", *w, *rate, *alive, *proxy)
	}
}

func TestApplyConfigFileCLIWins(t *testing.T) {
	fs, w, _, _, _ := newTestFlags()
	_ = fs.Parse([]string{"-w", "99"})
	p := writeConf(t, "w = 10\n")

	if _, err := applyConfigFile(fs, p); err != nil {
		t.Fatal(err)
	}
	if *w != 99 {
		t.Fatalf("CLI value should win, got %d", *w)
	}
}

func TestApplyConfigFileWarnings(t *testing.T) {
	fs, w, _, _, _ := newTestFlags()
	_ = fs.Parse(nil)
	p := writeConf(t, "bogus = 1\nversion = true\nw = notanumber\nnoequals\n")

	warns, err := applyConfigFile(fs, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 4 {
		t.Fatalf("expected 4 warnings, got %d: %v", len(warns), warns)
	}
	if *w != 25 {
		t.Fatalf("invalid line must not change defaults, got %d", *w)
	}
}

func TestApplyConfigFileMissingIsOK(t *testing.T) {
	fs, _, _, _, _ := newTestFlags()
	_ = fs.Parse(nil)
	warns, err := applyConfigFile(fs, filepath.Join(t.TempDir(), "nope.conf"))
	if err != nil || len(warns) != 0 {
		t.Fatalf("missing file should be silent, err=%v warns=%v", err, warns)
	}
}
