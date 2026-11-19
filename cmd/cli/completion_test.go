package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func completionTestFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.Bool("only-alive", false, "Only show hosts that are alive")
	fs.Int("w", 25, "Workers [default: 25] it's fast")
	fs.String("proxy", "", "Proxy host:port")
	return fs
}

func TestWriteCompletionBash(t *testing.T) {
	var b bytes.Buffer
	if err := writeCompletion(&b, "bash", completionTestFlags()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"-only-alive", "-proxy", "-w", "dedup", "complete -F _anon_scan anon-scan"} {
		if !strings.Contains(out, want) {
			t.Errorf("bash output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteCompletionZshEscapes(t *testing.T) {
	var b bytes.Buffer
	if err := writeCompletion(&b, "zsh", completionTestFlags()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, `\[default\: 25\]`) {
		t.Errorf("zsh brackets/colon not escaped:\n%s", out)
	}
	if !strings.Contains(out, `it'\''s`) {
		t.Errorf("zsh quote not escaped:\n%s", out)
	}
	if !strings.Contains(out, "'-proxy[Proxy host\\:port]:value:'") {
		t.Errorf("zsh value flag spec wrong:\n%s", out)
	}
	if !strings.Contains(out, "'-only-alive[Only show hosts that are alive]'") {
		t.Errorf("zsh bool flag spec wrong:\n%s", out)
	}
}

func TestWriteCompletionFish(t *testing.T) {
	var b bytes.Buffer
	if err := writeCompletion(&b, "fish", completionTestFlags()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "complete -c anon-scan -o proxy -r -d 'Proxy host:port'") {
		t.Errorf("fish value flag wrong:\n%s", out)
	}
	if !strings.Contains(out, `it\'s`) {
		t.Errorf("fish quote not escaped:\n%s", out)
	}
}

func TestWriteCompletionUnknownShell(t *testing.T) {
	var b bytes.Buffer
	if err := writeCompletion(&b, "powershell", completionTestFlags()); err == nil {
		t.Fatal("expected error for unsupported shell")
	}
}
