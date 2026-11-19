package main

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
)

// subcommands handled before flag parsing in main().
var subcommands = []string{"dedup", "split", "diff", "speed", "watch", "history", "update", "menu", "completion"}

type flagInfo struct {
	name  string
	usage string
	bool  bool
}

func collectFlags(fs *flag.FlagSet) []flagInfo {
	var out []flagInfo
	fs.VisitAll(func(f *flag.Flag) {
		isBool := false
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok {
			isBool = bf.IsBoolFlag()
		}
		out = append(out, flagInfo{name: f.Name, usage: f.Usage, bool: isBool})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// writeCompletion writes a completion script for "bash", "zsh" or "fish".
func writeCompletion(w io.Writer, shell string, fs *flag.FlagSet) error {
	flags := collectFlags(fs)

	switch strings.ToLower(strings.TrimSpace(shell)) {
	case "bash":
		var words []string
		for _, f := range flags {
			words = append(words, "-"+f.name)
		}
		words = append(words, subcommands...)
		fmt.Fprintf(w, `_anon_scan() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    COMPREPLY=( $(compgen -W "%s" -- "$cur") )
}
complete -F _anon_scan anon-scan
`, strings.Join(words, " "))

	case "zsh":
		fmt.Fprintln(w, "#compdef anon-scan")
		fmt.Fprintln(w, "_anon_scan() {")
		fmt.Fprintln(w, "  local -a subcmds")
		fmt.Fprintf(w, "  subcmds=(%s)\n", strings.Join(subcommands, " "))
		fmt.Fprintln(w, "  _arguments -s \\")
		for _, f := range flags {
			spec := "-" + f.name + "[" + zshEscape(f.usage) + "]"
			if !f.bool {
				spec += ":value:"
			}
			fmt.Fprintf(w, "    '%s' \\\n", spec)
		}
		fmt.Fprintln(w, "    '1:command:($subcmds)'")
		fmt.Fprintln(w, "}")
		fmt.Fprintln(w, `_anon_scan "$@"`)

	case "fish":
		for _, f := range flags {
			arg := ""
			if !f.bool {
				arg = " -r"
			}
			fmt.Fprintf(w, "complete -c anon-scan -o %s%s -d '%s'\n", f.name, arg, fishEscape(f.usage))
		}
		for _, s := range subcommands {
			fmt.Fprintf(w, "complete -c anon-scan -n '__fish_use_subcommand' -a %s\n", s)
		}

	default:
		return fmt.Errorf("unsupported shell %q (use bash, zsh or fish)", shell)
	}
	return nil
}

func zshEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `[`, `\[`, `]`, `\]`, `'`, `'\''`, `:`, `\:`)
	return r.Replace(s)
}

func fishEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return r.Replace(s)
}
