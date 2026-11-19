package tui

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[97m"
	Gray    = "\033[90m"
)

func ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

func PrintHeader(title string) {
	ClearScreen()
	fmt.Println(Magenta + Bold)
	switch title {
	case "HOST SCANNER":
		fmt.Println(" _   _  ___  ____ _____   ____   ____    _    _   _ _   _ _____ ____  ")
		fmt.Println("| | | |/ _ \\/ ___|_   _| / ___| / ___|  / \\  | \\ | | \\ | | ____|  _ \\ ")
		fmt.Println("| |_| | | | \\___ \\ | |   \\___ \\| |     / _ \\ |  \\| |  \\| |  _| | |_) |")
		fmt.Println("|  _  | |_| |___) || |    ___) | |___ / ___ \\| |\\  | |\\  | |___|  _ < ")
		fmt.Println("|_| |_|\\___/|____/ |_|   |____/ \\____/_/   \\_\\_| \\_|_| \\_|_____|_| \\_\\")
	case "SUBFINDER":
		fmt.Println(" ____  _   _ ____  _____ ___ _   _ ____  _____ ____  ")
		fmt.Println("/ ___|| | | | __ )|  ___|_ _| \\ | |  _ \\| ____|  _ \\ ")
		fmt.Println("\\___ \\| | | |  _ \\| |_   | ||  \\| | | | |  _| | |_) |")
		fmt.Println(" ___) | |_| | |_) |  _|  | || |\\  | |_| | |___|  _ < ")
		fmt.Println("|____/ \\___/|____/|_|   |___|_| \\_|____/|_____|_| \\_\\")
	default:
		fmt.Println("    _    _   _  ___  _   _   ____   ____    _    _   _ _   _ _____ ____  ")
		fmt.Println("   / \\  | \\ | |/ _ \\| \\ | | / ___| / ___|  / \\  | \\ | | \\ | | ____|  _ \\ ")
		fmt.Println("  / _ \\ |  \\| | | | |  \\| | \\___ \\| |     / _ \\ |  \\| |  \\| |  _| | |_) |")
		fmt.Println(" / ___ \\| |\\  | |_| | |\\  |  ___) | |___ / ___ \\| |\\  | |\\  | |___|  _ < ")
		fmt.Println("/_/   \\_\\_| \\_|\\___/|_| \\_| |____/ \\____/_/   \\_\\_| \\_|_| \\_|_____|_| \\_\\")
	}
	fmt.Println(Reset)
}

// PickTxtFile scans the current folder and Termux Downloads for .txt files and lets the user pick with arrows.
func PickTxtFile(prompt string) string {
	var files []string
	seen := make(map[string]bool)

	searchDirs := []string{"."}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dl := filepath.Join(home, "storage", "downloads")
		if _, err := os.Stat(dl); err == nil {
			searchDirs = append(searchDirs, dl)
		}
	}

	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".txt") {
				continue
			}
			full := e.Name()
			if dir != "." {
				full = filepath.Join(dir, e.Name())
			}
			if !seen[full] {
				seen[full] = true
				files = append(files, full)
				if len(files) >= 12 {
					break
				}
			}
		}
	}

	if len(files) == 0 {
		return AskInput(prompt, "hosts.txt")
	}

	files = append(files, "Enter custom filename or domain...")
	choice := SelectOption(prompt, files)
	if choice == "Enter custom filename or domain..." {
		return AskInput("Enter filename (or single domain)", "hosts.txt")
	}
	return choice
}

func SelectOption(prompt string, options []string) string {
	if len(options) == 0 {
		return ""
	}
	if err := setRawMode(true); err != nil {
		return fallbackSelect(prompt, options)
	}

	idx := 0
	fmt.Printf("%s%s:%s\n", Gray, prompt, Reset)
	renderOptions(options, idx)

	buf := make([]byte, 3)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			break
		}
		if buf[0] == 3 {
			_ = setRawMode(false)
			fmt.Println("\nCancelled.")
			os.Exit(0)
		}
		if buf[0] == '\r' || buf[0] == '\n' {
			break
		}
		if n == 3 && buf[0] == 27 && buf[1] == '[' {
			if buf[2] == 'A' {
				idx--
				if idx < 0 {
					idx = len(options) - 1
				}
			} else if buf[2] == 'B' {
				idx++
				if idx >= len(options) {
					idx = 0
				}
			}
			fmt.Printf("\033[%dA", len(options))
			renderOptions(options, idx)
		} else if buf[0] == 'k' || buf[0] == 'K' {
			idx--
			if idx < 0 {
				idx = len(options) - 1
			}
			fmt.Printf("\033[%dA", len(options))
			renderOptions(options, idx)
		} else if buf[0] == 'j' || buf[0] == 'J' {
			idx++
			if idx >= len(options) {
				idx = 0
			}
			fmt.Printf("\033[%dA", len(options))
			renderOptions(options, idx)
		}
	}

	_ = setRawMode(false)
	fmt.Printf("\033[%dA\033[J", len(options)+1)
	selected := options[idx]
	fmt.Printf("%s%s:%s %s%s%s\n", Gray, prompt, Reset, Green, selected, Reset)
	return selected
}

func SelectMultiOptions(prompt string, options []string, defaultChecked []int) []string {
	if len(options) == 0 {
		return nil
	}
	if err := setRawMode(true); err != nil {
		ans := AskInput(prompt+" (comma separated)", options[0])
		var res []string
		for _, p := range strings.Split(ans, ",") {
			p = strings.ToUpper(strings.TrimSpace(p))
			if p != "" {
				res = append(res, p)
			}
		}
		return res
	}

	checked := make([]bool, len(options))
	for _, i := range defaultChecked {
		if i >= 0 && i < len(options) {
			checked[i] = true
		}
	}

	idx := 0
	fmt.Printf("%s%s %s(Space: toggle, Enter: done)%s:\n", Gray, prompt, Dim, Reset)
	renderMultiOptions(options, checked, idx)

	buf := make([]byte, 3)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			break
		}
		if buf[0] == 3 {
			_ = setRawMode(false)
			fmt.Println("\nCancelled.")
			os.Exit(0)
		}
		if buf[0] == '\r' || buf[0] == '\n' {
			break
		}
		if buf[0] == ' ' {
			checked[idx] = !checked[idx]
			fmt.Printf("\033[%dA", len(options))
			renderMultiOptions(options, checked, idx)
		} else if n == 3 && buf[0] == 27 && buf[1] == '[' {
			if buf[2] == 'A' {
				idx--
				if idx < 0 {
					idx = len(options) - 1
				}
			} else if buf[2] == 'B' {
				idx++
				if idx >= len(options) {
					idx = 0
				}
			}
			fmt.Printf("\033[%dA", len(options))
			renderMultiOptions(options, checked, idx)
		} else if buf[0] == 'k' || buf[0] == 'K' {
			idx--
			if idx < 0 {
				idx = len(options) - 1
			}
			fmt.Printf("\033[%dA", len(options))
			renderMultiOptions(options, checked, idx)
		} else if buf[0] == 'j' || buf[0] == 'J' {
			idx++
			if idx >= len(options) {
				idx = 0
			}
			fmt.Printf("\033[%dA", len(options))
			renderMultiOptions(options, checked, idx)
		}
	}

	_ = setRawMode(false)

	var selected []string
	for i, opt := range options {
		if checked[i] {
			selected = append(selected, opt)
		}
	}
	if len(selected) == 0 {
		selected = []string{options[idx]}
	}

	fmt.Printf("\033[%dA\033[J", len(options)+1)
	fmt.Printf("%s%s:%s %s%s%s\n", Gray, prompt, Reset, Green, strings.Join(selected, ", "), Reset)
	return selected
}

func renderOptions(options []string, active int) {
	for i, opt := range options {
		if i == active {
			fmt.Printf("\033[2K%s❯ %s%s\n", Cyan+Bold, opt, Reset)
		} else {
			fmt.Printf("\033[2K  %s%s%s\n", White, opt, Reset)
		}
	}
}

func renderMultiOptions(options []string, checked []bool, active int) {
	for i, opt := range options {
		box := Gray + "[ ]" + Reset
		if checked[i] {
			box = Green + "[✓]" + Reset
		}
		if i == active {
			fmt.Printf("\033[2K%s❯%s %s %s%s%s\n", Cyan+Bold, Reset, box, Cyan+Bold, opt, Reset)
		} else {
			fmt.Printf("\033[2K  %s %s%s%s\n", box, White, opt, Reset)
		}
	}
}

func setRawMode(enable bool) error {
	var cmd *exec.Cmd
	if enable {
		cmd = exec.Command("stty", "-icanon", "-echo", "min", "1")
	} else {
		cmd = exec.Command("stty", "icanon", "echo")
	}
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func fallbackSelect(prompt string, options []string) string {
	fmt.Printf("%s%s:%s\n", Gray, prompt, Reset)
	for i, opt := range options {
		fmt.Printf("  [%d] %s\n", i+1, opt)
	}
	ans := AskInput("Enter number", "1")
	for i, opt := range options {
		if ans == fmt.Sprintf("%d", i+1) || strings.EqualFold(ans, opt) {
			return opt
		}
	}
	return options[0]
}

func AskInput(prompt, defVal string) string {
	if defVal != "" {
		fmt.Printf("%s%s [%s]:%s %s", Gray, prompt, defVal, Reset, Green)
	} else {
		fmt.Printf("%s%s:%s %s", Gray, prompt, Reset, Green)
	}
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	fmt.Print(Reset)
	line = strings.TrimSpace(line)
	if line == "" {
		return defVal
	}
	return line
}

func Pause() {
	fmt.Printf("\n%sPress Enter to continue...%s", Yellow, Reset)
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}

func PrintTableHeader() {
	fmt.Println()
	fmt.Printf("%s%-7s %s%-5s %s%-16s %s%-5s %s%-16s %s%s%s\n",
		Cyan, "Method",
		Green, "Code",
		Magenta, "Server",
		Yellow, "Port",
		Blue, "IP",
		White, "Host",
		Reset,
	)
	fmt.Printf("%s%-7s %-5s %-16s %-5s %-16s %s%s\n",
		Gray, "------", "----", "---------------", "----", "---------------", "------------------------", Reset)
}

func PrintTableRow(method string, code int, server string, port int, ip string, host string) {
	if server == "" {
		server = "-"
	}
	if len(server) > 15 {
		server = server[:13] + ".."
	}
	codeColor := Green
	if code >= 400 {
		codeColor = Yellow
	}
	if code == 0 || code >= 500 {
		codeColor = Red
	}
	if code == 101 {
		codeColor = Cyan + Bold
	}

	fmt.Printf("%s%-7s %s%-5d %s%-16s %s%-5d %s%-16s %s%s%s\n",
		Cyan, method,
		codeColor, code,
		Magenta, server,
		Yellow, port,
		Blue, ip,
		White, host,
		Reset,
	)
}
