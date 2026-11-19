package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"anon-scan/internal/models"
	"anon-scan/internal/recon"
	"anon-scan/internal/resolver"
	"anon-scan/internal/scanner"
	"anon-scan/internal/storage"
	"anon-scan/internal/tui"
)

// version can be overridden at build time:
//
//	go build -ldflags "-X main.version=v1.2.3" ./cmd/cli
var version = "9.6"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "dedup":
			handleDedup(os.Args[2:])
			return
		case "split":
			handleSplit(os.Args[2:])
			return
		case "diff":
			handleDiff(os.Args[2:])
			return
		case "speed":
			handleSpeed(os.Args[2:])
			return
		case "watch":
			handleWatch(os.Args[2:])
			return
		case "history":
			q := ""
			if len(os.Args) > 2 {
				q = os.Args[2]
			}
			storage.PrintHistory(q, 20)
			return
		case "update":
			handleSelfUpdate()
			return
		case "menu":
			runBugScanXTUI()
			return
		}
	}

	var (
		interactive = flag.Bool("i", false, "Launch BugScanX-style interactive arrow-key TUI menu")
		pkgMode     = flag.Bool("pkg-mode", false, "Social Media Package Mode (disables external APIs & uses ISP/System DNS)")
		proxyAddr   = flag.String("proxy", "", "Route probes & recon via local SOCKS5/HTTP proxy (e.g. 127.0.0.1:10808)")
		methodFlag  = flag.String("m", "GET", "HTTP method(s) comma-separated (GET,HEAD,POST,OPTIONS)")
		compactFlag = flag.Bool("compact", false, "Render compact single-line colored table (Method | Code | Server | Port | IP | Host)")
		speedFlag   = flag.Bool("speed", false, "Measure 128KB HTTP download throughput (KB/s)")
		tlsAudit    = flag.Bool("tls-audit", false, "Audit accepted TLS versions (1.0 / 1.1 / 1.2 / 1.3)")
		copyFlag    = flag.Bool("copy", false, "Copy fastest alive hosts to Termux clipboard")
		notifyFlag  = flag.Bool("notify", false, "Send Android notification via termux-notification when scan finishes")
		resumeFlag  = flag.Bool("resume", false, "Enable checkpointing & resume interrupted bulk/CIDR scans")
		ckptFile    = flag.String("checkpoint", ".anon_scan_resume.log", "Checkpoint file path for --resume")
		target      = flag.String("t", "", "Single target domain or IP (e.g. m.facebook.com)")
		cidrFlag    = flag.String("cidr", "", "IPv4 CIDR range to expand & scan (e.g. 104.16.0.0/24)")
		asnCIDR     = flag.String("asn-cidr", "", "Fetch announced CIDRs for an ASN via RIPEstat (e.g. AS13335)")
		filePath    = flag.String("f", "", "File containing hosts or CIDRs (one per line, or '-' for stdin)")
		sniFlag     = flag.String("sni", "", "Custom SNI override (e.g. m.facebook.com, www.whatsapp.com)")
		wsPath      = flag.String("ws-path", "/", "WebSocket upgrade test path (e.g. / or /vless)")
		dnsServer   = flag.String("dns", "1.1.1.1:53", "DNS server ('1.1.1.1:53' or 'system' for ISP DNS)")
		useDoH      = flag.Bool("doh", false, "Use DNS-over-HTTPS (requires normal data or -proxy)")
		dnsAll      = flag.Bool("dns-all", false, "Query full DNS records (NS, MX, TXT/SPF) alongside A/AAAA")
		checkIPv6   = flag.Bool("6", false, "Test IPv6 (AAAA) TCP latency alongside IPv4")
		portsFlag   = flag.String("p", "80,443,8080,8443", "Comma-separated TCP ports to probe")
		workers     = flag.Int("w", 25, "Number of concurrent workers (LMK-safe for Termux)")
		versionFlag = flag.Bool("version", false, "Print version and exit")
		configFlag  = flag.String("config", "", "Config file with default options as 'key = value' lines (default ~/.anon-scan.conf or $ANON_SCAN_CONFIG)")
		rateFlag    = flag.Float64("rate", 0, "Max targets scanned per second across all workers (0 = unlimited)")
		retriesFlag = flag.Int("retries", 0, "Retry transient HTTP probe errors N times with exponential backoff")
		timeoutSec  = flag.Int("timeout", 4, "Timeout in seconds per network operation")
		jsonOut     = flag.Bool("json", false, "Output results as JSONL (for Bot/script/diff integration)")
		outFile     = flag.String("o", "", "Optional output file path to stream results")
		csvFile     = flag.String("csv", "", "Export scan results to CSV file (e.g. -csv results.csv)")
		htmlFile    = flag.String("html", "", "Generate dark-mode HTML dashboard report (e.g. -html report.html)")
		insecure    = flag.Bool("k", true, "Skip TLS certificate verification for bug host probing")
		checkASN    = flag.Bool("asn", true, "Lookup ISP/ASN & Geo info for resolved IP (auto-off in -pkg-mode)")
		checkRDAP   = flag.Bool("rdap", true, "Lookup domain registrar & expiry via RDAP (auto-off in -pkg-mode)")
		benchCount  = flag.Int("bench", 0, "Run N-sample TCP latency & jitter benchmark (e.g. -bench 5)")
		no302       = flag.Bool("no-302", false, "Filter out 301/302/307/308 redirect hosts (DirectNon302)")
		onlyAlive   = flag.Bool("only-alive", false, "Only display/save hosts that are alive")
		fetchSubs   = flag.Bool("subs", false, "Fetch subdomains (crt.sh + HackerTarget + OTX)")
		scanSubs    = flag.Bool("scan-subs", false, "Fetch subdomains and scan all of them")
		revIP       = flag.Bool("rev", false, "Reverse IP lookup (domains hosted on target IP)")
		scanRev     = flag.Bool("scan-rev", false, "Reverse IP lookup and scan all discovered domains")
	)
	flag.Parse()

	if *versionFlag {
		fmt.Printf("anon-scan %s\n", version)
		return
	}

	// Defaults from the config file (~/.anon-scan.conf or $ANON_SCAN_CONFIG, or -config path);
	// flags given on the command line always take priority.
	cfgPath := strings.TrimSpace(*configFlag)
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	if warns, err := applyConfigFile(flag.CommandLine, cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Config file error: %v\n", err)
	} else {
		for _, w := range warns {
			fmt.Fprintf(os.Stderr, "[!] Config: %s\n", w)
		}
	}

	hasStdin := isStdinPiped() && !*interactive

	if *interactive || (*target == "" && *filePath == "" && *cidrFlag == "" && *asnCIDR == "" && flag.NArg() == 0 && !hasStdin) {
		runBugScanXTUI()
		return
	}

	if *pkgMode {
		*checkASN = false
		*checkRDAP = false
		*useDoH = false
		if *dnsServer == "1.1.1.1:53" {
			*dnsServer = "system"
		}
		if *portsFlag == "80,443,8080,8443" {
			*portsFlag = "80,443"
		}
	}

	if *asnCIDR != "" {
		handleASNCIDR(*asnCIDR, *outFile, *proxyAddr, *notifyFlag)
		return
	}

	if *target == "" && *filePath == "" && *cidrFlag == "" && flag.NArg() > 0 {
		arg := flag.Arg(0)
		if _, _, err := net.ParseCIDR(arg); err == nil {
			*cidrFlag = arg
		} else {
			*target = arg
		}
	}

	opts := models.ScanOptions{
		DNSServer:   *dnsServer,
		UseDoH:      *useDoH,
		DNSAll:      *dnsAll,
		CheckIPv6:   *checkIPv6,
		PackageMode: *pkgMode,
		ProxyAddr:   strings.TrimSpace(*proxyAddr),
		HTTPMethod:  strings.ToUpper(strings.TrimSpace(*methodFlag)),
		CompactMode: *compactFlag,
		SpeedTest:   *speedFlag,
		TLSAudit:    *tlsAudit,
		Timeout:     time.Duration(*timeoutSec) * time.Second,
		Ports:       parsePorts(*portsFlag),
		SNI:         *sniFlag,
		WSPath:      *wsPath,
		ALPN:        []string{"h2", "http/1.1"},
		SkipVerify:  *insecure,
		CheckASN:    *checkASN,
		CheckRDAP:   *checkRDAP,
		BenchCount:  *benchCount,
		No302:       *no302,
		OnlyAlive:   *onlyAlive,
		RatePerSec:  *rateFlag,
		Retries:     *retriesFlag,
	}

	executeScan(opts, *target, *cidrFlag, *filePath, *outFile, *csvFile, *htmlFile, *ckptFile, *workers, *jsonOut, *notifyFlag, *copyFlag, *resumeFlag, *fetchSubs, *scanSubs, *revIP, *scanRev, hasStdin)
}

func runBugScanXTUI() {
	for {
		tui.PrintHeader("ANON SCANNER")
		action := tui.SelectOption("Select tool", []string{
			"Host Scanner (Direct / Non-302 / SSL / Proxy)",
			"Subfinder (Single Domain or File)",
			"CIDR IP Range Scanner",
			"Reverse IP Lookup",
			"ASN to CIDR Prefix Fetcher",
			"Host Up/Down Speed Test (Download & Upload)",
			"Continuous Host Watch Monitor",
			"Scan History (Search Past Scans)",
			"File Utilities (Dedup / Split / Diff)",
			"Exit",
		})

		switch {
		case strings.HasPrefix(action, "Host Scanner"):
			runTUIHostScanner()
		case strings.HasPrefix(action, "Subfinder"):
			runTUISubfinder()
		case strings.HasPrefix(action, "CIDR"):
			runTUICIDRScanner()
		case strings.HasPrefix(action, "Reverse IP"):
			tui.PrintHeader("ANON SCANNER")
			t := tui.AskInput("Enter Target IP or Domain", "104.16.132.229")
			px := tui.AskInput("Local Proxy (optional, e.g. 127.0.0.1:10808)", "")
			out := tui.AskInput("Enter output filename", "reverse_hosts.txt")
			opts := defaultPkgOpts("GET", "80,443", 4, px)
			executeScan(opts, t, "", "", out, "", "", "", 20, false, false, false, false, false, false, true, false, false)
			tui.Pause()
		case strings.HasPrefix(action, "ASN to CIDR"):
			tui.PrintHeader("ANON SCANNER")
			asn := tui.AskInput("Enter ASN (e.g. AS13335)", "AS13335")
			px := tui.AskInput("Local Proxy (optional)", "")
			out := tui.AskInput("Enter output filename", "asn_cidrs.txt")
			handleASNCIDR(asn, out, px, false)
			tui.Pause()
		case strings.HasPrefix(action, "Host Up/Down Speed"):
			tui.PrintHeader("ANON SCANNER")
			st := tui.PickTxtFile("Select hosts .txt file (or enter domain)")
			ss := tui.AskInput("Custom SNI (leave blank for each host)", "")
			sp := tui.AskInput("Port (80 or 443)", "443")
			px := tui.AskInput("Local Proxy (optional)", "")
			out := tui.AskInput("Save results to file (optional)", "speed_results.txt")
			sArgs := []string{"-p", sp}
			if _, err := os.Stat(st); err == nil {
				sArgs = append(sArgs, "-f", st)
			} else {
				sArgs = append(sArgs, "-t", st)
			}
			if ss != "" {
				sArgs = append(sArgs, "-sni", ss)
			}
			if px != "" {
				sArgs = append(sArgs, "-proxy", px)
			}
			if out != "" {
				sArgs = append(sArgs, "-o", out)
			}
			handleSpeed(sArgs)
			tui.Pause()
		case strings.HasPrefix(action, "Continuous"):
			tui.PrintHeader("ANON SCANNER")
			wt := tui.AskInput("Enter Host or IP to watch", "cloudflare.com")
			iv := tui.AskInput("Check interval (seconds)", "15")
			handleWatch([]string{"-t", wt, "-interval", iv, "-pkg-mode"})
			tui.Pause()
		case strings.HasPrefix(action, "Scan History"):
			tui.PrintHeader("ANON SCANNER")
			q := tui.AskInput("Search query (leave blank for latest 20)", "")
			storage.PrintHistory(q, 20)
			tui.Pause()
		case strings.HasPrefix(action, "File Utilities"):
			tui.PrintHeader("ANON SCANNER")
			util := tui.SelectOption("Select utility", []string{"Deduplicate hosts.txt", "Split hosts.txt", "Scan Diff (JSONL)"})
			if strings.HasPrefix(util, "Split") {
				f := tui.PickTxtFile("Select hosts file")
				n := tui.AskInput("Lines per split file", "500")
				handleSplit([]string{"-f", f, "-n", n})
			} else if strings.HasPrefix(util, "Scan Diff") {
				oldF := tui.AskInput("Older JSONL file", "old.jsonl")
				newF := tui.AskInput("Newer JSONL file", "new.jsonl")
				handleDiff([]string{oldF, newF})
			} else {
				f := tui.PickTxtFile("Select hosts file")
				o := tui.AskInput("Output filename", "clean_hosts.txt")
				handleDedup([]string{"-f", f, "-o", o})
			}
			tui.Pause()
		default:
			fmt.Println("Goodbye!")
			return
		}
	}
}

func runTUIHostScanner() {
	tui.PrintHeader("HOST SCANNER")

	mode := tui.SelectOption("Select scanning mode", []string{
		"Direct",
		"DirectNon302",
		"SSL",
		"ProxyRoute",
		"Ping",
	})

	inputTarget := tui.PickTxtFile("Select hosts file (or enter domain)")
	portsStr := tui.AskInput("Enter port(s)", "80")
	timeoutStr := tui.AskInput("Enter timeout (seconds)", "3")
	outFile := tui.AskInput("Enter output filename", "results.txt")
	threadsStr := tui.AskInput("Enter threads", "50")

	methods := []string{"GET"}
	if mode == "Direct" || mode == "DirectNon302" || mode == "ProxyRoute" {
		methods = tui.SelectMultiOptions("Select HTTP method(s)", []string{
			"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH",
		}, []int{0})
	}
	method := strings.Join(methods, ",")

	sniOverride := ""
	if mode == "SSL" {
		sniOverride = tui.AskInput("Custom SNI (leave blank to use each host)", "")
		if portsStr == "80" {
			portsStr = "443"
		}
	}

	proxyAddr := ""
	if mode == "ProxyRoute" {
		proxyAddr = tui.AskInput("Enter Proxy (e.g. 127.0.0.1:10808)", "127.0.0.1:10808")
	}

	timeoutSec, err := strconv.Atoi(timeoutStr)
	if err != nil || timeoutSec <= 0 {
		timeoutSec = 3
	}
	workers, err := strconv.Atoi(threadsStr)
	if err != nil || workers <= 0 {
		workers = 50
	}

	opts := defaultPkgOpts(method, portsStr, timeoutSec, proxyAddr)
	opts.CompactMode = true
	opts.OnlyAlive = true
	opts.SNI = sniOverride
	if mode == "DirectNon302" {
		opts.No302 = true
	}

	var singleTarget, filePath string
	if _, statErr := os.Stat(inputTarget); statErr == nil {
		filePath = inputTarget
	} else {
		singleTarget = inputTarget
	}

	tui.PrintTableHeader()
	executeScan(opts, singleTarget, "", filePath, outFile, "", "", "", workers, false, false, true, false, false, false, false, false, false)
	tui.Pause()
}

func runTUISubfinder() {
	tui.PrintHeader("SUBFINDER")

	inMode := tui.SelectOption("Select input mode", []string{"Single Domain", "File"})
	proxyAddr := tui.AskInput("Local Proxy (optional, e.g. 127.0.0.1:10808)", "")

	var domains []string
	var defaultOut string

	if inMode == "File" {
		fPath := tui.PickTxtFile("Select domains file")
		defaultOut = strings.TrimSuffix(fPath, ".txt") + "_subdomains.txt"
		f, err := os.Open(fPath)
		if err != nil {
			fmt.Printf("%s[!] Cannot open %s: %v%s\n", tui.Red, fPath, err, tui.Reset)
			tui.Pause()
			return
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sanitizeHost(sc.Text())
			if line != "" {
				domains = append(domains, line)
			}
		}
		_ = f.Close()
	} else {
		dom := sanitizeHost(tui.AskInput("Enter domain", "tiktok.com"))
		if dom != "" {
			domains = []string{dom}
			defaultOut = dom + "_subdomains.txt"
		}
	}

	outPath := tui.AskInput("Enter output filename", defaultOut)
	if len(domains) == 0 {
		fmt.Printf("%s[!] No domains provided.%s\n", tui.Red, tui.Reset)
		tui.Pause()
		return
	}

	fmt.Println()
	seen := make(map[string]bool)
	var allSubs []string

	for idx, d := range domains {
		fmt.Printf("%sProcessing: %s%s\n", tui.Cyan, d, tui.Reset)
		subs, err := recon.FetchSubdomains(context.Background(), d, 20*time.Second, proxyAddr)
		if err != nil {
			fmt.Printf("%s%s: failed (%v)%s\n", tui.Red, d, err, tui.Reset)
		} else {
			newCount := 0
			for _, s := range subs {
				if !seen[s] {
					seen[s] = true
					allSubs = append(allSubs, s)
					newCount++
				}
			}
			fmt.Printf("%s%s: %d subdomains found%s\n", tui.Green, d, newCount, tui.Reset)
		}
		fmt.Printf("%sProgress: %s%d / %d%s\n", tui.White, tui.Cyan, idx+1, len(domains), tui.Reset)
	}

	sort.Strings(allSubs)
	if outPath != "" && len(allSubs) > 0 {
		if f, err := os.Create(outPath); err == nil {
			for _, s := range allSubs {
				_, _ = f.WriteString(s + "\n")
			}
			_ = f.Close()
			fmt.Printf("\n%s[✓] Saved %d unique subdomains to %s%s\n", tui.Green, len(allSubs), outPath, tui.Reset)
		}
	}
	tui.Pause()
}

func runTUICIDRScanner() {
	tui.PrintHeader("HOST SCANNER")
	cidr := tui.AskInput("Enter IPv4 CIDR range", "104.16.0.0/29")
	sni := tui.AskInput("Enter SNI / Host header", "www.cloudflare.com")
	portsStr := tui.AskInput("Enter port(s)", "80,443")
	timeoutStr := tui.AskInput("Enter timeout (seconds)", "3")
	outFile := tui.AskInput("Enter output filename", "cidr_results.txt")
	threadsStr := tui.AskInput("Enter threads", "50")
	methods := tui.SelectMultiOptions("Select HTTP method(s)", []string{"GET", "HEAD", "POST", "OPTIONS"}, []int{0})
	method := strings.Join(methods, ",")

	timeoutSec, _ := strconv.Atoi(timeoutStr)
	if timeoutSec <= 0 {
		timeoutSec = 3
	}
	workers, _ := strconv.Atoi(threadsStr)
	if workers <= 0 {
		workers = 50
	}

	opts := defaultPkgOpts(method, portsStr, timeoutSec, "")
	opts.CompactMode = true
	opts.OnlyAlive = true
	opts.SNI = sni

	tui.PrintTableHeader()
	executeScan(opts, "", cidr, "", outFile, "", "", "", workers, false, false, true, false, false, false, false, false, false)
	tui.Pause()
}

func defaultPkgOpts(method, portsStr string, timeoutSec int, proxyAddr string) models.ScanOptions {
	return models.ScanOptions{
		DNSServer:   "system",
		UseDoH:      false,
		PackageMode: true,
		ProxyAddr:   proxyAddr,
		HTTPMethod:  method,
		Timeout:     time.Duration(timeoutSec) * time.Second,
		Ports:       parsePorts(portsStr),
		WSPath:      "/",
		ALPN:        []string{"h2", "http/1.1"},
		SkipVerify:  true,
		CheckASN:    false,
		CheckRDAP:   false,
	}
}

func executeScan(
	opts models.ScanOptions,
	target, cidrFlag, filePath, outFile, csvFile, htmlFile, ckptFile string,
	workers int,
	jsonOut, notifyFlag, copyFlag, resumeFlag, fetchSubs, scanSubs, revIP, scanRev, hasStdin bool,
) {
	startTime := time.Now()

	var outWriter *os.File
	if outFile != "" {
		var err error
		flagMode := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		if resumeFlag {
			flagMode = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		}
		outWriter, err = os.OpenFile(outFile, flagMode, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to create output file: %v\n", err)
			return
		}
		defer outWriter.Close()
	}

	var csvWriter *csv.Writer
	if csvFile != "" {
		cf, err := os.Create(csvFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to create CSV file: %v\n", err)
			return
		}
		defer cf.Close()
		csvWriter = csv.NewWriter(cf)
		defer csvWriter.Flush()
		_ = csvWriter.Write([]string{
			"Target", "IP", "Alive", "LatencyMS", "HTTPStatus",
			"WebSocket101", "HTTP3Quic", "SpeedKBps", "CDN", "WAF", "TLSVersion", "ALPN",
			"SecScore", "ASN", "Country", "RDAPExpires",
		})
		csvWriter.Flush()
	}

	var targets []string
	if (fetchSubs || scanSubs) && target != "" {
		cleanDomain := sanitizeHost(target)
		if !jsonOut && !opts.CompactMode {
			printBanner()
			fmt.Printf("[*] Querying crt.sh + HackerTarget + OTX for %s...\n", cleanDomain)
		}
		subs, err := recon.FetchSubdomains(context.Background(), cleanDomain, 20*time.Second, opts.ProxyAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Subdomain fetch failed: %v\n", err)
			return
		}
		if fetchSubs && !scanSubs {
			for _, s := range subs {
				fmt.Println(s)
				if outWriter != nil {
					_, _ = outWriter.WriteString(s + "\n")
				}
			}
			return
		}
		targets = subs
	} else if (revIP || scanRev) && target != "" {
		cleanTarget := sanitizeHost(target)
		lookupIP := cleanTarget
		if net.ParseIP(cleanTarget) == nil {
			res := resolver.New(opts.DNSServer, opts.Timeout, opts.ProxyAddr)
			dnsInfo := res.Lookup(context.Background(), cleanTarget, false)
			if len(dnsInfo.IPv4) > 0 {
				lookupIP = dnsInfo.IPv4[0]
			}
			// A VPN/proxy "fake-ip" DNS mode hands out 198.18.0.0/15 placeholders.
			// DoH travels over HTTPS and is not hijacked, so retry with it to get the real IP.
			if recon.IsFakeOrPrivateIP(lookupIP) {
				fmt.Fprintf(os.Stderr, "[*] %s resolved to fake/private %s, retrying via DoH...\n", cleanTarget, lookupIP)
				dohInfo := res.LookupDoH(context.Background(), cleanTarget, false)
				for _, ip := range dohInfo.IPv4 {
					if !recon.IsFakeOrPrivateIP(ip) {
						lookupIP = ip
						break
					}
				}
			}
		}
		hosts, err := recon.ReverseIPLookup(context.Background(), lookupIP, 12*time.Second, opts.ProxyAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Reverse IP lookup failed: %v\n", err)
			return
		}
		if revIP && !scanRev {
			for _, h := range hosts {
				fmt.Println(h)
				if outWriter != nil {
					_, _ = outWriter.WriteString(h + "\n")
				}
			}
			return
		}
		targets = hosts
	} else {
		targets = collectTargets(target, cidrFlag, filePath, hasStdin)
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No valid targets found.")
		return
	}

	var tracker *storage.CheckpointTracker
	if resumeFlag {
		var err error
		tracker, err = storage.NewCheckpointTracker(ckptFile)
		if err == nil {
			var skipped int
			targets, skipped = tracker.FilterRemaining(targets)
			if skipped > 0 && !jsonOut {
				fmt.Printf("[*] Resume Checkpoint: Skipped %d already-scanned targets (%d remaining)\n", skipped, len(targets))
			}
			if len(targets) == 0 {
				fmt.Println("[✓] All targets already scanned!")
				tracker.Close(true)
				return
			}
		}
	}

	if len(targets) > 10 {
		opts.CheckASN = false
		opts.CheckRDAP = false
		opts.DNSAll = false
	}

	if !jsonOut && !opts.CompactMode {
		if !scanSubs && !scanRev {
			printBanner()
		}
		fmt.Printf("[*] Targets: %d | Workers: %d | DNS: %s | Method: %s\n\n",
			len(targets), workers, opts.DNSServer, emptyDefault(opts.HTTPMethod, "GET"))
	}

	scanCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	allResults, aliveResults, interrupted := runPool(scanCtx, targets, workers, opts, jsonOut, outWriter, csvWriter, tracker)

	if tracker != nil {
		if interrupted {
			tracker.Close(false)
			fmt.Fprintf(os.Stderr, "\n[!] Scan interrupted! Progress saved to %s.\n", ckptFile)
		} else {
			tracker.Close(true)
		}
	}

	if !jsonOut && !opts.CompactMode && len(targets) > 1 && len(aliveResults) > 0 {
		printTopFastestTable(aliveResults, 10)
	}

	if htmlFile != "" && len(allResults) > 0 {
		reportData := allResults
		if opts.OnlyAlive {
			reportData = aliveResults
		}
		if err := storage.WriteHTMLReport(htmlFile, reportData); err == nil && !jsonOut {
			fmt.Printf("\n[✓] Dark-mode HTML dashboard saved to: %s\n", htmlFile)
		}
	}

	if copyFlag && len(aliveResults) > 0 {
		sort.Slice(aliveResults, func(i, j int) bool {
			return aliveResults[i].BestLatency < aliveResults[j].BestLatency
		})
		var top []string
		for i, r := range aliveResults {
			if i >= 5 {
				break
			}
			top = append(top, r.Target)
		}
		copyToClipboard(strings.Join(top, "\n"))
	}

	if notifyFlag && !interrupted {
		elapsed := time.Since(startTime).Round(time.Second)
		msg := fmt.Sprintf("Scanned: %d | Alive: %d | Time: %s", len(targets), len(aliveResults), elapsed)
		sendTermuxNotification("🛰 ANON SCANNER Complete", msg)
	}
}

func copyToClipboard(text string) {
	binPath, err := exec.LookPath("termux-clipboard-set")
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!] termux-clipboard-set not found (install termux-api)")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath)
	cmd.Stdin = strings.NewReader(text)
	if err := cmd.Run(); err == nil {
		fmt.Printf("\n[📋] Copied top %d alive hosts to Android clipboard!\n", len(strings.Split(text, "\n")))
	}
}

func handleWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	target := fs.String("t", "", "Target domain or IP to monitor (required)")
	intervalSec := fs.Int("interval", 30, "Check interval in seconds")
	sniFlag := fs.String("sni", "", "Custom SNI override")
	wsPath := fs.String("ws-path", "/", "WebSocket test path")
	portsFlag := fs.String("p", "80,443", "Ports to monitor")
	dnsServer := fs.String("dns", "1.1.1.1:53", "DNS server ('1.1.1.1:53' or 'system')")
	pkgMode := fs.Bool("pkg-mode", false, "Social Package Mode")
	proxyAddr := fs.String("proxy", "", "Optional local proxy (e.g. 127.0.0.1:10808)")
	notify := fs.Bool("notify", false, "Send Termux notification when host status changes")
	_ = fs.Parse(args)

	if *target == "" && fs.NArg() > 0 {
		*target = fs.Arg(0)
	}
	if *target == "" {
		fmt.Println("Usage: anon-scan watch -t example.com [-interval 30] [-notify] [-pkg-mode]")
		return
	}
	if *intervalSec < 3 {
		*intervalSec = 3
	}
	if *pkgMode && *dnsServer == "1.1.1.1:53" {
		*dnsServer = "system"
	}

	opts := models.ScanOptions{
		DNSServer:   *dnsServer,
		PackageMode: true,
		ProxyAddr:   strings.TrimSpace(*proxyAddr),
		HTTPMethod:  "GET",
		Timeout:     4 * time.Second,
		Ports:       parsePorts(*portsFlag),
		SNI:         *sniFlag,
		WSPath:      *wsPath,
		ALPN:        []string{"h2", "http/1.1"},
		SkipVerify:  true,
	}

	fmt.Printf("[*] Continuous Watch Mode: %s | Interval: %ds | Notify: %v (Press Ctrl+C to stop)\n\n",
		*target, *intervalSec, *notify)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	res := resolver.New(opts.DNSServer, opts.Timeout, opts.ProxyAddr)
	var hasPrev, prevAlive, prevWS bool

	checkOnce := func() {
		r := scanSingleTarget(ctx, res, *target, opts)
		ts := time.Now().Format("15:04:05")
		status := "✗ DOWN"
		if r.Alive {
			status = "✓ ALIVE"
		}
		wsLabel := "NO"
		if r.HTTP.WebSocket101 {
			wsLabel = "101"
		}
		fmt.Printf("[%s] %-22s | %-7s | %4dms | HTTP %-3d | WS: %-3s | IP: %s\n",
			ts, r.Target, status, r.BestLatency, r.HTTP.StatusCode, wsLabel, emptyDefault(r.BestIP, "-"))

		if hasPrev && (prevAlive != r.Alive || prevWS != r.HTTP.WebSocket101) {
			alertMsg := fmt.Sprintf("%s changed state -> %s (%dms, HTTP %d)", r.Target, status, r.BestLatency, r.HTTP.StatusCode)
			if *notify {
				sendTermuxNotification("🛰 Watch Alert: "+r.Target, alertMsg)
			}
		}
		hasPrev = true
		prevAlive = r.Alive
		prevWS = r.HTTP.WebSocket101
	}

	checkOnce()
	ticker := time.NewTicker(time.Duration(*intervalSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\n[*] Watch mode stopped.")
			return
		case <-ticker.C:
			checkOnce()
		}
	}
}

func handleDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	oldFile := fs.String("old", "", "Older JSONL scan file")
	newFile := fs.String("new", "", "Newer JSONL scan file")
	_ = fs.Parse(args)

	if *oldFile == "" && *newFile == "" && fs.NArg() >= 2 {
		*oldFile = fs.Arg(0)
		*newFile = fs.Arg(1)
	}
	if *oldFile == "" || *newFile == "" {
		fmt.Println("Usage: anon-scan diff old.jsonl new.jsonl")
		return
	}

	summary, err := storage.CompareJSONLFiles(*oldFile, *newFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Diff failed: %v\n", err)
		return
	}

	fmt.Printf("  Total Hosts : Old=%d | New=%d\n", summary.TotalOld, summary.TotalNew)
	fmt.Printf("  Newly Alive : %d\n", len(summary.NewlyAlive))
	for _, r := range summary.NewlyAlive {
		fmt.Printf("    + [ALIVE] %s (%s | %dms | HTTP %d)\n", r.Target, r.BestIP, r.BestLatency, r.HTTP.StatusCode)
	}
	fmt.Printf("  Newly Down  : %d\n", len(summary.NewlyDown))
	for _, r := range summary.NewlyDown {
		fmt.Printf("    - [DOWN]  %s (was %s)\n", r.Target, r.BestIP)
	}
	fmt.Printf("  New WS 101  : %d\n", len(summary.NewWS101))
	fmt.Printf("  Changed IPs : %d\n", len(summary.ChangedIPs))
}

func handleASNCIDR(asn, outFile, proxyAddr string, notify bool) {
	fmt.Printf("[*] Querying RIPEstat announced CIDR prefixes for %s...\n", strings.ToUpper(asn))
	v4, v6, err := recon.FetchASNCIDRs(context.Background(), asn, 20*time.Second, proxyAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] ASN CIDR lookup failed: %v\n", err)
		return
	}
	fmt.Printf("[✓] Found %d IPv4 prefixes and %d IPv6 prefixes for %s.\n\n", len(v4), len(v6), strings.ToUpper(asn))

	var outWriter *os.File
	if outFile != "" {
		outWriter, _ = os.Create(outFile)
		if outWriter != nil {
			defer outWriter.Close()
		}
	}
	for _, p := range v4 {
		fmt.Println(p)
		if outWriter != nil {
			_, _ = outWriter.WriteString(p + "\n")
		}
	}
	if notify {
		sendTermuxNotification("ANON SCANNER: ASN CIDRs Ready", fmt.Sprintf("%s -> %d IPv4 prefixes", strings.ToUpper(asn), len(v4)))
	}
}

func sendTermuxNotification(title, message string) {
	binPath, err := exec.LookPath("termux-notification")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\a\n[🔔 Notification] %s — %s\n", title, message)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, binPath, "--title", title, "--content", message, "--id", "anon-scan-done", "--priority", "high").Run()
}

func handleDedup(args []string) {
	fs := flag.NewFlagSet("dedup", flag.ExitOnError)
	inPath := fs.String("f", "", "Input hosts file (required)")
	outPath := fs.String("o", "", "Output file path (optional)")
	_ = fs.Parse(args)
	if *inPath == "" {
		fmt.Println("Usage: anon-scan dedup -f hosts.txt [-o clean.txt]")
		return
	}
	total, unique, err := storage.DedupHostsFile(*inPath, *outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Dedup failed: %v\n", err)
		return
	}
	fmt.Printf("[✓] Dedup complete: %d lines -> %d unique hosts\n", total, unique)
}

func handleSplit(args []string) {
	fs := flag.NewFlagSet("split", flag.ExitOnError)
	inPath := fs.String("f", "", "Input hosts file (required)")
	chunkSize := fs.Int("n", 500, "Lines per split file")
	prefix := fs.String("o", "", "Output file prefix (optional)")
	_ = fs.Parse(args)
	if *inPath == "" {
		fmt.Println("Usage: anon-scan split -f hosts.txt [-n 500] [-o chunk]")
		return
	}
	files, total, err := storage.SplitHostsFile(*inPath, *chunkSize, *prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Split failed: %v\n", err)
		return
	}
	fmt.Printf("[✓] Split %d hosts into %d files\n", total, len(files))
}

func runPool(ctx context.Context, targets []string, workers int, opts models.ScanOptions, jsonMode bool, outFile *os.File, csvWriter *csv.Writer, tracker *storage.CheckpointTracker) ([]models.ScanResult, []models.ScanResult, bool) {
	if workers < 1 {
		workers = 1
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	total := int64(len(targets))
	var completed, aliveCount, filteredCount atomic.Int64

	jobs := make(chan string, workers*2)
	var wg sync.WaitGroup
	var outMu sync.Mutex
	var allResults, aliveResults []models.ScanResult

	res := resolver.New(opts.DNSServer, opts.Timeout, opts.ProxyAddr)
	showProgress := !jsonMode && total > 1
	limiter := scanner.NewLimiter(opts.RatePerSec)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := limiter.Wait(ctx); err != nil {
					return
				}
				result := scanSingleTarget(ctx, res, host, opts)
				if ctx.Err() != nil {
					return
				}
				if tracker != nil {
					tracker.MarkDone(host)
				}
				storage.AppendHistory(result)

				done := completed.Add(1)
				if result.Alive {
					aliveCount.Add(1)
				}

				outMu.Lock()
				allResults = append(allResults, result)
				outMu.Unlock()

				filtered := false
				if opts.OnlyAlive && !result.Alive {
					filtered = true
				} else if opts.No302 && isRedirectResult(result) {
					filtered = true
				}

				if filtered {
					filteredCount.Add(1)
					if showProgress {
						outMu.Lock()
						printProgress(done, total, aliveCount.Load(), filteredCount.Load())
						outMu.Unlock()
					}
					continue
				}

				outMu.Lock()
				if showProgress {
					fmt.Fprint(os.Stderr, "\r\033[K")
				}
				if opts.CompactMode && !jsonMode {
					methodsList := parseMethods(opts.HTTPMethod)
					if len(methodsList) > 1 && result.Alive && result.BestIP != "" {
						sni := emptyDefault(opts.SNI, result.Target)
						p := result.HTTP.Port
						if p == 0 {
							p = 80
						}
						for idxM, mName := range methodsList {
							if idxM == 0 {
								renderCompactRow(result, opts, outFile)
							} else {
								mInfo := scanner.ProbeHTTP(ctx, result.BestIP, p, sni, sni, mName, opts.SpeedTest, opts.Timeout, opts.SkipVerify, opts.ProxyAddr)
								subRes := result
								subRes.HTTP = mInfo
								subOpts := opts
								subOpts.HTTPMethod = mName
								renderCompactRow(subRes, subOpts, outFile)
							}
						}
					} else {
						renderCompactRow(result, opts, outFile)
					}
				} else {
					renderResult(result, jsonMode, outFile)
				}
				if csvWriter != nil {
					writeCSVRow(csvWriter, result)
				}
				if result.Alive {
					aliveResults = append(aliveResults, result)
				}
				if showProgress {
					printProgress(done, total, aliveCount.Load(), filteredCount.Load())
				}
				outMu.Unlock()
			}
		}()
	}

enqueueLoop:
	for _, t := range targets {
		select {
		case <-ctx.Done():
			break enqueueLoop
		case jobs <- t:
		}
	}
	close(jobs)
	wg.Wait()

	if showProgress {
		fmt.Fprint(os.Stderr, "\r\033[K\n")
	}
	return allResults, aliveResults, ctx.Err() != nil
}

func renderCompactRow(r models.ScanResult, opts models.ScanOptions, outFile *os.File) {
	method := emptyDefault(r.HTTP.Method, parseMethods(opts.HTTPMethod)[0])
	code := r.HTTP.StatusCode
	if r.HTTP.WebSocket101 {
		code = 101
	}
	server := emptyDefault(r.HTTP.Server, r.HTTP.DetectedCDN)
	port := r.HTTP.Port
	if port == 0 && len(r.Ports) > 0 {
		for _, p := range r.Ports {
			if p.Open {
				port = p.Port
				break
			}
		}
	}
	tui.PrintTableRow(method, code, server, port, r.BestIP, r.Target)
	if outFile != nil && r.Alive {
		_, _ = fmt.Fprintf(outFile, "%-6s %-4d %-16s %-5d %-16s %s\n", method, code, emptyDefault(server, "-"), port, r.BestIP, r.Target)
	}
}

func printProgress(done, total, alive, filtered int64) {
	pct := float64(done) / float64(total) * 100.0
	fmt.Fprintf(os.Stderr, "\r%sProgress: %s%d/%d (%.1f%%) | Alive: %d | Filtered: %d%s",
		tui.Gray, tui.Cyan, done, total, pct, alive, filtered, tui.Reset)
}

func printTopFastestTable(results []models.ScanResult, limit int) {
	if len(results) == 0 {
		return
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].BestLatency < results[j].BestLatency
	})
	if len(results) > limit {
		results = results[:limit]
	}
	tui.PrintTableHeader()
	for _, r := range results {
		renderCompactRow(r, models.ScanOptions{HTTPMethod: "GET"}, nil)
	}
}

func writeCSVRow(w *csv.Writer, r models.ScanResult) {
	cdn := emptyDefault(r.HTTP.DetectedCDN, r.CDNHint)
	secScore := fmt.Sprintf("%d/%d", r.HTTP.SecurityHeaders.Score, r.HTTP.SecurityHeaders.Total)
	_ = w.Write([]string{
		r.Target, r.BestIP, strconv.FormatBool(r.Alive), strconv.FormatInt(r.BestLatency, 10),
		strconv.Itoa(r.HTTP.StatusCode), strconv.FormatBool(r.HTTP.WebSocket101), strconv.FormatBool(r.HTTP.HTTP3Quic),
		fmt.Sprintf("%.1f", r.HTTP.SpeedKBps), cdn, r.HTTP.DetectedWAF, r.TLS.Version, r.TLS.NegotiatedALPN,
		secScore, r.ASN.ASN, r.ASN.Country, r.RDAP.Expires,
	})
	w.Flush()
}

func isRedirectResult(r models.ScanResult) bool {
	if len(r.HTTP.RedirectChain) > 0 {
		return true
	}
	return r.HTTP.StatusCode >= 300 && r.HTTP.StatusCode < 400
}

func scanSingleTarget(ctx context.Context, res *resolver.CustomResolver, rawTarget string, opts models.ScanOptions) models.ScanResult {
	host := sanitizeHost(rawTarget)
	result := models.ScanResult{
		Target:    host,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	var dnsInfo models.DNSInfo
	if opts.UseDoH {
		dnsInfo = res.LookupDoH(ctx, host, opts.DNSAll)
	} else {
		dnsInfo = res.Lookup(ctx, host, opts.DNSAll)
	}
	result.DNS = dnsInfo
	result.CDNHint = resolver.DetectCDNHint(dnsInfo.CNAME, dnsInfo.IPv4)
	result.TakeoverRisk = recon.CheckDanglingCNAME(dnsInfo.CNAME, dnsInfo.IPv4, dnsInfo.Error)

	var targetIP string
	if len(dnsInfo.IPv4) > 0 {
		targetIP = dnsInfo.IPv4[0]
	} else if len(dnsInfo.IPv6) > 0 {
		targetIP = dnsInfo.IPv6[0]
	} else {
		return result
	}
	result.BestIP = targetIP

	if opts.CheckIPv6 {
		result.IPv6.Checked = true
		if len(dnsInfo.IPv6) > 0 {
			v6Port := 443
			v6Res := scanner.ProbePort(ctx, dnsInfo.IPv6[0], v6Port, opts.Timeout, opts.ProxyAddr)
			result.IPv6.IP = dnsInfo.IPv6[0]
			result.IPv6.Port = v6Port
			result.IPv6.Open = v6Res.Open
			result.IPv6.LatencyMS = v6Res.LatencyMS
			result.IPv6.Error = v6Res.Error
		} else {
			result.IPv6.Error = "No AAAA record"
		}
	}

	if opts.CheckASN && !opts.PackageMode {
		result.ASN = recon.LookupASN(ctx, targetIP, opts.Timeout, opts.ProxyAddr)
	}
	if opts.CheckRDAP && !opts.PackageMode {
		result.RDAP = recon.LookupRDAP(ctx, host, opts.Timeout, opts.ProxyAddr)
	}

	var bestLatency int64 = -1
	bestPort := 443
	tlsPort := 443
	tlsPortOpen := false
	httpPort := 0

	for _, port := range opts.Ports {
		pStatus := scanner.ProbePort(ctx, targetIP, port, opts.Timeout, opts.ProxyAddr)
		result.Ports = append(result.Ports, pStatus)
		if pStatus.Open {
			result.Alive = true
			if bestLatency == -1 || pStatus.LatencyMS < bestLatency {
				bestLatency = pStatus.LatencyMS
				bestPort = port
			}
			if port == 443 || (port == 8443 && !tlsPortOpen) {
				tlsPort = port
				tlsPortOpen = true
			}
			if httpPort == 0 || port == 443 {
				httpPort = port
			}
		}
	}

	if bestLatency >= 0 {
		result.BestLatency = bestLatency
	}
	if opts.BenchCount > 0 && result.Alive {
		result.Benchmark = scanner.BenchmarkPort(ctx, targetIP, bestPort, opts.BenchCount, opts.Timeout, opts.ProxyAddr)
	}

	sniHost := opts.SNI
	if sniHost == "" {
		sniHost = host
	}

	if tlsPortOpen {
		result.TLS = scanner.ProbeTLS(ctx, targetIP, tlsPort, sniHost, opts.ALPN, opts.Timeout, opts.SkipVerify, opts.ProxyAddr)
		if opts.TLSAudit {
			result.TLS.AcceptedVersions = scanner.AuditTLSVersions(ctx, targetIP, tlsPort, sniHost, opts.Timeout, opts.SkipVerify, opts.ProxyAddr)
		}
		httpPort = tlsPort
	}

	if httpPort > 0 {
		firstMethod := parseMethods(opts.HTTPMethod)[0]
		httpInfo := scanner.ProbeHTTPWithRetry(ctx, opts.Retries, targetIP, httpPort, sniHost, sniHost, firstMethod, opts.SpeedTest, opts.Timeout, opts.SkipVerify, opts.ProxyAddr)
		if !opts.CompactMode {
			wsOK, wsCode, wsErr := scanner.ProbeWebSocket(ctx, targetIP, httpPort, sniHost, sniHost, opts.WSPath, opts.Timeout, opts.SkipVerify, opts.ProxyAddr)
			httpInfo.WebSocket101 = wsOK
			httpInfo.WSStatus = wsCode
			if httpInfo.Error == "" && wsErr != "" && wsCode == 0 {
				httpInfo.Error = wsErr
			}
		}
		result.HTTP = httpInfo
	}

	return result
}

func renderResult(r models.ScanResult, jsonMode bool, outFile *os.File) {
	if jsonMode {
		b, err := json.Marshal(r)
		if err == nil {
			line := string(b)
			fmt.Println(line)
			if outFile != nil {
				_, _ = outFile.WriteString(line + "\n")
			}
		}
		return
	}

	statusIcon := "✗ DOWN"
	if r.Alive {
		statusIcon = "✓ ALIVE"
	}

	fmt.Printf("━━━ %s [%s] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", r.Target, statusIcon)
	if r.TakeoverRisk != "" {
		fmt.Printf("  ⚠ Audit   : %s\n", r.TakeoverRisk)
	}
	if r.DNS.Error != "" {
		fmt.Printf("  DNS Error : %s\n\n", r.DNS.Error)
		return
	}

	fmt.Printf("  IP / CDN  : %s (%s) | DNS (%s): %dms\n", r.BestIP, r.CDNHint, r.DNS.Resolver, r.DNS.ResolveMS)
	if r.DNS.CNAME != "" {
		fmt.Printf("  CNAME     : %s\n", r.DNS.CNAME)
	}
	var openPorts []string
	for _, p := range r.Ports {
		if p.Open {
			openPorts = append(openPorts, fmt.Sprintf("%d (%dms)", p.Port, p.LatencyMS))
		}
	}
	if len(openPorts) > 0 {
		fmt.Printf("  Open Ports: %s\n", strings.Join(openPorts, ", "))
	}
	if r.TLS.Supported {
		fmt.Printf("  TLS / ALPN: %s | ALPN: %s | SNI: %s (%dms)\n",
			r.TLS.Version, emptyDefault(r.TLS.NegotiatedALPN, "none"), r.TLS.SNIUsed, r.TLS.HandshakeMS)
		if len(r.TLS.AcceptedVersions) > 0 {
			fmt.Printf("  TLS Audit : %s\n", strings.Join(r.TLS.AcceptedVersions, ", "))
		}
	}
	if r.HTTP.Probed {
		speedStr := ""
		if r.HTTP.SpeedKBps > 0 {
			speedStr = fmt.Sprintf(" | Speed: %.1f KB/s", r.HTTP.SpeedKBps)
		}
		fmt.Printf("  HTTP Probe: %s %s %d (%dms)%s | Server: %s\n",
			r.HTTP.Method, strings.ToUpper(r.HTTP.Scheme), r.HTTP.StatusCode, r.HTTP.ResponseMS, speedStr, emptyDefault(r.HTTP.Server, "hidden"))
		if len(r.HTTP.RedirectChain) > 0 {
			fmt.Printf("  Redirects : %s\n", strings.Join(r.HTTP.RedirectChain, " -> "))
		}
	}
	fmt.Println()

	if outFile != nil && r.Alive {
		_, _ = fmt.Fprintf(outFile, "%s | IP:%s | HTTP:%d | Server:%s | Latency:%dms\n",
			r.Target, r.BestIP, r.HTTP.StatusCode, emptyDefault(r.HTTP.Server, "-"), r.BestLatency)
	}
}

func isStdinPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}

func collectTargets(single, cidrFlag, filePath string, readStdin bool) []string {
	seen := make(map[string]bool)
	var list []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			return
		}
		if _, _, err := net.ParseCIDR(raw); err == nil {
			ips, expErr := recon.ExpandCIDR(raw, 65536)
			if expErr != nil {
				fmt.Fprintf(os.Stderr, "[!] %v\n", expErr)
				return
			}
			for _, ip := range ips {
				if !seen[ip] {
					seen[ip] = true
					list = append(list, ip)
				}
			}
			return
		}
		h := sanitizeHost(raw)
		if h != "" && !seen[h] {
			seen[h] = true
			list = append(list, h)
		}
	}

	if single != "" {
		add(single)
	}
	if cidrFlag != "" {
		add(cidrFlag)
	}
	if filePath != "" && filePath != "-" {
		if f, err := os.Open(filePath); err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				add(sc.Text())
			}
		}
	}
	if readStdin || filePath == "-" {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			add(sc.Text())
		}
	}
	return list
}

func sanitizeHost(input string) string {
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

func parsePorts(raw string) []int {
	var ports []int
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return []int{80, 443}
	}
	return ports
}

func parseMethods(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		m := strings.ToUpper(strings.TrimSpace(p))
		if m != "" {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return []string{"GET"}
	}
	return out
}

func emptyDefault(val, def string) string {
	if val == "" {
		return def
	}
	return val
}

func printBanner() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║   🛰  ANON SCANNER CLI v9.5 (Complete Edition)       ║")
	fmt.Println("║   Termux Ready • Speed • TLS Audit • Proxy • History ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
}

func handleSelfUpdate() {
	repoDir := "."
	if _, err := os.Stat("go.mod"); err != nil {
		if home, hErr := os.UserHomeDir(); hErr == nil {
			repoDir = home + "/anon-scan"
		}
	}
	fmt.Printf("[*] Updating ANON SCANNER from GitHub in %s...\n", repoDir)

	pullCmd := exec.Command("git", "-C", repoDir, "pull", "origin", "main")
	pullCmd.Stdout = os.Stdout
	pullCmd.Stderr = os.Stderr
	if err := pullCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] git pull failed: %v\n", err)
		return
	}

	fmt.Println("[*] Rebuilding binary...")
	buildCmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", "anon-scan", "./cmd/cli")
	buildCmd.Dir = repoDir
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] go build failed: %v\n", err)
		return
	}

	prefix := os.Getenv("PREFIX")
	if prefix == "" {
		prefix = "/usr/local"
	}
	dest := prefix + "/bin/anon-scan"
	_ = os.Remove(dest)
	cpCmd := exec.Command("cp", repoDir+"/anon-scan", dest)
	if err := cpCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to install to %s: %v\n", dest, err)
		return
	}
	_ = os.Chmod(dest, 0755)
	fmt.Printf("[✓] ANON SCANNER updated and installed to %s!\n", dest)
}

func handleSpeed(args []string) {
	fs := flag.NewFlagSet("speed", flag.ExitOnError)
	target := fs.String("t", "", "Single target domain or IP")
	filePath := fs.String("f", "", "File containing hosts (.txt, one per line)")
	sniFlag := fs.String("sni", "", "Custom SNI / Host header override")
	port := fs.Int("p", 443, "Port to test (80 or 443)")
	workers := fs.Int("w", 5, "Concurrent speed test workers")
	downKB := fs.Int("down-kb", 512, "Max download test size in KB")
	upKB := fs.Int("up-kb", 128, "Upload payload size in KB")
	outFile := fs.String("o", "", "Optional output file to save sorted results")
	proxyAddr := fs.String("proxy", "", "Optional local proxy (e.g. 127.0.0.1:10808)")
	pkgMode := fs.Bool("pkg-mode", false, "Use Android ISP DNS")
	_ = fs.Parse(args)

	if *target == "" && *filePath == "" && fs.NArg() > 0 {
		arg := fs.Arg(0)
		if _, err := os.Stat(arg); err == nil {
			*filePath = arg
		} else {
			*target = arg
		}
	}
	if *target == "" && *filePath == "" {
		fmt.Println("Usage:")
		fmt.Println("  Single : anon-scan speed -t speed.cloudflare.com [-p 443]")
		fmt.Println("  Bulk   : anon-scan speed -f hosts.txt [-w 5] [-o speed_results.txt]")
		return
	}

	targets := collectTargets(*target, "", *filePath, false)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No valid hosts found.")
		return
	}

	dnsSrv := "1.1.1.1:53"
	if *pkgMode {
		dnsSrv = "system"
	}
	res := resolver.New(dnsSrv, 4*time.Second, *proxyAddr)

	if len(targets) == 1 {
		host := targets[0]
		sni := emptyDefault(*sniFlag, host)
		dnsInfo := res.Lookup(context.Background(), host, false)
		ip := host
		if len(dnsInfo.IPv4) > 0 {
			ip = dnsInfo.IPv4[0]
		}
		fmt.Printf("\n[*] Running Up/Down Speed Test -> %s (%s:%d | SNI: %s)...\n", host, ip, *port, sni)
		sr := scanner.RunUpDownSpeedTest(context.Background(), ip, *port, sni, sni, int64(*downKB)*1024, (*upKB)*1024, 15*time.Second, true, *proxyAddr)

		fmt.Println("╔══════════════════════════════════════════════════════╗")
		fmt.Println("║            ⚡ ANON SCANNER SPEED REPORT              ║")
		fmt.Println("╠══════════════════════════════════════════════════════╣")
		fmt.Printf("  Target / IP : %s (%s:%d)\n", sr.Target, sr.IP, sr.Port)
		fmt.Printf("  TCP Latency : %d ms\n", sr.TCPMS)
		if sr.DownError != "" {
			fmt.Printf("  Download    : Error (%s)\n", sr.DownError)
		} else {
			fmt.Printf("  Download    : %.1f KB/s (%.2f Mbps) | %d KB | HTTP %d\n", sr.DownKBps, sr.DownMbps, sr.DownBytes/1024, sr.DownStatus)
		}
		if sr.UpError != "" {
			fmt.Printf("  Upload      : Error (%s) | Sent %d KB\n", sr.UpError, sr.UpBytes/1024)
		} else {
			fmt.Printf("  Upload      : %.1f KB/s (%.2f Mbps) | %d KB | HTTP %d\n", sr.UpKBps, sr.UpMbps, sr.UpBytes/1024, sr.UpStatus)
		}
		fmt.Println("╚══════════════════════════════════════════════════════╝")
		return
	}

	// Bulk .txt Speed Test
	if *workers < 1 {
		*workers = 1
	}
	if *workers > len(targets) {
		*workers = len(targets)
	}
	fmt.Printf("\n[*] Bulk Speed Test: %d hosts | Workers: %d | Port: %d\n\n", len(targets), *workers, *port)
	fmt.Printf("%-26s %-15s %-6s %-16s %-16s\n", "HOST", "IP", "TCP", "DOWNLOAD", "UPLOAD")
	fmt.Printf("%-26s %-15s %-6s %-16s %-16s\n", "--------------------------", "---------------", "------", "----------------", "----------------")

	jobs := make(chan string, *workers*2)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []scanner.SpeedResult

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				sni := emptyDefault(*sniFlag, host)
				dnsInfo := res.Lookup(context.Background(), host, false)
				ip := host
				if len(dnsInfo.IPv4) > 0 {
					ip = dnsInfo.IPv4[0]
				}
				sr := scanner.RunUpDownSpeedTest(context.Background(), ip, *port, sni, sni, int64(*downKB)*1024, (*upKB)*1024, 15*time.Second, true, *proxyAddr)
				sr.Target = host

				downStr := "ERR"
				if sr.DownError == "" {
					downStr = fmt.Sprintf("%.1f KB/s (%.1fM)", sr.DownKBps, sr.DownMbps)
				}
				upStr := "ERR"
				if sr.UpError == "" {
					upStr = fmt.Sprintf("%.1f KB/s (%.1fM)", sr.UpKBps, sr.UpMbps)
				}

				mu.Lock()
				fmt.Printf("%-26s %-15s %4dms %-16s %-16s\n",
					truncateStr(host, 26), truncateStr(ip, 15), sr.TCPMS, downStr, upStr)
				results = append(results, sr)
				mu.Unlock()
			}
		}()
	}

	for _, t := range targets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		return results[i].DownKBps > results[j].DownKBps
	})

	if *outFile != "" {
		if f, err := os.Create(*outFile); err == nil {
			for _, r := range results {
				_, _ = fmt.Fprintf(f, "%s | IP:%s | TCP:%dms | Down:%.1fKB/s (%.2fMbps) | Up:%.1fKB/s (%.2fMbps)\n",
					r.Target, r.IP, r.TCPMS, r.DownKBps, r.DownMbps, r.UpKBps, r.UpMbps)
			}
			_ = f.Close()
			fmt.Printf("\n[✓] Saved sorted speed results to %s\n", *outFile)
		}
	}
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-2] + ".."
}
