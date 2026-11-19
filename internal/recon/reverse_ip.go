package recon

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"anon-scan/internal/scanner"
)

func ReverseIPLookup(ctx context.Context, ip string, timeout time.Duration, proxyAddr string) ([]string, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}
	if timeout < 8*time.Second {
		timeout = 8 * time.Second
	}

	seen := make(map[string]bool)
	var hosts []string
	addHost := func(h string) {
		h = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(h, ".")))
		if h == "" || strings.Contains(h, " ") || net.ParseIP(h) != nil {
			return
		}
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}

	ptrCtx, ptrCancel := context.WithTimeout(ctx, 3*time.Second)
	if ptrs, err := net.DefaultResolver.LookupAddr(ptrCtx, ip); err == nil {
		for _, p := range ptrs {
			addHost(p)
		}
	}
	ptrCancel()

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", url.QueryEscape(ip))
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return hosts, err
	}
	req.Header.Set("User-Agent", "anon-scan/9.5")

	client := scanner.NewHTTPClientWithProxy(timeout, proxyAddr)
	resp, err := client.Do(req)
	if err != nil {
		return hosts, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return hosts, fmt.Errorf("HackerTarget HTTP %d", resp.StatusCode)
	}

	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "error") || strings.Contains(line, "API count exceeded") || strings.Contains(line, "No DNS A records") {
			if len(hosts) == 0 {
				return nil, fmt.Errorf("%s", line)
			}
			break
		}
		addHost(line)
	}

	sort.Strings(hosts)
	return hosts, nil
}
