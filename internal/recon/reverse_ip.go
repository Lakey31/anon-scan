package recon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"anon-scan/internal/scanner"
)

type otxIPPassiveDNS struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

func isFakeOrPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	// Check 198.18.0.0/15 (RFC 2544 / Clash & Sing-box FakeDNS TUN range)
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return true
		}
	}
	return false
}

// ReverseIPLookup finds hostnames associated with a public IP using PTR, HackerTarget,
// and AlienVault OTX Passive DNS fallback when HackerTarget quota is exceeded.
func ReverseIPLookup(ctx context.Context, ipStr string, timeout time.Duration, proxyAddr string) ([]string, error) {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	if isFakeOrPrivateIP(parsed) {
		return nil, fmt.Errorf("%s is a private/FakeDNS TUN IP (turn off VPN TUN mode or enter a public IP/domain)", ipStr)
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

	// 1. Standard PTR lookup
	ptrCtx, ptrCancel := context.WithTimeout(ctx, 3*time.Second)
	if ptrs, err := net.DefaultResolver.LookupAddr(ptrCtx, ipStr); err == nil {
		for _, p := range ptrs {
			addHost(p)
		}
	}
	ptrCancel()

	client := scanner.NewHTTPClientWithProxy(timeout, proxyAddr)

	// 2. HackerTarget Reverse IP API
	htQuotaExceeded := false
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	endpoint := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", url.QueryEscape(ipStr))
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err == nil {
		req.Header.Set("User-Agent", "anon-scan/9.6")
		if resp, err := client.Do(req); err == nil {
			if resp.StatusCode == http.StatusOK {
				sc := bufio.NewScanner(resp.Body)
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if line == "" {
						continue
					}
					if strings.Contains(line, "API count exceeded") {
						htQuotaExceeded = true
						break
					}
					if strings.HasPrefix(line, "error") || strings.Contains(line, "No DNS A records") {
						break
					}
					addHost(line)
				}
			}
			_ = resp.Body.Close()
		}
	}
	cancel()

	// 3. Fallback to AlienVault OTX IPv4 Passive DNS if HackerTarget quota exceeded or returned nothing
	if htQuotaExceeded || len(hosts) == 0 {
		otxCtx, otxCancel := context.WithTimeout(ctx, timeout)
		otxURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/passive_dns", url.PathEscape(ipStr))
		if otxReq, err := http.NewRequestWithContext(otxCtx, http.MethodGet, otxURL, nil); err == nil {
			otxReq.Header.Set("User-Agent", "anon-scan/9.6")
			if otxResp, err := client.Do(otxReq); err == nil {
				if otxResp.StatusCode == http.StatusOK {
					var data otxIPPassiveDNS
					if json.NewDecoder(otxResp.Body).Decode(&data) == nil {
						for _, rec := range data.PassiveDNS {
							addHost(rec.Hostname)
						}
					}
				}
				_ = otxResp.Body.Close()
			}
		}
		otxCancel()
	}

	if len(hosts) == 0 && htQuotaExceeded {
		return nil, fmt.Errorf("HackerTarget daily quota exceeded and OTX returned 0 records for %s", ipStr)
	}

	sort.Strings(hosts)
	return hosts, nil
}
