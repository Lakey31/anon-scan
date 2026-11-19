package recon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// IsFakeOrPrivateIP reports whether ipStr is a private, loopback, link-local or
// VPN FakeDNS (198.18.0.0/15) address that public lookups cannot answer for.
func IsFakeOrPrivateIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	return ip != nil && isFakeOrPrivateIP(ip)
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
	answered := false // true once any API gave a definitive reply (even "0 records")
	var lastErr error
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	endpoint := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", url.QueryEscape(ipStr))
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err == nil {
		req.Header.Set("User-Agent", "anon-scan/9.6")
		if resp, err := client.Do(req); err != nil {
			lastErr = fmt.Errorf("HackerTarget request failed: %w", err)
		} else {
			if resp.StatusCode == http.StatusOK {
				answered = true
				sc := bufio.NewScanner(io.LimitReader(resp.Body, 5<<20))
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if line == "" {
						continue
					}
					if strings.Contains(line, "API count exceeded") {
						htQuotaExceeded = true
						answered = false
						break
					}
					if strings.HasPrefix(line, "error") || strings.Contains(line, "No DNS A records") {
						break
					}
					addHost(line)
				}
			} else {
				lastErr = fmt.Errorf("HackerTarget returned HTTP %d", resp.StatusCode)
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
			if otxResp, err := client.Do(otxReq); err != nil {
				lastErr = fmt.Errorf("OTX request failed: %w", err)
			} else {
				if otxResp.StatusCode == http.StatusOK {
					var data otxIPPassiveDNS
					// Cap the body so an unexpectedly large reply can't exhaust memory.
					if err := json.NewDecoder(io.LimitReader(otxResp.Body, 5<<20)).Decode(&data); err != nil {
						lastErr = fmt.Errorf("OTX returned invalid JSON: %w", err)
					} else {
						answered = true
						for _, rec := range data.PassiveDNS {
							addHost(rec.Hostname)
						}
					}
				} else {
					lastErr = fmt.Errorf("OTX returned HTTP %d", otxResp.StatusCode)
				}
				_ = otxResp.Body.Close()
			}
		}
		otxCancel()
	}

	if len(hosts) == 0 && htQuotaExceeded {
		return nil, fmt.Errorf("HackerTarget daily quota exceeded and OTX returned 0 records for %s", ipStr)
	}

	// Nothing found and no API gave a definitive answer: report the failure
	// instead of silently returning an empty list.
	if len(hosts) == 0 && !answered && lastErr != nil {
		return nil, fmt.Errorf("reverse IP lookup failed for %s: %w", ipStr, lastErr)
	}

	sort.Strings(hosts)
	return hosts, nil
}
