package resolver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"anon-scan/internal/models"
	"anon-scan/internal/scanner"
)

type CustomResolver struct {
	Server     string
	ProxyAddr  string
	Timeout    time.Duration
	netRes     *net.Resolver
	httpClient *http.Client
}

type dohJSONResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func New(server string, timeout time.Duration, proxyAddr string) *CustomResolver {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	server = strings.TrimSpace(server)
	if server == "" {
		server = "1.1.1.1:53"
	}

	var netRes *net.Resolver
	if strings.EqualFold(server, "system") || strings.EqualFold(server, "isp") {
		ispDNS := detectAndroidSystemDNS()
		if ispDNS != "" {
			server = "ISP (" + ispDNS + ")"
			dialer := &net.Dialer{Timeout: timeout}
			netRes = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					return dialer.DialContext(ctx, "udp", ispDNS)
				},
			}
		} else {
			server = "system"
			netRes = &net.Resolver{PreferGo: false}
		}
	} else {
		if !strings.Contains(server, ":") {
			server = server + ":53"
		}
		dialer := &net.Dialer{Timeout: timeout}
		netRes = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				if proxyAddr != "" {
					return scanner.DialContextWithProxy(ctx, server, proxyAddr, timeout)
				}
				return dialer.DialContext(ctx, "udp", server)
			},
		}
	}

	return &CustomResolver{
		Server:     server,
		ProxyAddr:  proxyAddr,
		Timeout:    timeout,
		netRes:     netRes,
		httpClient: scanner.NewHTTPClientWithProxy(timeout, proxyAddr),
	}
}

func detectAndroidSystemDNS() string {
	// 1. Check Android getprop
	for _, p := range []string{"net.dns1", "net.dns2"} {
		out, err := exec.Command("getprop", p).Output()
		if err == nil {
			val := strings.TrimSpace(string(out))
			if ip := net.ParseIP(val); ip != nil && ip.To4() != nil {
				return val + ":53"
			}
		}
	}
	// 2. Check Termux resolv.conf
	if f, err := os.Open("/data/data/com.termux/files/usr/etc/resolv.conf"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "nameserver ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if ip := net.ParseIP(fields[1]); ip != nil && ip.To4() != nil {
						return fields[1] + ":53"
					}
				}
			}
		}
	}
	return ""
}

// lookupAndroidNetd uses Termux's native bionic/netd resolver (identical to Python/BugScanX)
// via `getent ahosts` or `python3` socket fallback, working even on zero-balance social packages.
func lookupAndroidNetd(ctx context.Context, host string, timeout time.Duration) ([]string, []string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if bin, err := exec.LookPath("getent"); err == nil {
		out, err := exec.CommandContext(cmdCtx, bin, "ahosts", host).Output()
		if err == nil && len(out) > 0 {
			return parseIPsFromOutput(string(out))
		}
	}

	if bin, err := exec.LookPath("python3"); err == nil {
		pyCode := fmt.Sprintf("import socket; print('\\n'.join(set(x[4][0] for x in socket.getaddrinfo(%q, None))))", host)
		out, err := exec.CommandContext(cmdCtx, bin, "-c", pyCode).Output()
		if err == nil && len(out) > 0 {
			return parseIPsFromOutput(string(out))
		}
	}

	return nil, nil, fmt.Errorf("android netd resolver unavailable")
}

func parseIPsFromOutput(text string) ([]string, []string, error) {
	seenV4 := make(map[string]bool)
	seenV6 := make(map[string]bool)
	var v4, v6 []string

	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			s := ip4.String()
			if !seenV4[s] {
				seenV4[s] = true
				v4 = append(v4, s)
			}
		} else {
			s := ip.String()
			if !seenV6[s] {
				seenV6[s] = true
				v6 = append(v6, s)
			}
		}
	}

	if len(v4) == 0 && len(v6) == 0 {
		return nil, nil, fmt.Errorf("no IPs resolved")
	}
	return v4, v6, nil
}

func (r *CustomResolver) Lookup(ctx context.Context, host string, fullRecords bool) models.DNSInfo {
	start := time.Now()
	info := models.DNSInfo{
		Resolver: r.Server,
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			info.IPv4 = []string{ip.String()}
		} else {
			info.IPv6 = []string{ip.String()}
		}
		info.ResolveMS = 0
		return info
	}

	// In system/ISP mode (used by -pkg-mode), try Android native netd FIRST (just like BugScanX)
	if r.Server == "system" || strings.HasPrefix(r.Server, "ISP") {
		if v4, v6, err := lookupAndroidNetd(ctx, host, r.Timeout); err == nil {
			info.IPv4 = v4
			info.IPv6 = v6
			info.Resolver = "Android ISP DNS (netd)"
			info.ResolveMS = time.Since(start).Milliseconds()
			return info
		}
	}

	lookupCtx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	if cname, err := r.netRes.LookupCNAME(lookupCtx, host); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if !strings.EqualFold(cname, host) {
			info.CNAME = cname
		}
	}

	ips, err := r.netRes.LookupIPAddr(lookupCtx, host)
	info.ResolveMS = time.Since(start).Milliseconds()

	// Fallback to Android native netd if custom UDP DNS (1.1.1.1:53) is blocked by ISP
	if err != nil {
		if v4, v6, netdErr := lookupAndroidNetd(ctx, host, r.Timeout); netdErr == nil {
			info.IPv4 = v4
			info.IPv6 = v6
			info.Resolver = "Android ISP DNS (netd)"
			info.ResolveMS = time.Since(start).Milliseconds()
			return info
		}
		info.Error = err.Error()
		return info
	}

	seenV4 := make(map[string]bool)
	seenV6 := make(map[string]bool)

	for _, ipAddr := range ips {
		ip := ipAddr.IP
		if v4 := ip.To4(); v4 != nil {
			s := v4.String()
			if !seenV4[s] {
				seenV4[s] = true
				info.IPv4 = append(info.IPv4, s)
			}
		} else if len(ip) == net.IPv6len {
			s := ip.String()
			if !seenV6[s] {
				seenV6[s] = true
				info.IPv6 = append(info.IPv6, s)
			}
		}
	}

	if fullRecords {
		r.populateExtraUDP(ctx, host, &info)
	}

	return info
}

func (r *CustomResolver) populateExtraUDP(ctx context.Context, host string, info *models.DNSInfo) {
	nsCtx, nsCancel := context.WithTimeout(ctx, r.Timeout)
	if nsList, err := r.netRes.LookupNS(nsCtx, host); err == nil {
		for _, ns := range nsList {
			h := strings.TrimSuffix(ns.Host, ".")
			if h != "" {
				info.NS = append(info.NS, h)
			}
		}
	}
	nsCancel()

	mxCtx, mxCancel := context.WithTimeout(ctx, r.Timeout)
	if mxList, err := r.netRes.LookupMX(mxCtx, host); err == nil {
		for _, mx := range mxList {
			h := strings.TrimSuffix(mx.Host, ".")
			if h != "" {
				info.MX = append(info.MX, fmt.Sprintf("%s (pref %d)", h, mx.Pref))
			}
		}
	}
	mxCancel()

	txtCtx, txtCancel := context.WithTimeout(ctx, r.Timeout)
	if txtList, err := r.netRes.LookupTXT(txtCtx, host); err == nil {
		for _, t := range txtList {
			t = strings.TrimSpace(t)
			if t != "" {
				info.TXT = append(info.TXT, t)
			}
		}
	}
	txtCancel()
}

func (r *CustomResolver) LookupDoH(ctx context.Context, host string, fullRecords bool) models.DNSInfo {
	start := time.Now()
	info := models.DNSInfo{
		Resolver: "DoH (cloudflare-dns.com)",
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			info.IPv4 = []string{ip.String()}
		} else {
			info.IPv6 = []string{ip.String()}
		}
		info.ResolveMS = 0
		return info
	}

	seenV4 := make(map[string]bool)
	seenV6 := make(map[string]bool)

	aAnswers, err := r.queryDoH(ctx, host, "A")
	if err != nil {
		info.ResolveMS = time.Since(start).Milliseconds()
		info.Error = err.Error()
		return info
	}
	for _, ans := range aAnswers {
		switch ans.Type {
		case 5:
			if info.CNAME == "" {
				info.CNAME = strings.TrimSuffix(ans.Data, ".")
			}
		case 1:
			if ip := net.ParseIP(ans.Data); ip != nil && ip.To4() != nil {
				s := ip.String()
				if !seenV4[s] {
					seenV4[s] = true
					info.IPv4 = append(info.IPv4, s)
				}
			}
		}
	}

	if aaaaAnswers, err := r.queryDoH(ctx, host, "AAAA"); err == nil {
		for _, ans := range aaaaAnswers {
			if ans.Type == 28 {
				if ip := net.ParseIP(ans.Data); ip != nil && ip.To4() == nil {
					s := ip.String()
					if !seenV6[s] {
						seenV6[s] = true
						info.IPv6 = append(info.IPv6, s)
					}
				}
			}
		}
	}

	info.ResolveMS = time.Since(start).Milliseconds()

	if fullRecords {
		r.populateExtraDoH(ctx, host, &info)
	}

	return info
}

func (r *CustomResolver) populateExtraDoH(ctx context.Context, host string, info *models.DNSInfo) {
	if nsAnswers, err := r.queryDoH(ctx, host, "NS"); err == nil {
		for _, ans := range nsAnswers {
			if ans.Type == 2 {
				info.NS = append(info.NS, strings.TrimSuffix(ans.Data, "."))
			}
		}
	}
	if mxAnswers, err := r.queryDoH(ctx, host, "MX"); err == nil {
		for _, ans := range mxAnswers {
			if ans.Type == 15 {
				info.MX = append(info.MX, strings.TrimSuffix(ans.Data, "."))
			}
		}
	}
	if txtAnswers, err := r.queryDoH(ctx, host, "TXT"); err == nil {
		for _, ans := range txtAnswers {
			if ans.Type == 16 {
				clean := strings.Trim(ans.Data, "\"")
				if clean != "" {
					info.TXT = append(info.TXT, clean)
				}
			}
		}
	}
}

func (r *CustomResolver) queryDoH(ctx context.Context, host, qtype string) ([]struct {
	Type int    `json:"type"`
	Data string `json:"data"`
}, error) {
	endpoints := []string{
		fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=%s", url.QueryEscape(host), qtype),
		fmt.Sprintf("https://dns.google/resolve?name=%s&type=%s", url.QueryEscape(host), qtype),
	}

	var lastErr error
	for _, ep := range endpoints {
		reqCtx, cancel := context.WithTimeout(ctx, r.Timeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, ep, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		req.Header.Set("User-Agent", "anon-scan/8.6")

		resp, err := r.httpClient.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}

		var data dohJSONResponse
		decErr := json.NewDecoder(resp.Body).Decode(&data)
		_ = resp.Body.Close()
		cancel()

		if decErr != nil {
			lastErr = decErr
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("DoH HTTP %d", resp.StatusCode)
			continue
		}
		return data.Answer, nil
	}
	return nil, lastErr
}

func DetectCDNHint(cname string, ipv4 []string) string {
	lower := strings.ToLower(cname)
	switch {
	case strings.Contains(lower, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(lower, "cloudfront.net"):
		return "AWS CloudFront"
	case strings.Contains(lower, "akamai") || strings.Contains(lower, "edgekey") || strings.Contains(lower, "edgesuite"):
		return "Akamai"
	case strings.Contains(lower, "fastly"):
		return "Fastly"
	case strings.Contains(lower, "imperva") || strings.Contains(lower, "incapdns"):
		return "Imperva"
	case strings.Contains(lower, "bunnycdn") || strings.Contains(lower, "b-cdn.net"):
		return "BunnyCDN"
	case strings.Contains(lower, "azureedge"):
		return "Azure CDN"
	}

	for _, ip := range ipv4 {
		if strings.HasPrefix(ip, "104.16.") || strings.HasPrefix(ip, "104.17.") ||
			strings.HasPrefix(ip, "104.18.") || strings.HasPrefix(ip, "104.19.") ||
			strings.HasPrefix(ip, "104.20.") || strings.HasPrefix(ip, "104.21.") ||
			strings.HasPrefix(ip, "172.64.") || strings.HasPrefix(ip, "172.67.") ||
			strings.HasPrefix(ip, "162.159.") {
			return "Cloudflare"
		}
	}

	return "Direct / Unknown"
}
