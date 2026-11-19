package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"anon-scan/internal/models"
	"anon-scan/internal/scanner"
)

type ipAPIResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Country string `json:"country"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	AS      string `json:"as"`
}

type ripeStatResponse struct {
	Status string `json:"status"`
	Data   struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

func LookupASN(ctx context.Context, ip string, timeout time.Duration, proxyAddr string) models.ASNInfo {
	var info models.ASNInfo

	if parsed := net.ParseIP(ip); parsed == nil {
		info.Error = "invalid IP address"
		return info
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,city,isp,org,as", ip)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	req.Header.Set("User-Agent", "anon-scan/9.5")

	client := scanner.NewHTTPClientWithProxy(timeout, proxyAddr)
	resp, err := client.Do(req)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	defer resp.Body.Close()

	var data ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		info.Error = err.Error()
		return info
	}

	if data.Status != "success" {
		info.Error = data.Message
		return info
	}

	asParts := strings.SplitN(data.AS, " ", 2)
	if len(asParts) > 0 {
		info.ASN = asParts[0]
	}
	info.Org = data.Org
	info.ISP = data.ISP
	info.Country = data.Country
	info.City = data.City

	return info
}

func FetchASNCIDRs(ctx context.Context, asn string, timeout time.Duration, proxyAddr string) ([]string, []string, error) {
	cleanASN := strings.ToUpper(strings.TrimSpace(asn))
	if cleanASN == "" {
		return nil, nil, fmt.Errorf("empty ASN")
	}
	if !strings.HasPrefix(cleanASN, "AS") {
		cleanASN = "AS" + cleanASN
	}
	if timeout < 15*time.Second {
		timeout = 15 * time.Second
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=%s", url.QueryEscape(cleanASN))
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "anon-scan/9.5 (Termux RIPEstat)")
	req.Header.Set("Accept", "application/json")

	client := scanner.NewHTTPClientWithProxy(timeout, proxyAddr)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("RIPEstat request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("RIPEstat returned HTTP %d", resp.StatusCode)
	}

	var parsed ripeStatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, nil, fmt.Errorf("failed to parse RIPEstat JSON: %w", err)
	}

	seenV4 := make(map[string]bool)
	seenV6 := make(map[string]bool)
	var v4List, v6List []string

	for _, item := range parsed.Data.Prefixes {
		pfx := strings.TrimSpace(item.Prefix)
		if pfx == "" {
			continue
		}
		if strings.Contains(pfx, ":") {
			if !seenV6[pfx] {
				seenV6[pfx] = true
				v6List = append(v6List, pfx)
			}
		} else {
			if !seenV4[pfx] {
				seenV4[pfx] = true
				v4List = append(v4List, pfx)
			}
		}
	}

	sort.Strings(v4List)
	sort.Strings(v6List)
	return v4List, v6List, nil
}
