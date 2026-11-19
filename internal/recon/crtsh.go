package recon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"anon-scan/internal/scanner"
)

type crtshEntry struct {
	NameValue string `json:"name_value"`
}

type otxResponse struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

func FetchSubdomains(ctx context.Context, domain string, timeout time.Duration, proxyAddr string) ([]string, error) {
	if timeout < 15*time.Second {
		timeout = 15 * time.Second
	}

	cleanDomain := strings.ToLower(strings.TrimSpace(domain))
	suffix := "." + cleanDomain

	var mu sync.Mutex
	seen := make(map[string]bool)
	addHost := func(raw string) {
		h := strings.ToLower(strings.TrimSpace(raw))
		h = strings.TrimPrefix(h, "*.")
		if h == "" || strings.Contains(h, "*") || strings.Contains(h, " ") {
			return
		}
		if h == cleanDomain || strings.HasSuffix(h, suffix) {
			mu.Lock()
			seen[h] = true
			mu.Unlock()
		}
	}

	client := scanner.NewHTTPClientWithProxy(timeout, proxyAddr)

	var wg sync.WaitGroup
	var errs []string
	var errMu sync.Mutex
	recordErr := func(src string, err error) {
		if err != nil {
			errMu.Lock()
			errs = append(errs, fmt.Sprintf("%s: %v", src, err))
			errMu.Unlock()
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := fetchFromCrtsh(ctx, client, cleanDomain, timeout, addHost); err != nil {
			recordErr("crt.sh", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := fetchFromHackerTarget(ctx, client, cleanDomain, timeout, addHost); err != nil {
			recordErr("HackerTarget", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := fetchFromOTX(ctx, client, cleanDomain, timeout, addHost); err != nil {
			recordErr("OTX", err)
		}
	}()

	wg.Wait()

	subs := make([]string, 0, len(seen))
	for h := range seen {
		subs = append(subs, h)
	}
	sort.Strings(subs)

	if len(subs) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("all subdomain sources failed (%s)", strings.Join(errs, "; "))
	}
	return subs, nil
}

func fetchFromCrtsh(ctx context.Context, client *http.Client, domain string, timeout time.Duration, add func(string)) error {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape("%."+domain))
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "anon-scan/9.5")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var entries []crtshEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return err
	}
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			add(line)
		}
	}
	return nil
}

func fetchFromHackerTarget(ctx context.Context, client *http.Client, domain string, timeout time.Duration, add func(string)) error {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "anon-scan/9.5")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "error") || strings.Contains(line, "API count exceeded") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) >= 1 {
			add(parts[0])
		}
	}
	return nil
}

func fetchFromOTX(ctx context.Context, client *http.Client, domain string, timeout time.Duration, add func(string)) error {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", url.PathEscape(domain))
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "anon-scan/9.5")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var data otxResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}
	for _, rec := range data.PassiveDNS {
		add(rec.Hostname)
	}
	return nil
}
