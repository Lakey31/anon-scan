package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"anon-scan/internal/models"
	"anon-scan/internal/scanner"
)

type rdapResponse struct {
	LDHName string `json:"ldhName"`
	Events  []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles      []string `json:"roles"`
		VCardArray []any    `json:"vcardArray"`
	} `json:"entities"`
}

func LookupRDAP(ctx context.Context, host string, timeout time.Duration, proxyAddr string) models.RDAPInfo {
	var info models.RDAPInfo

	if net.ParseIP(host) != nil {
		info.Error = "RDAP domain lookup skipped for raw IP"
		return info
	}

	rootDomain := extractRootDomain(host)
	info.Domain = rootDomain

	if timeout < 8*time.Second {
		timeout = 8 * time.Second
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := fmt.Sprintf("https://rdap.org/domain/%s", rootDomain)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	req.Header.Set("User-Agent", "anon-scan/9.5")
	req.Header.Set("Accept", "application/rdap+json, application/json")

	client := scanner.NewHTTPClientWithProxy(timeout, proxyAddr)
	resp, err := client.Do(req)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("RDAP HTTP %d", resp.StatusCode)
		return info
	}

	var data rdapResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		info.Error = err.Error()
		return info
	}

	for _, ev := range data.Events {
		switch strings.ToLower(ev.EventAction) {
		case "registration":
			if t, err := time.Parse(time.RFC3339, ev.EventDate); err == nil {
				info.Created = t.UTC().Format("2006-01-02")
			}
		case "expiration":
			if t, err := time.Parse(time.RFC3339, ev.EventDate); err == nil {
				info.Expires = t.UTC().Format("2006-01-02")
				info.DaysRemaining = int(math.Floor(time.Until(t).Hours() / 24))
			}
		}
	}

	for _, ent := range data.Entities {
		isRegistrar := false
		for _, r := range ent.Roles {
			if strings.EqualFold(r, "registrar") {
				isRegistrar = true
				break
			}
		}
		if isRegistrar {
			info.Registrar = parseVCardFN(ent.VCardArray)
			if info.Registrar != "" {
				break
			}
		}
	}

	return info
}

func extractRootDomain(host string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(host)), ".")
	if len(parts) <= 2 {
		return host
	}
	last := parts[len(parts)-1]
	secondLast := parts[len(parts)-2]
	if len(last) == 2 && (secondLast == "co" || secondLast == "com" || secondLast == "org" || secondLast == "net" || secondLast == "ac" || secondLast == "gov") {
		if len(parts) >= 3 {
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func parseVCardFN(vcard []any) string {
	if len(vcard) < 2 {
		return ""
	}
	props, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		arr, ok := p.([]any)
		if !ok || len(arr) < 4 {
			continue
		}
		if name, ok := arr[0].(string); ok && strings.EqualFold(name, "fn") {
			if val, ok := arr[3].(string); ok {
				return strings.TrimSpace(val)
			}
		}
	}
	return ""
}
