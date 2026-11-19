package recon

import "strings"

var cloudCNAMEProviders = map[string]string{
	"github.io":         "GitHub Pages",
	"herokuapp.com":     "Heroku",
	"s3.amazonaws.com":  "AWS S3",
	"netlify.app":       "Netlify",
	"netlify.com":       "Netlify",
	"azurewebsites.net": "Azure App Service",
	"cloudapp.net":      "Azure Cloud",
	"pantheonsite.io":   "Pantheon",
	"myshopify.com":     "Shopify",
	"readthedocs.io":    "ReadTheDocs",
	"zendesk.com":       "Zendesk",
}

// CheckDanglingCNAME performs a defensive audit to detect if a CNAME points
// to an external cloud/SaaS provider without resolving to an active IP.
func CheckDanglingCNAME(cname string, ipv4 []string, dnsErr string) string {
	if cname == "" || len(ipv4) > 0 {
		return ""
	}
	lower := strings.ToLower(cname)
	for suffix, provider := range cloudCNAMEProviders {
		if strings.HasSuffix(lower, suffix) || strings.Contains(lower, "."+suffix) {
			return "Potential Dangling CNAME -> " + provider + " (" + cname + ")"
		}
	}
	if strings.Contains(strings.ToLower(dnsErr), "no such host") {
		return "Unresolved CNAME -> " + cname
	}
	return ""
}
