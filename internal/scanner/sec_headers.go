package scanner

import (
	"net/http"

	"anon-scan/internal/models"
)

var trackedSecurityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
}

func AuditSecurityHeaders(h http.Header) models.SecurityHeadersInfo {
	var info models.SecurityHeadersInfo
	info.Total = len(trackedSecurityHeaders)

	for _, name := range trackedSecurityHeaders {
		if h.Get(name) != "" {
			info.Present = append(info.Present, name)
		} else {
			info.Missing = append(info.Missing, name)
		}
	}
	info.Score = len(info.Present)
	return info
}
