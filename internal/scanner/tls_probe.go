package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"strconv"
	"time"

	"anon-scan/internal/models"
)

func ProbePort(ctx context.Context, ip string, port int, timeout time.Duration, proxyAddr string) models.PortStatus {
	status := models.PortStatus{
		Port: port,
		Open: false,
	}

	address := net.JoinHostPort(ip, strconv.Itoa(port))
	start := time.Now()
	conn, err := DialContextWithProxy(ctx, address, proxyAddr, timeout)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		status.Error = err.Error()
		return status
	}
	_ = conn.Close()

	status.Open = true
	status.LatencyMS = elapsed
	return status
}

func ProbeTLS(ctx context.Context, ip string, port int, sni string, alpn []string, timeout time.Duration, skipVerify bool, proxyAddr string) models.TLSInfo {
	info := models.TLSInfo{
		Supported: false,
		SNIUsed:   sni,
	}

	if len(alpn) == 0 {
		alpn = []string{"h2", "http/1.1"}
	}

	address := net.JoinHostPort(ip, strconv.Itoa(port))
	tlsCfg := &tls.Config{
		ServerName:         sni,
		NextProtos:         alpn,
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	start := time.Now()
	rawConn, err := DialContextWithProxy(ctx, address, proxyAddr, timeout)
	if err != nil {
		info.Error = fmt.Sprintf("tcp connect failed: %v", err)
		return info
	}
	defer rawConn.Close()

	_ = rawConn.SetDeadline(time.Now().Add(timeout))
	tlsConn := tls.Client(rawConn, tlsCfg)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		info.Error = fmt.Sprintf("tls handshake failed: %v", err)
		return info
	}
	info.HandshakeMS = time.Since(start).Milliseconds()
	info.Supported = true

	state := tlsConn.ConnectionState()
	info.Version = tlsVersionName(state.Version)
	info.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	info.NegotiatedALPN = state.NegotiatedProtocol

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.Issuer = cert.Issuer.CommonName
		if info.Issuer == "" && len(cert.Issuer.Organization) > 0 {
			info.Issuer = cert.Issuer.Organization[0]
		}
		info.SubjectCN = cert.Subject.CommonName
		info.DNSNames = cert.DNSNames
		info.NotBefore = cert.NotBefore.UTC().Format("2006-01-02")
		info.NotAfter = cert.NotAfter.UTC().Format("2006-01-02")

		days := math.Floor(time.Until(cert.NotAfter).Hours() / 24)
		info.DaysRemaining = int(days)
	}

	return info
}

// AuditTLSVersions probes which TLS protocol versions (1.0, 1.1, 1.2, 1.3) the server accepts.
func AuditTLSVersions(ctx context.Context, ip string, port int, sni string, timeout time.Duration, skipVerify bool, proxyAddr string) []string {
	versions := []struct {
		code uint16
		name string
	}{
		{tls.VersionTLS10, "TLS 1.0 (Weak)"},
		{tls.VersionTLS11, "TLS 1.1 (Weak)"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}

	address := net.JoinHostPort(ip, strconv.Itoa(port))
	var accepted []string

	for _, v := range versions {
		rawConn, err := DialContextWithProxy(ctx, address, proxyAddr, timeout)
		if err != nil {
			continue
		}
		_ = rawConn.SetDeadline(time.Now().Add(timeout))
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: skipVerify,
			MinVersion:         v.code,
			MaxVersion:         v.code,
		})
		if err := tlsConn.HandshakeContext(ctx); err == nil {
			accepted = append(accepted, v.name)
		}
		_ = rawConn.Close()
	}

	return accepted
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "Unknown"
	}
}
