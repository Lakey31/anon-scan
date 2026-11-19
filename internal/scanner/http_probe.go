package scanner

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"anon-scan/internal/models"
)

func ProbeHTTP(ctx context.Context, ip string, port int, hostHeader string, sni string, method string, measureSpeed bool, timeout time.Duration, skipVerify bool, proxyAddr string) models.HTTPInfo {
	if method == "" {
		method = http.MethodGet
	}
	method = strings.ToUpper(strings.TrimSpace(method))

	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	info := models.HTTPInfo{
		Probed: true,
		Method: method,
		Port:   port,
		Scheme: scheme,
	}

	dialTarget := net.JoinHostPort(ip, strconv.Itoa(port))

	transport := &http.Transport{
		DialContext: func(dCtx context.Context, network, addr string) (net.Conn, error) {
			return DialContextWithProxy(dCtx, dialTarget, proxyAddr, timeout)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: skipVerify,
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	targetURL := fmt.Sprintf("%s://%s/", scheme, hostHeader)
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	req.Host = hostHeader
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126.0.0.0 Mobile Safari/537.36")
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	resp, err := client.Do(req)
	info.ResponseMS = time.Since(start).Milliseconds()
	if err != nil {
		info.Error = err.Error()
		return info
	}
	defer resp.Body.Close()

	if measureSpeed && method == http.MethodGet {
		dlStart := time.Now()
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 128*1024))
		dlSec := time.Since(dlStart).Seconds()
		if n > 0 && dlSec > 0 {
			info.SpeedKBps = math.Round(((float64(n)/1024.0)/dlSec)*10) / 10
		}
	}

	info.StatusCode = resp.StatusCode
	info.Server = resp.Header.Get("Server")
	if loc := resp.Header.Get("Location"); loc != "" {
		info.RedirectChain = []string{fmt.Sprintf("%d -> %s", resp.StatusCode, loc)}
	}
	info.DetectedCDN, info.DetectedWAF = detectHeaderSignatures(resp.Header)
	info.SecurityHeaders = AuditSecurityHeaders(resp.Header)
	info.HTTP3Quic, info.AltSvc = detectHTTP3AltSvc(resp.Header)

	return info
}

func detectHTTP3AltSvc(h http.Header) (bool, string) {
	values := h.Values("Alt-Svc")
	if len(values) == 0 {
		return false, ""
	}
	joined := strings.Join(values, ", ")
	lower := strings.ToLower(joined)
	if strings.Contains(lower, "h3=") || strings.Contains(lower, "h3-") || strings.Contains(lower, "quic=") {
		return true, joined
	}
	return false, joined
}

func ProbeWebSocket(ctx context.Context, ip string, port int, hostHeader string, sni string, wsPath string, timeout time.Duration, skipVerify bool, proxyAddr string) (bool, int, string) {
	if wsPath == "" {
		wsPath = "/"
	}
	if !strings.HasPrefix(wsPath, "/") {
		wsPath = "/" + wsPath
	}

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return false, 0, err.Error()
	}
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	address := net.JoinHostPort(ip, strconv.Itoa(port))

	var conn net.Conn
	if port == 443 || port == 8443 {
		rawConn, dialErr := DialContextWithProxy(ctx, address, proxyAddr, timeout)
		if dialErr != nil {
			return false, 0, dialErr.Error()
		}
		_ = rawConn.SetDeadline(time.Now().Add(timeout))
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: skipVerify,
			NextProtos:         []string{"http/1.1"},
		})
		if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
			_ = rawConn.Close()
			return false, 0, hsErr.Error()
		}
		conn = tlsConn
	} else {
		rawConn, dialErr := DialContextWithProxy(ctx, address, proxyAddr, timeout)
		if dialErr != nil {
			return false, 0, dialErr.Error()
		}
		_ = rawConn.SetDeadline(time.Now().Add(timeout))
		conn = rawConn
	}
	defer conn.Close()

	reqStr := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"User-Agent: Mozilla/5.0\r\n\r\n",
		wsPath, hostHeader, wsKey,
	)

	if _, err := conn.Write([]byte(reqStr)); err != nil {
		return false, 0, err.Error()
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return false, 0, err.Error()
	}

	parts := strings.Fields(strings.TrimSpace(statusLine))
	if len(parts) < 2 {
		return false, 0, "invalid HTTP response"
	}

	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return false, 0, "failed to parse status code"
	}

	return code == http.StatusSwitchingProtocols, code, ""
}

func detectHeaderSignatures(h http.Header) (cdn string, waf string) {
	server := strings.ToLower(h.Get("Server"))
	via := strings.ToLower(h.Get("Via"))
	xCache := strings.ToLower(h.Get("X-Cache"))

	switch {
	case h.Get("CF-Ray") != "" || strings.Contains(server, "cloudflare"):
		cdn = "Cloudflare"
	case h.Get("X-Amz-Cf-Id") != "" || strings.Contains(via, "cloudfront") || strings.Contains(server, "cloudfront"):
		cdn = "AWS CloudFront"
	case h.Get("Fastly-Debug-Digest") != "" || strings.Contains(via, "varnish"):
		cdn = "Fastly"
	case h.Get("Akamai-GRN") != "" || strings.Contains(server, "akamaighost"):
		cdn = "Akamai"
	case strings.Contains(server, "bunnycdn"):
		cdn = "BunnyCDN"
	case strings.Contains(xCache, "hit") || strings.Contains(xCache, "miss"):
		cdn = "Cached / Edge Proxy"
	}

	switch {
	case h.Get("CF-RAY") != "" && h.Get("CF-Mitigated") != "":
		waf = "Cloudflare WAF"
	case h.Get("X-Sucuri-ID") != "" || strings.Contains(server, "sucuri"):
		waf = "Sucuri WAF"
	case h.Get("X-Iinfo") != "" || strings.Contains(server, "imperva") || h.Get("X-CDN") == "Imperva":
		waf = "Imperva / Incapsula"
	case strings.Contains(server, "awselb") || h.Get("X-Amzn-Waf-Action") != "":
		waf = "AWS WAF"
	case h.Get("X-Akamai-Transformed") != "":
		waf = "Akamai Kona WAF"
	case strings.Contains(server, "cloudflare"):
		waf = "Cloudflare (Proxy/WAF)"
	}

	return cdn, waf
}
