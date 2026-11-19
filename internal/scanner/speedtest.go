package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type SpeedResult struct {
	Target     string  `json:"target"`
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	TCPMS      int64   `json:"tcp_ms"`
	DownBytes  int64   `json:"down_bytes"`
	DownKBps   float64 `json:"down_kbps"`
	DownMbps   float64 `json:"down_mbps"`
	DownStatus int     `json:"down_status"`
	DownError  string  `json:"down_error,omitempty"`
	UpBytes    int64   `json:"up_bytes"`
	UpKBps     float64 `json:"up_kbps"`
	UpMbps     float64 `json:"up_mbps"`
	UpStatus   int     `json:"up_status"`
	UpError    string  `json:"up_error,omitempty"`
}

type countingReader struct {
	r     io.Reader
	total int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.total += int64(n)
	return n, err
}

func RunUpDownSpeedTest(ctx context.Context, ip string, port int, hostHeader string, sni string, downBytesLimit int64, upBytesSize int, timeout time.Duration, skipVerify bool, proxyAddr string) SpeedResult {
	res := SpeedResult{
		Target: hostHeader,
		IP:     ip,
		Port:   port,
	}
	if downBytesLimit <= 0 {
		downBytesLimit = 1024 * 1024
	}
	if upBytesSize <= 0 {
		upBytesSize = 256 * 1024
	}
	if timeout < 10*time.Second {
		timeout = 10 * time.Second
	}

	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	dialTarget := net.JoinHostPort(ip, strconv.Itoa(port))

	tcpStatus := ProbePort(ctx, ip, port, 4*time.Second, proxyAddr)
	if !tcpStatus.Open {
		res.DownError = "TCP connect failed: " + tcpStatus.Error
		res.UpError = res.DownError
		return res
	}
	res.TCPMS = tcpStatus.LatencyMS

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
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	downPath := "/"
	if strings.EqualFold(hostHeader, "speed.cloudflare.com") {
		downPath = fmt.Sprintf("/__down?bytes=%d", downBytesLimit)
	}
	downURL := fmt.Sprintf("%s://%s%s", scheme, hostHeader, downPath)
	downReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downURL, nil)
	if err == nil {
		downReq.Host = hostHeader
		downReq.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126.0.0.0 Mobile Safari/537.36")
		dlStart := time.Now()
		resp, dlErr := client.Do(downReq)
		if dlErr != nil {
			res.DownError = dlErr.Error()
		} else {
			res.DownStatus = resp.StatusCode
			n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, downBytesLimit))
			_ = resp.Body.Close()
			sec := time.Since(dlStart).Seconds()
			res.DownBytes = n
			if n > 0 && sec > 0 {
				res.DownKBps = math.Round(((float64(n)/1024.0)/sec)*10) / 10
				res.DownMbps = math.Round(((float64(n)*8.0/1e6)/sec)*100) / 100
			}
		}
	} else {
		res.DownError = err.Error()
	}

	upPath := "/"
	if strings.EqualFold(hostHeader, "speed.cloudflare.com") {
		upPath = "/__up"
	}
	payload := make([]byte, upBytesSize)
	for i := range payload {
		payload[i] = 'A'
	}
	cr := &countingReader{r: strings.NewReader(string(payload))}

	upURL := fmt.Sprintf("%s://%s%s", scheme, hostHeader, upPath)
	upReq, err := http.NewRequestWithContext(ctx, http.MethodPost, upURL, cr)
	if err == nil {
		upReq.Host = hostHeader
		upReq.ContentLength = int64(upBytesSize)
		upReq.Header.Set("Content-Type", "application/octet-stream")
		upReq.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126.0.0.0 Mobile Safari/537.36")

		upStart := time.Now()
		resp, upErr := client.Do(upReq)
		sec := time.Since(upStart).Seconds()
		res.UpBytes = cr.total
		if upErr != nil {
			res.UpError = upErr.Error()
		} else {
			res.UpStatus = resp.StatusCode
			_ = resp.Body.Close()
		}
		if res.UpBytes > 0 && sec > 0 {
			res.UpKBps = math.Round(((float64(res.UpBytes)/1024.0)/sec)*10) / 10
			res.UpMbps = math.Round(((float64(res.UpBytes)*8.0/1e6)/sec)*100) / 100
		}
	} else {
		res.UpError = err.Error()
	}

	return res
}
