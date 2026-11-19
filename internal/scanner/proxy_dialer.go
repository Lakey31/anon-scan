package scanner

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func DialContextWithProxy(ctx context.Context, targetAddr string, proxyRaw string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	proxyRaw = strings.TrimSpace(proxyRaw)
	if proxyRaw == "" {
		return dialer.DialContext(ctx, "tcp", targetAddr)
	}

	scheme := "socks5"
	proxyHostPort := proxyRaw

	if strings.Contains(proxyRaw, "://") {
		u, err := url.Parse(proxyRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyRaw, err)
		}
		scheme = strings.ToLower(u.Scheme)
		proxyHostPort = u.Host
	} else if strings.HasSuffix(proxyRaw, ":8080") || strings.HasSuffix(proxyRaw, ":8888") || strings.HasSuffix(proxyRaw, ":10809") {
		scheme = "http"
	}

	conn, err := dialer.DialContext(ctx, "tcp", proxyHostPort)
	if err != nil {
		return nil, fmt.Errorf("proxy connect (%s) failed: %w", proxyHostPort, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if strings.HasPrefix(scheme, "http") {
		if err := handshakeHTTPConnect(conn, targetAddr); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}

	if err := handshakeSOCKS5(conn, targetAddr); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func NewHTTPClientWithProxy(timeout time.Duration, proxyRaw string) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	proxyRaw = strings.TrimSpace(proxyRaw)
	if proxyRaw == "" {
		return &http.Client{Timeout: timeout}
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return DialContextWithProxy(ctx, addr, proxyRaw, timeout)
		},
		DisableKeepAlives: true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}

func handshakeHTTPConnect(conn net.Conn, targetAddr string) error {
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: anon-scan/8.0\r\nProxy-Connection: Keep-Alive\r\n\r\n", targetAddr, targetAddr)
	if _, err := conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("http proxy write failed: %w", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("http proxy read failed: %w", err)
	}
	if !strings.Contains(statusLine, " 200 ") {
		return fmt.Errorf("http proxy CONNECT rejected: %s", strings.TrimSpace(statusLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	return nil
}

func handshakeSOCKS5(conn net.Conn, targetAddr string) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("invalid target address %q: %w", targetAddr, err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port in %q", targetAddr)
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("socks5 greeting write failed: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 greeting read failed: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("socks5 auth not supported by proxy (resp: %v)", resp)
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("hostname too long for socks5: %s", host)
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portNum))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect write failed: %w", err)
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("socks5 reply read failed: %w", err)
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed with code 0x%02x", hdr[1])
	}

	var skipLen int
	switch hdr[3] {
	case 0x01:
		skipLen = 4 + 2
	case 0x04:
		skipLen = 16 + 2
	case 0x03:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return err
		}
		skipLen = int(lenByte[0]) + 2
	default:
		skipLen = 6
	}
	discard := make([]byte, skipLen)
	_, _ = io.ReadFull(conn, discard)

	return nil
}
