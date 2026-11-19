package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// flakyServer drops the first `failures` connections without replying
// (a transient transport error for the client), then answers 200 OK.
func flakyServer(t *testing.T, failures int32) (port int, hits *atomic.Int32, closeFn func()) {
	t.Helper()
	hits = &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= failures {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("hijacking unsupported")
				return
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	_, p, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ = strconv.Atoi(p)
	return port, hits, srv.Close
}

func TestProbeHTTPWithRetryRecovers(t *testing.T) {
	port, hits, closeFn := flakyServer(t, 2)
	defer closeFn()

	info := ProbeHTTPWithRetry(context.Background(), 3, "127.0.0.1", port, "127.0.0.1", "", "GET", false, 2*time.Second, true, "")
	if info.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after retries, got status=%d err=%q", info.StatusCode, info.Error)
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("expected 3 attempts (2 failures + 1 success), got %d", got)
	}
}

func TestProbeHTTPWithRetryDisabledFailsOnce(t *testing.T) {
	port, hits, closeFn := flakyServer(t, 2)
	defer closeFn()

	info := ProbeHTTPWithRetry(context.Background(), 0, "127.0.0.1", port, "127.0.0.1", "", "GET", false, 2*time.Second, true, "")
	if info.StatusCode != 0 || info.Error == "" {
		t.Fatalf("expected a transport error with retries disabled, got status=%d err=%q", info.StatusCode, info.Error)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected exactly 1 attempt, got %d", got)
	}
}

func TestProbeHTTPWithRetryStopsOnCancel(t *testing.T) {
	port, _, closeFn := flakyServer(t, 100)
	defer closeFn()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	info := ProbeHTTPWithRetry(ctx, 50, "127.0.0.1", port, "127.0.0.1", "", "GET", false, 2*time.Second, true, "")
	if info.StatusCode != 0 {
		t.Fatalf("expected failure, got status=%d", info.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("retry loop ignored context cancellation (took %v)", elapsed)
	}
}
