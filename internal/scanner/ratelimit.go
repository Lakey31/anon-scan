package scanner

import (
	"context"
	"math/rand"
	"strings"
	"sync"
	"time"

	"anon-scan/internal/models"
)

// Limiter is a small, dependency-free rate limiter that spaces out
// operations to at most `rate` per second across all workers.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// NewLimiter returns a limiter allowing ratePerSec operations per second.
// A rate <= 0 returns nil, which means "unlimited".
func NewLimiter(ratePerSec float64) *Limiter {
	if ratePerSec <= 0 {
		return nil
	}
	return &Limiter{interval: time.Duration(float64(time.Second) / ratePerSec)}
}

// Wait blocks until the caller may proceed or ctx is cancelled.
// It is safe to call on a nil *Limiter (no-op).
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return ctx.Err()
	}

	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if wait <= 0 {
		return ctx.Err()
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// isTransientError reports whether a probe error looks like a flaky
// network condition worth retrying (as opposed to a definitive failure).
func isTransientError(msg string) bool {
	if msg == "" {
		return false
	}
	m := strings.ToLower(msg)
	for _, s := range []string{
		"timeout", "timed out", "deadline exceeded",
		"connection reset", "connection refused", "broken pipe",
		"unexpected eof", "eof", "temporary", "i/o timeout",
		"network is unreachable", "no route to host",
	} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

// backoffDelay returns an exponential delay with jitter for a 0-based attempt.
func backoffDelay(attempt int) time.Duration {
	base := 200 * time.Millisecond << uint(attempt)
	if base > 3*time.Second {
		base = 3 * time.Second
	}
	jitter := time.Duration(rand.Int63n(int64(base)/2 + 1))
	return base + jitter
}

// ProbeHTTPWithRetry wraps ProbeHTTP and retries transient transport errors
// up to `retries` extra times using exponential backoff with jitter.
// With retries <= 0 it behaves exactly like ProbeHTTP.
func ProbeHTTPWithRetry(ctx context.Context, retries int, ip string, port int, hostHeader string, sni string, method string, measureSpeed bool, timeout time.Duration, skipVerify bool, proxyAddr string) models.HTTPInfo {
	info := ProbeHTTP(ctx, ip, port, hostHeader, sni, method, measureSpeed, timeout, skipVerify, proxyAddr)

	for attempt := 0; attempt < retries; attempt++ {
		if ctx.Err() != nil || info.StatusCode != 0 || !isTransientError(info.Error) {
			break
		}
		timer := time.NewTimer(backoffDelay(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return info
		case <-timer.C:
		}
		info = ProbeHTTP(ctx, ip, port, hostHeader, sni, method, measureSpeed, timeout, skipVerify, proxyAddr)
	}
	return info
}
