package scanner

import (
	"context"
	"testing"
	"time"
)

func TestNewLimiterUnlimited(t *testing.T) {
	if NewLimiter(0) != nil {
		t.Fatal("rate 0 should return nil (unlimited)")
	}
	var l *Limiter
	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("nil limiter Wait should be a no-op, got %v", err)
	}
}

func TestLimiterSpacing(t *testing.T) {
	l := NewLimiter(20) // 50ms between operations
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// 5 calls => first immediate, then 4 gaps of ~50ms = ~200ms
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Fatalf("limiter too fast: %v", elapsed)
	}
}

func TestLimiterContextCancel(t *testing.T) {
	l := NewLimiter(0.5) // 2s between operations
	_ = l.Wait(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx); err == nil {
		t.Fatal("expected context error")
	}
}

func TestIsTransientError(t *testing.T) {
	cases := map[string]bool{
		"":                               false,
		"dial tcp: i/o timeout":          true,
		"read: connection reset by peer": true,
		"x509: certificate has expired":  false,
		"context deadline exceeded":      true,
		"tls: handshake failure":         false,
	}
	for msg, want := range cases {
		if got := isTransientError(msg); got != want {
			t.Errorf("isTransientError(%q) = %v, want %v", msg, got, want)
		}
	}
}

func TestBackoffDelayBounded(t *testing.T) {
	for i := 0; i < 10; i++ {
		if d := backoffDelay(i); d <= 0 || d > 5*time.Second {
			t.Errorf("attempt %d: delay %v out of range", i, d)
		}
	}
}
