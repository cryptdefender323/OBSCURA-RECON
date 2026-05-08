package reqconfig

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDelayAndJitter(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := Config{
		Delay:     40 * time.Millisecond,
		Jitter:    20 * time.Millisecond,
		UserAgent: "test-ua",
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := client.Get(srv.URL); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < cfg.Delay {
		t.Fatalf("expected at least delay, got %v", d)
	}
	if hits.Load() != 1 {
		t.Fatalf("unexpected hits %d", hits.Load())
	}
}

func TestCustomHeadersAndRotation(t *testing.T) {
	var lastUA atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastUA.Store(r.Header.Get("User-Agent"))
		if r.Header.Get("X-Scan") != "1" {
			t.Error("missing custom header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := make(http.Header)
	h.Set("X-Scan", "1")
	cfg := Config{
		Headers:    h,
		UserAgents: []string{"ua-a", "ua-b"},
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 40; i++ {
		if _, err := client.Get(srv.URL); err != nil {
			t.Fatal(err)
		}
		ua := lastUA.Load().(string)
		seen[ua] = true
	}
	if !seen["ua-a"] || !seen["ua-b"] {
		t.Fatalf("expected rotation, got %v", seen)
	}
}

func TestInvalidProxy(t *testing.T) {
	_, err := NewRoundTripper(Config{ProxyURL: "ftp://nope"})
	if err == nil {
		t.Fatal("expected error")
	}
}
