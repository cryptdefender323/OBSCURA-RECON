package gobusterexec

import (
	"testing"
)

func TestParseLineDir(t *testing.T) {
	tests := []struct {
		line     string
		wantPath string
		wantCode int
	}{
		{"/admin (Status: 302)", "/admin", 302},
		{"\x1b[36m/admin\x1b[0m \x1b[37m(Status: 302)\x1b[0m", "/admin", 302},
		{"https://ex.com/x (Status: 200) [Size: 42]", "https://ex.com/x", 200},
		{`/p (Status: 301) [Size: 0] [--> https://ex.com/q]`, "/p", 301},
	}
	for _, tt := range tests {
		h, ok := ParseLine(ModeDir, tt.line)
		if !ok {
			t.Fatalf("dir parse failed: %q", tt.line)
		}
		if h.Path != tt.wantPath || h.StatusCode == nil || *h.StatusCode != tt.wantCode {
			t.Fatalf("dir %q: got %+v want path=%q code=%d", tt.line, h, tt.wantPath, tt.wantCode)
		}
	}
}

func TestParseLineVhost(t *testing.T) {
	line := "admin.example.com \x1b[32mStatus: 200\x1b[0m [Size: 1234]"
	h, ok := ParseLine(ModeVhost, line)
	if !ok {
		t.Fatal("vhost parse failed")
	}
	if h.Path != "admin.example.com" || h.StatusCode == nil || *h.StatusCode != 200 {
		t.Fatalf("vhost: %+v", h)
	}
	if h.Size == nil || *h.Size != 1234 {
		t.Fatalf("size: %+v", h)
	}
}

func TestParseLineDNS(t *testing.T) {
	h, ok := ParseLine(ModeDNS, "www\x1b[32m 10.0.0.1,10.0.0.2\x1b[0m")
	if !ok || h.Path != "www" || len(h.IPs) != 2 {
		t.Fatalf("dns ips: %+v ok=%v", h, ok)
	}
	h2, ok := ParseLine(ModeDNS, "api 192.168.1.1 CNAME: lb.example.org")
	if !ok || h2.Path != "api" || h2.CNAME != "lb.example.org" || len(h2.IPs) != 1 {
		t.Fatalf("dns cname: %+v ok=%v", h2, ok)
	}
}

func TestParseLineIgnoreProgress(t *testing.T) {
	_, ok := ParseLine(ModeDir, "Progress: 50%")
	if ok {
		t.Fatal("expected non-result line to not parse")
	}
}
