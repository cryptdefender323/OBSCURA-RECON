package gobusterparse

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseLineDir(t *testing.T) {
	tests := []struct {
		line     string
		wantPath string
		wantCode int
		wantLen  *int64
		wantOk   bool
	}{
		{"/admin (Status: 302)", "/admin", 302, nil, true},
		{"https://ex.com/x (Status: 200) [Size: 42]", "https://ex.com/x", 200, ptrI64(42), true},
		{`/p (Status: 301) [Size: 0] [--> https://ex.com/q]`, "/p", 301, ptrI64(0), true},
		{"\x1b[36m/x\x1b[0m \x1b[37m(Status: 404)\x1b[0m", "/x", 404, nil, true},
		{"Progress: 50%", "", 0, nil, false},
		{"", "", 0, nil, false},
	}
	for _, tt := range tests {
		rec, ok := ParseLine(ModeDir, tt.line)
		if ok != tt.wantOk {
			t.Fatalf("dir ok=%v want=%v line=%q", ok, tt.wantOk, tt.line)
		}
		if !tt.wantOk {
			continue
		}
		if rec.Path != tt.wantPath || rec.StatusCode == nil || *rec.StatusCode != tt.wantCode {
			t.Fatalf("dir %q: %+v", tt.line, rec)
		}
		switch {
		case tt.wantLen == nil && rec.ResponseLength != nil:
			t.Fatalf("dir %q: unexpected length %v", tt.line, *rec.ResponseLength)
		case tt.wantLen != nil && (rec.ResponseLength == nil || *tt.wantLen != *rec.ResponseLength):
			t.Fatalf("dir %q: length got=%v want=%v", tt.line, rec.ResponseLength, tt.wantLen)
		}
	}
}

func TestParseLineVhost(t *testing.T) {
	line := "admin.example.com \x1b[32mStatus: 200\x1b[0m [Size: 1234]"
	rec, ok := ParseLine(ModeVhost, line)
	if !ok || rec.Path != "admin.example.com" || *rec.StatusCode != 200 || *rec.ResponseLength != 1234 {
		t.Fatalf("vhost: %+v ok=%v", rec, ok)
	}
}

func TestParseLineDNS(t *testing.T) {
	rec, ok := ParseLine(ModeDNS, "www 10.0.0.1 CNAME: x")
	if !ok || rec.Path != "www" || rec.StatusCode != nil || rec.ResponseLength != nil {
		t.Fatalf("dns: %+v", rec)
	}
}

func TestStreamJSONLines(t *testing.T) {
	in := strings.NewReader("/a (Status: 200) [Size: 1]\nnoise\n/b (Status: 404)\n")
	var out bytes.Buffer
	err := StreamJSONLines(&out, in, StreamOptions{Mode: ModeDir})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 json lines, got %d: %q", len(lines), out.String())
	}
	var r Record
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Path != "/a" || *r.StatusCode != 200 || *r.ResponseLength != 1 {
		t.Fatalf("first: %+v", r)
	}
}

func TestStripANSIFastPath(t *testing.T) {
	s := "/plain (Status: 200)"
	if StripANSI(s) != s {
		t.Fatal("expected unchanged string when no ESC sequences are present")
	}
}

func ptrI64(v int64) *int64 { return &v }
