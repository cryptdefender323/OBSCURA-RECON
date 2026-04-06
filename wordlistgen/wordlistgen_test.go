package wordlistgen

import (
	"strings"
	"testing"
)

func TestExtractURLKeywords(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinTokenLen = 2
	kw, err := ExtractURLKeywords("https://api-dev.example.com/v2/internal/users.php?id=1&ref=beta", cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(kw, ",")
	for _, want := range []string{"api-dev", "example", "com", "v2", "internal", "users", "id", "ref"} {
		if !containsFold(kw, want) {
			t.Fatalf("missing %q in %v", want, kw)
		}
	}
	if strings.Contains(got, "www") {
		t.Fatalf("unexpected www: %v", kw)
	}
}

func TestExtractResponseKeywords(t *testing.T) {
	cfg := DefaultConfig()
	body := []byte(`<a href="/admin-panel">Dashboard</a> token_x secretValue`)
	kw := ExtractResponseKeywords(body, cfg)
	if !containsFold(kw, "admin-panel") {
		t.Fatalf("expected hyphenated token: %v", kw)
	}
	if !containsFold(kw, "token_x") || !containsFold(kw, "secretValue") {
		t.Fatalf("expected identifiers: %v", kw)
	}
}

func TestVariations(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Suffixes = []string{"dev", "test"}
	cfg.Prefixes = []string{"dev"}
	out := Variations("admin", cfg)
	want := map[string]bool{"admin-dev": true, "admin-test": true, "dev-admin": true}
	for _, s := range out {
		if !want[s] {
			t.Errorf("unexpected %q", s)
		}
		delete(want, s)
	}
	if len(want) != 0 {
		t.Fatalf("missing: %v", want)
	}
}

func TestMergeOrder(t *testing.T) {
	cfg := DefaultConfig()
	got := Merge(cfg, []string{"zebra", "admin"}, []string{"admin", "admin-dev", "apple"})
	if len(got) != 4 {
		t.Fatalf("got %v", got)
	}
	if got[0] != "zebra" || got[1] != "admin" {
		t.Fatalf("base order broken: %v", got)
	}
}

func TestBuild(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Suffixes = []string{"dev", "test"}
	cfg.Prefixes = nil
	base := []string{"login", "logout"}
	urls := []string{"https://corp.test/assets/admin.js"}
	res := [][]byte{[]byte(`href="/api/internal"`)}
	out, err := Build(cfg, base, urls, res)
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != "login" || out[1] != "logout" {
		t.Fatalf("base not first: %v", out)
	}
	if !containsFold(out, "admin-dev") || !containsFold(out, "internal") {
		t.Fatalf("expected dynamic entries: %v", out)
	}
}

func TestReadLines(t *testing.T) {
	r := strings.NewReader("alpha\n#comment\n\nbeta\r\n")
	got, err := ReadLines(r)
	if err != nil || len(got) != 2 || got[0] != "alpha" || got[1] != "beta" {
		t.Fatalf("got %v err %v", got, err)
	}
}

func containsFold(hay []string, needle string) bool {
	for _, s := range hay {
		if strings.EqualFold(s, needle) {
			return true
		}
	}
	return false
}
