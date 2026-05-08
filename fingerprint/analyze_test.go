package fingerprint

import (
	"net/http"
	"testing"
)

func TestAnalyzeIncludesConfidenceAndEvidence(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "nginx/1.24.0")

	res := Analyze(headers, nil, DefaultSignatures)
	if len(res.Techs) == 0 {
		t.Fatal("expected at least one technology")
	}

	var nginx TechResult
	for _, tech := range res.Techs {
		if tech.Name == "Nginx" {
			nginx = tech
			break
		}
	}
	if nginx.Name == "" {
		t.Fatalf("expected nginx fingerprint: %#v", res.Techs)
	}
	if nginx.Version != "1.24.0" {
		t.Fatalf("expected version evidence, got %q", nginx.Version)
	}
	if nginx.Confidence == "" || len(nginx.Evidence) == 0 {
		t.Fatalf("expected confidence and evidence: %#v", nginx)
	}
}
