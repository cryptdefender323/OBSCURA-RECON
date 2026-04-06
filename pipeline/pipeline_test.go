package pipeline

import (
	"testing"

	"obscura/gobusterexec"
	"obscura/responseanalyze"
)

func TestJoinTarget(t *testing.T) {
	u, err := joinTarget("https://ex.com/app", "/api/v1")
	if err != nil || u != "https://ex.com/api/v1" {
		t.Fatalf("got %q %v", u, err)
	}
	u2, err := joinTarget("https://ex.com", "https://other.test/x")
	if err != nil || u2 != "https://other.test/x" {
		t.Fatalf("got %q %v", u2, err)
	}
}

func TestHitsToSamples(t *testing.T) {
	st := 200
	sz := int64(99)
	hits := []gobusterexec.Hit{
		{Path: "/a", StatusCode: &st, Size: &sz, Raw: "/a (Status: 200) [Size: 99]"},
	}
	s := HitsToSamples(hits)
	if len(s) != 1 || s[0].ReportedLength != 99 || s[0].Status != 200 {
		t.Fatalf("%+v", s)
	}
	recs := ParseHits(hits)
	if len(recs) != 1 || recs[0].Path != "/a" {
		t.Fatalf("%+v", recs)
	}
}

func TestAnalyzeIntegrationWithHits(t *testing.T) {
	var hits []gobusterexec.Hit
	st404 := 404
	sz100 := int64(100)
	for i := 0; i < 8; i++ {
		hits = append(hits, gobusterexec.Hit{
			Path:       "/n",
			StatusCode: &st404,
			Size:       &sz100,
		})
	}
	sz5 := int64(5)
	hits = append(hits, gobusterexec.Hit{Path: "/rare", StatusCode: &st404, Size: &sz5})
	opt := responseanalyze.DefaultOptions()
	opt.HashBodyPrefixBytes = 0
	opt.MinDominantCount = 3
	opt.MinSimilarCluster = 2
	r := responseanalyze.Analyze(HitsToSamples(hits), opt)
	if len(r.Anomalies) < 1 {
		t.Fatalf("expected anomalies: %#v", r.Anomalies)
	}
}
