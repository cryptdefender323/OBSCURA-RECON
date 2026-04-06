package responseanalyze

import (
	"fmt"
	"testing"
)

func TestAnalyzeBaselineVsOutlier(t *testing.T) {
	body404 := bytesRepeat('a', 120)
	bodyRare := bytesRepeat('b', 40)
	var samples []Sample
	for i := 0; i < 20; i++ {
		samples = append(samples, Sample{Key: fmt.Sprintf("/k%d", i), Status: 404, Body: body404})
	}
	samples = append(samples, Sample{Key: "/interesting", Status: 404, Body: bodyRare})

	opt := DefaultOptions()
	opt.HashBodyPrefixBytes = 0
	opt.MinDominantCount = 5
	opt.MinSimilarCluster = 2

	r := Analyze(samples, opt)
	if len(r.SimilarClusters) < 1 || r.SimilarClusters[0].Count != 20 {
		t.Fatalf("expected dominant similar cluster 20: %#v", r.SimilarClusters)
	}
	if len(r.Anomalies) != 1 || r.Anomalies[0].Key != "/interesting" {
		t.Fatalf("expected one anomaly: %#v", r.Anomalies)
	}
}

func TestAnalyzeReportedLength(t *testing.T) {
	var samples []Sample
	for i := 0; i < 10; i++ {
		samples = append(samples, Sample{Key: fmt.Sprintf("/x%d", i), Status: 404, ReportedLength: 100})
	}
	samples = append(samples, Sample{Key: "/y", Status: 404, ReportedLength: 5})
	opt := DefaultOptions()
	opt.HashBodyPrefixBytes = 0
	opt.MinDominantCount = 3
	opt.MinSimilarCluster = 2
	r := Analyze(samples, opt)
	if len(r.Anomalies) < 1 {
		t.Fatalf("expected anomaly on reported length outlier: %#v", r.Anomalies)
	}
}

func TestAnalyzePrefixHashSplitsSameLength(t *testing.T) {
	a := append([]byte("alpha"), bytesRepeat('x', 100)...)
	b := append([]byte("bravo"), bytesRepeat('y', 100)...)
	samples := []Sample{
		{Key: "/1", Status: 200, Body: a},
		{Key: "/2", Status: 200, Body: b},
	}
	opt := DefaultOptions()
	opt.MinDominantCount = 10
	opt.MinSimilarCluster = 2

	r := Analyze(samples, opt)
	if len(r.Clusters) != 2 {
		t.Fatalf("want 2 clusters with hash, got %d: %#v", len(r.Clusters), r.Clusters)
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(nil, DefaultOptions())
	if len(r.Clusters) != 0 || len(r.Anomalies) != 0 {
		t.Fatalf("expected empty: %#v", r)
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
