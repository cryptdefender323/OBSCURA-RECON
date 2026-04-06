package discovery

import (
	"sync"
	"testing"
)

func TestExpandVersionPatterns(t *testing.T) {
	opt := ExpandOptions{VersionRadius: 2, IncludeParents: false}
	out, err := Expand("/api/v1/users", opt)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"/api/v0/users": true,
		"/api/v2/users": true,
		"/api/v3/users": true,
	}
	for _, p := range out {
		delete(want, p)
	}
	if len(want) != 0 {
		t.Fatalf("missing %v in %v", want, out)
	}
}

func TestExpandParentsAndCap(t *testing.T) {
	opt := ExpandOptions{VersionRadius: 0, IncludeParents: true, MaxCandidates: 2}
	opt.normalize()
	out, err := Expand("/a/b/c", opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected cap 2, got %v", out)
	}
}

func TestDetectVersionPatternsURL(t *testing.T) {
	out, err := DetectVersionPatterns("https://ex.com/api/V2/x", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(out, "/api/v1/x") || !contains(out, "/api/v3/x") {
		t.Fatalf("got %v", out)
	}
}

func TestScanQueueDedupeAndExpand(t *testing.T) {
	q := NewScanQueue()
	if !q.Push("/seed") {
		t.Fatal("first push")
	}
	if q.Push("/seed") {
		t.Fatal("dup should fail")
	}
	n, err := q.PushExpanded("/api/v1/a", ExpandOptions{VersionRadius: 1, IncludeParents: false})
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v len=%d", n, err, q.Len())
	}
	total, err := q.FeedEndpoints([]string{"/api/v1/a"}, ExpandOptions{VersionRadius: 1})
	if err != nil || total != 0 {
		t.Fatalf("feed should add nothing new: total=%d err=%v", total, err)
	}
}

func TestScanQueueConcurrent(t *testing.T) {
	q := NewScanQueue()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			q.Push("/p")
			q.PushExpanded("/x/v1/y", ExpandOptions{VersionRadius: 1, IncludeParents: false})
		}(i)
	}
	wg.Wait()
	if q.Len() == 0 {
		t.Fatal("expected items")
	}
}

func TestNumericBump(t *testing.T) {
	out, err := Expand("/items/10/detail", ExpandOptions{
		VersionRadius:       1,
		IncludeParents:      false,
		BumpNumericSegments: true,
		NumericRadius:       1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(out, "/items/9/detail") || !contains(out, "/items/11/detail") {
		t.Fatalf("got %v", out)
	}
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
