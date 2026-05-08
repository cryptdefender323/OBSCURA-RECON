package discovery

import (
	"sync"
)

type ScanQueue struct {
	mu   sync.Mutex
	seen map[string]struct{}
	q    []string
}

func NewScanQueue() *ScanQueue {
	return &ScanQueue{
		seen: make(map[string]struct{}),
	}
}

func (s *ScanQueue) Push(raw string) bool {
	p, err := NormalizePath(raw)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[p]; ok {
		return false
	}
	s.seen[p] = struct{}{}
	s.q = append(s.q, p)
	return true
}

func (s *ScanQueue) Pop() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.q) == 0 {
		return "", false
	}
	p := s.q[0]
	copy(s.q, s.q[1:])
	s.q = s.q[:len(s.q)-1]
	return p, true
}

func (s *ScanQueue) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.q)
}

func (s *ScanQueue) PushExpanded(raw string, opt ExpandOptions) (int, error) {
	cands, err := Expand(raw, opt)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range cands {
		if s.Push(c) {
			n++
		}
	}
	return n, nil
}

func (s *ScanQueue) FeedEndpoints(endpoints []string, opt ExpandOptions) (int, error) {
	total := 0
	for _, e := range endpoints {
		n, err := s.PushExpanded(e, opt)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
