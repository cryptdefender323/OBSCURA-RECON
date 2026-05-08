package stats

import (
	"fmt"
	"sync"
	"time"
)

type Stats struct {
	mu              sync.RWMutex
	StartTime       time.Time
	TotalRequests   int
	TotalHits       int
	TotalAnomalies  int
	TotalCVEs       int
	CurrentRound    int
	TotalRounds     int
	WordlistSize    int
	ValidatedHits   int
	RejectedHits    int
	TechnologiesFound int
}

func New(totalRounds int) *Stats {
	return &Stats{
		StartTime:    time.Now(),
		TotalRounds:  totalRounds,
	}
}

func (s *Stats) IncrementRequests(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalRequests += n
}

func (s *Stats) AddHits(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalHits += n
}

func (s *Stats) AddValidatedHits(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ValidatedHits += n
}

func (s *Stats) AddRejectedHits(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RejectedHits += n
}

func (s *Stats) AddAnomalies(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalAnomalies += n
}

func (s *Stats) AddCVEs(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalCVEs += n
}

func (s *Stats) AddTechnologies(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TechnologiesFound += n
}

func (s *Stats) SetRound(round int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentRound = round
}

func (s *Stats) SetWordlistSize(size int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.WordlistSize = size
}

func (s *Stats) Print() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	elapsed := time.Since(s.StartTime)
	reqPerSec := float64(s.TotalRequests) / elapsed.Seconds()

	fmt.Println("\n\033[1;36m╔════════════════════════════════════════════════════════════════╗\033[0m")
	fmt.Println("\033[1;36m║                    SCAN STATISTICS                             ║\033[0m")
	fmt.Println("\033[1;36m╠════════════════════════════════════════════════════════════════╣\033[0m")
	fmt.Printf("\033[1;36m║\033[0m  \033[1;32m⏱  Elapsed Time:\033[0m       %-35s \033[1;36m║\033[0m\n", elapsed.Round(time.Second))
	fmt.Printf("\033[1;36m║\033[0m  \033[1;32m📊 Current Round:\033[0m       %-35s \033[1;36m║\033[0m\n", fmt.Sprintf("%d/%d", s.CurrentRound, s.TotalRounds))
	fmt.Printf("\033[1;36m║\033[0m  \033[1;32m📝 Wordlist Size:\033[0m       %-35s \033[1;36m║\033[0m\n", fmt.Sprintf("%d words", s.WordlistSize))
	fmt.Printf("\033[1;36m║\033[0m  \033[1;32m🚀 Total Requests:\033[0m      %-35s \033[1;36m║\033[0m\n", fmt.Sprintf("%d (%.1f req/s)", s.TotalRequests, reqPerSec))
	fmt.Println("\033[1;36m╠════════════════════════════════════════════════════════════════╣\033[0m")
	fmt.Printf("\033[1;36m║\033[0m  \033[1;33m🎯 Total Hits:\033[0m          %-35s \033[1;36m║\033[0m\n", fmt.Sprintf("%d", s.TotalHits))
	fmt.Printf("\033[1;36m║\033[0m  \033[1;32m✓  Validated Hits:\033[0m      %-35s \033[1;36m║\033[0m\n", fmt.Sprintf("%d", s.ValidatedHits))
	fmt.Printf("\033[1;36m║\033[0m  \033[1;31m✗  Rejected Hits:\033[0m       %-35s \033[1;36m║\033[0m\n", fmt.Sprintf("%d (false positives)", s.RejectedHits))
	fmt.Println("\033[1;36m╠════════════════════════════════════════════════════════════════╣\033[0m")
	fmt.Printf("\033[1;36m║\033[0m  \033[1;35m🔍 Technologies:\033[0m        %-35s \033[1;36m║\033[0m\n", fmt.Sprintf("%d detected", s.TechnologiesFound))
	fmt.Printf("\033[1;36m║\033[0m  \033[1;31m🚨 CVEs Found:\033[0m          %-35s \033[1;36m║\033[0m\n", fmt.Sprintf("%d vulnerabilities", s.TotalCVEs))
	fmt.Printf("\033[1;36m║\033[0m  \033[1;33m⚠  Anomalies:\033[0m           %-35s \033[1;36m║\033[0m\n", fmt.Sprintf("%d suspicious patterns", s.TotalAnomalies))
	fmt.Println("\033[1;36m╚════════════════════════════════════════════════════════════════╝\033[0m\n")
}

func (s *Stats) PrintFinal() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	elapsed := time.Since(s.StartTime)
	
	fmt.Println("\n\033[1;32m╔════════════════════════════════════════════════════════════════╗\033[0m")
	fmt.Println("\033[1;32m║                    SCAN COMPLETED ✓                            ║\033[0m")
	fmt.Println("\033[1;32m╠════════════════════════════════════════════════════════════════╣\033[0m")
	fmt.Printf("\033[1;32m║\033[0m  Total Time:          %-38s \033[1;32m║\033[0m\n", elapsed.Round(time.Second))
	fmt.Printf("\033[1;32m║\033[0m  Validated Hits:      %-38s \033[1;32m║\033[0m\n", fmt.Sprintf("%d", s.ValidatedHits))
	fmt.Printf("\033[1;32m║\033[0m  CVEs Discovered:     %-38s \033[1;32m║\033[0m\n", fmt.Sprintf("%d", s.TotalCVEs))
	fmt.Printf("\033[1;32m║\033[0m  Anomalies Detected:  %-38s \033[1;32m║\033[0m\n", fmt.Sprintf("%d", s.TotalAnomalies))
	fmt.Println("\033[1;32m╚════════════════════════════════════════════════════════════════╝\033[0m\n")
}
