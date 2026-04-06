package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Vulnerability struct {
	ID          string `json:"id"`
	Description string `json:"summary"`
	Severity    string `json:"cvss"`
	URL         string `json:"url"`
}

type Result struct {
	TechName string          `json:"tech_name"`
	Version  string          `json:"version"`
	CVEs     []Vulnerability `json:"cves"`
}

var (
	cache      = make(map[string]Result)
	cacheMutex sync.RWMutex
)

func Lookup(tech, version string) Result {
	cacheKey := fmt.Sprintf("%s:%s", tech, version)

	cacheMutex.RLock()
	if res, ok := cache[cacheKey]; ok {
		cacheMutex.RUnlock()
		return res
	}
	cacheMutex.RUnlock()

	res := Result{
		TechName: tech,
		Version:  version,
		CVEs:     []Vulnerability{},
	}

	apiURL := fmt.Sprintf("https://cve.circl.lu/api/search/%s", strings.ToLower(tech))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return res
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return res
	}

	var allCVEs []Vulnerability
	if err := json.Unmarshal(body, &allCVEs); err != nil {

		var wrapper struct {
			Results []Vulnerability `json:"results"`
		}
		if err2 := json.Unmarshal(body, &wrapper); err2 == nil {
			allCVEs = wrapper.Results
		}
	}

	for _, v := range allCVEs {
		if version == "" || strings.Contains(v.Description, version) {

			if v.Severity != "" {
				v.Severity = fmt.Sprintf("CVSS: %s", v.Severity)
			}
			res.CVEs = append(res.CVEs, v)
		}

		if len(res.CVEs) >= 10 {
			break
		}
	}

	if len(res.CVEs) == 0 && version != "" {
		res.Version = version + " (Potential match but no version-specific CVEs found)"
	}

	cacheMutex.Lock()
	cache[cacheKey] = res
	cacheMutex.Unlock()

	return res
}
