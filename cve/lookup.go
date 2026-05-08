package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Vulnerability struct {
	ID          string   `json:"id"`
	Description string   `json:"summary"`
	Severity    string   `json:"cvss"`
	CVSS        float64  `json:"cvss_score,omitempty"`
	URL         string   `json:"url"`
	Confidence  string   `json:"confidence"`
	Evidence    []string `json:"evidence"`
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


func semverParts(v string) []int {
	v = strings.TrimSpace(v)
	// Strip leading 'v' or 'V'
	v = strings.TrimLeft(v, "vV")
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {

		p = strings.FieldsFunc(p, func(r rune) bool {
			return r < '0' || r > '9'
		})[0]
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

func versionAffected(description, detectedVersion string) bool {
	if detectedVersion == "" || description == "" {
		return false
	}

	tokenMatch := func(text, token string) bool {
		if token == "" {
			return false
		}

		pattern := `(?:^|[^0-9A-Za-z.])` + regexp.QuoteMeta(token) + `(?:$|[^0-9A-Za-z.])`
		return regexp.MustCompile(pattern).MatchString(text)
	}

	parts := semverParts(detectedVersion)

	if tokenMatch(description, detectedVersion) {
		return true
	}

	if len(parts) >= 2 {
		majorMinor := fmt.Sprintf("%d.%d", parts[0], parts[1])
		if tokenMatch(description, majorMinor) {
			return true
		}
	}

	if len(parts) == 1 {
		majorOnly := strconv.Itoa(parts[0])
		if tokenMatch(description, majorOnly) {
			return true
		}
	}

	return false
}

func parseCVSS(raw string) float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if f, err := strconv.ParseFloat(raw, 64); err == nil {
		return f
	}

	re := regexp.MustCompile(`(\d+\.\d+)`)
	m := re.FindString(raw)
	if m != "" {
		if f, err := strconv.ParseFloat(m, 64); err == nil {
			return f
		}
	}
	return 0
}

func severityLabel(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func Lookup(tech, version string) Result {
	version = strings.TrimSpace(version)
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

	if version == "" {
		cacheMutex.Lock()
		cache[cacheKey] = res
		cacheMutex.Unlock()
		return res
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

	var rawCVEs []json.RawMessage
	if err := json.Unmarshal(body, &rawCVEs); err != nil {
		var wrapper struct {
			Results []json.RawMessage `json:"results"`
		}
		if err2 := json.Unmarshal(body, &wrapper); err2 != nil {
			return res
		}
		rawCVEs = wrapper.Results
	}

	for _, raw := range rawCVEs {
		var v Vulnerability
		if err := json.Unmarshal(raw, &v); err != nil {
			continue
		}

		if !versionAffected(v.Description, version) {
			continue
		}

		v.CVSS = parseCVSS(v.Severity)
		if v.CVSS > 0 {
			v.Severity = fmt.Sprintf("%s (CVSS %.1f)", severityLabel(v.CVSS), v.CVSS)
		} else {
			v.Severity = "UNKNOWN"
		}

		v.Confidence = "Version match — manual verification recommended"
		v.Evidence = []string{
			fmt.Sprintf("Detected: %s v%s", tech, version),
			fmt.Sprintf("CVE description contains version token %q", version),
		}

		res.CVEs = append(res.CVEs, v)

		if len(res.CVEs) >= 10 {
			break
		}
	}

	cacheMutex.Lock()
	cache[cacheKey] = res
	cacheMutex.Unlock()

	return res
}
