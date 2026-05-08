package fingerprint

import (
	"net/http"
)

type TechResult struct {
	Name       string
	Version    string
	Category   string
	Confidence string
	Evidence   []string
}

type Result struct {
	Techs []TechResult
}

func Analyze(headers http.Header, body []byte, sigs []Signature) Result {
	var results []TechResult
	seen := make(map[string]struct{})

	for _, sig := range sigs {
		version := ""
		var evidence []string

		for key, re := range sig.Headers {
			for _, val := range headers[http.CanonicalHeaderKey(key)] {
				matches := re.FindStringSubmatch(val)
				if len(matches) > 0 {
					if len(matches) > 1 && matches[1] != "" {
						version = matches[1]
					}
					evidence = append(evidence, "header "+http.CanonicalHeaderKey(key)+" matched "+re.String())
				}
			}
		}

		if len(body) > 0 {
			for _, re := range sig.Body {
				matches := re.FindStringSubmatch(string(body))
				if len(matches) > 0 {
					if len(matches) > 1 && matches[1] != "" {
						version = matches[1]
					}
					evidence = append(evidence, "body matched "+re.String())
				}
			}
		}

		if len(evidence) > 0 {
			if _, ok := seen[sig.Name]; !ok {
				results = append(results, TechResult{
					Name:       sig.Name,
					Version:    version,
					Category:   sig.Category,
					Confidence: confidenceFor(sig.Category, version, evidence),
					Evidence:   evidence,
				})
				seen[sig.Name] = struct{}{}
			}
		}
	}

	return Result{Techs: results}
}

func Merge(results ...Result) Result {
	merged := make(map[string]TechResult)
	for _, r := range results {
		for _, t := range r.Techs {
			if existing, ok := merged[t.Name]; ok {
				if existing.Version == "" && t.Version != "" {
					merged[t.Name] = t
					continue
				}
				if confidenceRank(t.Confidence) > confidenceRank(existing.Confidence) {
					merged[t.Name] = t
				}
			} else {
				merged[t.Name] = t
			}
		}
	}

	var out []TechResult
	for _, t := range merged {
		out = append(out, t)
	}
	return Result{Techs: out}
}

func confidenceFor(category, version string, evidence []string) string {
	if category == "Analytics" {
		return "Informational"
	}
	if version != "" && len(evidence) >= 2 {
		return "Confirmed"
	}
	if version != "" || len(evidence) >= 2 {
		return "Likely"
	}
	return "Informational"
}

func confidenceRank(conf string) int {
	switch conf {
	case "Confirmed":
		return 3
	case "Likely":
		return 2
	case "Informational":
		return 1
	default:
		return 0
	}
}
