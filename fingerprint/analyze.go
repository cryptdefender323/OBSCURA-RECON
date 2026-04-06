package fingerprint

import (
	"net/http"
)

type TechResult struct {
	Name     string
	Version  string
	Category string
}

type Result struct {
	Techs []TechResult
}

func Analyze(headers http.Header, body []byte, sigs []Signature) Result {
	var results []TechResult
	seen := make(map[string]struct{})

	for _, sig := range sigs {
		found := false
		version := ""

		for key, re := range sig.Headers {
			for _, val := range headers[http.CanonicalHeaderKey(key)] {
				matches := re.FindStringSubmatch(val)
				if len(matches) > 0 {
					found = true
					if len(matches) > 1 && matches[1] != "" {
						version = matches[1]
					}
					break
				}
			}
			if found {
				break
			}
		}

		if !found && len(body) > 0 {
			for _, re := range sig.Body {
				matches := re.FindStringSubmatch(string(body))
				if len(matches) > 0 {
					found = true
					if len(matches) > 1 && matches[1] != "" {
						version = matches[1]
					}
					break
				}
			}
		}

		if found {
			if _, ok := seen[sig.Name]; !ok {
				results = append(results, TechResult{
					Name:     sig.Name,
					Version:  version,
					Category: sig.Category,
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
