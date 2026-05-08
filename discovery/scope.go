package discovery

import (
	"net/url"
	"strings"
)

func InScope(targetURL, candidateURL string) bool {
	t, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || t.Host == "" {
		return false
	}
	c, err := url.Parse(strings.TrimSpace(candidateURL))
	if err != nil || c.Host == "" {
		return false
	}

	if !strings.EqualFold(t.Scheme, c.Scheme) {
		return false
	}

	tHost := strings.ToLower(stripPort(t.Host))
	cHost := strings.ToLower(stripPort(c.Host))

	if tHost == cHost {
		return true
	}

	if strings.HasSuffix(cHost, "."+tHost) {
		return true
	}

	return false
}

func FilterInScope(targetURL string, urls []string) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		if InScope(targetURL, u) {
			out = append(out, u)
		}
	}
	return out
}

func stripPort(host string) string {
	if idx := strings.LastIndex(host, ":"); idx >= 0 {

		if !strings.Contains(host[:idx], ":") {
			return host[:idx]
		}
	}
	return host
}
