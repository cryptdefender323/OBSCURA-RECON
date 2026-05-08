package discovery

import (
	"net/url"
	"path"
	"strings"
)

func NormalizePath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrEmptyInput
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		if u.Path == "" {
			u.Path = "/"
		}
		return cleanPath(u.Path), nil
	}
	return cleanPath(raw), nil
}

func cleanPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

func splitSegments(p string) []string {
	p = strings.Trim(path.Clean(p), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func joinSegments(segs []string) string {
	if len(segs) == 0 {
		return "/"
	}
	return "/" + strings.Join(segs, "/")
}
