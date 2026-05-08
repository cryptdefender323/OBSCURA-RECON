package pipeline

import (
	"net/url"
	"strings"
)

func joinTarget(targetURL, pathOrURL string) (string, error) {
	pathOrURL = strings.TrimSpace(pathOrURL)
	if pathOrURL == "" {
		return targetURL, nil
	}
	base, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(pathOrURL)
	if err != nil {
		return "", err
	}
	if ref.IsAbs() {
		return ref.String(), nil
	}
	return base.ResolveReference(ref).String(), nil
}
