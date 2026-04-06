package wordlistgen

import (
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var tokenPattern = regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9_-]*`)

func ExtractURLKeywords(raw string, cfg Config) ([]string, error) {
	cfg.normalize()
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = normalizeToken(s, cfg)
		if s == "" {
			return
		}
		key := s
		if cfg.DedupeCaseFold {
			key = strings.ToLower(s)
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}

	host := u.Hostname()
	if host != "" {
		for _, label := range strings.Split(host, ".") {
			if label == "" || strings.EqualFold(label, "www") {
				continue
			}
			add(label)
		}
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if seg == "" {
			continue
		}
		unescaped, err := url.PathUnescape(seg)
		if err != nil {
			unescaped = seg
		}
		base := path.Base(unescaped)
		if dot := strings.LastIndex(base, "."); dot > 0 {
			ext := base[dot+1:]
			if isLikelyExtension(ext) {
				base = base[:dot]
			}
		}
		add(base)
	}
	for key := range u.Query() {
		add(key)
	}
	return out, nil
}

func ExtractResponseKeywords(body []byte, cfg Config) []string {
	cfg.normalize()
	if len(body) > cfg.MaxResponseBytes {
		body = body[:cfg.MaxResponseBytes]
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = normalizeToken(s, cfg)
		if s == "" {
			return
		}
		key := s
		if cfg.DedupeCaseFold {
			key = strings.ToLower(s)
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	for _, m := range tokenPattern.FindAllString(string(body), -1) {
		add(m)
	}
	return out
}

func normalizeToken(s string, cfg Config) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	r, _ := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError || !unicode.IsLetter(r) && !unicode.IsDigit(r) {
		return ""
	}
	if len(s) > cfg.MaxTokenLen {
		return ""
	}
	if utf8.RuneCountInString(s) < cfg.MinTokenLen {
		return ""
	}
	return s
}

func isLikelyExtension(ext string) bool {
	if len(ext) > 8 || len(ext) < 1 {
		return false
	}
	for _, r := range ext {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
