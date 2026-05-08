package wordlistgen

import (
	"bufio"
	"io"
	"strings"
)

func Merge(cfg Config, base []string, extra ...[]string) []string {
	cfg.normalize()
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
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
	for _, s := range base {
		add(s)
		if cfg.WAFBypassLevel > 0 {
			for _, v := range Variations(s, cfg) {
				add(v)
			}
		}
	}
	for _, list := range extra {
		for _, s := range list {
			add(s)
			if cfg.WAFBypassLevel > 0 {
				for _, v := range Variations(s, cfg) {
					add(v)
				}
			}
		}
	}
	return out
}

func ReadLines(r io.Reader) ([]string, error) {
	sc := bufio.NewScanner(r)
	var out []string
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}
