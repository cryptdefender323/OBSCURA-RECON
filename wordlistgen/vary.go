package wordlistgen

import (
	"fmt"
	"strings"
)

func Variations(word string, cfg Config) []string {
	cfg.normalize()
	word = strings.TrimSpace(word)
	if word == "" {
		return nil
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
	for _, suf := range cfg.Suffixes {
		suf = strings.TrimSpace(suf)
		if suf == "" {
			continue
		}
		add(word + "-" + suf)
	}
	for _, pre := range cfg.Prefixes {
		pre = strings.TrimSpace(pre)
		if pre == "" {
			continue
		}
		add(pre + "-" + word)
	}

	if cfg.WAFBypassLevel >= 2 {

		add(strings.Title(word))
		add(strings.ToUpper(word))

		add(word + ";")
		add(word + "//")
		add(word + "/.")
		add(word + "/..;")
	}

	if cfg.WAFBypassLevel >= 3 {

		encoded := ""
		for i := 0; i < len(word); i++ {
			if i == 0 {
				encoded += fmt.Sprintf("%%%02x", word[i]) + word[1:]
				add(encoded)
			}
		}
		if len(word) > 0 {
			double := fmt.Sprintf("%%25%02x", word[0]) + word[1:]
			add(double)
		}
	}

	return out
}
