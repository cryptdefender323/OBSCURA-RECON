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
		add(word + "/..;/")
		add(word + "/..;/..;/")
	}

	if cfg.WAFBypassLevel >= 3 {
		// Unicode Bypass: Fullwidth Solidus
		add("%ef%bc%8f" + word)
		
		// Trailing Control Characters
		add(word + "%20")
		add(word + "%09")
		add(word + "%00")
		
		// Header-based path redirection (already handled in transport)
		// but we can add some 'decoy' prefix variations
		add("./" + word)
		add(".////" + word)

		// Encoding
		if len(word) > 0 {
			encoded := fmt.Sprintf("%%%02x", word[0]) + word[1:]
			add(encoded)
			
			double := fmt.Sprintf("%%25%02x", word[0]) + word[1:]
			add(double)
		}
	}

	return out
}
