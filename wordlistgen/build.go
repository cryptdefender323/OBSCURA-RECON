package wordlistgen

import (
	"io"
	"strings"
)

func Build(cfg Config, base []string, urls []string, responses [][]byte) ([]string, error) {
	cfg.normalize()
	var dynamic []string
	seenDyn := make(map[string]struct{})
	addDyn := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		key := s
		if cfg.DedupeCaseFold {
			key = strings.ToLower(s)
		}
		if _, ok := seenDyn[key]; ok {
			return
		}
		seenDyn[key] = struct{}{}
		dynamic = append(dynamic, s)
	}

	for _, raw := range urls {
		kw, err := ExtractURLKeywords(raw, cfg)
		if err != nil {
			return nil, err
		}
		for _, w := range kw {
			addDyn(w)
			for _, v := range Variations(w, cfg) {
				addDyn(v)
			}
		}
	}
	for _, body := range responses {
		for _, w := range ExtractResponseKeywords(body, cfg) {
			addDyn(w)
			for _, v := range Variations(w, cfg) {
				addDyn(v)
			}
		}
	}
	return Merge(cfg, base, dynamic), nil
}

func BuildFromReaders(cfg Config, base io.Reader, urls []string, responses [][]byte) ([]string, error) {
	var baseLines []string
	if base != nil {
		var err error
		baseLines, err = ReadLines(base)
		if err != nil {
			return nil, err
		}
	}
	return Build(cfg, baseLines, urls, responses)
}
