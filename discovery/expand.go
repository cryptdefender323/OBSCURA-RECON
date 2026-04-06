package discovery

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
)

var (
	reVersionSeg = regexp.MustCompile(`(?i)^v(\d+)$`)
	reNumericSeg = regexp.MustCompile(`^\d+$`)
)

func Expand(raw string, opt ExpandOptions) ([]string, error) {
	opt.normalize()
	base, err := NormalizePath(raw)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(p string) {
		p = cleanPath(p)
		if p == "" || p == base {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
		if opt.MaxCandidates > 0 && len(out) >= opt.MaxCandidates {
			return
		}
	}

	segs := splitSegments(base)
	if len(segs) == 0 {
		return out, nil
	}

	for i, seg := range segs {
		m := reVersionSeg.FindStringSubmatch(seg)
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		for d := -opt.VersionRadius; d <= opt.VersionRadius; d++ {
			if d == 0 {
				continue
			}
			nn := n + d
			if nn < 0 {
				continue
			}
			alt := fmt.Sprintf("v%d", nn)
			clone := append([]string(nil), segs...)
			clone[i] = alt
			add(joinSegments(clone))
			if opt.MaxCandidates > 0 && len(out) >= opt.MaxCandidates {
				return out, nil
			}
		}
	}

	if opt.BumpNumericSegments {
		for i, seg := range segs {
			if reVersionSeg.MatchString(seg) {
				continue
			}
			if !reNumericSeg.MatchString(seg) {
				continue
			}
			n, _ := strconv.Atoi(seg)
			for d := -opt.NumericRadius; d <= opt.NumericRadius; d++ {
				if d == 0 {
					continue
				}
				nn := n + d
				if nn < 0 {
					continue
				}
				alt := strconv.Itoa(nn)
				if alt == seg {
					continue
				}
				clone := append([]string(nil), segs...)
				clone[i] = alt
				add(joinSegments(clone))
				if opt.MaxCandidates > 0 && len(out) >= opt.MaxCandidates {
					return out, nil
				}
			}
		}
	}

	if opt.IncludeParents {
		for k := len(segs) - 1; k > 0; k-- {
			parent := joinSegments(segs[:k])
			add(parent)
			if opt.MaxCandidates > 0 && len(out) >= opt.MaxCandidates {
				break
			}
		}
	}

	return out, nil
}

func DetectVersionPatterns(raw string, radius int) ([]string, error) {
	if radius <= 0 {
		radius = 2
	}
	opt := ExpandOptions{VersionRadius: radius, IncludeParents: false, BumpNumericSegments: false}
	return Expand(raw, opt)
}

func ParentPaths(raw string) ([]string, error) {
	base, err := NormalizePath(raw)
	if err != nil {
		return nil, err
	}
	segs := splitSegments(base)
	if len(segs) <= 1 {
		return nil, nil
	}
	var out []string
	for k := len(segs) - 1; k > 0; k-- {
		out = append(out, joinSegments(segs[:k]))
	}
	return out, nil
}

func Join(elem ...string) string {
	if len(elem) == 0 {
		return "/"
	}
	return path.Clean("/" + path.Join(elem...))
}
