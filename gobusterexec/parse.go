package gobusterexec

import (
	"regexp"
	"strconv"
	"strings"
)

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

var (
	reDir = regexp.MustCompile(
		`^(.+?) \(Status: (\d+)\)(?: \[Size: (\d+)\])?(?: \[--> ([^\]]+)\])?\s*$`,
	)
	reVhost = regexp.MustCompile(
		`^(\S+)\s+Status: (\d+) \[Size: (\d+)\](?: \[--> ([^\]]+)\])?\s*$`,
	)
)

func StripANSI(s string) string {
	return ansiEscape.ReplaceAllString(s, "")
}

func ParseLine(mode Mode, line string) (hit Hit, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Hit{}, false
	}

	clean := StripANSI(line)
	hit.Mode = mode
	hit.Raw = line

	switch mode {
	case ModeDir:
		return parseDirHit(hit, clean)
	case ModeVhost:
		return parseVhostHit(hit, clean)
	case ModeDNS:
		return parseDNSHit(hit, clean)
	default:
		return Hit{}, false
	}
}

func parseDirHit(hit Hit, clean string) (Hit, bool) {
	m := reDir.FindStringSubmatch(clean)
	if m == nil {
		return Hit{}, false
	}
	code, _ := strconv.Atoi(m[2])
	hit.Path = m[1]
	hit.StatusCode = &code
	if m[3] != "" {
		sz, _ := strconv.ParseInt(m[3], 10, 64)
		hit.Size = &sz
	}
	hit.Location = strings.TrimSpace(m[4])
	return hit, true
}

func parseVhostHit(hit Hit, clean string) (Hit, bool) {
	m := reVhost.FindStringSubmatch(clean)
	if m == nil {
		return Hit{}, false
	}
	code, _ := strconv.Atoi(m[2])
	sz, _ := strconv.ParseInt(m[3], 10, 64)
	hit.Path = m[1]
	hit.StatusCode = &code
	hit.Size = &sz
	hit.Location = strings.TrimSpace(m[4])
	return hit, true
}

func parseDNSHit(hit Hit, clean string) (Hit, bool) {

	line := clean
	if idx := strings.Index(line, " CNAME: "); idx >= 0 {
		hit.CNAME = strings.TrimSpace(line[idx+len(" CNAME: "):])
		line = strings.TrimSpace(line[:idx])
	}
	sp := strings.IndexByte(line, ' ')
	if sp < 0 {
		hit.Path = line
		return hit, hit.Path != ""
	}
	hit.Path = strings.TrimSpace(line[:sp])
	rest := strings.TrimSpace(line[sp+1:])
	if rest == "" {
		return hit, true
	}
	parts := strings.Split(rest, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	hit.IPs = parts
	return hit, true
}
