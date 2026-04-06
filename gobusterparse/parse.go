package gobusterparse

import (
	"strings"
	"unicode"
)

const (
	dirStatusPrefix  = " (Status: "
	vhostStatusToken = " Status: "
	sizeOpen         = "[Size: "
)

func StripANSI(s string) string {
	if strings.IndexByte(s, '\x1b') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				i = j + 1
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func ParseLine(mode Mode, line string) (rec Record, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Record{}, false
	}
	clean := StripANSI(line)
	switch mode {
	case ModeDir:
		return parseDirRecord(clean)
	case ModeVhost:
		return parseVhostRecord(clean)
	case ModeDNS:
		return parseDNSRecord(clean)
	default:
		return Record{}, false
	}
}

func parseDirRecord(clean string) (Record, bool) {
	idx := strings.Index(clean, dirStatusPrefix)
	if idx <= 0 {
		return Record{}, false
	}
	path := strings.TrimRightFunc(clean[:idx], unicode.IsSpace)
	if path == "" {
		return Record{}, false
	}
	rest := clean[idx+len(dirStatusPrefix):]
	code, rest, ok := parseUintPrefix(rest)
	if !ok || len(rest) == 0 || rest[0] != ')' {
		return Record{}, false
	}
	rest = strings.TrimSpace(rest[1:])
	rec := Record{Path: path}
	rec.StatusCode = new(int)
	*rec.StatusCode = int(code)
	if after, ok := consumeSizeSuffix(rest); ok {
		rec.ResponseLength = new(int64)
		*rec.ResponseLength = int64(after)
	}
	return rec, true
}

func parseVhostRecord(clean string) (Record, bool) {
	idx := strings.Index(clean, vhostStatusToken)
	if idx <= 0 {
		return Record{}, false
	}
	path := strings.TrimRightFunc(clean[:idx], unicode.IsSpace)
	if path == "" {
		return Record{}, false
	}
	rest := strings.TrimSpace(clean[idx+len(vhostStatusToken):])
	code, rest, ok := parseUintPrefix(rest)
	if !ok {
		return Record{}, false
	}
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, sizeOpen) {
		return Record{}, false
	}
	rest = rest[len(sizeOpen):]
	sz, rest2, ok := parseUintPrefix(rest)
	if !ok || len(rest2) == 0 || rest2[0] != ']' {
		return Record{}, false
	}
	rec := Record{Path: path}
	rec.StatusCode = new(int)
	*rec.StatusCode = int(code)
	rec.ResponseLength = new(int64)
	*rec.ResponseLength = int64(sz)
	return rec, true
}

func parseDNSRecord(clean string) (Record, bool) {
	line := clean
	if i := strings.Index(line, " CNAME: "); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	sp := strings.IndexByte(line, ' ')
	if sp < 0 {
		host := strings.TrimSpace(line)
		if host == "" {
			return Record{}, false
		}
		return Record{Path: host}, true
	}
	host := strings.TrimSpace(line[:sp])
	if host == "" {
		return Record{}, false
	}
	return Record{Path: host}, true
}

func parseUintPrefix(s string) (n uint64, rest string, ok bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		n = n*10 + uint64(s[i]-'0')
		i++
	}
	if i == 0 {
		return 0, s, false
	}
	return n, s[i:], true
}

func consumeSizeSuffix(rest string) (uint64, bool) {
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, sizeOpen) {
		return 0, false
	}
	rest = rest[len(sizeOpen):]
	n, tail, ok := parseUintPrefix(rest)
	if !ok || len(tail) == 0 || tail[0] != ']' {
		return 0, false
	}
	return n, true
}
