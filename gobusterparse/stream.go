package gobusterparse

import (
	"bufio"
	"encoding/json"
	"io"
)

const defaultMaxToken = 1024 * 1024

type StreamOptions struct {
	Mode Mode

	MaxLineBytes int
}

func Stream(r io.Reader, opts StreamOptions, emit func(Record) error) error {
	max := opts.MaxLineBytes
	if max <= 0 {
		max = defaultMaxToken
	}
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, max)
	for sc.Scan() {
		rec, ok := ParseLine(opts.Mode, sc.Text())
		if !ok {
			continue
		}
		if err := emit(rec); err != nil {
			return err
		}
	}
	return sc.Err()
}

func StreamJSONLines(w io.Writer, r io.Reader, opts StreamOptions) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return Stream(r, opts, func(rec Record) error {
		return enc.Encode(rec)
	})
}
