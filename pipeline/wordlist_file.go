package pipeline

import (
	"fmt"
	"os"
)

func writeWordlist(lines []string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "obscura-wl-*.txt")
	if err != nil {
		return "", nil, err
	}
	path = f.Name()
	cleanup = func() { _ = os.Remove(path) }
	for _, line := range lines {
		if _, err := fmt.Fprintln(f, line); err != nil {
			_ = f.Close()
			cleanup()
			return "", nil, err
		}
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}
