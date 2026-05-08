package gobusterexec

import (
	"errors"
	"fmt"
)

var (
	ErrBinaryNotFound = errors.New("gobuster: executable not found")

	ErrInvalidArgs = errors.New("gobuster: invalid arguments")
)

type RunError struct {
	ExitCode int
	Err      error
}

func (e *RunError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("gobuster exited with code %d: %v", e.ExitCode, e.Err)
	}
	return fmt.Sprintf("gobuster exited with code %d", e.ExitCode)
}

func (e *RunError) Unwrap() error {
	return e.Err
}
