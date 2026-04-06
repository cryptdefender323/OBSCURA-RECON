package pipeline

import "errors"

var (
	ErrNoTarget   = errors.New("pipeline: TargetURL is required")
	ErrNoWordlist = errors.New("pipeline: base wordlist path or BaseLines required")
)
