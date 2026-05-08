package gobusterexec

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
)

type Runner struct {
	Path string
}

func NewRunner(path string) *Runner {
	if path == "" {
		path = "gobuster"
	}
	return &Runner{Path: path}
}

type Options struct {
	Mode Mode

	Args []string

	OnHit func(Hit) error

	OnStdoutLine func(string)

	OnStderrLine func(string)

	Stderr io.Writer
}

func (r *Runner) Run(ctx context.Context, opt Options) error {
	if len(opt.Args) == 0 {
		return fmt.Errorf("%w: args is empty", ErrInvalidArgs)
	}
	if opt.Mode != ModeDir && opt.Mode != ModeDNS && opt.Mode != ModeVhost {
		return fmt.Errorf("%w: unknown mode %q", ErrInvalidArgs, opt.Mode)
	}

	cmd := exec.CommandContext(ctx, r.Path, opt.Args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("gobuster stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("gobuster stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return fmt.Errorf("%w: %q", ErrBinaryNotFound, r.Path)
		}
		return fmt.Errorf("gobuster start: %w", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		s := bufio.NewScanner(stderr)
		for s.Scan() {
			line := s.Text()
			if opt.OnStderrLine != nil {
				opt.OnStderrLine(line)
			}
			if opt.Stderr != nil {
				_, _ = fmt.Fprintln(opt.Stderr, line)
			}
		}
		if err := s.Err(); err != nil {
			errCh <- fmt.Errorf("gobuster stderr read: %w", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			line := s.Text()
			if opt.OnStdoutLine != nil {
				opt.OnStdoutLine(line)
			}
			if hit, ok := ParseLine(opt.Mode, line); ok && opt.OnHit != nil {
				if err := opt.OnHit(hit); err != nil {
					errCh <- err
					_ = cmd.Cancel()
					return
				}
			}
		}
		if err := s.Err(); err != nil {
			errCh <- fmt.Errorf("gobuster stdout read: %w", err)
		}
	}()

	wg.Wait()
	close(errCh)
	for e := range errCh {
		if e != nil {
			_ = cmd.Wait()
			return e
		}
	}

	waitErr := cmd.Wait()
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			return &RunError{ExitCode: ee.ExitCode(), Err: waitErr}
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return ctx.Err()
		}
		return fmt.Errorf("gobuster wait: %w", waitErr)
	}
	return nil
}

func (r *Runner) CollectHits(ctx context.Context, mode Mode, args []string, stderr io.Writer) ([]Hit, error) {
	var hits []Hit
	err := r.Run(ctx, Options{
		Mode:   mode,
		Args:   args,
		Stderr: stderr,
		OnHit: func(h Hit) error {
			hits = append(hits, h)
			return nil
		},
	})
	return hits, err
}

func (r *Runner) SummaryJSON(ctx context.Context, mode Mode, args []string, stderr io.Writer) ([]byte, error) {
	hits, err := r.CollectHits(ctx, mode, args, stderr)
	sum := RunSummary{
		Mode: mode,
		Hits: hits,
	}
	if err != nil {
		var re *RunError
		if errors.As(err, &re) {
			sum.ExitCode = re.ExitCode
		} else {
			sum.ExitCode = -1
		}
		sum.Error = err.Error()
	} else {
		sum.ExitCode = 0
	}
	return json.Marshal(sum)
}
