package driver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"
)

const (
	// maxOutputBytes is the bytes-stdout cap per RFC-0128 R16 (64 MB).
	maxOutputBytes = 64 << 20

	// maxStderrBytes caps captured stderr to a manageable diagnostic budget.
	maxStderrBytes = 1 << 20

	// execTimeout is the wall-clock cap per RFC-0128 R16 (60 s).
	execTimeout = 60 * time.Second
)

// cappedBuffer drops bytes beyond max — used for stderr without OOM risk.
type cappedBuffer struct {
	bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	remaining := c.max - c.Len()
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) <= remaining {
		_, _ = c.Buffer.Write(p)
		return len(p), nil
	}
	_, _ = c.Buffer.Write(p[:remaining])
	return len(p), nil
}

// runWithLimits executes a command under the RFC-0128 timeout/output caps.
// Non-zero exit codes fold into the returned error.
func runWithLimits(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, _, code, err := runWithLimitsTolerateExit(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("wait %s: exit status %d", name, code)
	}
	return out, nil
}

// runWithLimitsTolerateExit runs a command and returns stdout+stderr+exitCode
// without folding exit code into err. Useful for CLIs that exit non-zero on
// benign conditions.
func runWithLimitsTolerateExit(ctx context.Context, name string, args ...string) (stdout, stderr []byte, exitCode int, err error) {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...) //#nosec G204 -- callers pass hardcoded binary names

	stderrBuf := &cappedBuffer{max: maxStderrBytes}
	cmd.Stderr = stderrBuf

	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("stdout pipe: %w", err)
	}
	if err = cmd.Start(); err != nil {
		return nil, nil, 0, fmt.Errorf("start %s: %w", name, err)
	}

	stdout, err = io.ReadAll(io.LimitReader(pipe, maxOutputBytes))
	if err != nil {
		_ = cmd.Wait()
		return nil, nil, 0, fmt.Errorf("reading output: %w", err)
	}

	waitErr := cmd.Wait()
	stderr = stderrBuf.Bytes()
	if waitErr == nil {
		return stdout, stderr, 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return stdout, stderr, exitErr.ExitCode(), nil
	}
	return nil, stderr, 0, fmt.Errorf("wait %s: %w", name, waitErr)
}
