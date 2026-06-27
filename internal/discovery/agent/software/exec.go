package software

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
	// maxOutputBytes is the maximum number of bytes read from a package
	// manager's stdout. This prevents unbounded memory usage when a
	// collector produces unexpectedly large output.
	maxOutputBytes = 64 << 20 // 64 MB

	// maxStderrBytes caps the captured stderr from a tolerant exec.
	// Stderr is typically a handful of warnings (kilobytes); 1 MB is
	// enough to capture diagnostic messages without risking OOM if a
	// misbehaving CLI prints heavily to stderr.
	maxStderrBytes = 1 << 20 // 1 MB

	// execTimeout is the wall-clock limit for any single package manager
	// invocation.
	execTimeout = 60 * time.Second
)

// cappedBuffer is a write-only bytes.Buffer that silently drops anything
// beyond max bytes. Used to bound captured stderr without risking OOM.
type cappedBuffer struct {
	bytes.Buffer
	max int
}

// Write implements io.Writer with a hard byte cap. bytes.Buffer.Write
// never returns an error (per its documented contract), so we deliberately
// drop the unused error return rather than propagate a value that is
// always nil.
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

// runWithLimits executes a command with a 60-second timeout and reads at most
// 64 MB of stdout. A non-zero exit code is folded into the returned error;
// callers that want to tolerate exit codes (e.g. composer/pipx, which exit
// 1 on the benign "no packages" condition) should use
// runWithLimitsTolerateExit instead.
func runWithLimits(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, _, exitCode, err := runWithLimitsTolerateExit(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("wait %s: exit status %d", name, exitCode)
	}
	return out, nil
}

// runWithLimitsTolerateExit is the form used by collectors whose underlying
// CLI exits non-zero on benign conditions (composer with no project, pipx
// with no venvs, etc.). It returns the captured stdout, the captured stderr
// (bounded to maxStderrBytes), and the raw exit code, never folding a
// non-zero exit into the error.
//
// err is non-nil only for fatal failures: context cancellation, exec
// setup failure, or stdout read failure. A non-zero exitCode with a nil
// err is the caller's signal to inspect stdout (it may still contain a
// usable JSON payload) and stderr (which often carries actionable
// diagnostics like "run pipx reinstall-all") to decide the policy.
func runWithLimitsTolerateExit(ctx context.Context, name string, args ...string) (stdout, stderr []byte, exitCode int, err error) {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...) //#nosec G204 -- callers pass hardcoded binary names, not user input

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
