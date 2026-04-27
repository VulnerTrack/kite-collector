package software

import (
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

	// execTimeout is the wall-clock limit for any single package manager
	// invocation.
	execTimeout = 60 * time.Second
)

// runWithLimits executes a command with a 60-second timeout and reads at most
// 64 MB of stdout. A non-zero exit code is folded into the returned error;
// callers that want to tolerate exit codes (e.g. composer/pipx, which exit
// 1 on the benign "no packages" condition) should use
// runWithLimitsTolerateExit instead.
func runWithLimits(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, exitCode, err := runWithLimitsTolerateExit(ctx, name, args...)
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
// with no venvs, etc.). It returns whatever stdout was captured plus the
// raw exit code, never folding a non-zero exit into the error.
//
// err is non-nil only for fatal failures: context cancellation, exec
// setup failure, or stdout read failure. A non-zero exitCode with a nil
// err is the caller's signal to inspect stdout (it may still contain a
// usable JSON payload) and decide the policy.
func runWithLimitsTolerateExit(ctx context.Context, name string, args ...string) (out []byte, exitCode int, err error) {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...) //#nosec G204 -- callers pass hardcoded binary names, not user input
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, fmt.Errorf("stdout pipe: %w", err)
	}

	if err = cmd.Start(); err != nil {
		return nil, 0, fmt.Errorf("start %s: %w", name, err)
	}

	out, err = io.ReadAll(io.LimitReader(pipe, maxOutputBytes))
	if err != nil {
		_ = cmd.Wait()
		return nil, 0, fmt.Errorf("reading output: %w", err)
	}

	waitErr := cmd.Wait()
	if waitErr == nil {
		return out, 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return out, exitErr.ExitCode(), nil
	}
	return nil, 0, fmt.Errorf("wait %s: %w", name, waitErr)
}
