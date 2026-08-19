package driver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/osutil"
)

const (
	// maxOutputBytes is the bytes-stdout cap per RFC-0128 R16 (64 MB).
	maxOutputBytes = 64 << 20

	// maxStderrBytes caps captured stderr to a manageable diagnostic budget.
	maxStderrBytes = 1 << 20

	// execTimeout is the wall-clock cap per RFC-0128 R16 (60 s).
	execTimeout = 60 * time.Second

	// maxStderrErrBytes bounds the stderr excerpt folded into an
	// exit-status error — enough for real diagnostics, small enough
	// for a single log line.
	maxStderrErrBytes = 512
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
// Non-zero exit codes fold into the returned error together with a bounded
// excerpt of the tool's stderr, so a collector failure is diagnosable from
// its log line alone.
func runWithLimits(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, stderr, code, err := runWithLimitsTolerateExit(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, exitError(name, code, stderr)
	}
	return out, nil
}

// exitError renders a non-zero exit as an error carrying the tool's
// stderr excerpt.
func exitError(name string, exitCode int, stderr []byte) error {
	if tail := stderrTail(stderr); tail != "" {
		return fmt.Errorf("wait %s: exit status %d: %s", name, exitCode, tail)
	}
	return fmt.Errorf("wait %s: exit status %d", name, exitCode)
}

// stderrTail collapses captured stderr into a single space-separated
// line bounded to maxStderrErrBytes, suitable for embedding in an error.
func stderrTail(stderr []byte) string {
	s := strings.Join(strings.Fields(string(stderr)), " ")
	if len(s) > maxStderrErrBytes {
		s = s[:maxStderrErrBytes] + "…"
	}
	return s
}

// runWithLimitsTolerateExit runs a command and returns stdout+stderr+exitCode
// without folding exit code into err. Useful for CLIs that exit non-zero on
// benign conditions.
func runWithLimitsTolerateExit(ctx context.Context, name string, args ...string) (stdout, stderr []byte, exitCode int, err error) {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...) //#nosec G204 -- callers pass hardcoded binary names
	osutil.HideWindow(cmd)

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
