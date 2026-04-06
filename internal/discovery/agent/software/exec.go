package software

import (
	"context"
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
// 64 MB of stdout. If the output exceeds the limit the excess is silently
// discarded but the partial result is still returned.
func runWithLimits(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...) //#nosec G204 -- callers pass hardcoded binary names, not user input
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err = cmd.Start(); err != nil {
		return nil, err
	}

	out, err := io.ReadAll(io.LimitReader(pipe, maxOutputBytes))
	if err != nil {
		return nil, fmt.Errorf("reading output: %w", err)
	}

	if err = cmd.Wait(); err != nil {
		return nil, err
	}

	return out, nil
}
