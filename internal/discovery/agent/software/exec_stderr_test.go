package software

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeFakeTool drops an executable shell script into a temp dir and
// returns its absolute path. Used to simulate package-manager CLIs with
// controlled stdout/stderr/exit behavior.
func writeFakeTool(t *testing.T, name, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-tool shell scripts are not runnable on windows")
	}
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755))
	return path
}

// fakeToolOnPath drops an executable shell script named name into a temp
// dir and prepends that dir to PATH so exec.LookPath / exec.Command
// resolve it. Returns the directory.
func fakeToolOnPath(t *testing.T, name, script string) string {
	t.Helper()
	path := writeFakeTool(t, name, script)
	dir := filepath.Dir(path)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

// Reproduces the field failure signature "software: collector failed ...
// error: wait <bin>: exit status 1" — the exit-status error must carry
// the tool's stderr so operators can diagnose the failure from the log
// line alone.
func TestRunWithLimits_NonZeroExitIncludesStderr(t *testing.T) {
	bin := writeFakeTool(t, "failing-tool", `echo "boom: actionable diagnostic" >&2
exit 1
`)
	_, err := runWithLimits(context.Background(), bin)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exit status 1")
	assert.Contains(t, err.Error(), "boom: actionable diagnostic",
		"the tool's stderr must be folded into the error for diagnosability")
}

func TestRunWithLimits_ZeroExitReturnsStdout(t *testing.T) {
	bin := writeFakeTool(t, "ok-tool", `echo "pkg 1.0"
echo "warning noise" >&2
exit 0
`)
	out, err := runWithLimits(context.Background(), bin)
	require.NoError(t, err)
	assert.Equal(t, "pkg 1.0\n", string(out))
}

func TestRunWithLimits_StderrTailTruncated(t *testing.T) {
	// A tool that floods stderr must not produce an unbounded error string.
	bin := writeFakeTool(t, "flood-tool", `i=0
while [ $i -lt 200 ]; do echo "0123456789012345678901234567890123456789" >&2; i=$((i+1)); done
exit 1
`)
	_, err := runWithLimits(context.Background(), bin)
	require.Error(t, err)
	assert.LessOrEqual(t, len(err.Error()), 2048,
		"error string must be bounded even when the tool floods stderr")
}
