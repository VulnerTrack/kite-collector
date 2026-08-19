package driver

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
// returns its absolute path. Used to simulate driver-enumeration CLIs
// with controlled stdout/stderr/exit behavior.
func writeFakeTool(t *testing.T, name, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-tool shell scripts are not runnable on windows")
	}
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755))
	return path
}

// Reproduces the field failure signature "driver: collector failed ...
// error: kmutil showloaded: wait /usr/bin/kmutil: exit status 1" — the
// exit-status error must carry the tool's stderr so operators can
// diagnose the failure from the log line alone.
func TestRunWithLimits_NonZeroExitIncludesStderr(t *testing.T) {
	bin := writeFakeTool(t, "failing-tool", `echo "Error: unknown option '--no-symbols'" >&2
exit 1
`)
	_, err := runWithLimits(context.Background(), bin)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exit status 1")
	assert.Contains(t, err.Error(), "unknown option '--no-symbols'",
		"the tool's stderr must be folded into the error for diagnosability")
}
