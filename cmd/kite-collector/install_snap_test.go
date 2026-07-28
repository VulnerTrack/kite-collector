package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

func TestRunInstallInsideSnapDoesNotCopyToHost(t *testing.T) {
	commonDir := filepath.Join(t.TempDir(), "common")
	t.Setenv("SNAP", "/snap/kite-collector/42")
	t.Setenv("SNAP_COMMON", commonDir)

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)

	require.NoError(t, runInstall(cmd, installArgs{
		binaryDir: "/usr/local/bin",
		certsDir:  "/var/lib/kite-collector",
		noStart:   true,
	}))

	assert.DirExists(t, commonDir)
	assert.Contains(t, out.String(), "binary installed and updates managed by snapd")
	assert.Contains(t, out.String(), commonDir)
	assert.Contains(t, out.String(), installer.SnapServiceName)
	assert.NotContains(t, out.String(), "/usr/local/bin")
	assert.NotContains(t, out.String(), "/var/lib/kite-collector")
}

func TestRunInstallInsideSnapDryRunIsNonMutating(t *testing.T) {
	commonDir := filepath.Join(t.TempDir(), "common")
	t.Setenv("SNAP", "/snap/kite-collector/42")
	t.Setenv("SNAP_COMMON", commonDir)

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)

	require.NoError(t, runInstall(cmd, installArgs{dryRun: true}))
	assert.NoDirExists(t, commonDir)
	assert.Contains(t, out.String(), "binary and service are managed by snapd")
	assert.Contains(t, out.String(), "enable service "+installer.SnapServiceName)
}

func TestDefaultKiteDataDirUsesSnapCommon(t *testing.T) {
	t.Setenv("SNAP", "/snap/kite-collector/42")
	t.Setenv("SNAP_COMMON", "/var/snap/kite-collector/common")
	t.Setenv("XDG_DATA_HOME", "")

	assert.Equal(t, "/var/snap/kite-collector/common", defaultKiteDataDir())
}
