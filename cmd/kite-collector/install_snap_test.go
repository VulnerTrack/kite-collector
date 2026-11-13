package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

func fakeSnapctl(t *testing.T, body string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("snapctl is Linux-only")
	}
	binDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "snapctl"), []byte("#!/bin/sh\n"+body), 0o700))
	t.Setenv("PATH", binDir)
	t.Setenv("SNAP", "/snap/kite-collector/42")
	t.Setenv("SNAP_COMMON", filepath.Join(t.TempDir(), "common"))
}

func TestRunSnapInstallStartsServiceBeforeEnrollment(t *testing.T) {
	fakeSnapctl(t, "printf '%s' \"$*\" > \"$KITE_TEST_SNAP_CALL\"\n")
	callFile := filepath.Join(t.TempDir(), "call")
	t.Setenv("KITE_TEST_SNAP_CALL", callFile)
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	require.NoError(t, runSnapInstall(cmd, installArgs{}))
	call, err := os.ReadFile(callFile)
	require.NoError(t, err)
	assert.Equal(t, "start --enable "+installer.SnapServiceName, string(call))
}

func TestRunSnapInstallReportsStartFailure(t *testing.T) {
	fakeSnapctl(t, "echo 'service unavailable' >&2\nexit 1\n")
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	err := runSnapInstall(cmd, installArgs{})
	require.ErrorContains(t, err, "service unavailable")
	assert.Contains(t, out.String(), "service start failed")
}

func TestRunSnapInstallHonorsExplicitNoStart(t *testing.T) {
	fakeSnapctl(t, "exit 1\n")
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	require.NoError(t, runSnapInstall(cmd, installArgs{noStart: true}))
	assert.NotContains(t, out.String(), "service start failed")
}

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

	certsDir := filepath.Join(commonDir, "certs")
	assert.DirExists(t, certsDir)
	assert.Contains(t, out.String(), "binary installed and updates managed by snapd")
	assert.Contains(t, out.String(), certsDir)
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

func TestDefaultKiteDataDirUsesSnapCertsSubdirectory(t *testing.T) {
	t.Setenv("SNAP", "/snap/kite-collector/42")
	t.Setenv("SNAP_COMMON", "/var/snap/kite-collector/common")
	t.Setenv("XDG_DATA_HOME", "")

	assert.Equal(t, "/var/snap/kite-collector/common/certs", defaultKiteDataDir())
}
