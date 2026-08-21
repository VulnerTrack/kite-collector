package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

func TestWriteLine(t *testing.T) {
	assert.NotPanics(t, func() { writeLine(nil, "ignored") })

	var buf bytes.Buffer
	writeLine(&buf, "  ✓  osquery ready")
	assert.Equal(t, "  ✓  osquery ready\n", buf.String())
}

func TestLogEvent_NilLogIsSafe(t *testing.T) {
	assert.NotPanics(t, func() {
		logEvent(nil, "code.x", "message", "k", "v")
	})
}

func TestResolveBundleInstallDir_NoPriorInstallKeepsOptions(t *testing.T) {
	// Linux builds always report a fresh install (dpkg/rpm own the
	// duplicate-install guarantee), so the options pass through untouched
	// and nothing is written to the progress writer.
	opts := installer.Options{BinaryDir: "/opt/kite", CertsDir: "/etc/kite/certs"}
	var buf bytes.Buffer

	got := resolveBundleInstallDir(opts, &buf, nil)

	assert.Equal(t, opts, got)
	assert.Empty(t, buf.String(), "no prior install → no detection line")
}

func TestBundledOsqueryHelpers_NoopOnPlainBuild(t *testing.T) {
	if installer.BundleAvailable() {
		t.Skip("bundle build: install/uninstall would touch the real service manager")
	}

	var buf bytes.Buffer
	require.NoError(t, installBundledOsquery(installer.Options{}, &buf, nil))
	assert.Empty(t, buf.String(), "plain build install is silent")

	require.NoError(t, uninstallBundledOsquery(installer.Options{}))
}

func TestSetHideWindow_NoopOffWindows(t *testing.T) {
	assert.NotPanics(t, func() { setHideWindow(nil) })
}
