package main

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// Without --with-osquery a plain build must not touch the sibling daemon at
// all: registering a machine-wide service is not something `install` gets to
// do because it happened to find osqueryd on the host.
func TestInstallSiblingOsquery_NotRequestedIsSilent(t *testing.T) {
	if installer.BundleAvailable() {
		t.Skip("bundle artifact always installs its payload")
	}
	var buf bytes.Buffer
	require.NoError(t, installSiblingOsquery(installer.Options{}, false, &buf, nil))
	assert.Empty(t, buf.String())
}

// A flag that silently does nothing is worse than one that says why. On Linux
// and Windows the kite-collector-osquery package owns kite-osqueryd, and a
// second registration would shadow the packaged unit.
func TestInstallSiblingOsquery_RefusedOffDarwin(t *testing.T) {
	if installer.BundleAvailable() || installer.HostOsqueryInstallSupported() {
		t.Skip("this platform has a lane that accepts the flag")
	}
	var buf bytes.Buffer
	err := installSiblingOsquery(installer.Options{}, true, &buf, nil)

	require.Error(t, err)
	assert.True(t, errors.Is(err, installer.ErrHostOsqueryUnsupported))
	assert.Contains(t, err.Error(), "kite-collector-osquery",
		"the refusal must name the package that does own the daemon here")
}

func TestPrintOsqueryPlan_NotRequestedPrintsNothing(t *testing.T) {
	if installer.BundleAvailable() {
		t.Skip("bundle artifact always plans its payload")
	}
	var buf bytes.Buffer
	printOsqueryPlan(&buf, installer.Options{}, false)
	assert.Empty(t, buf.String())
}

// The point of a dry run is to learn whether --with-osquery would find a
// daemon BEFORE a system service gets registered, so detection runs for real.
func TestPrintOsqueryPlan_ReportsWhatWouldHappen(t *testing.T) {
	if installer.BundleAvailable() {
		t.Skip("bundle artifact plans a different lane")
	}
	var buf bytes.Buffer
	printOsqueryPlan(&buf, installer.Options{CertsDir: t.TempDir()}, true)
	out := buf.String()
	require.NotEmpty(t, out, "an explicit --with-osquery must always be accounted for")

	if !installer.HostOsqueryInstallSupported() {
		assert.Contains(t, out, "REFUSED")
		assert.Contains(t, out, runtime.GOOS)
		return
	}
	if _, found := installer.DetectHostOsqueryd(); !found {
		assert.Contains(t, out, "no osqueryd found")
		return
	}
	assert.Contains(t, out, installer.OsquerySvcName)
	assert.Contains(t, out, installer.OsqueryExtensionsEndpoint())
}

// Uninstall tears down both lanes, not just the one this binary could have
// installed: an operator who ran `install --with-osquery` and later moved to
// the bundle artifact must still end up with zero kite-osqueryd registrations.
func TestUninstallBundledOsquery_SafeOnEveryPlatform(t *testing.T) {
	assert.NotPanics(t, func() {
		_ = uninstallBundledOsquery(installer.Options{CertsDir: t.TempDir()})
	})
}

func TestInstallHelpDocumentsTheOsqueryFlag(t *testing.T) {
	cmd := newInstallCmd()
	flag := cmd.Flags().Lookup("with-osquery")
	require.NotNil(t, flag, "--with-osquery must be registered")
	assert.Contains(t, strings.ToLower(flag.Usage), "osqueryd")
	assert.Contains(t, cmd.Long, "kite-osqueryd",
		"the long help must name the service the flag registers")
}
