package main

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// osquery is optional on every platform, so the check must never fail a
// doctor run — a host without osqueryd is a supported configuration, not a
// broken one. Fixing this to "fail" would make `doctor` exit non-zero in CI
// for every containerized agent.
func TestDoctorOsqueryCheck_NeverFails(t *testing.T) {
	got := doctorOsqueryCheck(context.Background(), installer.Options{CertsDir: t.TempDir()}, time.Second)

	assert.Equal(t, "osquery", got.Name)
	assert.NotEqual(t, doctorFail, got.Status)
	assert.Contains(t, []string{doctorPass, doctorWarn, doctorSkip}, got.Status)
	assert.NotEmpty(t, got.Detail, "every outcome must say what it found")
}

// A host with no daemon and no socket must point at the platform's actual way
// of getting one, not at a generic shrug.
func TestDoctorOsqueryCheck_HintNamesThePlatformLane(t *testing.T) {
	got := doctorOsqueryCheck(context.Background(), installer.Options{CertsDir: t.TempDir()}, time.Second)
	if got.Status != doctorSkip {
		t.Skip("this host has an osquery socket; the remediation hint is not exercised")
	}
	require.NotEmpty(t, got.Hint)
	if installer.HostOsqueryInstallSupported() {
		assert.Contains(t, got.Hint, "--with-osquery")
	} else {
		assert.Contains(t, got.Hint, "kite-collector-osquery")
	}
}

// The Full Disk Access caveat is the one thing a green osquery check cannot
// rule out on macOS, so a passing check has to carry it.
func TestOsqueryReadHint_FullDiskAccessOnDarwinOnly(t *testing.T) {
	hint := osqueryReadHint()
	if runtime.GOOS != "darwin" {
		assert.Empty(t, hint, "TCC is a macOS concept")
		return
	}
	assert.Contains(t, strings.ToLower(hint), "full disk access")
}

func TestDoctorRunIncludesTheOsqueryStage(t *testing.T) {
	checks := runDoctorChecks(context.Background(), doctorOptions{
		CertsDir: t.TempDir(),
		Offline:  true,
	})
	var found bool
	for _, c := range checks {
		if c.Name == "osquery" {
			found = true
		}
	}
	assert.True(t, found, "the osquery stage must be part of a normal doctor run")
}
