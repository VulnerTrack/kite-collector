package software

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Reproduces the field failure "swift package show-dependencies: wait
// swift: exit status 1" seen when the agent runs from a directory that
// is not a SwiftPM package root (e.g. ~/.ssh): `swift package
// show-dependencies` requires a Package.swift at or above the working
// directory and exits 1 otherwise. That is an environment condition,
// not a collector failure — Collect must return a benign empty
// inventory.
func TestSwiftPMCollect_NoManifestIsBenign(t *testing.T) {
	fakeToolOnPath(t, "swift", `echo "error: Could not find Package.swift in this directory or any of its parent directories" >&2
exit 1
`)

	res, err := NewSwiftPM().Collect(context.Background())
	require.NoError(t, err, "a missing Package.swift must not surface as a collector failure")
	assert.Empty(t, res.Items)
	assert.Empty(t, res.Errs)
}

// Any other non-zero swift exit is a genuine failure and must surface —
// with swift's stderr folded in so the log line is diagnosable.
func TestSwiftPMCollect_OtherFailureSurfacesStderr(t *testing.T) {
	fakeToolOnPath(t, "swift", `echo "error: manifest parse error at Package.swift:3" >&2
exit 1
`)

	_, err := NewSwiftPM().Collect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "manifest parse error",
		"swift's stderr must be folded into the error for diagnosability")
}

// swiftpm is a project-scoped package manager: the collector is only
// applicable when the working directory is inside a SwiftPM package.
// A host with the swift toolchain but no Package.swift in scope must
// report the collector unavailable instead of running a command that
// is guaranteed to fail.
func TestSwiftPMAvailable_RequiresManifest(t *testing.T) {
	fakeToolOnPath(t, "swift", "exit 0\n")
	t.Chdir(t.TempDir())
	assert.False(t, NewSwiftPM().Available())
}

func TestSwiftPMAvailable_ManifestInParent(t *testing.T) {
	fakeToolOnPath(t, "swift", "exit 0\n")
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "Package.swift"), []byte("// swift-tools-version:6.0\n"), 0o644))
	nested := filepath.Join(root, "Sources", "App")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	t.Chdir(nested)
	assert.True(t, NewSwiftPM().Available())
}
