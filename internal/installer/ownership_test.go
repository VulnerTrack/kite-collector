package installer

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyBinary_HomebrewCaskSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix ownership classification")
	}
	// Fake brew prefix: <prefix>/Caskroom/kite-collector/1.0/kite-collector
	// with the conventional <prefix>/bin symlink pointing at it.
	prefix := t.TempDir()
	payloadDir := filepath.Join(prefix, "Caskroom", "kite-collector", "1.0")
	require.NoError(t, os.MkdirAll(payloadDir, 0o755))
	payload := filepath.Join(payloadDir, BinaryName())
	require.NoError(t, os.WriteFile(payload, []byte("bin"), 0o755)) //#nosec G306 -- test binary
	binDir := filepath.Join(prefix, "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	link := filepath.Join(binDir, BinaryName())
	require.NoError(t, os.Symlink(payload, link))

	// Invoked via the prefix-bin symlink (the common PATH-resolved case).
	owner := ClassifyBinary(link)
	assert.Equal(t, "homebrew", owner.Manager)
	assert.Equal(t, link, owner.StablePath,
		"stable path must be the prefix-bin symlink brew re-points on upgrade")

	// Invoked via the Caskroom payload directly — stable path still
	// resolves to the prefix-bin symlink, not the versioned payload.
	owner = ClassifyBinary(payload)
	assert.Equal(t, "homebrew", owner.Manager)
	assert.Equal(t, link, owner.StablePath)
}

func TestClassifyBinary_PackageDBOwned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix ownership classification")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, BinaryName())
	require.NoError(t, os.WriteFile(bin, []byte("bin"), 0o755)) //#nosec G306 -- test binary

	origLook, origExec := lookPath, execCommand
	t.Cleanup(func() { lookPath, execCommand = origLook, origExec })

	// Only dpkg "exists", and it claims the file.
	lookPath = func(name string) (string, error) {
		if name == "dpkg" {
			return "/usr/bin/dpkg", nil
		}
		return "", exec.ErrNotFound
	}
	execCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "echo", "kite-collector: "+bin)
	}

	owner := ClassifyBinary(bin)
	assert.Equal(t, "dpkg", owner.Manager)
	assert.Equal(t, bin, owner.StablePath)
	assert.Contains(t, owner.Detail, "kite-collector")
}

func TestClassifyBinary_UnmanagedAndDegraded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix ownership classification")
	}
	origLook := lookPath
	t.Cleanup(func() { lookPath = origLook })
	// No package managers present at all → unmanaged, copy semantics.
	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }

	dir := t.TempDir()
	bin := filepath.Join(dir, BinaryName())
	require.NoError(t, os.WriteFile(bin, []byte("bin"), 0o755)) //#nosec G306 -- test binary

	assert.False(t, ClassifyBinary(bin).Managed())
	assert.False(t, ClassifyBinary("").Managed())
	assert.False(t, ClassifyBinary(filepath.Join(dir, "absent")).Managed(),
		"unresolvable path degrades to unmanaged, never errors")
}

func TestInstallBinary_RefusesForeignSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink guard is a unix package-manager protection")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "new-binary")
	require.NoError(t, os.WriteFile(src, []byte("new"), 0o755)) //#nosec G306 -- test binary
	target := filepath.Join(dir, "payload")
	require.NoError(t, os.WriteFile(target, []byte("payload"), 0o755)) //#nosec G306 -- test binary
	dst := filepath.Join(dir, "kite-collector")
	require.NoError(t, os.Symlink(target, dst))

	err := InstallBinary(src, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to overwrite symlink")

	// The symlink must be untouched.
	fi, lerr := os.Lstat(dst)
	require.NoError(t, lerr)
	assert.NotZero(t, fi.Mode()&os.ModeSymlink)
}

func TestInstallManifest_RoundTripAndAbsent(t *testing.T) {
	opts := Options{CertsDir: t.TempDir()}

	_, ok := ReadInstallManifest(opts)
	assert.False(t, ok, "no manifest yet")

	in := InstallManifest{
		BinaryPath:   "/opt/homebrew/bin/kite-collector",
		BinaryCopied: false,
		Owner:        "homebrew",
		PackagedUnit: "/usr/lib/systemd/system/kite-collector.service",
		UserMode:     true,
	}
	require.NoError(t, WriteInstallManifest(opts, in))

	out, ok := ReadInstallManifest(opts)
	require.True(t, ok)
	assert.Equal(t, in.BinaryPath, out.BinaryPath)
	assert.False(t, out.BinaryCopied)
	assert.Equal(t, "homebrew", out.Owner)
	assert.Equal(t, in.PackagedUnit, out.PackagedUnit)
	assert.True(t, out.UserMode)
	assert.NotEmpty(t, out.WrittenAt)

	// Corrupt manifest degrades to "absent", not an error.
	require.NoError(t, os.WriteFile(InstallManifestPath(opts), []byte("{not json"), 0o640)) //#nosec G306 -- test fixture
	_, ok = ReadInstallManifest(opts)
	assert.False(t, ok)
}

func TestPackagedUnitPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd unit detection is linux-only; on linux the dirs are overridable")
	}
	origDirs := packagedUnitDirs
	t.Cleanup(func() { packagedUnitDirs = origDirs })

	// No packaged unit anywhere → "" (install registers via kardianos).
	packagedUnitDirs = []string{t.TempDir()}
	if runtime.GOOS == "linux" {
		assert.Empty(t, PackagedUnitPath())
	}

	// A package-shipped unit is found and returned.
	dir := t.TempDir()
	unit := filepath.Join(dir, SvcName+".service")
	require.NoError(t, os.WriteFile(unit, []byte("[Unit]"), 0o644)) //#nosec G306 -- test fixture unit
	packagedUnitDirs = []string{dir}
	if runtime.GOOS == "linux" {
		assert.Equal(t, unit, PackagedUnitPath())
	} else {
		assert.Empty(t, PackagedUnitPath(), "non-linux must never report a packaged unit")
	}
}
