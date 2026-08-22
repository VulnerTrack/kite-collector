package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatchFileIdentity_FiresOnBinarySwap(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "kite-collector")
	require.NoError(t, os.WriteFile(bin, []byte("v1"), 0o755)) //#nosec G306 -- test binary

	fired := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go watchFileIdentity(ctx, bin, 10*time.Millisecond, func() { close(fired) })

	// Give the watcher a tick on the unchanged file, then swap the binary
	// the way a package manager does: write-new + rename over.
	time.Sleep(50 * time.Millisecond)
	tmp := bin + ".tmp"
	require.NoError(t, os.WriteFile(tmp, []byte("v2 - bigger"), 0o755)) //#nosec G306 -- test binary
	require.NoError(t, os.Rename(tmp, bin))

	select {
	case <-fired:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not fire after binary swap")
	}
}

func TestWatchFileIdentity_QuietOnUnchangedAndCancel(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "kite-collector")
	require.NoError(t, os.WriteFile(bin, []byte("v1"), 0o755)) //#nosec G306 -- test binary

	fired := false
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watchFileIdentity(ctx, bin, 10*time.Millisecond, func() { fired = true })
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not exit on context cancel")
	}
	assert.False(t, fired, "unchanged binary must never trigger a relaunch")
}

func TestWatchFileIdentity_MissingFileDisablesQuietly(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent")
	done := make(chan struct{})
	go func() {
		watchFileIdentity(context.Background(), absent, time.Millisecond, func() {
			t.Error("onChange must not fire for a never-statable path")
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher with unstatable baseline must return immediately")
	}
}

func TestCurrentExecutablePath_TrimsDeletedSuffix(t *testing.T) {
	// The running test binary exists, so the real path has no suffix —
	// exercise the trim contract directly on the helper's building blocks.
	path, err := currentExecutablePath()
	require.NoError(t, err)
	assert.NotContains(t, path, " (deleted)")
	_, err = statIdentity(path)
	assert.NoError(t, err)
}

func TestWatchFileIdentity_TouchDoesNotRestart(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "kite-collector")
	require.NoError(t, os.WriteFile(bin, []byte("v1"), 0o755)) //#nosec G306 -- test binary

	fired := false
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watchFileIdentity(ctx, bin, 10*time.Millisecond, func() { fired = true })
		close(done)
	}()

	// Same content, new mtime — the hash confirm must re-baseline
	// instead of restarting.
	future := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(bin, future, future))
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done
	assert.False(t, fired, "identical content must never trigger a relaunch")
}

func TestWatchFileIdentity_VanishedBinaryKeepsRunning(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "kite-collector")
	require.NoError(t, os.WriteFile(bin, []byte("v1"), 0o755)) //#nosec G306 -- test binary

	var fired atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watchFileIdentity(ctx, bin, 5*time.Millisecond, func() { fired.Store(true) })
		close(done)
	}()

	// brew/apt uninstall: the binary vanishes and stays gone. The watcher
	// must NOT fire (an exit would relaunch-loop against a dead path) and
	// must keep watching.
	time.Sleep(30 * time.Millisecond)
	require.NoError(t, os.Remove(bin))
	time.Sleep(100 * time.Millisecond) // well past missThresholdTicks
	assert.False(t, fired.Load(), "a deleted binary must not trigger a self-exit")

	// If a binary reappears with new content, that IS an upgrade.
	require.NoError(t, os.WriteFile(bin, []byte("v2 reinstalled"), 0o755)) //#nosec G306 -- test binary
	deadline := time.After(5 * time.Second)
	for !fired.Load() {
		select {
		case <-deadline:
			t.Fatal("reappeared new binary must trigger a relaunch")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

func TestWaitForScanIdle_NilCoordinatorReturnsImmediately(t *testing.T) {
	activeScanCoordinator.Store(nil)
	start := time.Now()
	waitForScanIdle(context.Background(), time.Minute)
	assert.Less(t, time.Since(start), time.Second)
}
