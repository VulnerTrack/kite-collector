package installer

import (
	"os"
	"path/filepath"
)

const (
	// SnapDaemonApp is the app name declared as a daemon in .goreleaser.yaml.
	SnapDaemonApp = "kite-collector-daemon"
	// SnapServiceName is the snapd-qualified service name operators can pass
	// to `snap start`, `snap stop`, and `snap logs`.
	SnapServiceName = "kite-collector." + SnapDaemonApp
)

// RunningInSnap reports whether snapd launched the current process. SNAP is
// the read-only mount containing the installed revision; SNAP_COMMON is the
// root-owned writable directory shared by every revision.
func RunningInSnap() bool {
	snapRoot := filepath.Clean(os.Getenv("SNAP"))
	if snapRoot == "." || os.Getenv("SNAP_COMMON") == "" {
		return false
	}
	// Desktop launchers (notably VS Code installed as a snap) export their
	// SNAP_* variables to terminals and every child process. Do not mistake
	// that inherited environment for Kite itself running under snapd.
	return filepath.Base(filepath.Dir(snapRoot)) == "kite-collector"
}

// SnapCommonDir returns snapd's revision-independent writable data directory.
func SnapCommonDir() string {
	return filepath.Clean(os.Getenv("SNAP_COMMON"))
}
