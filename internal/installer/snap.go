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
	return os.Getenv("SNAP") != "" && os.Getenv("SNAP_COMMON") != ""
}

// SnapCommonDir returns snapd's revision-independent writable data directory.
func SnapCommonDir() string {
	return filepath.Clean(os.Getenv("SNAP_COMMON"))
}
