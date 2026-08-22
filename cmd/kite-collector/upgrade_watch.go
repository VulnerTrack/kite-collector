package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vulnertrack/kite-collector/internal/scan"
)

// activeScanCoordinator is set by runAgent so the upgrade watcher can
// defer a self-restart until no scan is in flight. A nil pointer (agent
// not up yet, or a non-agent invocation) means "no scan to wait for".
var activeScanCoordinator atomic.Pointer[scan.Coordinator]

// missThresholdTicks is how many consecutive failed stats of the
// executable path count as "the binary is gone" rather than the sub-second
// window of a package manager's swap. At the 30s service cadence this is
// two minutes of absence — a brew/apt uninstall, not an upgrade.
const missThresholdTicks = 4

// executableIdentity is the on-disk fingerprint the upgrade watcher
// compares: size + mtime notices any package-manager swap (brew re-points
// its symlink at a new payload; dpkg/rpm/pacman replace the file) without
// platform-specific inode syscalls. A content hash confirms suspicions so
// a bare `touch` on the binary never restarts the service.
type executableIdentity struct {
	size    int64
	modTime time.Time
}

// currentExecutablePath returns the path to watch. On Linux a replaced
// binary makes /proc/self/exe read "…/kite-collector (deleted)"; the
// suffix is trimmed so the stat sees the NEW file at the original path —
// exactly the change the watcher exists to notice.
func currentExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate current executable: %w", err)
	}
	return strings.TrimSuffix(exe, " (deleted)"), nil
}

func statIdentity(path string) (executableIdentity, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return executableIdentity{}, fmt.Errorf("stat executable: %w", err)
	}
	return executableIdentity{size: fi.Size(), modTime: fi.ModTime()}, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //#nosec G304 -- path is the service's own executable
	if err != nil {
		return "", fmt.Errorf("open for hash: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash executable: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// waitForScanIdle blocks until no scan is in flight (or the timeout
// lapses), so a self-restart for an upgraded binary never truncates a
// running scan. The hard deadline guarantees a stuck scan cannot block
// upgrades forever.
func waitForScanIdle(ctx context.Context, timeout time.Duration) {
	coord := activeScanCoordinator.Load()
	if coord == nil {
		return
	}
	deadline := time.Now().Add(timeout)
	logged := false
	for time.Now().Before(deadline) {
		if _, busy := coord.Active(); !busy {
			return
		}
		if !logged {
			logged = true
			slog.Info("scan in flight — deferring upgrade restart until it completes",
				"code", string(LogCodeBinarySwapRelaunch), "max_wait", timeout.String())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
	slog.Warn("scan still running at upgrade-restart deadline — restarting anyway",
		"code", string(LogCodeBinarySwapRelaunch))
}

// watchExecutableIdentity makes package-manager upgrades zero-step: it
// polls the running service's own binary path and invokes onChange once
// when the file on disk is no longer the one that launched. The caller
// drains the agent and exits cleanly; launchd KeepAlive / systemd
// Restart=always (both set by buildSvcConfig, and by the packaged units)
// relaunch the new version. On Windows the loader keeps the running
// executable locked, so a swap-in-place cannot occur and the watcher
// simply never fires.
func watchExecutableIdentity(ctx context.Context, interval time.Duration, onChange func()) {
	path, err := currentExecutablePath()
	if err != nil {
		slog.Debug("upgrade watcher disabled: executable path unavailable",
			"code", string(LogCodeBinarySwapDetected), "error", err)
		return
	}
	watchFileIdentity(ctx, path, interval, onChange)
}

// watchFileIdentity is the path-parameterized core of the upgrade watcher,
// separated so tests can point it at a temp file instead of the running
// test binary.
//
// Three cases beyond the happy path:
//   - transient stat failure (the instant mid-swap where the path is
//     absent): skipped; the next tick sees either the old identity or the
//     new file.
//   - persistent absence (missThresholdTicks consecutive misses — e.g.
//     `brew uninstall` removed the binary under a still-registered
//     service): logged loudly ONCE, and the service keeps running from
//     its held inode. Exiting would put the service manager into a
//     relaunch throw-loop against a dead path.
//   - size+mtime changed but content identical (a bare `touch`): the
//     hash confirm re-baselines instead of restarting.
func watchFileIdentity(ctx context.Context, path string, interval time.Duration, onChange func()) {
	baseline, err := statIdentity(path)
	if err != nil {
		slog.Debug("upgrade watcher disabled: executable not statable",
			"code", string(LogCodeBinarySwapDetected), "path", path, "error", err)
		return
	}
	// Baseline hash for the touch-false-positive guard. Hashing failure
	// degrades to identity-only mode (the historical behavior).
	baselineHash, hashErr := fileSHA256(path)
	if hashErr != nil {
		baselineHash = ""
	}

	misses := 0
	missingReported := false
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, statErr := statIdentity(path)
			if statErr != nil {
				misses++
				if misses >= missThresholdTicks && !missingReported {
					missingReported = true
					slog.Error("binary removed from disk while service is running — the next restart will fail; reinstall the package or re-run `kite-collector install`",
						"code", string(LogCodeBinaryMissing), "path", path)
				}
				continue
			}
			misses = 0
			missingReported = false
			if current == baseline {
				continue
			}
			if baselineHash != "" {
				if h, hErr := fileSHA256(path); hErr == nil && h == baselineHash {
					// Metadata changed, content did not (touch,
					// reinstall of the identical version): adopt the
					// new metadata, no restart.
					baseline = current
					continue
				}
			}
			slog.Info("binary on disk changed since launch",
				"code", string(LogCodeBinarySwapDetected),
				"path", path,
				"old_mtime", baseline.modTime.UTC().Format(time.RFC3339),
				"new_mtime", current.modTime.UTC().Format(time.RFC3339))
			onChange()
			return
		}
	}
}
