package installer

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// packageQueryTimeout bounds each package-DB ownership query. A held
// database lock (pacman/dpkg mid-transaction) must degrade classification
// to "unmanaged", never hang the install.
const packageQueryTimeout = 5 * time.Second

// BinaryOwner describes which package manager, if any, owns an installed
// kite-collector binary. When a manager owns the binary, install registers
// the service against StablePath instead of copying — one owner per
// artifact. The zero value means "unmanaged": install's copy semantics
// apply.
type BinaryOwner struct {
	// Manager is "homebrew", "dpkg", "rpm", "pacman", or "" (unmanaged).
	Manager string
	// StablePath is the path the service registration should exec: the
	// path the manager keeps stable across upgrades (brew's prefix-bin
	// symlink, the packaged /usr/bin path).
	StablePath string
	// Detail is the manager's own description of the owning package
	// (e.g. "kite-collector 0.53.2-1"), for install output and logs.
	Detail string
}

// Managed reports whether a package manager owns the binary.
func (o BinaryOwner) Managed() bool { return o.Manager != "" }

// execCommand and lookPath are swapped in tests to fake package-manager
// queries without depending on the host's installed managers.
var (
	execCommand = exec.CommandContext
	lookPath    = exec.LookPath
)

// ClassifyBinary reports which package manager owns the binary at path.
// Windows always classifies as unmanaged here — MSI ownership is handled
// by the existing DetectPriorInstall/R7 pre-flight — and snap installs
// never reach this (install branches to runSnapInstall first).
//
// Detection is best-effort: a failed or missing manager query classifies
// as unmanaged, which degrades to the historical copy behavior.
func ClassifyBinary(path string) BinaryOwner {
	if runtime.GOOS == "windows" || path == "" {
		return BinaryOwner{}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}

	if owner := classifyHomebrew(path, resolved); owner.Managed() {
		return owner
	}
	return classifyPackageDB(resolved)
}

// classifyHomebrew detects a Homebrew-owned binary by its Caskroom/Cellar
// payload path. StablePath is the prefix-bin symlink brew re-points on
// every upgrade — the one path that survives `brew upgrade`.
func classifyHomebrew(path, resolved string) BinaryOwner {
	for _, marker := range []string{"/Caskroom/", "/Cellar/"} {
		idx := strings.Index(resolved, marker)
		if idx < 0 {
			continue
		}
		prefix := resolved[:idx]
		stable := filepath.Join(prefix, "bin", BinaryName())
		// Prefer the path the user invoked when it already is the
		// prefix-bin symlink — identical string, but keeps intent clear.
		if filepath.Clean(path) == stable {
			stable = filepath.Clean(path)
		}
		return BinaryOwner{
			Manager:    "homebrew",
			StablePath: stable,
			Detail:     "payload " + resolved,
		}
	}
	return BinaryOwner{}
}

// packagedUnitDirs are the systemd unit directories package managers own.
// /etc/systemd/system is deliberately absent: units there are written by
// `kite-collector install` (kardianos), not by packages. Overridable in
// tests.
var packagedUnitDirs = []string{"/usr/lib/systemd/system", "/lib/systemd/system"}

// PackagedUnitPath returns the path of a package-shipped systemd unit for
// the collector, or "" when none exists. When a package owns the unit,
// install skips kardianos registration entirely — writing an /etc unit
// would shadow the package's, and the shadow survives package removal
// (uninstalled yet still running). Linux-only by construction.
func PackagedUnitPath() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	for _, dir := range packagedUnitDirs {
		p := filepath.Join(dir, SvcName+".service")
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// classifyPackageDB asks the native package databases who owns the
// resolved file. The first manager present on the system that claims the
// path wins; the resolved path itself is the stable path (packages own
// fixed locations).
func classifyPackageDB(resolved string) BinaryOwner {
	queries := []struct {
		manager string
		bin     string
		args    []string
	}{
		{"dpkg", "dpkg", []string{"-S", resolved}},
		{"rpm", "rpm", []string{"-qf", resolved}},
		{"pacman", "pacman", []string{"-Qoq", resolved}},
	}
	for _, q := range queries {
		if _, err := lookPath(q.bin); err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), packageQueryTimeout)
		out, err := execCommand(ctx, q.bin, q.args...).Output()
		cancel()
		if err != nil {
			continue
		}
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			continue
		}
		return BinaryOwner{Manager: q.manager, StablePath: resolved, Detail: detail}
	}
	return BinaryOwner{}
}
