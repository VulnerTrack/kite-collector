package osquery

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The default socket list is the only thing standing between "osqueryd is
// running on this host" and "osquery discovery is inert": a scan with no
// sources.osquery block and no KITE_OSQUERY_SOCKET finds the daemon here or
// not at all.
func TestDefaultSocketPathsAreWellFormed(t *testing.T) {
	if len(defaultSocketPaths) == 0 {
		t.Fatal("every platform needs at least one default socket path")
	}
	seen := map[string]bool{}
	for _, p := range defaultSocketPaths {
		if seen[p] {
			t.Errorf("duplicate candidate %q", p)
		}
		seen[p] = true
		if runtime.GOOS == "windows" {
			if !strings.HasPrefix(p, `\\.\pipe\`) {
				t.Errorf("windows candidate %q is not a named pipe", p)
			}
			continue
		}
		if !filepath.IsAbs(p) {
			t.Errorf("candidate %q is not an absolute path", p)
		}
		// sun_path is 104 bytes on Darwin, 108 on Linux. Pin the tighter
		// bound everywhere: a path that fits on Linux and not on macOS is a
		// bind failure nobody finds until a mac shows up.
		if len(p) >= 104 {
			t.Errorf("candidate %q is %d bytes; AF_UNIX sun_path caps at 104", p, len(p))
		}
	}
}

// The kite-namespaced daemon must be probed before any stock osquery: on a
// host with both, the kite one is the daemon kite configured.
func TestKiteSocketIsProbedFirst(t *testing.T) {
	if !strings.Contains(defaultSocketPaths[0], "kite-osquery") {
		t.Fatalf("first candidate = %q, want the kite-namespaced socket", defaultSocketPaths[0])
	}
}

// macOS has no /run, and its /var/run is emptied on every boot — a socket
// directory created once at install time would be gone after the first
// restart. This is the same contract installer.OsqueryDarwinSocket asserts
// from the other side.
func TestDarwinSocketAvoidsVolatileRuntimeDirs(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only path contract")
	}
	for _, p := range defaultSocketPaths {
		for _, bad := range []string{"/run/", "/var/run/kite"} {
			if strings.HasPrefix(p, bad) {
				t.Errorf("candidate %q sits under %s, which macOS clears at boot", p, bad)
			}
		}
	}
	// A stock osqueryd — the official pkg or `brew install --cask osquery`,
	// which installs that same pkg — must be found with no kite-side setup.
	if !contains(defaultSocketPaths, "/var/osquery/osquery.em") {
		t.Error("the stock osquery socket must stay in the darwin candidate list")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// detectSocket only accepts sockets. A leftover regular file at a candidate
// path (a daemon killed mid-write, or an operator's `touch`) would otherwise
// be dialed and fail every scan with a confusing transport error.
func TestDetectSocketIgnoresNonSockets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named pipes have no file-type check")
	}
	dir := t.TempDir()
	regular := filepath.Join(dir, "osquery.em")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	orig := defaultSocketPaths
	defaultSocketPaths = []string{regular}
	t.Cleanup(func() { defaultSocketPaths = orig })

	if got := detectSocket(); got != "" {
		t.Fatalf("detectSocket() = %q, want empty for a regular file", got)
	}
}

// ResolveSocket is what `kite-collector doctor` reads, so it has to agree with
// a scan about precedence — env beats auto-detection, cfg beats env.
func TestResolveSocketPrecedence(t *testing.T) {
	t.Setenv("KITE_OSQUERY_SOCKET", "/tmp/from-env.em")
	if got := ResolveSocket(nil); got != "/tmp/from-env.em" {
		t.Fatalf("ResolveSocket(nil) = %q, want the env value", got)
	}
	cfg := map[string]any{"socket": "/tmp/from-cfg.em"}
	if got := ResolveSocket(cfg); got != "/tmp/from-cfg.em" {
		t.Fatalf("ResolveSocket(cfg) = %q, want the cfg value", got)
	}
}
