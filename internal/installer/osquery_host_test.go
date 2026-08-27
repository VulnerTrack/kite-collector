package installer

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The macOS socket path is the whole reason this lane exists as its own
// constant. /run does not exist on macOS and /var/run is emptied on every
// boot, so either would produce a daemon that binds once and then fails after
// the first reboot — a failure nobody sees until a month later.
func TestOsqueryDarwinSocketIsNotAVolatileRuntimeDir(t *testing.T) {
	if OsqueryDarwinSocket == OsqueryUnixSocket {
		t.Fatalf("darwin socket must not reuse the Linux runtime path %q", OsqueryUnixSocket)
	}
	for _, bad := range []string{"/run/", "/var/run/"} {
		if strings.HasPrefix(OsqueryDarwinSocket, bad) {
			t.Errorf("darwin socket %q sits under %s, which macOS clears at boot",
				OsqueryDarwinSocket, bad)
		}
	}
	// AF_UNIX sun_path is 104 bytes on Darwin (sizeof(struct sockaddr_un)),
	// shorter than Linux's 108. A path that fits on Linux can fail to bind on
	// macOS, so pin it here rather than discovering it on a host.
	if len(OsqueryDarwinSocket) >= 104 {
		t.Errorf("darwin socket path %q is %d bytes; sun_path caps at 104",
			OsqueryDarwinSocket, len(OsqueryDarwinSocket))
	}
}

func TestOsquerySocketDirMatchesEndpoint(t *testing.T) {
	endpoint := OsqueryExtensionsEndpoint()
	dir := OsquerySocketDir()
	if runtime.GOOS == "windows" {
		if dir != "" {
			t.Fatalf("named pipes have no parent directory, got %q", dir)
		}
		return
	}
	if want := filepath.Dir(endpoint); dir != want {
		t.Fatalf("socket dir = %q, want %q", dir, want)
	}
	if !filepath.IsAbs(dir) {
		t.Fatalf("socket dir %q must be absolute", dir)
	}
}

func TestResolveDaemonAcceptsExecutableAndFollowsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits and symlink creation differ on Windows")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "osqueryd")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "osqueryd-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	// The symlink must resolve to the real binary: the official macOS pkg
	// puts a /usr/local/bin symlink next to the app-bundle binary, and
	// /usr/local/bin is admin-group writable — handing that path to launchd
	// is what osqueryd's own safe-permissions check rejects.
	got, ok := resolveDaemon(link)
	if !ok {
		t.Fatal("symlink to an executable must resolve")
	}
	realResolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if got != realResolved {
		t.Fatalf("resolveDaemon = %q, want %q", got, realResolved)
	}
}

func TestResolveDaemonRejectsUnusableCandidates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits and symlink creation differ on Windows")
	}
	dir := t.TempDir()

	nonExec := filepath.Join(dir, "not-exec")
	if err := os.WriteFile(nonExec, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "gone"), dangling); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"missing":           filepath.Join(dir, "absent"),
		"directory":         dir,
		"not executable":    nonExec,
		"dangling symlink":  dangling,
		"empty path string": "",
	}
	for name, path := range cases {
		if _, ok := resolveDaemon(path); ok {
			t.Errorf("%s: resolveDaemon(%q) accepted an unusable candidate", name, path)
		}
	}
}

func TestHostOsquerydCandidatesAreAbsoluteAndOrdered(t *testing.T) {
	got := hostOsquerydCandidates()
	if len(got) == 0 {
		t.Fatal("every platform needs at least one candidate")
	}
	for _, c := range got {
		if !filepath.IsAbs(c.Path) {
			t.Errorf("candidate %q is not absolute", c.Path)
		}
		if c.Origin == "" {
			t.Errorf("candidate %q has no origin label", c.Path)
		}
	}
	if runtime.GOOS != "darwin" {
		return
	}
	// The app-bundle binary must come first: it is the signed, root-owned one,
	// and the /usr/local/bin entry below it is only the pkg's symlink to it.
	if !strings.Contains(got[0].Path, "osquery.app") {
		t.Errorf("first darwin candidate = %q, want the pkg's app bundle", got[0].Path)
	}
	if got[0].Origin != HostOsqueryOriginPkg {
		t.Errorf("first darwin candidate origin = %q, want %q", got[0].Origin, HostOsqueryOriginPkg)
	}
}

func TestHostOsqueryInstallSupportedOnlyOnDarwin(t *testing.T) {
	// Linux and Windows must stay out: on both, a package already owns
	// kite-osqueryd, and a second registration would shadow it.
	if got, want := HostOsqueryInstallSupported(), runtime.GOOS == "darwin"; got != want {
		t.Fatalf("HostOsqueryInstallSupported() = %v on %s, want %v", got, runtime.GOOS, want)
	}
}

func TestStageOsqueryConfigWritesThenPreserves(t *testing.T) {
	opts := Options{CertsDir: t.TempDir()}

	preserved, err := StageOsqueryConfig(opts)
	if err != nil {
		t.Fatalf("first stage: %v", err)
	}
	if preserved {
		t.Fatal("a fresh directory has nothing to preserve")
	}

	conf, flags := OsqueryConfigPath(opts), OsqueryFlagsPath(opts)
	for _, path := range []string{conf, flags} {
		fi, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("stat %s: %v", path, statErr)
		}
		// osqueryd refuses to load a config that is group- or world-writable.
		if perm := fi.Mode().Perm(); runtime.GOOS != "windows" && perm&0o077 != 0 {
			t.Errorf("%s mode = %04o, want no group/other bits", path, perm)
		}
	}
	if _, statErr := os.Stat(OsqueryLogDir(opts)); statErr != nil {
		t.Errorf("log dir not created: %v", statErr)
	}

	// The second run must not clobber operator edits: osquery.conf is where
	// FIM file_paths and YARA rules get armed, and silently reverting that on
	// upgrade would disarm monitoring somebody deliberately turned on.
	edited := []byte("{ \"operator\": \"edited\" }\n")
	if wErr := os.WriteFile(conf, edited, 0o600); wErr != nil {
		t.Fatal(wErr)
	}
	preserved, err = StageOsqueryConfig(opts)
	if err != nil {
		t.Fatalf("second stage: %v", err)
	}
	if !preserved {
		t.Fatal("an existing config must be reported as preserved")
	}
	got, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(edited) {
		t.Fatalf("operator edits were overwritten: %q", got)
	}
}

func TestStagedOsqueryConfigIsTheEmbeddedDefault(t *testing.T) {
	opts := Options{CertsDir: t.TempDir()}
	if _, err := StageOsqueryConfig(opts); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(OsqueryConfigPath(opts))
	if err != nil {
		t.Fatal(err)
	}
	// --enable_file_events lives in the flags file, and file_paths ships
	// commented out: an install that did not ask for FIM must arm no watches.
	if strings.Contains(string(conf), "\n  \"file_paths\"") {
		t.Error("shipped osquery.conf must not arm file_paths by default")
	}
	flags, err := os.ReadFile(OsqueryFlagsPath(opts))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(flags), "--enable_file_events=true") {
		t.Error("flags must enable the file_events subscriber; without it, " +
			"configuring file_paths silently produces zero events")
	}
	// Path flags ride the launchd job's command line so a relocated install
	// keeps working; the flagfile carries behavior only. Comment lines are
	// skipped — the file documents that split in prose.
	for _, line := range strings.Split(string(flags), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, pathFlag := range []string{"--config_path", "--database_path", "--logger_path", "--extensions_socket"} {
			if strings.HasPrefix(line, pathFlag) {
				t.Errorf("%s belongs on the service command line, not in the flagfile", pathFlag)
			}
		}
	}
}

func TestBuildHostOsquerySvcConfigMirrorsTheBundledContract(t *testing.T) {
	opts := Options{CertsDir: t.TempDir(), BinaryDir: t.TempDir()}
	daemon := "/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd"
	cfg := BuildHostOsquerySvcConfig(opts, daemon)

	// One service name across both lanes: ProbeOsquery, `service status`, and
	// the dashboard all key on it, so a divergence would present as two
	// different daemons to three different surfaces.
	if cfg.Name != OsquerySvcName {
		t.Fatalf("service name = %q, want %q", cfg.Name, OsquerySvcName)
	}
	if cfg.Executable != daemon {
		t.Fatalf("executable = %q, want the host daemon %q", cfg.Executable, daemon)
	}
	if cfg.Option["UserService"] != false {
		t.Error("kite-osqueryd is a machine daemon; it reads system-wide state")
	}

	bundled := BuildOsquerySvcConfig(opts)
	socketArg := "--extensions_socket=" + OsqueryExtensionsEndpoint()
	for _, want := range []string{socketArg} {
		if !hasArg(cfg.Arguments, want) {
			t.Errorf("host config missing %q", want)
		}
		if !hasArg(bundled.Arguments, want) {
			t.Errorf("bundled config missing %q — the two lanes must share one socket", want)
		}
	}
	if !hasArg(cfg.Arguments, "--flagfile="+OsqueryFlagsPath(opts)) {
		t.Error("host config must point at the flagfile it stages")
	}
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestInstallHostOsqueryRefusesUserMode(t *testing.T) {
	if !HostOsqueryInstallSupported() {
		t.Skip("host lane is darwin-only")
	}
	_, err := InstallHostOsquery(Options{CertsDir: t.TempDir(), UserMode: true})
	if !errors.Is(err, ErrHostOsqueryUserMode) {
		t.Fatalf("err = %v, want ErrHostOsqueryUserMode", err)
	}
}

func TestInstallHostOsqueryRefusedOffDarwin(t *testing.T) {
	if HostOsqueryInstallSupported() {
		t.Skip("darwin has the host lane")
	}
	// A package owns kite-osqueryd on Linux and Windows. Registering a second
	// one would put a unit in /etc/systemd/system that shadows the deb's, and
	// the next `apt upgrade` would stop managing the daemon it installed.
	_, err := InstallHostOsquery(Options{CertsDir: t.TempDir()})
	if !errors.Is(err, ErrHostOsqueryUnsupported) {
		t.Fatalf("err = %v, want ErrHostOsqueryUnsupported", err)
	}
}
