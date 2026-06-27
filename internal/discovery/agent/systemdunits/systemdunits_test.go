package systemdunits

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedUnitKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindService), "service"},
		{string(KindSocket), "socket"},
		{string(KindTimer), "timer"},
		{string(KindMount), "mount"},
		{string(KindPath), "path"},
		{string(KindTarget), "target"},
		{string(KindUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("unit_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedSourceDirStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceEtc), "etc"},
		{string(SourceLib), "lib"},
		{string(SourceUsrLib), "usrlib"},
		{string(SourceRun), "run"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source_dir drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("[Service]\nExecStart=/bin/true\n"))
	b := HashContents([]byte("[Service]\nExecStart=/bin/true\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestNormalizeUnitKind(t *testing.T) {
	cases := map[string]UnitKind{
		"sshd.service":       KindService,
		"docker.socket":      KindSocket,
		"daily-backup.timer": KindTimer,
		"home.mount":         KindMount,
		"watcher.path":       KindPath,
		"multi-user.target":  KindTarget,
		"unknown":            KindUnknown,
		"":                   KindUnknown,
	}
	for in, want := range cases {
		if got := NormalizeUnitKind(in); got != want {
			t.Fatalf("NormalizeUnitKind(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNormalizeSourceDir(t *testing.T) {
	cases := map[string]SourceDir{
		"/etc/systemd/system":     SourceEtc,
		"/lib/systemd/system":     SourceLib,
		"/usr/lib/systemd/system": SourceUsrLib,
		"/run/systemd/system":     SourceRun,
		"/opt/random":             SourceUnknown,
	}
	for in, want := range cases {
		if got := NormalizeSourceDir(in); got != want {
			t.Fatalf("NormalizeSourceDir(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsBoolHelpers(t *testing.T) {
	for _, s := range []string{"yes", "YES", "true", "on", "1", " yes "} {
		if !IsBoolTrue(s) {
			t.Fatalf("%q must flag true", s)
		}
	}
	for _, s := range []string{"no", "false", "off", "0", "", " no "} {
		if !IsBoolFalse(s) {
			t.Fatalf("%q must flag false", s)
		}
		if IsBoolTrue(s) {
			t.Fatalf("%q must NOT flag true", s)
		}
	}
}

func TestIsRootUser(t *testing.T) {
	for _, s := range []string{"", "root", "ROOT", "0", " root "} {
		if !IsRootUser(s) {
			t.Fatalf("%q must flag root", s)
		}
	}
	for _, s := range []string{"nobody", "1000", "www-data"} {
		if IsRootUser(s) {
			t.Fatalf("%q must NOT flag root", s)
		}
	}
}

func TestProtectSystemIsWritable(t *testing.T) {
	for _, s := range []string{"", "no", "false", "off", "0"} {
		if !ProtectSystemIsWritable(s) {
			t.Fatalf("%q must flag writable", s)
		}
	}
	for _, s := range []string{"true", "yes", "full", "strict"} {
		if ProtectSystemIsWritable(s) {
			t.Fatalf("%q must NOT flag writable", s)
		}
	}
}

func TestHasDangerousAmbientCaps(t *testing.T) {
	hit := []string{
		"CAP_SYS_ADMIN",
		"cap_sys_admin cap_net_bind_service",
		"CAP_DAC_OVERRIDE",
		"cap_setuid",
	}
	for _, s := range hit {
		if !HasDangerousAmbientCaps(s) {
			t.Fatalf("%q must flag dangerous", s)
		}
	}
	miss := []string{"", "CAP_NET_BIND_SERVICE", "cap_chown"}
	for _, s := range miss {
		if HasDangerousAmbientCaps(s) {
			t.Fatalf("%q must NOT flag dangerous", s)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateHardenedService(t *testing.T) {
	u := Unit{
		UnitKind:              KindService,
		UserName:              "nobody",
		NoNewPrivileges:       "yes",
		PrivateTmp:            "yes",
		ProtectSystem:         "strict",
		ProtectHome:           "yes",
		SystemCallFilter:      "@system-service",
		CapabilityBoundingSet: "CAP_NET_BIND_SERVICE",
		AmbientCapabilities:   "",
	}
	AnnotateSecurity(&u)
	if u.RunsAsRoot {
		t.Fatal("nobody must NOT flag root")
	}
	if u.IsNoNewPrivilegesOff || u.IsPrivateTmpOff {
		t.Fatalf("hardened flags: %+v", u)
	}
	if u.IsWritableSystem || u.IsWritableHome {
		t.Fatal("ProtectSystem=strict / ProtectHome=yes must clear writable flags")
	}
	if u.HasNoSeccompFilter || u.HasUnrestrictedCapabilities {
		t.Fatal("seccomp + capability set present; must NOT flag")
	}
	if !u.IsHardenedBaseline {
		t.Fatalf("baseline must hold: %+v", u)
	}
}

func TestAnnotateUnhardenedRootService(t *testing.T) {
	// The classic vendor unit: no hardening, runs as root.
	u := Unit{
		UnitKind: KindService,
		// No User= → defaults to root.
	}
	AnnotateSecurity(&u)
	if !u.RunsAsRoot {
		t.Fatal("unset User must default to root")
	}
	if !u.IsNoNewPrivilegesOff || !u.IsPrivateTmpOff || !u.IsWritableSystem ||
		!u.IsWritableHome || !u.HasNoSeccompFilter ||
		!u.HasUnrestrictedCapabilities {
		t.Fatalf("every hardening directive missing must flag: %+v", u)
	}
	if u.IsHardenedBaseline {
		t.Fatal("nothing-set must NOT be hardened")
	}
}

func TestAnnotateDangerousAmbientCapsFlag(t *testing.T) {
	u := Unit{
		UnitKind:            KindService,
		AmbientCapabilities: "CAP_SYS_ADMIN",
	}
	AnnotateSecurity(&u)
	if !u.HasDangerousAmbientCaps {
		t.Fatal("CAP_SYS_ADMIN ambient must flag")
	}
}

func TestAnnotateNonServiceSkipped(t *testing.T) {
	u := Unit{UnitKind: KindTarget, UserName: ""}
	AnnotateSecurity(&u)
	// Target units shouldn't flag — they don't carry hardening.
	if u.RunsAsRoot || u.IsHardenedBaseline {
		t.Fatalf("target unit must stay unannotated: %+v", u)
	}
}

// -- Parse end-to-end ----------------------------------------------

func TestParseTypicalHardenedUnit(t *testing.T) {
	body := []byte(`# /etc/systemd/system/foo.service
[Unit]
Description=Foo widget service
After=network.target

[Service]
Type=simple
User=foo
ExecStart=/usr/local/bin/foo --flag
WorkingDirectory=/var/lib/foo
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
SystemCallFilter=@system-service
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
`)
	got := Parse(body, "/etc/systemd/system/foo.service")
	if got.UnitKind != KindService || got.SourceDir != SourceEtc {
		t.Fatalf("classifiers: %+v", got)
	}
	if got.UserName != "foo" {
		t.Fatalf("user=%q", got.UserName)
	}
	if got.Description != "Foo widget service" {
		t.Fatalf("description=%q", got.Description)
	}
	if got.ExecStart != "/usr/local/bin/foo --flag" {
		t.Fatalf("exec_start=%q", got.ExecStart)
	}
	if !got.IsHardenedBaseline {
		t.Fatalf("hardened unit must flag baseline: %+v", got)
	}
	if got.RunsAsRoot {
		t.Fatal("User=foo must NOT flag root")
	}
}

func TestParseWorstCaseRootService(t *testing.T) {
	body := []byte(`[Service]
ExecStart=/usr/local/bin/legacy-daemon
`)
	got := Parse(body, "/etc/systemd/system/legacy.service")
	if !got.RunsAsRoot {
		t.Fatal("no User= must default to root")
	}
	if !got.IsNoNewPrivilegesOff || !got.IsWritableSystem ||
		!got.HasNoSeccompFilter || !got.HasUnrestrictedCapabilities {
		t.Fatalf("every defense missing must flag: %+v", got)
	}
}

func TestParseInlineCommentSkipped(t *testing.T) {
	body := []byte(`[Service]
# this is a comment
; semicolon comments also work
ExecStart=/bin/true
`)
	got := Parse(body, "x.service")
	if got.ExecStart != "/bin/true" {
		t.Fatalf("exec=%q", got.ExecStart)
	}
}

func TestParseContinuationLines(t *testing.T) {
	body := []byte("[Service]\nExecStart=/bin/foo \\\n   --really-long-flag \\\n   --another\n")
	got := Parse(body, "x.service")
	if got.ExecStart == "" || !strings.Contains(got.ExecStart, "--really-long-flag") || !strings.Contains(got.ExecStart, "--another") {
		t.Fatalf("continuation: %q", got.ExecStart)
	}
}

func TestParseLastWriteWinsForRepeatedKey(t *testing.T) {
	body := []byte(`[Service]
ExecStart=/bin/first
ExecStart=/bin/second
`)
	got := Parse(body, "x.service")
	if got.ExecStart != "/bin/second" {
		t.Fatalf("last-wins broken: %q", got.ExecStart)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksUnitDirs(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "systemd-units")
	must(t, os.MkdirAll(dir, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "good.service"),
		[]byte(`[Service]
User=nobody
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
SystemCallFilter=@system-service
CapabilityBoundingSet=
`), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "legacy.service"),
		[]byte(`[Service]
ExecStart=/bin/x
`), 0o644))
	// Non-unit files must be skipped.
	must(t, os.WriteFile(filepath.Join(dir, "README"), []byte("skip me"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, ".hidden.service"), []byte(`[Service]
ExecStart=/x
`), 0o644))

	c := &fileCollector{
		dirs:     []string{dir},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (skip README + hidden), got %d: %+v", len(got), got)
	}

	var good, legacy Unit
	for _, u := range got {
		switch u.UnitName {
		case "good.service":
			good = u
		case "legacy.service":
			legacy = u
		}
	}
	if !good.IsHardenedBaseline {
		t.Fatalf("good.service must flag baseline: %+v", good)
	}
	if legacy.IsHardenedBaseline {
		t.Fatal("legacy must NOT flag baseline")
	}
	if !legacy.RunsAsRoot {
		t.Fatal("legacy must flag root (no User=)")
	}
}

func TestFileCollectorMissingDirsOK(t *testing.T) {
	c := &fileCollector{
		dirs:     []string{"/nope-a", "/nope-b"},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortUnits ---------------------------------------------------

func TestSortUnitsDeterministic(t *testing.T) {
	in := []Unit{
		{FilePath: "/lib/systemd/system/z.service"},
		{FilePath: "/etc/systemd/system/a.service"},
		{FilePath: "/lib/systemd/system/a.service"},
	}
	SortUnits(in)
	if in[0].FilePath != "/etc/systemd/system/a.service" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].FilePath != "/lib/systemd/system/z.service" {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
