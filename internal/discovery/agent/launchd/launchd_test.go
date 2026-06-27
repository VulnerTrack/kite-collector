package launchd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPinnedScopeStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ScopeSystemDaemon), "system-daemon"},
		{string(ScopeSystemAgent), "system-agent"},
		{string(ScopeUserAgent), "user-agent"},
		{string(ScopeUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("scope drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte(`<plist><dict></dict></plist>`))
	b := HashContents([]byte(`<plist><dict></dict></plist>`))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestLabelDomain(t *testing.T) {
	cases := map[string]string{
		"com.apple.Spotlight":  "com.apple",
		"com.docker.helper":    "com.docker",
		"com.evilcorp.implant": "com.evilcorp",
		"single-segment":       "single-segment",
		"":                     "",
	}
	for in, want := range cases {
		if got := LabelDomain(in); got != want {
			t.Fatalf("LabelDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsAppleSignedDomain(t *testing.T) {
	hit := []string{"com.apple.Spotlight", "COM.APPLE.x", "com.openssh.sshd", "org.cups.cupsd"}
	for _, l := range hit {
		if !IsAppleSignedDomain(l) {
			t.Fatalf("%q must flag", l)
		}
	}
	miss := []string{"com.docker.helper", "io.evilcorp", "", "user.label"}
	for _, l := range miss {
		if IsAppleSignedDomain(l) {
			t.Fatalf("%q must NOT flag", l)
		}
	}
}

func TestIsProgramInWorldWritableDir(t *testing.T) {
	hit := []string{
		"/tmp/payload",
		"/Users/Shared/agent",
		"/private/var/folders/abc/payload",
		"/var/tmp/x",
	}
	for _, p := range hit {
		if !IsProgramInWorldWritableDir(p) {
			t.Fatalf("%q must flag world-writable", p)
		}
	}
	miss := []string{
		"/usr/local/bin/foo",
		"/Library/Application Support/Vendor/foo",
		"/Applications/App.app/Contents/MacOS/App",
		"",
		"/tmpish/foo", // prefix-similar but not a /tmp/ child
	}
	for _, p := range miss {
		if IsProgramInWorldWritableDir(p) {
			t.Fatalf("%q must NOT flag", p)
		}
	}
}

func TestIsRootUser(t *testing.T) {
	for _, s := range []string{"root", "ROOT", " root ", "0"} {
		if !IsRootUser(s) {
			t.Fatalf("%q must flag root", s)
		}
	}
	for _, s := range []string{"_spotlight", "1000", "", "rooty"} {
		if IsRootUser(s) {
			t.Fatalf("%q must NOT flag", s)
		}
	}
}

func TestPlistScopeFromPath(t *testing.T) {
	cases := map[string]PlistScope{
		"/Library/LaunchDaemons/com.docker.helper.plist":     ScopeSystemDaemon,
		"/Library/LaunchAgents/com.user.agent.plist":         ScopeSystemAgent,
		"/System/Library/LaunchDaemons/com.apple.x.plist":    ScopeSystemDaemon,
		"/System/Library/LaunchAgents/com.apple.agent.plist": ScopeSystemAgent,
		"/Users/alice/Library/LaunchAgents/com.x.plist":      ScopeUserAgent,
		"/etc/something.plist":                               ScopeUnknown,
	}
	for in, want := range cases {
		if got := PlistScopeFromPath(in); got != want {
			t.Fatalf("PlistScopeFromPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"/bin/x", "--flag"}); got != `["/bin/x","--flag"]` {
		t.Fatalf("got %q", got)
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateThirdPartyPersistentRoot(t *testing.T) {
	s := Service{
		FilePath:     "/Library/LaunchDaemons/com.evilcorp.helper.plist",
		PlistScope:   ScopeSystemDaemon,
		Label:        "com.evilcorp.helper",
		UserName:     "root",
		Program:      "/usr/local/evilcorp/helper",
		IsRunAtLoad:  true,
		FileMode:     0o644,
		FileOwnerUID: 0,
	}
	AnnotateSecurity(&s)
	if !s.RunsAsRoot {
		t.Fatal("root user must flag")
	}
	if s.IsAppleSignedDomain {
		t.Fatal("com.evilcorp is not Apple-signed")
	}
	if !s.IsPersistentThirdPartyRoot {
		t.Fatalf("must flag third-party persistent root: %+v", s)
	}
}

func TestAnnotateSystemDaemonImplicitRoot(t *testing.T) {
	// LaunchDaemons with no explicit UserName run as root by default.
	s := Service{
		PlistScope:  ScopeSystemDaemon,
		Label:       "com.docker.helper",
		Program:     "/Library/Docker/helper",
		IsRunAtLoad: true,
	}
	AnnotateSecurity(&s)
	if !s.RunsAsRoot {
		t.Fatal("system-daemon with no UserName defaults to root")
	}
	if !s.IsPersistentThirdPartyRoot {
		t.Fatal("must flag third-party persistent root for docker-as-root")
	}
}

func TestAnnotateAppleDaemonSuppressed(t *testing.T) {
	s := Service{
		PlistScope:  ScopeSystemDaemon,
		Label:       "com.apple.Spotlight",
		IsRunAtLoad: true,
	}
	AnnotateSecurity(&s)
	if s.IsPersistentThirdPartyRoot {
		t.Fatal("Apple-signed daemon must NOT flag third-party")
	}
}

func TestAnnotatePlistFileModeFlags(t *testing.T) {
	s := Service{
		PlistScope: ScopeSystemDaemon,
		Label:      "com.docker.helper",
		FileMode:   0o666,
	}
	AnnotateSecurity(&s)
	if !s.IsPlistWritableByGroup || !s.IsPlistWritableByOther {
		t.Fatalf("0o666 must flag both group+other writable: %+v", s)
	}

	s2 := Service{FileMode: 0o644}
	AnnotateSecurity(&s2)
	if s2.IsPlistWritableByGroup || s2.IsPlistWritableByOther {
		t.Fatalf("0o644 must be clean: %+v", s2)
	}
}

func TestAnnotateProgramArgumentsTriggerBadPath(t *testing.T) {
	// When Program is empty, the first ProgramArguments entry is the
	// effective executable.
	s := Service{
		PlistScope:       ScopeSystemDaemon,
		Label:            "com.evilcorp.x",
		ProgramArguments: []string{"/tmp/dropper", "--silent"},
		UserName:         "root",
		IsRunAtLoad:      true,
	}
	AnnotateSecurity(&s)
	if !s.IsProgramInWorldWritableDir {
		t.Fatal("first program argument in /tmp must flag")
	}
}

// -- ParsePlist typical fixture ---------------------------------------

func TestParsePlistTypical(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.docker.helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/Docker/helper</string>
        <string>--verbose</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>root</string>
    <key>StandardOutPath</key>
    <string>/var/log/docker-helper.log</string>
    <key>StartInterval</key>
    <integer>30</integer>
</dict>
</plist>`)
	got, err := ParsePlist(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Label != "com.docker.helper" {
		t.Fatalf("label=%q", got.Label)
	}
	if len(got.ProgramArguments) != 2 || got.ProgramArguments[0] != "/Library/Docker/helper" {
		t.Fatalf("ProgramArguments=%v", got.ProgramArguments)
	}
	if !got.IsRunAtLoad || !got.IsKeepAlive {
		t.Fatalf("flags=%+v", got)
	}
	if got.UserName != "root" {
		t.Fatalf("UserName=%q", got.UserName)
	}
	if got.StartIntervalSeconds != 30 {
		t.Fatalf("interval=%d", got.StartIntervalSeconds)
	}
}

func TestParsePlistKeepAliveAsDict(t *testing.T) {
	// `KeepAlive` may be a boolean OR a dict of conditions.
	body := []byte(`<plist version="1.0"><dict>
        <key>Label</key><string>com.example</string>
        <key>KeepAlive</key>
        <dict>
            <key>NetworkState</key><true/>
        </dict>
    </dict></plist>`)
	got, err := ParsePlist(body)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsKeepAlive {
		t.Fatal("dict-form KeepAlive must propagate true")
	}
}

func TestParsePlistStartCalendarIntervalPresence(t *testing.T) {
	body := []byte(`<plist version="1.0"><dict>
        <key>Label</key><string>com.example.cron</string>
        <key>StartCalendarInterval</key>
        <dict>
            <key>Hour</key><integer>3</integer>
            <key>Minute</key><integer>30</integer>
        </dict>
    </dict></plist>`)
	got, err := ParsePlist(body)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasStartCalendarInterval {
		t.Fatal("StartCalendarInterval presence must flag")
	}
}

func TestParsePlistWatchPaths(t *testing.T) {
	body := []byte(`<plist version="1.0"><dict>
        <key>Label</key><string>com.example.watcher</string>
        <key>WatchPaths</key>
        <array>
            <string>/Users/Shared/inbox</string>
            <string>/tmp/drop</string>
        </array>
    </dict></plist>`)
	got, err := ParsePlist(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.WatchPaths) != 2 {
		t.Fatalf("WatchPaths=%v", got.WatchPaths)
	}
	AnnotateSecurity(&got)
	if !got.HasWatchPaths {
		t.Fatal("HasWatchPaths must flag")
	}
}

func TestParsePlistEmptyError(t *testing.T) {
	if _, err := ParsePlist(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParsePlistMalformedError(t *testing.T) {
	if _, err := ParsePlist([]byte("not xml")); err == nil {
		t.Fatal("malformed must error")
	}
}

func TestParsePlistBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte(`<plist><dict><key>Label</key><string>x</string></dict></plist>`)...)
	got, err := ParsePlist(body)
	if err != nil {
		t.Fatalf("BOM should be tolerated: %v", err)
	}
	if got.Label != "x" {
		t.Fatalf("label=%q", got.Label)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksLibraryRoots(t *testing.T) {
	tmp := t.TempDir()
	daemons := filepath.Join(tmp, "Library/LaunchDaemons")
	agents := filepath.Join(tmp, "Library/LaunchAgents")
	must(t, os.MkdirAll(daemons, 0o755))
	must(t, os.MkdirAll(agents, 0o755))

	mustWritePlist(t, filepath.Join(daemons, "com.docker.helper.plist"), `com.docker.helper`, `/Library/Docker/helper`, "root")
	mustWritePlist(t, filepath.Join(daemons, "com.apple.foo.plist"), `com.apple.foo`, `/usr/libexec/applefoo`, "root")
	mustWritePlist(t, filepath.Join(agents, "com.user.agent.plist"), `com.user.agent`, `/usr/local/bin/agent`, "")
	must(t, os.WriteFile(filepath.Join(daemons, "ignored.txt"), []byte("skip me"), 0o644))
	must(t, os.WriteFile(filepath.Join(daemons, ".hidden.plist"), []byte("skip me"), 0o644))

	roots := []string{daemons, agents}
	c := &fileCollector{
		roots:    roots,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	// Rewrite PlistScopeFromPath input: the collector uses the actual
	// file path, but our test paths don't start with /Library/. Swap
	// in a stat function that won't matter, and verify by label not
	// scope here.
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// daemons: com.apple.foo + com.docker.helper = 2.
	// agents:  com.user.agent = 1.
	// .txt / .hidden.plist are skipped.
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}

	var docker, apple, user Service
	for _, s := range got {
		switch s.Label {
		case "com.docker.helper":
			docker = s
		case "com.apple.foo":
			apple = s
		case "com.user.agent":
			user = s
		}
	}
	if docker.Label == "" || apple.Label == "" || user.Label == "" {
		t.Fatalf("missing labels: %+v", got)
	}
	if !docker.IsAppleSignedDomain == false {
		// (Verbose negation: we want "is not Apple-signed".)
		t.Fatal("docker label must NOT be Apple-signed")
	}
	if !apple.IsAppleSignedDomain {
		t.Fatal("apple label must flag")
	}
	if docker.FileHash == "" {
		t.Fatal("file_hash must be populated")
	}
}

func TestFileCollectorMissingRootsOK(t *testing.T) {
	c := &fileCollector{
		roots:    []string{"/nope-a", "/nope-b"},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortServices ---------------------------------------------------

func TestSortServicesDeterministic(t *testing.T) {
	in := []Service{
		{FilePath: "/Library/LaunchDaemons/com.x.plist", Label: "com.x"},
		{FilePath: "/Library/LaunchAgents/z.plist", Label: "z"},
		{FilePath: "/Library/LaunchDaemons/com.x.plist", Label: "com.a"},
	}
	SortServices(in)
	// "LaunchAgents" < "LaunchDaemons" lexically.
	if in[0].FilePath != "/Library/LaunchAgents/z.plist" {
		t.Fatalf("first=%+v", in[0])
	}
	// Within the daemons path, "com.a" < "com.x".
	if in[1].Label != "com.a" || in[2].Label != "com.x" {
		t.Fatalf("daemon order: in[1]=%+v in[2]=%+v", in[1], in[2])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustWritePlist(t *testing.T, p, label, program, userName string) {
	t.Helper()
	user := ""
	if userName != "" {
		user = "<key>UserName</key><string>" + userName + "</string>"
	}
	body := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
    <key>Label</key><string>` + label + `</string>
    <key>Program</key><string>` + program + `</string>
    <key>RunAtLoad</key><true/>
    ` + user + `
</dict></plist>`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// Refresh mtime so the entry is fresh in the dir.
	_ = os.Chtimes(p, time.Now(), time.Now())
}
