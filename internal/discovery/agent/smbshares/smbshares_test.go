package smbshares

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedSectionKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SectionGlobal), "global"},
		{string(SectionShare), "share"},
		{string(SectionHomes), "homes"},
		{string(SectionPrinters), "printers"},
		{string(SectionPrintDS), "print$"},
		{string(SectionUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("section_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("[share]\npath = /srv\n"))
	b := HashContents([]byte("[share]\npath = /srv\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestNormalizeSectionKind(t *testing.T) {
	cases := map[string]SectionKind{
		"global":   SectionGlobal,
		"GLOBAL":   SectionGlobal,
		"homes":    SectionHomes,
		"printers": SectionPrinters,
		"print$":   SectionPrintDS,
		"team-fs":  SectionShare,
		"":         SectionUnknown,
	}
	for in, want := range cases {
		if got := NormalizeSectionKind(in); got != want {
			t.Fatalf("NormalizeSectionKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseBool(t *testing.T) {
	for _, s := range []string{"yes", "YES", "true", "on", "1", " yes "} {
		if !ParseBool(s) {
			t.Fatalf("%q must parse true", s)
		}
	}
	for _, s := range []string{"no", "NO", "false", "off", "0", "", "garbage"} {
		if ParseBool(s) {
			t.Fatalf("%q must parse false", s)
		}
	}
}

func TestCanonicalKey(t *testing.T) {
	cases := map[string]string{
		"read only":   "readonly",
		"READ ONLY":   "readonly",
		"writeable":   "writeable",
		"hosts allow": "hostsallow",
		" Path ":      "path",
	}
	for in, want := range cases {
		if got := CanonicalKey(in); got != want {
			t.Fatalf("CanonicalKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsWideCreateMask(t *testing.T) {
	hit := []string{"0666", "0777", "0622", "0667", "0002"}
	for _, m := range hit {
		if !IsWideCreateMask(m) {
			t.Fatalf("%q must flag wide", m)
		}
	}
	miss := []string{"0750", "0700", "0744", "0664", "0775", "0660", "0640", "", "garbage"}
	for _, m := range miss {
		if IsWideCreateMask(m) {
			t.Fatalf("%q must NOT flag wide", m)
		}
	}
}

func TestIsForceUserRoot(t *testing.T) {
	for _, s := range []string{"root", "ROOT", "0", " root "} {
		if !IsForceUserRoot(s) {
			t.Fatalf("%q must flag root", s)
		}
	}
	for _, s := range []string{"alice", "1000", "", "rooty"} {
		if IsForceUserRoot(s) {
			t.Fatalf("%q must NOT flag root", s)
		}
	}
}

func TestHasHostsAllowRestriction(t *testing.T) {
	if HasHostsAllowRestriction("") || HasHostsAllowRestriction("   ") {
		t.Fatal("empty must NOT count as restriction")
	}
	if !HasHostsAllowRestriction("10.0.0.0/24") {
		t.Fatal("non-empty must count")
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateSecurityWorstCase(t *testing.T) {
	s := Share{
		SectionName: "anon",
		SectionKind: SectionShare,
		Path:        "/srv/public",
		IsGuestOK:   true,
		IsWritable:  true,
		CreateMask:  "0666",
		ForceUser:   "root",
	}
	AnnotateSecurity(&s)
	if !s.IsGuestWritable {
		t.Fatal("guest+writable must flag")
	}
	if !s.IsWorldExposed {
		t.Fatal("no hosts allow → world-exposed")
	}
	if !s.IsWideCreateMask {
		t.Fatal("0666 mask must flag wide")
	}
	if !s.IsForceUserRoot {
		t.Fatal("force user=root must flag")
	}
}

func TestAnnotateSecurityHealthyShare(t *testing.T) {
	s := Share{
		SectionName: "team-fs",
		SectionKind: SectionShare,
		Path:        "/srv/team",
		ValidUsers:  "+lan-users",
		HostsAllow:  "10.0.0.0/24",
		CreateMask:  "0660",
		IsWritable:  true,
	}
	AnnotateSecurity(&s)
	if s.IsGuestWritable || s.IsWorldExposed || s.IsWideCreateMask ||
		s.IsForceUserRoot {
		t.Fatalf("healthy share must be clean: %+v", s)
	}
}

func TestAnnotateSecurityGlobalGuestOKAlone(t *testing.T) {
	// [global] guest ok = yes alone is a default-setting, not a finding.
	s := Share{
		SectionName: "global",
		SectionKind: SectionGlobal,
		IsGuestOK:   true,
		IsWritable:  true, // hypothetical
	}
	AnnotateSecurity(&s)
	if s.IsGuestWritable {
		t.Fatal("[global] section must NOT flag guest-writable")
	}
	if s.IsWorldExposed {
		t.Fatal("[global] section must NOT flag world-exposed")
	}
}

// -- Parse end-to-end ------------------------------------------------

func TestParseTypicalSmbConf(t *testing.T) {
	body := []byte(`# /etc/samba/smb.conf

[global]
   workgroup = WORKGROUP
   server string = Samba %v
   security = user
   guest account = nobody
   map to guest = bad user
   hosts allow = 127.0.0.1 10.0.0.0/24

[homes]
   comment = Home Directories
   browseable = no
   writable = yes
   valid users = %S
   create mask = 0700
   directory mask = 0700

[team-fs]
   comment = Team file server
   path = /srv/team
   valid users = +team
   read only = no
   create mask = 0664
   directory mask = 0775
   hosts allow = 10.0.0.0/24

[anon]
   comment = Anonymous drop zone (BAD CONFIG)
   path = /srv/anon
   browseable = yes
   guest ok = yes
   writable = yes
   create mask = 0666
   force user = root
`)
	got := Parse(body, "/etc/samba/smb.conf")
	if len(got) != 4 {
		t.Fatalf("sections=%d, want 4: %+v", len(got), got)
	}

	byName := map[string]Share{}
	for _, s := range got {
		byName[s.SectionName] = s
	}

	g := byName["global"]
	if g.SectionKind != SectionGlobal {
		t.Fatalf("global section_kind=%q", g.SectionKind)
	}
	if g.IsWorldExposed {
		t.Fatal("[global] never flags world-exposed")
	}

	h := byName["homes"]
	if h.SectionKind != SectionHomes {
		t.Fatalf("homes section_kind=%q", h.SectionKind)
	}
	if h.IsBrowseable {
		t.Fatal("homes has browseable=no")
	}

	team := byName["team-fs"]
	if team.SectionKind != SectionShare {
		t.Fatalf("team-fs section_kind=%q", team.SectionKind)
	}
	if !team.IsWritable {
		t.Fatal("team-fs: read only = no must flag IsWritable")
	}
	if team.IsWorldExposed {
		t.Fatal("team-fs has hosts allow; must NOT flag world-exposed")
	}
	if team.IsWideCreateMask {
		t.Fatal("0664/0775 must NOT flag wide (group, not other write)")
	}
	if team.IsGuestWritable {
		t.Fatal("team-fs is not guest-accessible")
	}
	if team.HostsAllow != "10.0.0.0/24" {
		t.Fatalf("hosts_allow=%q", team.HostsAllow)
	}

	anon := byName["anon"]
	if !anon.IsGuestWritable {
		t.Fatal("anon must flag guest-writable")
	}
	if !anon.IsWorldExposed {
		t.Fatal("anon has no hosts allow; must flag world-exposed")
	}
	if !anon.IsWideCreateMask {
		t.Fatal("0666 mask must flag wide")
	}
	if !anon.IsForceUserRoot {
		t.Fatal("force user=root must flag")
	}

	// File hash on every row.
	for _, s := range got {
		if s.FileHash == "" {
			t.Fatalf("file_hash missing: %+v", s)
		}
	}
}

func TestParseAliasBrowseableSpelling(t *testing.T) {
	body := []byte(`[s]
   path = /srv/s
   browsable = yes
`)
	got := Parse(body, "x")
	if len(got) != 1 {
		t.Fatal("len")
	}
	if !got[0].IsBrowseable {
		t.Fatal("browsable spelling must work")
	}
}

func TestParsePublicAlias(t *testing.T) {
	body := []byte(`[s]
   path = /srv/s
   public = yes
   writable = yes
`)
	got := Parse(body, "x")
	if !got[0].IsPublic || !got[0].IsGuestOK {
		t.Fatalf("public alias must set both: %+v", got[0])
	}
	if !got[0].IsGuestWritable {
		t.Fatal("public+writable must flag guest-writable")
	}
}

func TestParseWritableInverseReadOnly(t *testing.T) {
	body := []byte(`[s]
   path = /srv/s
   read only = yes
`)
	got := Parse(body, "x")
	if !got[0].IsReadOnly || got[0].IsWritable {
		t.Fatalf("read only=yes must mark not writable: %+v", got[0])
	}

	body2 := []byte(`[s2]
   path = /srv/s2
   writable = yes
`)
	got2 := Parse(body2, "x")
	if !got2[0].IsWritable || got2[0].IsReadOnly {
		t.Fatalf("writable=yes must mark not read only: %+v", got2[0])
	}
}

func TestParseSkipsCommentVariants(t *testing.T) {
	body := []byte("# hash\n; semi\n[s]\n   path = /srv\n")
	got := Parse(body, "x")
	if len(got) != 1 {
		t.Fatalf("expected 1 share, got %d", len(got))
	}
}

func TestParseContinuationLine(t *testing.T) {
	body := []byte("[s]\n   path = \\\n       /srv/very/long/path\n")
	got := Parse(body, "x")
	if len(got) != 1 {
		t.Fatal("len")
	}
	if got[0].Path != "/srv/very/long/path" {
		t.Fatalf("continuation merge broken: %q", got[0].Path)
	}
}

func TestParseHonoursMaxShares(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < MaxShares+50; i++ {
		sb.WriteString("[s")
		sb.WriteString(string(rune('a' + (i % 26))))
		sb.WriteString("]\n   path = /srv\n")
	}
	got := Parse([]byte(sb.String()), "x")
	if len(got) > MaxShares {
		t.Fatalf("got %d > MaxShares %d", len(got), MaxShares)
	}
}

// -- collector end-to-end --------------------------------------------

func TestFileCollectorWalksMainAndDropIns(t *testing.T) {
	tmp := t.TempDir()
	main := filepath.Join(tmp, "smb.conf")
	dropIn := filepath.Join(tmp, "smb.conf.d")
	must(t, os.MkdirAll(dropIn, 0o755))
	mustWrite(t, main, "[global]\n  workgroup = X\n[main-share]\n  path = /srv/main\n  hosts allow = 10.0.0.0/24\n")
	mustWrite(t, filepath.Join(dropIn, "10-anon.conf"),
		"[anon]\n  path = /srv/anon\n  guest ok = yes\n  writable = yes\n  create mask = 0666\n")
	mustWrite(t, filepath.Join(dropIn, "ignored.bak"),
		"[evil]\n  path = /srv/evil\n  guest ok = yes\n")

	c := &fileCollector{
		mainFile:  main,
		dropInDir: dropIn,
		readFile:  os.ReadFile,
		readDir:   os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// main: [global] + [main-share] = 2.
	// drop-in: [anon] = 1.
	// .bak ignored.
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}
	var anon Share
	for _, s := range got {
		if s.SectionName == "anon" {
			anon = s
		}
	}
	if !anon.IsGuestWritable || !anon.IsWideCreateMask {
		t.Fatalf("anon flags wrong: %+v", anon)
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		mainFile:  "/nope",
		dropInDir: "/nope-dir",
		readFile:  os.ReadFile,
		readDir:   os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortSharesDeterministic(t *testing.T) {
	in := []Share{
		{FilePath: "/etc/samba/smb.conf.d/zzz.conf", SectionName: "a"},
		{FilePath: "/etc/samba/smb.conf", SectionName: "z"},
		{FilePath: "/etc/samba/smb.conf", SectionName: "a"},
	}
	SortShares(in)
	if in[0].FilePath != "/etc/samba/smb.conf" || in[0].SectionName != "a" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].FilePath != "/etc/samba/smb.conf.d/zzz.conf" {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers ---------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
