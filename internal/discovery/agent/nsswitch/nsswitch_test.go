package nsswitch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedDatabaseStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(DatabasePasswd), "passwd"},
		{string(DatabaseShadow), "shadow"},
		{string(DatabaseGroup), "group"},
		{string(DatabaseHosts), "hosts"},
		{string(DatabaseServices), "services"},
		{string(DatabaseNetworks), "networks"},
		{string(DatabaseProtocols), "protocols"},
		{string(DatabaseRPC), "rpc"},
		{string(DatabaseEthers), "ethers"},
		{string(DatabaseNetmasks), "netmasks"},
		{string(DatabaseBootparams), "bootparams"},
		{string(DatabaseNetgroup), "netgroup"},
		{string(DatabaseAutomount), "automount"},
		{string(DatabaseAliases), "aliases"},
		{string(DatabasePublickey), "publickey"},
		{string(DatabaseGshadow), "gshadow"},
		{string(DatabaseSudoers), "sudoers"},
		{string(DatabaseInitgroups), "initgroups"},
		{string(DatabaseUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("database drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"files", "sss"}); got != `["files","sss"]` {
		t.Fatalf("got %q", got)
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("passwd: files\n"))
	b := HashContents([]byte("passwd: files\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestNormalizeDatabase(t *testing.T) {
	cases := map[string]Database{
		"passwd":     DatabasePasswd,
		"PASSWD":     DatabasePasswd,
		" hosts ":    DatabaseHosts,
		"sudoers":    DatabaseSudoers,
		"initgroups": DatabaseInitgroups,
		"made-up-db": DatabaseUnknown,
		"":           DatabaseUnknown,
	}
	for in, want := range cases {
		if got := NormalizeDatabase(in); got != want {
			t.Fatalf("NormalizeDatabase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsLocalSource(t *testing.T) {
	for _, l := range []string{"files", "compat", "db", "cache", "myhostname"} {
		if !IsLocalSource(l) {
			t.Fatalf("%q must be local", l)
		}
	}
	for _, r := range []string{
		"sss", "ldap", "nis", "dns", "mdns4_minimal",
		"wins", "winbind",
	} {
		if IsLocalSource(r) {
			t.Fatalf("%q must NOT be local", r)
		}
	}
}

func TestIsSecurityCriticalDatabase(t *testing.T) {
	for _, d := range []Database{
		DatabasePasswd, DatabaseShadow, DatabaseGroup,
		DatabaseGshadow, DatabaseInitgroups, DatabaseSudoers,
	} {
		if !IsSecurityCriticalDatabase(d) {
			t.Fatalf("%q must be critical", d)
		}
	}
	for _, d := range []Database{
		DatabaseHosts, DatabaseServices, DatabaseNetworks,
		DatabaseAliases, DatabaseUnknown,
	} {
		if IsSecurityCriticalDatabase(d) {
			t.Fatalf("%q must NOT be critical", d)
		}
	}
}

func TestAnnotateSecurityCriticalAllFiles(t *testing.T) {
	e := Entry{Database: DatabasePasswd, Sources: []string{"files", "systemd"}}
	AnnotateSecurity(&e)
	if !e.IsSecurityCritical {
		t.Fatal("passwd must be critical")
	}
	if !e.HasNonLocalSource {
		t.Fatal("systemd is non-local (nss_systemd queries DBus)")
	}
	if e.IsFilesMissing {
		t.Fatal("files present → not missing")
	}
	if e.IsFilesLast {
		t.Fatal("files first → not last")
	}
}

func TestAnnotateSecurityFilesLast(t *testing.T) {
	e := Entry{
		Database: DatabaseHosts,
		Sources:  []string{"dns", "mdns4_minimal", "files"},
	}
	AnnotateSecurity(&e)
	if e.IsSecurityCritical {
		t.Fatal("hosts is NOT in critical set")
	}
	if !e.HasNonLocalSource {
		t.Fatal("dns is non-local")
	}
	if e.IsFilesMissing {
		t.Fatal("files present at end")
	}
	if !e.IsFilesLast {
		t.Fatal("files must be flagged last (network sources queried first)")
	}
}

func TestAnnotateSecurityFilesMissing(t *testing.T) {
	e := Entry{Database: DatabasePasswd, Sources: []string{"sss"}}
	AnnotateSecurity(&e)
	if !e.IsFilesMissing {
		t.Fatal("no files entry → IsFilesMissing")
	}
	if !e.HasNonLocalSource {
		t.Fatal("sss is non-local")
	}
}

func TestAnnotateSecurityFilesOnly(t *testing.T) {
	e := Entry{Database: DatabasePasswd, Sources: []string{"files"}}
	AnnotateSecurity(&e)
	if e.HasNonLocalSource {
		t.Fatal("files-only must not flag non-local")
	}
	if e.IsFilesMissing {
		t.Fatal("files present")
	}
	if e.IsFilesLast {
		t.Fatal("only-source can't be 'last' by our definition")
	}
}

// -- Parse end-to-end ---------------------------------------------------

func TestParseTypicalNsswitch(t *testing.T) {
	body := []byte(`# /etc/nsswitch.conf
passwd:    files systemd
group:     files systemd
shadow:    files
gshadow:   files

hosts:     files mdns4_minimal [NOTFOUND=return] dns
networks:  files

protocols: db files
services:  db files
ethers:    db files
rpc:       db files

netgroup:  nis
`)
	got := Parse(body, "/etc/nsswitch.conf")
	if len(got) < 10 {
		t.Fatalf("len=%d, want >=10: %+v", len(got), got)
	}

	byDB := map[Database]Entry{}
	for _, e := range got {
		byDB[e.Database] = e
	}

	// passwd: files systemd → critical + has non-local (systemd) + files present + not last.
	pw := byDB[DatabasePasswd]
	if !pw.IsSecurityCritical || !pw.HasNonLocalSource ||
		pw.IsFilesMissing || pw.IsFilesLast {
		t.Fatalf("passwd flags wrong: %+v", pw)
	}
	if len(pw.Sources) != 2 || pw.Sources[0] != "files" || pw.Sources[1] != "systemd" {
		t.Fatalf("passwd sources=%v", pw.Sources)
	}

	// shadow: files → critical + all local + not last.
	sh := byDB[DatabaseShadow]
	if !sh.IsSecurityCritical || sh.HasNonLocalSource || sh.IsFilesMissing {
		t.Fatalf("shadow flags wrong: %+v", sh)
	}

	// hosts: files mdns4_minimal dns → non-local + files NOT last (files first).
	h := byDB[DatabaseHosts]
	if h.IsSecurityCritical {
		t.Fatal("hosts must not be critical")
	}
	if !h.HasNonLocalSource {
		t.Fatal("hosts has dns")
	}
	if h.IsFilesLast {
		t.Fatal("hosts has files FIRST in this fixture")
	}
	// Action block [NOTFOUND=return] must NOT appear in sources.
	for _, s := range h.Sources {
		if s == "NOTFOUND=return" || s == "[NOTFOUND=return]" {
			t.Fatalf("action block leaked into sources: %v", h.Sources)
		}
	}

	// netgroup: nis → no files at all.
	ng := byDB[DatabaseNetgroup]
	if !ng.IsFilesMissing {
		t.Fatal("netgroup has no files; must flag IsFilesMissing")
	}

	for _, e := range got {
		if e.FileHash == "" {
			t.Fatalf("file_hash missing on %+v", e)
		}
	}
}

func TestParseHostsFilesLast(t *testing.T) {
	body := []byte("hosts: dns mdns4_minimal files\n")
	got := Parse(body, "x")
	if len(got) != 1 {
		t.Fatal("len")
	}
	if !got[0].IsFilesLast {
		t.Fatal("hosts: dns first, files last must flag IsFilesLast")
	}
}

func TestParseUnknownDatabase(t *testing.T) {
	body := []byte("custom-db: files\n")
	got := Parse(body, "x")
	if len(got) != 1 || got[0].Database != DatabaseUnknown {
		t.Fatalf("unknown db classification: %+v", got)
	}
}

func TestParseSkipsCommentsAndBlanks(t *testing.T) {
	body := []byte("# comment\n\n# more\n")
	if got := Parse(body, "x"); len(got) != 0 {
		t.Fatalf("expected empty, got %d", len(got))
	}
}

func TestExtractSourcesActionBlocks(t *testing.T) {
	got := extractSources("files [SUCCESS=return] sss [NOTFOUND=continue] ldap")
	want := []string{"files", "sss", "ldap"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pos %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// -- collector end-to-end ---------------------------------------------

func TestFileCollectorTypical(t *testing.T) {
	tmp := t.TempDir()
	conf := filepath.Join(tmp, "nsswitch.conf")
	mustWrite(t, conf, `passwd: files sss
hosts: files dns
`)
	c := &fileCollector{
		mainFile: conf,
		readFile: os.ReadFile,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
	for _, e := range got {
		if !e.HasNonLocalSource {
			t.Fatalf("both have non-local sources: %+v", e)
		}
	}
}

func TestFileCollectorMissingOK(t *testing.T) {
	c := &fileCollector{mainFile: "/nope", readFile: os.ReadFile}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortEntriesDeterministic(t *testing.T) {
	in := []Entry{
		{FilePath: "/etc/nsswitch.conf", LineNo: 5},
		{FilePath: "/etc/nsswitch.conf", LineNo: 2},
		{FilePath: "/etc/zzz", LineNo: 1},
	}
	SortEntries(in)
	if in[0].LineNo != 2 {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].FilePath != "/etc/zzz" {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers -----------------------------------------------------------

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
