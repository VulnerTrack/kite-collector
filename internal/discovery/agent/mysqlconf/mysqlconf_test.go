package mysqlconf

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedSectionKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SectionServer), "server"},
		{string(SectionClient), "client"},
		{string(SectionCommon), "common"},
		{string(SectionUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("section_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("[mysqld]\nbind-address=127.0.0.1\n"))
	b := HashContents([]byte("[mysqld]\nbind-address=127.0.0.1\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestNormalizeSectionKind(t *testing.T) {
	cases := map[string]SectionKind{
		"mysqld":         SectionServer,
		"MYSQLD":         SectionServer,
		"mariadb":        SectionServer,
		"mariadbd":       SectionServer,
		"mysqld-8.0":     SectionServer,
		"mariadb-10.6":   SectionServer,
		"client":         SectionClient,
		"mysql":          SectionClient,
		"mysqldump":      SectionClient,
		"client-server":  SectionCommon,
		"client-mariadb": SectionCommon,
		"random":         SectionUnknown,
		"":               SectionUnknown,
	}
	for in, want := range cases {
		if got := NormalizeSectionKind(in); got != want {
			t.Fatalf("NormalizeSectionKind(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsLoopbackAddress(t *testing.T) {
	hit := []string{"127.0.0.1", "::1", "localhost", "127.0.0.2"}
	for _, a := range hit {
		if !IsLoopbackAddress(a) {
			t.Fatalf("%q must flag loopback", a)
		}
	}
	miss := []string{"0.0.0.0", "::", "10.0.0.5", "*", "", "fe80::1"}
	for _, a := range miss {
		if IsLoopbackAddress(a) {
			t.Fatalf("%q must NOT flag loopback", a)
		}
	}
}

func TestIsLoopbackOnlyRequiresExplicitValue(t *testing.T) {
	if IsLoopbackOnly("") {
		t.Fatal("empty bind-address means listen-on-everything → NOT loopback-only")
	}
	if !IsLoopbackOnly("127.0.0.1") {
		t.Fatal("explicit loopback must flag loopback-only")
	}
	if IsLoopbackOnly("0.0.0.0") {
		t.Fatal("0.0.0.0 must NOT flag loopback-only")
	}
}

func TestIsExternalBindCoversUnset(t *testing.T) {
	if !IsExternalBind("") {
		t.Fatal("empty bind-address means external by default")
	}
	if !IsExternalBind("0.0.0.0") {
		t.Fatal("0.0.0.0 must flag external")
	}
	if IsExternalBind("127.0.0.1") {
		t.Fatal("loopback must NOT flag external")
	}
}

func TestIsUnrestrictedSecureFilePriv(t *testing.T) {
	cases := []struct {
		val    string
		wasSet bool
		want   bool
	}{
		{"", true, true},                       // empty = unrestricted
		{"", false, true},                      // unset = unrestricted (MariaDB default)
		{"NULL", true, false},                  // explicitly disabled
		{"null", true, false},                  // case-insensitive
		{"/var/lib/mysql-files/", true, false}, // scoped to a directory
	}
	for _, c := range cases {
		if got := IsUnrestrictedSecureFilePriv(c.val, c.wasSet); got != c.want {
			t.Fatalf("IsUnrestrictedSecureFilePriv(%q, %v) = %v want %v", c.val, c.wasSet, got, c.want)
		}
	}
}

func TestIsBoolTrue(t *testing.T) {
	for _, s := range []string{"on", "ON", "true", "yes", "1", " on ", "TRUE"} {
		if !IsBoolTrue(s) {
			t.Fatalf("%q must flag true", s)
		}
	}
	for _, s := range []string{"off", "false", "no", "0", "", "garbage"} {
		if IsBoolTrue(s) {
			t.Fatalf("%q must NOT flag true", s)
		}
	}
}

// -- Parse end-to-end ------------------------------------------------

func TestParseTypicalHardened(t *testing.T) {
	body := []byte(`# my.cnf — hardened defaults
[client]
port = 3306
socket = /var/run/mysqld/mysqld.sock

[mysqld]
bind-address = 127.0.0.1
port = 3306
user = mysql
datadir = /var/lib/mysql
secure_file_priv = NULL
local_infile = OFF
require_secure_transport = ON
skip-name-resolve

[mysqldump]
quick
`)
	res := Parse(body, "/etc/mysql/my.cnf")
	if len(res.Rows) != 3 {
		t.Fatalf("rows=%d, want 3: %+v", len(res.Rows), res.Rows)
	}

	var server, client Row
	for _, r := range res.Rows {
		if r.SectionName == "mysqld" {
			server = r
		}
		if r.SectionName == "client" {
			client = r
		}
	}

	if server.SectionKind != SectionServer {
		t.Fatalf("server section_kind=%q", server.SectionKind)
	}
	if !server.IsBoundToLoopbackOnly {
		t.Fatalf("127.0.0.1 must flag loopback-only: %+v", server)
	}
	if server.IsExternallyBound {
		t.Fatal("loopback bind must NOT flag external")
	}
	if server.HasUnrestrictedSecureFilePriv {
		t.Fatal("secure_file_priv=NULL must NOT flag unrestricted")
	}
	if server.IsLocalInfileEnabled {
		t.Fatal("local_infile=OFF must NOT flag")
	}
	if !server.IsSecureTransportRequired {
		t.Fatal("require_secure_transport=ON must propagate")
	}
	if !server.IsNameResolveSkipped {
		t.Fatal("boolean-shortcut skip-name-resolve must flag")
	}
	if server.IsGrantTablesSkipped {
		t.Fatal("must NOT flag grant-tables-skipped on healthy config")
	}
	if server.IsUnauthenticatedWorldExposed {
		t.Fatal("healthy config must NOT flag world-exposed")
	}

	if client.SectionKind != SectionClient {
		t.Fatalf("client section_kind=%q", client.SectionKind)
	}
	if client.HasCleartextClientPassword {
		t.Fatal("no `password=` line → must NOT flag cleartext")
	}
}

func TestParseWorstCase(t *testing.T) {
	body := []byte(`[mysqld]
bind-address = 0.0.0.0
skip-grant-tables
local-infile = 1
# secure_file_priv intentionally unset = unrestricted
`)
	res := Parse(body, "/etc/my.cnf")
	if len(res.Rows) != 1 {
		t.Fatalf("rows=%d", len(res.Rows))
	}
	r := res.Rows[0]
	if !r.IsExternallyBound {
		t.Fatal("0.0.0.0 must flag external")
	}
	if !r.IsGrantTablesSkipped {
		t.Fatal("skip-grant-tables boolean-shortcut must propagate")
	}
	if !r.IsLocalInfileEnabled {
		t.Fatal("local_infile=1 must propagate")
	}
	if !r.HasUnrestrictedSecureFilePriv {
		t.Fatal("unset secure_file_priv must flag unrestricted")
	}
	if !r.IsUnauthenticatedWorldExposed {
		t.Fatalf("worst-case must flag world-exposed: %+v", r)
	}
}

func TestParseCleartextClientPassword(t *testing.T) {
	body := []byte(`[client]
user = root
password = "hunter2"
`)
	res := Parse(body, "~/.my.cnf")
	if !res.Rows[0].HasCleartextClientPassword {
		t.Fatalf("[client] password= must flag cleartext: %+v", res.Rows[0])
	}
}

func TestParseDashUnderscoreEquivalence(t *testing.T) {
	body := []byte(`[mysqld]
skip-grant-tables = ON
skip_networking = ON
local-infile = ON
`)
	r := Parse(body, "x").Rows[0]
	if !r.IsGrantTablesSkipped || !r.IsNetworkingSkipped || !r.IsLocalInfileEnabled {
		t.Fatalf("dash/underscore normalisation broken: %+v", r)
	}
}

func TestParseInlineComments(t *testing.T) {
	body := []byte(`[mysqld]
bind-address = 127.0.0.1   # listen loopback only
local-infile = OFF         ; mysql also accepts ;
`)
	r := Parse(body, "x").Rows[0]
	if r.BindAddress != "127.0.0.1" {
		t.Fatalf("inline comment stripped wrong: %q", r.BindAddress)
	}
	if r.IsLocalInfileEnabled {
		t.Fatal("OFF must propagate after `;` strip")
	}
}

func TestParseQuotedValues(t *testing.T) {
	body := []byte(`[mysqld]
secure_file_priv = "/var/lib/mysql-files/"
datadir = '/srv/mysql data'
`)
	r := Parse(body, "x").Rows[0]
	if r.SecureFilePriv != "/var/lib/mysql-files/" {
		t.Fatalf("double-quoted strip wrong: %q", r.SecureFilePriv)
	}
	if r.Datadir != "/srv/mysql data" {
		t.Fatalf("single-quoted strip wrong: %q", r.Datadir)
	}
}

func TestParseIncludes(t *testing.T) {
	body := []byte(`[mysqld]
bind-address = 127.0.0.1

!include /etc/mysql/extra.cnf
!includedir /etc/mysql/conf.d/
`)
	res := Parse(body, "/etc/mysql/my.cnf")
	if len(res.Includes) != 1 || res.Includes[0] != "/etc/mysql/extra.cnf" {
		t.Fatalf("!include: %v", res.Includes)
	}
	if len(res.IncludeDirs) != 1 || res.IncludeDirs[0] != "/etc/mysql/conf.d/" {
		t.Fatalf("!includedir: %v", res.IncludeDirs)
	}
}

func TestParseHonoursMaxRows(t *testing.T) {
	// Build a body with more sections than MaxRows.
	var sb []byte
	for i := 0; i < MaxRows+10; i++ {
		sb = append(sb, []byte("[mysqld-")...)
		sb = append(sb, byte('a'+(i%26)))
		sb = append(sb, []byte("]\n")...)
	}
	res := Parse(sb, "x")
	if len(res.Rows) > MaxRows {
		t.Fatalf("rows=%d > MaxRows=%d", len(res.Rows), MaxRows)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksDropInDirAndIncludes(t *testing.T) {
	tmp := t.TempDir()
	confd := filepath.Join(tmp, "conf.d")
	must(t, os.MkdirAll(confd, 0o755))

	main := filepath.Join(tmp, "my.cnf")
	must(t, os.WriteFile(main, []byte(`[mysqld]
bind-address = 0.0.0.0

!includedir `+confd+`
!include `+filepath.Join(tmp, "extra.cnf")+`
`), 0o600))
	must(t, os.WriteFile(filepath.Join(tmp, "extra.cnf"), []byte(`[mysqld]
skip-grant-tables
`), 0o600))
	must(t, os.WriteFile(filepath.Join(confd, "10-app.cnf"), []byte(`[mysqld]
local-infile = ON
`), 0o600))
	// .bak should be skipped — only .cnf files in includedir count.
	must(t, os.WriteFile(filepath.Join(confd, "ignored.bak"), []byte(`[mysqld]
skip-grant-tables
`), 0o600))

	c := &fileCollector{
		seeds:    []string{main},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// main: 1 section. extra.cnf: 1. conf.d/10-app.cnf: 1. .bak skipped.
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}

	// Validate that the !include + !includedir actually fired.
	var skipGrants, localInfile bool
	for _, r := range got {
		if r.IsGrantTablesSkipped {
			skipGrants = true
		}
		if r.IsLocalInfileEnabled {
			localInfile = true
		}
	}
	if !skipGrants {
		t.Fatal("!include row should have flagged skip-grant-tables")
	}
	if !localInfile {
		t.Fatal("!includedir row should have flagged local-infile")
	}
}

func TestFileCollectorIgnoresCycles(t *testing.T) {
	tmp := t.TempDir()
	a := filepath.Join(tmp, "a.cnf")
	b := filepath.Join(tmp, "b.cnf")
	must(t, os.WriteFile(a, []byte(`[mysqld]
bind-address = 127.0.0.1
!include `+b+`
`), 0o600))
	must(t, os.WriteFile(b, []byte(`[mysqld]
!include `+a+`
`), 0o600))

	c := &fileCollector{
		seeds:    []string{a},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("cycle must visit each file exactly once: %d", len(got))
	}
}

func TestFileCollectorMissingSeedsOK(t *testing.T) {
	c := &fileCollector{
		seeds:    []string{"/none-a", "/none-b"},
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

// -- SortRows -------------------------------------------------------

func TestSortRowsDeterministic(t *testing.T) {
	in := []Row{
		{FilePath: "/etc/my.cnf", SectionName: "client"},
		{FilePath: "/etc/my.cnf", SectionName: "mysqld"},
		{FilePath: "/etc/mysql/my.cnf", SectionName: "mysqld"},
	}
	SortRows(in)
	if in[0].FilePath != "/etc/my.cnf" || in[0].SectionName != "client" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].FilePath != "/etc/mysql/my.cnf" {
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
