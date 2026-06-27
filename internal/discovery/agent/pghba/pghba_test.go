package pghba

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedConnectionTypeStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ConnectionLocal), "local"},
		{string(ConnectionHost), "host"},
		{string(ConnectionHostSSL), "hostssl"},
		{string(ConnectionHostNoSSL), "hostnossl"},
		{string(ConnectionHostGSSEnc), "hostgssenc"},
		{string(ConnectionHostNoGSSEnc), "hostnogssenc"},
		{string(ConnectionUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("connection_type drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedMethodStrings(t *testing.T) {
	for _, p := range []struct{ got, want string }{
		{string(MethodTrust), "trust"},
		{string(MethodReject), "reject"},
		{string(MethodMD5), "md5"},
		{string(MethodSCRAMSHA256), "scram-sha-256"},
		{string(MethodPassword), "password"},
		{string(MethodGSS), "gss"},
		{string(MethodSSPI), "sspi"},
		{string(MethodIdent), "ident"},
		{string(MethodPeer), "peer"},
		{string(MethodLDAP), "ldap"},
		{string(MethodRadius), "radius"},
		{string(MethodCert), "cert"},
		{string(MethodPAM), "pam"},
		{string(MethodBSD), "bsd"},
		{string(MethodUnknown), "unknown"},
	} {
		if p.got != p.want {
			t.Fatalf("method drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("host all all 0.0.0.0/0 md5\n"))
	b := HashContents([]byte("host all all 0.0.0.0/0 md5\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsWeakMethod(t *testing.T) {
	for _, m := range []Method{MethodMD5, MethodPassword, MethodIdent, MethodPeer} {
		if !IsWeakMethod(m) {
			t.Fatalf("%q must flag weak", m)
		}
	}
	for _, m := range []Method{
		MethodSCRAMSHA256, MethodCert, MethodGSS, MethodLDAP,
		MethodTrust, MethodReject, MethodUnknown,
	} {
		if IsWeakMethod(m) {
			t.Fatalf("%q must NOT flag weak", m)
		}
	}
}

func TestIsInternetExposedAddress(t *testing.T) {
	hit := []string{"0.0.0.0/0", "::/0", "all", "ALL", " 0.0.0.0/0 "}
	for _, a := range hit {
		if !IsInternetExposedAddress(a) {
			t.Fatalf("%q must flag", a)
		}
	}
	miss := []string{
		"10.0.0.0/24", "192.168.1.42", "samehost", "samenet",
		"fd00::/8", "internal.corp.local", "",
	}
	for _, a := range miss {
		if IsInternetExposedAddress(a) {
			t.Fatalf("%q must NOT flag", a)
		}
	}
}

func TestIsReplicationDB(t *testing.T) {
	for _, d := range []string{"replication", "REPLICATION", "replication,foo", "foo,replication", " replication "} {
		if !IsReplicationDB(d) {
			t.Fatalf("%q must flag", d)
		}
	}
	for _, d := range []string{"all", "mydb", "mydb,otherdb", ""} {
		if IsReplicationDB(d) {
			t.Fatalf("%q must NOT flag", d)
		}
	}
}

func TestIsAll(t *testing.T) {
	for _, s := range []string{"all", "ALL", "  all  ", "foo,all,bar"} {
		if !IsAll(s) {
			t.Fatalf("%q must flag all", s)
		}
	}
	for _, s := range []string{"alice", "+admins", "mydb", ""} {
		if IsAll(s) {
			t.Fatalf("%q must NOT flag all", s)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateSecurityWideOpen(t *testing.T) {
	r := Row{
		ConnectionType: ConnectionHost,
		Database:       "all",
		DBRole:         "all",
		Address:        "0.0.0.0/0",
		Method:         MethodTrust,
	}
	AnnotateSecurity(&r)
	if !r.IsTrust || !r.IsInternetExposed || !r.IsWideOpen {
		t.Fatalf("worst-case rule must flag everything: %+v", r)
	}
}

func TestAnnotateSecurityLocalTrustIsNotInternetExposed(t *testing.T) {
	r := Row{
		ConnectionType: ConnectionLocal,
		Database:       "all",
		DBRole:         "postgres",
		Method:         MethodTrust,
	}
	AnnotateSecurity(&r)
	if !r.IsTrust {
		t.Fatal("trust on local must flag is_trust")
	}
	if r.IsInternetExposed {
		t.Fatal("local connection_type must NEVER flag internet-exposed")
	}
}

func TestAnnotateSecurityScramSafe(t *testing.T) {
	r := Row{
		ConnectionType: ConnectionHostSSL,
		Database:       "production",
		DBRole:         "app",
		Address:        "10.0.0.0/24",
		Method:         MethodSCRAMSHA256,
	}
	AnnotateSecurity(&r)
	if r.IsTrust || r.IsWeakMethod || r.IsInternetExposed || r.IsWideOpen {
		t.Fatalf("scram on RFC1918 with named db/role must be clean: %+v", r)
	}
}

func TestAnnotateSecurityReplicationFlag(t *testing.T) {
	r := Row{
		ConnectionType: ConnectionHostSSL,
		Database:       "replication",
		DBRole:         "replicator",
		Address:        "10.0.0.0/24",
		Method:         MethodSCRAMSHA256,
	}
	AnnotateSecurity(&r)
	if !r.IsReplication {
		t.Fatal("replication db must flag")
	}
}

// -- Parse end-to-end ------------------------------------------------

func TestParseTypicalDebianHbaConf(t *testing.T) {
	body := []byte(`# PostgreSQL Client Authentication Configuration File

# TYPE  DATABASE        USER            ADDRESS                 METHOD

# "local" is for Unix domain socket connections only
local   all             postgres                                peer
local   all             all                                     md5

# IPv4 local connections:
host    all             all             127.0.0.1/32            scram-sha-256

# IPv6 local connections:
host    all             all             ::1/128                 scram-sha-256

# Allow replication connections from localhost.
local   replication     all                                     peer
host    replication     all             127.0.0.1/32            scram-sha-256
host    replication     all             ::1/128                 scram-sha-256

# Public-internet hole punched by an attacker:
host    all             all             0.0.0.0/0               trust
`)
	got := Parse(body, "/etc/postgresql/15/main/pg_hba.conf")
	if len(got) != 8 {
		t.Fatalf("rows=%d, want 8: %+v", len(got), got)
	}

	// First row: local + peer + postgres user.
	r0 := got[0]
	if r0.ConnectionType != ConnectionLocal {
		t.Fatalf("r0 type=%q", r0.ConnectionType)
	}
	if r0.Method != MethodPeer {
		t.Fatalf("r0 method=%q", r0.Method)
	}
	if !r0.IsWeakMethod {
		t.Fatal("peer must flag weak")
	}
	if r0.IsInternetExposed {
		t.Fatal("local must NEVER flag internet-exposed")
	}

	// Replication entry — count them.
	repl := 0
	for _, r := range got {
		if r.IsReplication {
			repl++
		}
	}
	if repl != 3 {
		t.Fatalf("replication rows=%d, want 3", repl)
	}

	// Last row: the wide-open trust grant.
	rL := got[len(got)-1]
	if !rL.IsTrust || !rL.IsInternetExposed || !rL.IsWideOpen {
		t.Fatalf("last row must flag every danger: %+v", rL)
	}
	if rL.FilePath != "/etc/postgresql/15/main/pg_hba.conf" {
		t.Fatalf("file_path=%q", rL.FilePath)
	}
	if rL.FileHash == "" {
		t.Fatal("file_hash must be populated")
	}
}

func TestParseLegacyDottedQuadMask(t *testing.T) {
	body := []byte(`host all all 10.0.0.0 255.255.255.0 md5
host all all 10.0.0.0 255.255.0.0   trust
`)
	got := Parse(body, "x.conf")
	if len(got) != 2 {
		t.Fatalf("rows=%d", len(got))
	}
	if got[0].Address != "10.0.0.0/24" {
		t.Fatalf("/24 fold failed: %q", got[0].Address)
	}
	if got[0].Method != MethodMD5 {
		t.Fatalf("method=%q", got[0].Method)
	}
	if got[1].Address != "10.0.0.0/16" {
		t.Fatalf("/16 fold failed: %q", got[1].Address)
	}
}

func TestParseContinuationLine(t *testing.T) {
	body := []byte("host \\\n  all all 10.0.0.0/24 md5\n")
	got := Parse(body, "x.conf")
	if len(got) != 1 {
		t.Fatalf("continuation merge broken: %+v", got)
	}
	if got[0].Address != "10.0.0.0/24" {
		t.Fatalf("address=%q", got[0].Address)
	}
}

func TestParseSkipsCommentsAndBlanks(t *testing.T) {
	body := []byte("# only comments\n\n# more\n")
	if got := Parse(body, "x.conf"); len(got) != 0 {
		t.Fatalf("expected empty, got %d", len(got))
	}
}

func TestParseUnknownTypeDropped(t *testing.T) {
	body := []byte("notatype all all 10.0.0.0/24 md5\nlocal all postgres peer\n")
	got := Parse(body, "x.conf")
	if len(got) != 1 {
		t.Fatalf("unknown type must be dropped: %+v", got)
	}
}

func TestParseInternetExposedWeakMethod(t *testing.T) {
	body := []byte("host all all 0.0.0.0/0 md5\n")
	got := Parse(body, "x.conf")
	r := got[0]
	if !r.IsInternetExposed {
		t.Fatal("0.0.0.0/0 must flag exposed")
	}
	if !r.IsWeakMethod {
		t.Fatal("md5 must flag weak")
	}
	if r.IsTrust {
		t.Fatal("md5 is not trust")
	}
}

func TestParseHonoursMaxRowsCeiling(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < MaxRows+50; i++ {
		sb.WriteString("host all all 10.0.0.0/24 md5\n")
	}
	got := Parse([]byte(sb.String()), "x.conf")
	if len(got) > MaxRows {
		t.Fatalf("got %d > MaxRows %d", len(got), MaxRows)
	}
}

func TestMaskToPrefix(t *testing.T) {
	cases := map[string]string{
		"255.255.255.0":   "24",
		"255.255.0.0":     "16",
		"255.0.0.0":       "8",
		"255.255.255.255": "32",
		"0.0.0.0":         "0",
		"255.255.255.128": "25",
	}
	for in, want := range cases {
		if got := maskToPrefix(in); got != want {
			t.Fatalf("maskToPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLooksDottedQuadMask(t *testing.T) {
	for _, s := range []string{"255.255.255.0", "0.0.0.0", "255.0.0.0"} {
		if !looksDottedQuadMask(s) {
			t.Fatalf("%q must look like mask", s)
		}
	}
	for _, s := range []string{
		"10.0.0.0/24", "192.168.1.1", "all", "md5", "",
	} {
		if looksDottedQuadMask(s) {
			t.Fatalf("%q must NOT look like mask", s)
		}
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorFindsConventionalLayouts(t *testing.T) {
	tmp := t.TempDir()
	// Simulate /etc/postgresql/15/main/pg_hba.conf layout.
	pg15 := filepath.Join(tmp, "etc-postgresql", "15", "main")
	must(t, os.MkdirAll(pg15, 0o755))
	mustWrite(t, filepath.Join(pg15, "pg_hba.conf"),
		"host all all 10.0.0.0/24 scram-sha-256\n")
	// Simulate the unversioned /var/lib/pgsql/data layout.
	pgsqlData := filepath.Join(tmp, "var-lib-pgsql", "data")
	must(t, os.MkdirAll(pgsqlData, 0o755))
	mustWrite(t, filepath.Join(pgsqlData, "pg_hba.conf"),
		"host all all 0.0.0.0/0 trust\n")

	c := &fileCollector{
		roots: []string{
			filepath.Join(tmp, "etc-postgresql"),
			filepath.Join(tmp, "var-lib-pgsql"),
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("rows=%d (want 2): %+v", len(got), got)
	}

	// One row must be the wide-open trust grant.
	var wideOpen bool
	for _, r := range got {
		if r.IsWideOpen {
			wideOpen = true
		}
	}
	if !wideOpen {
		t.Fatal("wide-open trust grant must surface")
	}
}

func TestFileCollectorMissingRootsOK(t *testing.T) {
	c := &fileCollector{
		roots:    []string{"/nope/one", "/nope/two"},
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

func TestFileCollectorDedupesSameFile(t *testing.T) {
	tmp := t.TempDir()
	// Same file reachable from two configured roots.
	dir := filepath.Join(tmp, "ver", "main")
	must(t, os.MkdirAll(dir, 0o755))
	mustWrite(t, filepath.Join(dir, "pg_hba.conf"),
		"host all all 10.0.0.0/24 scram-sha-256\n")

	c := &fileCollector{
		roots: []string{
			filepath.Join(tmp, "ver", "main"),
			filepath.Join(tmp, "ver"), // walker finds the same leaf via main/pg_hba.conf
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("dedupe broken: %d rows", len(got))
	}
}

func TestSortRowsDeterministic(t *testing.T) {
	in := []Row{
		{FilePath: "/etc/postgresql/zzz/pg_hba.conf", LineNo: 1},
		{FilePath: "/etc/postgresql/aaa/pg_hba.conf", LineNo: 5},
		{FilePath: "/etc/postgresql/aaa/pg_hba.conf", LineNo: 2},
	}
	SortRows(in)
	if in[0].FilePath != "/etc/postgresql/aaa/pg_hba.conf" || in[0].LineNo != 2 {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].FilePath != "/etc/postgresql/zzz/pg_hba.conf" {
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

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
