package nfsexports

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"rw", "sync"}); got != `["rw","sync"]` {
		t.Fatalf("got %q", got)
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("/srv *(ro)\n"))
	b := HashContents([]byte("/srv *(ro)\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsWorldExposedClient(t *testing.T) {
	for _, c := range []string{"*", "0.0.0.0/0", "::/0", ""} {
		if !IsWorldExposedClient(c) {
			t.Fatalf("%q must flag world-exposed", c)
		}
	}
	for _, c := range []string{
		"10.0.0.0/24", "192.168.1.42",
		"*.corp.local", "@lan",
	} {
		if IsWorldExposedClient(c) {
			t.Fatalf("%q must NOT flag world-exposed", c)
		}
	}
}

func TestHasOption(t *testing.T) {
	opts := []string{"rw", "no_root_squash", "anonuid=1000", "sync"}
	for _, want := range []string{"rw", "no_root_squash", "anonuid", "sync"} {
		if !HasOption(opts, want) {
			t.Fatalf("%q must be present in %v", want, opts)
		}
	}
	for _, miss := range []string{"ro", "all_squash", "async", ""} {
		if HasOption(opts, miss) {
			t.Fatalf("%q must NOT be present", miss)
		}
	}
}

func TestHasOptionCaseInsensitive(t *testing.T) {
	if !HasOption([]string{"RW", "NO_ROOT_SQUASH"}, "rw") {
		t.Fatal("case-insensitive match must work")
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateSecurityWorstCase(t *testing.T) {
	r := Row{
		Client:      "*",
		OptionsList: []string{"rw", "no_root_squash", "async", "insecure"},
	}
	AnnotateSecurity(&r)
	if !r.IsReadWrite || !r.IsNoRootSquash || !r.IsAsync ||
		!r.IsInsecure || !r.IsWorldExposed {
		t.Fatalf("must flag every danger: %+v", r)
	}
}

func TestAnnotateSecurityHealthyShare(t *testing.T) {
	r := Row{
		Client:      "10.0.0.0/24",
		OptionsList: []string{"ro", "root_squash", "sync"},
	}
	AnnotateSecurity(&r)
	if r.IsReadWrite || r.IsNoRootSquash || r.IsAsync || r.IsInsecure ||
		r.IsWorldExposed || r.IsAllSquash {
		t.Fatalf("healthy share must be clean: %+v", r)
	}
}

func TestAnnotateSecurityAllSquash(t *testing.T) {
	r := Row{
		Client:      "10.0.0.0/24",
		OptionsList: []string{"ro", "all_squash", "anonuid=65534"},
	}
	AnnotateSecurity(&r)
	if !r.IsAllSquash {
		t.Fatal("all_squash must flag")
	}
}

// -- Parse end-to-end -----------------------------------------------

func TestParseTypicalExports(t *testing.T) {
	body := []byte(`# /etc/exports - exports(5)

# Internal corp lab share (anonymous, ro)
/srv/lab       10.0.0.0/24(ro,sync,no_subtree_check) *.corp.local(ro,sync)

# Backups, accessible only from the backup VLAN.
/srv/backups   10.10.10.0/24(rw,sync,root_squash,no_subtree_check)

# WORST CASE: world-exposed RW with no_root_squash
/srv/danger    *(rw,sync,no_root_squash,insecure,async)

# Replication target
/srv/replica   10.20.0.5(rw,sync,root_squash)
`)
	got := Parse(body, "/etc/exports")
	// Row counts:
	//   /srv/lab: 2 clients → 2 rows
	//   /srv/backups: 1 → 1
	//   /srv/danger: 1 → 1
	//   /srv/replica: 1 → 1
	// Total 5.
	if len(got) != 5 {
		t.Fatalf("rows=%d, want 5: %+v", len(got), got)
	}

	// Find the danger row.
	var danger Row
	for _, r := range got {
		if r.ExportPath == "/srv/danger" {
			danger = r
		}
	}
	if !danger.IsReadWrite || !danger.IsNoRootSquash || !danger.IsAsync ||
		!danger.IsInsecure || !danger.IsWorldExposed {
		t.Fatalf("worst-case row must flag every danger: %+v", danger)
	}

	// Backup share — RW but root_squash, not no_root_squash.
	var backups Row
	for _, r := range got {
		if r.ExportPath == "/srv/backups" {
			backups = r
		}
	}
	if !backups.IsReadWrite {
		t.Fatal("backups must flag RW")
	}
	if backups.IsNoRootSquash {
		t.Fatal("backups has root_squash; must NOT flag no_root_squash")
	}
	if backups.IsWorldExposed {
		t.Fatal("RFC1918 client must NOT flag world-exposed")
	}

	// File hash present on every row.
	for _, r := range got {
		if r.FileHash == "" {
			t.Fatalf("file_hash missing: %+v", r)
		}
	}
}

func TestParseExportWithNoClientGetsStarFallback(t *testing.T) {
	body := []byte("/srv/public\n")
	got := Parse(body, "x")
	if len(got) != 1 {
		t.Fatalf("rows=%d", len(got))
	}
	if got[0].Client != "*" {
		t.Fatalf("default client must be *, got %q", got[0].Client)
	}
	if !got[0].IsWorldExposed {
		t.Fatal("client * must flag world-exposed")
	}
}

func TestParseWhitespaceInsideOptionsParens(t *testing.T) {
	body := []byte("/srv/x  *(rw, async, no_root_squash)\n")
	got := Parse(body, "x")
	if len(got) != 1 {
		t.Fatal("len")
	}
	r := got[0]
	if !r.IsReadWrite || !r.IsAsync || !r.IsNoRootSquash {
		t.Fatalf("whitespace inside parens broke option parse: %+v", r)
	}
}

func TestParseQuotedExportPath(t *testing.T) {
	body := []byte(`"/srv/path with space"  *(ro)` + "\n")
	got := Parse(body, "x")
	if len(got) != 1 {
		t.Fatal("len")
	}
	if got[0].ExportPath != "/srv/path with space" {
		t.Fatalf("path=%q", got[0].ExportPath)
	}
}

func TestParseSkipsCommentsAndBlanks(t *testing.T) {
	body := []byte("# comment\n\n# more\n")
	if got := Parse(body, "x"); len(got) != 0 {
		t.Fatalf("expected empty, got %d", len(got))
	}
}

func TestParseContinuationLine(t *testing.T) {
	body := []byte("/srv/share  \\\n  10.0.0.0/24(rw,sync,no_subtree_check) \\\n  *.corp.local(ro,sync)\n")
	got := Parse(body, "x")
	if len(got) != 2 {
		t.Fatalf("rows=%d (continuation merge broken): %+v", len(got), got)
	}
}

func TestParseMultipleClientsOnOneLine(t *testing.T) {
	body := []byte("/srv/x  a(ro) b(rw) c(rw,no_root_squash)\n")
	got := Parse(body, "x")
	if len(got) != 3 {
		t.Fatalf("rows=%d", len(got))
	}
	if got[0].Client != "a" || got[1].Client != "b" || got[2].Client != "c" {
		t.Fatalf("clients order broken: %+v", got)
	}
	if !got[2].IsNoRootSquash {
		t.Fatal("last tuple's no_root_squash must propagate")
	}
}

func TestParseHonoursMaxRows(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < MaxRows+50; i++ {
		sb.WriteString("/srv 10.0.0.0/24(ro)\n")
	}
	got := Parse([]byte(sb.String()), "x")
	if len(got) > MaxRows {
		t.Fatalf("got %d > MaxRows %d", len(got), MaxRows)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksMainAndDropIns(t *testing.T) {
	tmp := t.TempDir()
	main := filepath.Join(tmp, "exports")
	dropIn := filepath.Join(tmp, "exports.d")
	must(t, os.MkdirAll(dropIn, 0o755))
	mustWrite(t, main, "/srv/main 10.0.0.0/24(ro,sync)\n")
	mustWrite(t, filepath.Join(dropIn, "10-app.exports"),
		"/srv/app 10.0.0.0/24(rw,sync,no_root_squash)\n")
	mustWrite(t, filepath.Join(dropIn, "ignored.bak"),
		"/srv/should-skip *(rw)\n")

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
	// main: 1 row. drop-in: 1 row. .bak ignored.
	if len(got) != 2 {
		t.Fatalf("want 2, got %d: %+v", len(got), got)
	}
	// Drop-in row must flag no_root_squash.
	var drop Row
	for _, r := range got {
		if r.ExportPath == "/srv/app" {
			drop = r
		}
	}
	if !drop.IsNoRootSquash || !drop.IsReadWrite {
		t.Fatalf("drop-in row didn't propagate flags: %+v", drop)
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

func TestSortRowsDeterministic(t *testing.T) {
	in := []Row{
		{FilePath: "/etc/exports.d/z.exports", LineNo: 1, Client: "a"},
		{FilePath: "/etc/exports", LineNo: 5, Client: "z"},
		{FilePath: "/etc/exports", LineNo: 2, Client: "b"},
		{FilePath: "/etc/exports", LineNo: 2, Client: "a"},
	}
	SortRows(in)
	if in[0].FilePath != "/etc/exports" || in[0].LineNo != 2 || in[0].Client != "a" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[3].FilePath != "/etc/exports.d/z.exports" {
		t.Fatalf("last=%+v", in[3])
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
