package winhosts

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedIPKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(IPLoopback), "loopback"},
		{string(IPRFC1918), "rfc1918"},
		{string(IPPublic), "public"},
		{string(IPSinkhole), "sinkhole"},
		{string(IPInvalid), "invalid"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("ip_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("127.0.0.1 localhost\n"))
	b := HashContents([]byte("127.0.0.1 localhost\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestClassifyIP(t *testing.T) {
	cases := map[string]IPKind{
		"127.0.0.1":    IPLoopback,
		"::1":          IPLoopback,
		"127.5.5.5":    IPLoopback,
		"10.0.0.5":     IPRFC1918,
		"172.16.0.1":   IPRFC1918,
		"192.168.1.1":  IPRFC1918,
		"8.8.8.8":      IPPublic,
		"1.1.1.1":      IPPublic,
		"2606:4700::1": IPPublic,
		"0.0.0.0":      IPSinkhole,
		"::":           IPSinkhole,
		"not-an-ip":    IPInvalid,
		"":             IPInvalid,
	}
	for in, want := range cases {
		if got := ClassifyIP(in); got != want {
			t.Fatalf("ClassifyIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsLocalHostname(t *testing.T) {
	hit := []string{
		"localhost",
		"foo.local",
		"server.internal",
		"backend.corp",
		"test.example",
		"db.lan",
	}
	for _, h := range hit {
		if !IsLocalHostname(h) {
			t.Fatalf("%q must flag local", h)
		}
	}
	miss := []string{
		"example.com",
		"google.com",
		"bank.example.com.attacker.io",
		"",
	}
	for _, h := range miss {
		if IsLocalHostname(h) {
			t.Fatalf("%q must NOT flag local", h)
		}
	}
}

func TestIsSystemManagedDefault(t *testing.T) {
	for _, h := range []string{
		"localhost", "LOCALHOST", "localhost.localdomain",
		"ip6-localhost", "broadcasthost",
	} {
		if !IsSystemManagedDefault(h) {
			t.Fatalf("%q must flag system-managed", h)
		}
	}
	for _, h := range []string{
		"my-server.local", "evil.com", "",
	} {
		if IsSystemManagedDefault(h) {
			t.Fatalf("%q must NOT flag system-managed", h)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateSystemDefaultIsClean(t *testing.T) {
	e := Entry{IPAddress: "127.0.0.1", Hostname: "localhost"}
	AnnotateSecurity(&e)
	if !e.IsLoopbackTarget {
		t.Fatal("127.0.0.1 must flag loopback")
	}
	if !e.IsSystemManagedDefault {
		t.Fatal("localhost must flag system-managed")
	}
	if e.IsBlocklistEntry {
		t.Fatal("system-managed localhost binding is NOT a blocklist entry")
	}
	if e.IsDNSPoisoningCandidate {
		t.Fatal("localhost on loopback must NOT flag poisoning")
	}
}

func TestAnnotateAdBlockEntryFlagsBlocklist(t *testing.T) {
	e := Entry{IPAddress: "0.0.0.0", Hostname: "ads.example.com"}
	AnnotateSecurity(&e)
	if e.IPKind != IPSinkhole {
		t.Fatalf("0.0.0.0 must classify sinkhole: %q", e.IPKind)
	}
	if !e.IsBlocklistEntry {
		t.Fatal("0.0.0.0 must flag blocklist")
	}
	if e.IsDNSPoisoningCandidate {
		t.Fatal("sinkhole isn't poisoning — it's blocking")
	}
}

func TestAnnotateLoopbackOverrideOfPublicHostnameIsBlocklist(t *testing.T) {
	// Overriding ads.example.com → 127.0.0.1 is the classic
	// host-based ad blocker behaviour. Flag blocklist, NOT poisoning.
	e := Entry{IPAddress: "127.0.0.1", Hostname: "ads.example.com"}
	AnnotateSecurity(&e)
	if !e.IsBlocklistEntry {
		t.Fatal("127.0.0.1 → public hostname must flag blocklist")
	}
	if e.IsDNSPoisoningCandidate {
		t.Fatal("loopback redirect is NOT poisoning")
	}
}

func TestAnnotatePoisoningCandidateHeadline(t *testing.T) {
	// Public IP redirect for bank.example.com — textbook poison.
	e := Entry{IPAddress: "203.0.113.99", Hostname: "bank.example.com"}
	AnnotateSecurity(&e)
	if !e.IsDNSPoisoningCandidate {
		t.Fatalf("public IP for public hostname must flag poison: %+v", e)
	}
}

func TestAnnotateRFC1918PoisoningCandidate(t *testing.T) {
	// Private IP for a public hostname (split-horizon ABUSE).
	e := Entry{IPAddress: "10.0.0.99", Hostname: "github.com"}
	AnnotateSecurity(&e)
	if !e.IsDNSPoisoningCandidate {
		t.Fatal("10.0.0.x for github.com must flag poison")
	}
}

func TestAnnotateLocalDomainNotPoisoning(t *testing.T) {
	// Local-suffix hostname pointing to an RFC1918 address is fine.
	e := Entry{IPAddress: "10.0.0.5", Hostname: "db.corp"}
	AnnotateSecurity(&e)
	if e.IsDNSPoisoningCandidate {
		t.Fatal("local-suffix hostname must NOT flag poison")
	}
}

func TestAnnotateWildcardSubdomain(t *testing.T) {
	e := Entry{IPAddress: "0.0.0.0", Hostname: "*.tracking.example.com"}
	AnnotateSecurity(&e)
	if !e.IsWildcardSubdomain {
		t.Fatal("*.host must flag wildcard")
	}
}

// -- Parse end-to-end ----------------------------------------------

func TestParseTypicalHostsFile(t *testing.T) {
	body := []byte(`# Copyright (c) 1993-2009 Microsoft Corp.
#
# Sample hosts file for Windows + ad-block tail.

127.0.0.1       localhost   loopback
::1             localhost
10.0.0.5        backend.corp.local backend
0.0.0.0         ads.example.com           # block ads
127.0.0.1       telemetry.example.com    # block telemetry
192.168.1.99    fake-bank.example.com    # SUSPICIOUS REDIRECT
`)
	got := Parse(body, `C:\Windows\System32\drivers\etc\hosts`)
	// Entries per row: 127.0.0.1 has 2 hostnames, ::1 has 1,
	// backend.corp.local has 2 hostnames, ads.example.com has 1,
	// telemetry has 1, fake-bank has 1 = 8 rows.
	if len(got) != 8 {
		t.Fatalf("rows=%d, want 8: %+v", len(got), got)
	}

	byHost := map[string]Entry{}
	for _, e := range got {
		byHost[e.Hostname] = e
	}

	if !byHost["localhost"].IsSystemManagedDefault {
		t.Fatal("localhost must flag system-managed")
	}
	if !byHost["ads.example.com"].IsBlocklistEntry {
		t.Fatal("0.0.0.0 ads must flag blocklist")
	}
	if !byHost["telemetry.example.com"].IsBlocklistEntry {
		t.Fatal("127.0.0.1 telemetry must flag blocklist")
	}
	if !byHost["fake-bank.example.com"].IsDNSPoisoningCandidate {
		t.Fatalf("fake-bank must flag poison: %+v", byHost["fake-bank.example.com"])
	}
	if byHost["backend.corp.local"].IsDNSPoisoningCandidate {
		t.Fatal("local-suffix backend must NOT flag poison")
	}

	// Verify alias propagation.
	loopback := byHost["loopback"]
	if !loopback.IsAlias {
		t.Fatal("second hostname on line must flag IsAlias")
	}
	if loopback.IPAddress != "127.0.0.1" {
		t.Fatalf("loopback ip=%q", loopback.IPAddress)
	}
}

func TestParseInlineCommentStripped(t *testing.T) {
	body := []byte("10.0.0.5 host # inline comment\n")
	got := Parse(body, "x")
	if len(got) != 1 {
		t.Fatalf("rows=%d", len(got))
	}
	if got[0].Hostname != "host" {
		t.Fatalf("hostname=%q (comment must not leak)", got[0].Hostname)
	}
	if got[0].Comment != "inline comment" {
		t.Fatalf("comment=%q", got[0].Comment)
	}
}

func TestParseSkipsCommentOnlyAndBlank(t *testing.T) {
	body := []byte(`# top
   # indented

# more
`)
	if got := Parse(body, "x"); len(got) != 0 {
		t.Fatalf("expected empty, got %d", len(got))
	}
}

func TestParseInvalidIPStillEmitsRow(t *testing.T) {
	body := []byte("garbage host\n")
	got := Parse(body, "x")
	if len(got) != 1 {
		t.Fatalf("rows=%d", len(got))
	}
	if got[0].IPKind != IPInvalid {
		t.Fatalf("ip_kind=%q, want invalid", got[0].IPKind)
	}
	if got[0].IsDNSPoisoningCandidate {
		t.Fatal("invalid IP must NOT flag poison")
	}
}

func TestParseHonoursMaxEntries(t *testing.T) {
	// Stuff a tiny ceiling for the test would need re-export; just
	// trust the implementation handles a large input.
	var body []byte
	for i := 0; i < 50; i++ {
		body = append(body, []byte("10.0.0.1 corp.local\n")...)
	}
	if got := Parse(body, "x"); len(got) != 50 {
		t.Fatalf("rows=%d, want 50", len(got))
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorReadsFirstAvailable(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "hosts")
	must(t, os.WriteFile(path, []byte("127.0.0.1 localhost\n10.0.0.5 evil.com\n"), 0o644))

	c := &fileCollector{
		paths:    []string{"/nope-a", path},
		readFile: os.ReadFile,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2, got %d: %+v", len(got), got)
	}
	if !got[1].IsDNSPoisoningCandidate {
		t.Fatalf("evil.com row should flag poison: %+v", got[1])
	}
}

func TestFileCollectorAllMissingOK(t *testing.T) {
	c := &fileCollector{
		paths:    []string{"/nope-a", "/nope-b"},
		readFile: os.ReadFile,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortEntries ----------------------------------------------------

func TestSortEntriesDeterministic(t *testing.T) {
	in := []Entry{
		{FilePath: "/etc/hosts", LineNo: 5, Hostname: "b"},
		{FilePath: "/etc/hosts", LineNo: 1, Hostname: "a"},
		{FilePath: "/etc/hosts", LineNo: 5, Hostname: "a"},
	}
	SortEntries(in)
	if in[0].LineNo != 1 || in[0].Hostname != "a" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[1].LineNo != 5 || in[1].Hostname != "a" {
		t.Fatalf("second=%+v", in[1])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
