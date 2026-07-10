package intranetweb

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPinnedSchemeStrings prevents drift between the Go const values
// and the SQLite CHECK constraint on host_intranet_webs.scheme.
func TestPinnedSchemeStrings(t *testing.T) {
	if string(SchemeHTTP) != "http" {
		t.Fatalf("SchemeHTTP = %q (breaks SQLite CHECK)", SchemeHTTP)
	}
	if string(SchemeHTTPS) != "https" {
		t.Fatalf("SchemeHTTPS = %q (breaks SQLite CHECK)", SchemeHTTPS)
	}
}

// TestPinnedSourceStrings prevents drift on discovery_source CHECK enum.
func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct {
		got, want string
	}{
		{string(SourceMDNS), "mdns"},
		{string(SourceSSDP), "ssdp"},
		{string(SourceWSDiscovery), "wsdiscovery"},
		{string(SourceNetBIOS), "netbios"},
		{string(SourceLLDP), "lldp"},
		{string(SourceHostsFile), "hosts-file"},
		{string(SourceProxyPAC), "proxy-pac"},
		{string(SourceManual), "manual"},
		{string(SourceSubnetSweep), "subnet-sweep"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestDefaultPortsCoverCommon(t *testing.T) {
	got := DefaultPorts()
	want := map[int]bool{80: true, 443: true, 8080: true, 8443: true}
	for w := range want {
		found := false
		for _, p := range got {
			if p == w {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("port %d missing from DefaultPorts: %v", w, got)
		}
	}
}

func TestIsCleartextAndTLSPortMutuallyExclusive(t *testing.T) {
	for _, p := range DefaultPorts() {
		if IsCleartextPort(p) && IsTLSPort(p) {
			t.Fatalf("port %d classified as both", p)
		}
	}
	// Sanity: standard pairs.
	if !IsCleartextPort(80) || !IsTLSPort(443) {
		t.Fatal("standard 80/443 misclassified")
	}
}

func TestHashPageStableAndSensitive(t *testing.T) {
	a := HashPage(200, "nginx/1.27", "text/html", "Login")
	b := HashPage(200, "nginx/1.27", "text/html", "Login")
	if a != b {
		t.Fatal("not deterministic")
	}
	c := HashPage(200, "nginx/1.27", "text/html", "Welcome")
	if a == c {
		t.Fatal("title change must alter hash")
	}
	d := HashPage(401, "nginx/1.27", "text/html", "Login")
	if a == d {
		t.Fatal("status change must alter hash")
	}
}

func TestIsDefaultLandingTitle(t *testing.T) {
	for _, want := range []string{
		"Welcome to nginx!",
		"Apache2 Ubuntu Default Page: It works",
		"It works!",
		"IIS Windows Server",
	} {
		if !IsDefaultLandingTitle(want) {
			t.Fatalf("%q must flag as default", want)
		}
	}
	for _, miss := range []string{
		"GitLab",
		"Grafana / Dashboard",
		"",
		"Custom login",
	} {
		if IsDefaultLandingTitle(miss) {
			t.Fatalf("%q must NOT flag as default", miss)
		}
	}
}

func TestIsDirectoryListingBody(t *testing.T) {
	cases := map[string]bool{
		`<html><head><title>Index of /backups</title></head>`: true,
		`<html><body><h1>Index of /etc</h1>`:                  true,
		`<html><body><h1>Welcome</h1></body></html>`:          false,
		"": false,
		`<html><head><title>INDEX OF /UPPER</title></head></html>`: true,
	}
	for in, want := range cases {
		got := IsDirectoryListingBody([]byte(in))
		if got != want {
			t.Fatalf("IsDirectoryListingBody(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestDedupeTargets(t *testing.T) {
	ts := []Target{
		{IP: "10.0.0.1", Port: 80, Source: SourceMDNS},
		{IP: "10.0.0.1", Port: 80, Source: SourceHostsFile}, // dup
		{IP: "10.0.0.1", Port: 443, Source: SourceMDNS},
		{IP: "10.0.0.2", Port: 80, Source: SourceSubnetSweep},
	}
	got := DedupeTargets(ts)
	if len(got) != 3 {
		t.Fatalf("len=%d, want 3 unique (ip,port) pairs: %+v", len(got), got)
	}
	// First-write-wins on source.
	if got[0].Source != SourceMDNS {
		t.Fatalf("first source should win: got %q", got[0].Source)
	}
}

func TestExtractTitle(t *testing.T) {
	cases := map[string]string{
		`<html><head><title>Login</title></head>`: "Login",
		`<HTML><HEAD><TITLE>UPPER</TITLE>`:        "UPPER",
		`<title id="x">spaced  out</title>`:       "spaced out",
		`<title>Foo &amp; Bar</title>`:            "Foo & Bar",
		`<title>multi
line</title>`: "multi line",
		``:                           "",
		`<body>no title here</body>`: "",
	}
	for in, want := range cases {
		if got := extractTitle([]byte(in)); got != want {
			t.Fatalf("extractTitle(%q) = %q, want %q", in, got, want)
		}
	}
}

// -- HostsFileResolver --------------------------------------------------

func TestHostsFileResolverPrivateOnly(t *testing.T) {
	body := `# typical hosts file
127.0.0.1   localhost
192.168.1.10 nas internal-nas
10.0.0.5    gitlab
::1         ip6-localhost
fc00::42    private-ula
8.8.8.8     dns.google
93.184.216.34 example.com
`
	r := &HostsFileResolver{
		Path:     "hosts-fake",
		Ports:    []int{80, 443},
		ReadFile: func(_ string) ([]byte, error) { return []byte(body), nil },
	}
	ts, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	hostnames := map[string]bool{}
	for _, t := range ts {
		hostnames[t.Host] = true
	}
	want := []string{"localhost", "nas", "gitlab", "ip6-localhost", "private-ula"}
	for _, w := range want {
		if !hostnames[w] {
			t.Fatalf("missing private host %q: %+v", w, ts)
		}
	}
	forbidden := []string{"dns.google", "example.com"}
	for _, f := range forbidden {
		if hostnames[f] {
			t.Fatalf("public host %q must NOT be included", f)
		}
	}
	// 5 private entries × 2 ports = 10 targets.
	if len(ts) != 10 {
		t.Fatalf("targets=%d, want 10", len(ts))
	}
}

func TestHostsFileResolverMissingOK(t *testing.T) {
	r := &HostsFileResolver{
		Path:  "/nope",
		Ports: []int{80},
		ReadFile: func(_ string) ([]byte, error) {
			return nil, errors.New("not found")
		},
	}
	ts, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(ts) != 0 {
		t.Fatalf("want empty, got %d", len(ts))
	}
}

func TestHostsFileResolverHandlesRealFileShape(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "hosts")
	must(t, os.WriteFile(tmp, []byte("192.168.1.1 router\n#10.0.0.1 commented\n"), 0o600))
	r := &HostsFileResolver{
		Path:     tmp,
		Ports:    []int{80},
		ReadFile: os.ReadFile,
	}
	ts, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 1 || ts[0].Host != "router" {
		t.Fatalf("unexpected targets: %+v", ts)
	}
}

func TestChainResolverSkipsFailures(t *testing.T) {
	good := &StaticResolver{Targets: []Target{{IP: "10.0.0.1", Port: 80, Source: SourceMDNS}}}
	bad := &failingResolver{}
	c := &ChainResolver{Resolvers: []TargetResolver{bad, good}}
	got, err := c.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 || got[0].IP != "10.0.0.1" {
		t.Fatalf("got %+v", got)
	}
}

type failingResolver struct{}

func (f *failingResolver) Resolve(_ context.Context) ([]Target, error) {
	return nil, errors.New("dns kaboom")
}

// -- HTTPProbe (httptest server) -----------------------------------------

func TestHTTPProbeCaptureTitleAndBanner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		w.Header().Set("X-Powered-By", "PHP/8.3")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>GitLab Login</title></head><body>hi</body></html>`))
	}))
	defer srv.Close()

	host, port := splitHostPort(t, srv.URL)
	probe := HTTPProbe{Timeout: 2 * time.Second}
	ep, err := probe.Probe(context.Background(), SchemeHTTP, Target{
		IP:     host,
		Port:   port,
		Source: SourceManual,
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if ep.StatusCode != 200 {
		t.Fatalf("status=%d", ep.StatusCode)
	}
	if ep.ServerHeader != "TestServer/1.0" {
		t.Fatalf("server=%q", ep.ServerHeader)
	}
	if ep.PoweredBy != "PHP/8.3" {
		t.Fatalf("powered_by=%q", ep.PoweredBy)
	}
	if ep.Title != "GitLab Login" {
		t.Fatalf("title=%q", ep.Title)
	}
	if !ep.IsCleartext {
		t.Fatal("http probe must flag IsCleartext")
	}
	if ep.PageHash == "" {
		t.Fatal("page_hash must be populated")
	}
	if ep.IsDefaultPage {
		t.Fatal("GitLab Login must NOT flag as default")
	}
}

func TestHTTPProbeDetectsNginxDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.27.1")
		_, _ = w.Write([]byte(`<html><head><title>Welcome to nginx!</title></head></html>`))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)
	ep, err := HTTPProbe{}.Probe(context.Background(), SchemeHTTP, Target{IP: host, Port: port, Source: SourceManual})
	if err != nil {
		t.Fatal(err)
	}
	if !ep.IsDefaultPage {
		t.Fatal("Welcome to nginx must flag IsDefaultPage")
	}
}

func TestHTTPProbeDetectsDirectoryListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><head><title>Index of /backups</title></head><body><h1>Index of /backups</h1></body></html>`))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)
	ep, err := HTTPProbe{}.Probe(context.Background(), SchemeHTTP, Target{IP: host, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if !ep.IsDirectoryListing {
		t.Fatal("autoindex page must flag IsDirectoryListing")
	}
}

func TestHTTPProbeCapturesBasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Admin"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)
	ep, err := HTTPProbe{}.Probe(context.Background(), SchemeHTTP, Target{IP: host, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if ep.StatusCode != 401 {
		t.Fatalf("status=%d", ep.StatusCode)
	}
	if ep.AuthScheme != "Basic" {
		t.Fatalf("auth_scheme=%q", ep.AuthScheme)
	}
}

func TestHTTPProbeFollowsNoRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)
	ep, err := HTTPProbe{}.Probe(context.Background(), SchemeHTTP, Target{IP: host, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if ep.StatusCode != 302 {
		t.Fatalf("status=%d (probe must NOT follow redirects)", ep.StatusCode)
	}
}

func TestHTTPProbeTLSSelfSignedAndExpiredFlags(t *testing.T) {
	// Use httptest.NewTLSServer for a real self-signed cert.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "TestTLS/1.0")
		_, _ = w.Write([]byte(`<html><head><title>Secure UI</title></head></html>`))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)
	ep, err := HTTPProbe{}.Probe(context.Background(), SchemeHTTPS, Target{IP: host, Port: port, Source: SourceMDNS})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if ep.IsCleartext {
		t.Fatal("https probe must NOT flag IsCleartext")
	}
	if ep.TLSFingerprintSHA256 == "" || len(ep.TLSFingerprintSHA256) != 64 {
		t.Fatalf("tls_fingerprint missing/wrong length: %q", ep.TLSFingerprintSHA256)
	}
	if ep.TLSSubject == "" {
		t.Fatal("tls_subject must be populated")
	}
	if !ep.TLSSelfSigned {
		t.Fatal("httptest cert is self-signed; flag must be set")
	}
	if ep.TLSExpired {
		t.Fatal("httptest cert should be valid")
	}
}

func TestHTTPProbeTLSExpiredDetected(t *testing.T) {
	cert, _ := mustExpiredCert(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)
	ep, err := HTTPProbe{}.Probe(context.Background(), SchemeHTTPS, Target{IP: host, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if !ep.TLSExpired {
		t.Fatalf("expired cert must flag tls_expired (notAfter=%s)", ep.TLSNotAfter)
	}
}

func TestHTTPProbeReverseDNSWhenTargetHostEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><head><title>OK</title></head></html>`))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	calls := 0
	probe := HTTPProbe{
		Timeout: 2 * time.Second,
		LookupAddr: func(_ context.Context, ip string) ([]string, error) {
			calls++
			if ip != host {
				t.Fatalf("LookupAddr got ip=%q want %q", ip, host)
			}
			return []string{"router.lan."}, nil
		},
	}
	ep, err := probe.Probe(context.Background(), SchemeHTTP, Target{
		IP:     host,
		Port:   port,
		Source: SourceSubnetSweep,
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if calls != 1 {
		t.Fatalf("LookupAddr calls=%d want 1", calls)
	}
	if ep.Host != "router.lan" {
		t.Fatalf("Host=%q want router.lan (trailing dot stripped)", ep.Host)
	}
}

func TestHTTPProbeReverseDNSFallsBackToIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><head><title>OK</title></head></html>`))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	probe := HTTPProbe{
		Timeout: 2 * time.Second,
		LookupAddr: func(_ context.Context, _ string) ([]string, error) {
			return nil, errors.New("nxdomain")
		},
	}
	ep, err := probe.Probe(context.Background(), SchemeHTTP, Target{
		IP:     host,
		Port:   port,
		Source: SourceMDNS,
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if ep.Host != host {
		t.Fatalf("Host=%q want %q (IP fallback on reverse-DNS failure)", ep.Host, host)
	}
}

func TestHTTPProbeReverseDNSSkippedWhenTargetHostProvided(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><head><title>OK</title></head></html>`))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	calls := 0
	probe := HTTPProbe{
		Timeout: 2 * time.Second,
		LookupAddr: func(_ context.Context, _ string) ([]string, error) {
			calls++
			return []string{"would-be-overridden.lan."}, nil
		},
	}
	ep, err := probe.Probe(context.Background(), SchemeHTTP, Target{
		IP:     host,
		Port:   port,
		Host:   "router.lan",
		Source: SourceHostsFile,
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if calls != 0 {
		t.Fatalf("LookupAddr must NOT be called when Target.Host is set; calls=%d", calls)
	}
	if ep.Host != "router.lan" {
		t.Fatalf("Host=%q want router.lan (Target.Host wins)", ep.Host)
	}
}

func TestHTTPProbeUsesTLSSANForHostnameWhenTargetEmpty(t *testing.T) {
	cert, _ := mustCertWithSANs(t, []string{"primary.intranet.lan", "alt.intranet.lan"}, "primary.intranet.lan")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>x</title></head></html>`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	calls := 0
	probe := HTTPProbe{
		LookupAddr: func(_ context.Context, _ string) ([]string, error) {
			calls++
			return []string{"reverse.lan."}, nil
		},
	}
	ep, err := probe.Probe(context.Background(), SchemeHTTPS, Target{IP: host, Port: port, Source: SourceSubnetSweep})
	if err != nil {
		t.Fatal(err)
	}
	if ep.Host != "primary.intranet.lan" {
		t.Fatalf("Host=%q want primary.intranet.lan (first SAN DNSName)", ep.Host)
	}
	if calls != 0 {
		t.Fatalf("reverse-DNS must NOT be called when TLS cert supplied a name; calls=%d", calls)
	}
}

func TestHTTPProbeFallsBackToTLSCommonName(t *testing.T) {
	cert, _ := mustCertWithSANs(t, nil, "legacy.intranet.lan")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	ep, err := HTTPProbe{}.Probe(context.Background(), SchemeHTTPS,
		Target{IP: host, Port: port, Source: SourceMDNS})
	if err != nil {
		t.Fatal(err)
	}
	if ep.Host != "legacy.intranet.lan" {
		t.Fatalf("Host=%q want legacy.intranet.lan (CN fallback when SAN empty)", ep.Host)
	}
}

func TestHTTPProbeSkipsTLSWildcardSAN(t *testing.T) {
	cert, _ := mustCertWithSANs(t, []string{"*.cluster.lan", "node-7.cluster.lan"}, "wild.lan")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	ep, err := HTTPProbe{}.Probe(context.Background(), SchemeHTTPS,
		Target{IP: host, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if ep.Host != "node-7.cluster.lan" {
		t.Fatalf("Host=%q want node-7.cluster.lan (wildcard SAN skipped)", ep.Host)
	}
}

func TestHTTPProbeHostDerivationPriority(t *testing.T) {
	// Target.Host wins over TLS cert + reverse-DNS even when both could fire.
	cert, _ := mustCertWithSANs(t, []string{"cert.example.lan"}, "cert.example.lan")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	ep, err := HTTPProbe{
		LookupAddr: func(_ context.Context, _ string) ([]string, error) {
			t.Fatal("reverse-DNS must NOT be called when Target.Host is set")
			return nil, nil
		},
	}.Probe(context.Background(), SchemeHTTPS,
		Target{IP: host, Port: port, Host: "explicit.lan", Source: SourceHostsFile})
	if err != nil {
		t.Fatal(err)
	}
	if ep.Host != "explicit.lan" {
		t.Fatalf("Host=%q want explicit.lan (Target.Host wins)", ep.Host)
	}
}

func TestHTTPProbeUnreachableErrors(t *testing.T) {
	// 127.0.0.1:1 will reject immediately on linux/darwin.
	_, err := HTTPProbe{Timeout: 200 * time.Millisecond}.Probe(
		context.Background(), SchemeHTTP, Target{IP: "127.0.0.1", Port: 1},
	)
	if err == nil {
		t.Fatal("expected probe error against unreachable port")
	}
}

// -- collector end-to-end -----------------------------------------------

func TestActiveCollectorEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		_, _ = w.Write([]byte(`<html><head><title>App</title></head></html>`))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	resolver := &StaticResolver{Targets: []Target{
		{IP: host, Port: port, Source: SourceManual},
		{IP: "127.0.0.1", Port: 1, Source: SourceManual}, // unreachable, must be dropped
	}}
	c := NewCollectorWith(resolver, HTTPProbe{Timeout: 500 * time.Millisecond}, 4)
	eps, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("want 1 reachable endpoint, got %d: %+v", len(eps), eps)
	}
	if eps[0].Title != "App" {
		t.Fatalf("title=%q", eps[0].Title)
	}
}

func TestActiveCollectorRespectsCancel(t *testing.T) {
	resolver := &StaticResolver{Targets: []Target{
		{IP: "10.255.255.255", Port: 80, Source: SourceManual},
	}}
	c := NewCollectorWith(resolver, HTTPProbe{Timeout: time.Second}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Collect(ctx)
	if err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestSortEndpoints(t *testing.T) {
	in := []Endpoint{
		{IP: "10.0.0.2", Port: 80},
		{IP: "10.0.0.1", Port: 443},
		{IP: "10.0.0.1", Port: 80},
	}
	SortEndpoints(in)
	if in[0].IP != "10.0.0.1" || in[0].Port != 80 {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].IP != "10.0.0.2" {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers -------------------------------------------------------------

func splitHostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, p
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// mustCertWithSANs builds a self-signed ECDSA cert with the supplied
// SAN DNSNames and CN. Used to exercise the TLS-based hostname
// derivation paths.
func mustCertWithSANs(t *testing.T, sans []string, commonName string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     sans,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return pair, leaf
}

// mustExpiredCert generates a self-signed ECDSA cert whose NotAfter is
// in the past. Used to exercise the tls_expired detection.
func mustExpiredCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired.intranet.test"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	// Confirm the test-side assertion: cert really is expired now.
	if time.Now().Before(leaf.NotAfter) {
		t.Fatal("test cert claims to be expired but isn't")
	}
	if !strings.Contains(leaf.Subject.String(), "expired.intranet.test") {
		t.Fatal("cert subject lost CommonName")
	}
	return pair, leaf
}
