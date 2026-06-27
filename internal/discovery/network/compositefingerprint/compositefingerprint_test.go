package compositefingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/apifingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/filefingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/headerfingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/jsfingerprint"
)

// hostPortFrom turns an httptest.Server.URL into (host, port).
func hostPortFrom(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return u.Hostname(), port
}

// multiSignalHandler emits headers (Cloudflare CF-Ray + nginx Server),
// the Grafana /api/health JSON for the API probe, a Supabase
// createClient inline for the JS probe, and an exposed /.git/HEAD for
// the file probe — a one-server stand-in for "every mechanism fires".
func multiSignalHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("CF-Ray", "7d0f8c5b6e3c1a2b-LAX")
		w.Header().Set("CF-Cache-Status", "DYNAMIC")
		switch r.URL.Path {
		case "/api/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"commit":"abc","database":"ok","version":"10.4.0"}`))
		case "/.git/HEAD":
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
		case "/":
			_, _ = w.Write([]byte(`<html><body><script>
const supabase = createClient('https://abcdefghijklmnopqrstuvwx.supabase.co', 'k')
</script></body></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestScan_FansOutAcrossMechanisms(t *testing.T) {
	srv := httptest.NewServer(multiSignalHandler())
	defer srv.Close()
	host, port := hostPortFrom(t, srv.URL)

	s := NewScannerWithClient(srv.Client())
	res, err := s.Scan(context.Background(), "http", host, port, Options{
		// TLS is impossible against a plain-HTTP httptest server;
		// leave it enabled to confirm the scanner *correctly skips*
		// it (scheme=http) rather than counting it as a failure.
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// TLS must be nil since scheme=http.
	if res.TLS != nil {
		t.Errorf("expected nil TLS section for http scheme, got %+v", res.TLS)
	}
	// Header should detect nginx + Cloudflare.
	if res.Header == nil {
		t.Fatalf("expected Header section populated")
	}
	if !hasHeaderProduct(res.Header.Fingerprints, "nginx") {
		t.Errorf("expected nginx via header, got %+v", res.Header.Fingerprints)
	}
	if !hasHeaderProduct(res.Header.Fingerprints, "Cloudflare edge") {
		t.Errorf("expected Cloudflare via CF-Ray, got %+v", res.Header.Fingerprints)
	}
	// JS should extract Supabase + ProjectID.
	if res.JS == nil {
		t.Fatalf("expected JS section populated")
	}
	if !hasJSProduct(res.JS.Fingerprints, "Supabase") {
		t.Errorf("expected Supabase via JS, got %+v", res.JS.Fingerprints)
	}
	// File should detect .git/HEAD as critical.
	if res.File == nil {
		t.Fatalf("expected File section populated")
	}
	if !hasFilePath(res.File.Findings, "/.git/HEAD") {
		t.Errorf("expected .git/HEAD via file, got %+v", res.File.Findings)
	}
	// API should detect Grafana via /api/health.
	if res.API == nil {
		t.Fatalf("expected API section populated")
	}
	if !hasAPIProduct(res.API.Fingerprints, "Grafana") {
		t.Errorf("expected Grafana via API probe, got %+v", res.API.Fingerprints)
	}
	// Errors should be empty when nothing failed.
	if len(res.Errors) != 0 {
		t.Errorf("expected zero errors, got %+v", res.Errors)
	}
	// Total fingerprints count is the sum.
	if total := res.TotalFingerprints(); total < 5 {
		t.Errorf("expected ≥5 total fingerprints across sections, got %d", total)
	}
}

func TestScan_DisableMechanismsHonoured(t *testing.T) {
	srv := httptest.NewServer(multiSignalHandler())
	defer srv.Close()
	host, port := hostPortFrom(t, srv.URL)
	s := NewScannerWithClient(srv.Client())

	res, err := s.Scan(context.Background(), "http", host, port, Options{
		DisableFile:   true,
		DisableAPI:    true,
		DisableJS:     true,
		DisableHeader: false, // only header runs
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.File != nil || res.API != nil || res.JS != nil {
		t.Errorf("disabled mechanisms must yield nil sections, got file=%v api=%v js=%v",
			res.File, res.API, res.JS)
	}
	if res.Header == nil {
		t.Fatalf("header section must remain populated")
	}
}

func TestScan_PerMechanismTimeoutDoesNotBlockOthers(t *testing.T) {
	// File scanner gets a 50ms timeout against a 200ms-slow server —
	// it should error/abort while the other mechanisms continue.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("CF-Ray", "x")
			_, _ = w.Write([]byte(`<html></html>`))
			return
		}
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	host, port := hostPortFrom(t, srv.URL)
	s := NewScannerWithClient(srv.Client())
	res, err := s.Scan(context.Background(), "http", host, port, Options{
		PerMechanismTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// Header should still detect Cloudflare (fast: served by root handler).
	if res.Header == nil || !hasHeaderProduct(res.Header.Fingerprints, "Cloudflare edge") {
		t.Errorf("expected header section populated despite file timeout, got %+v", res.Header)
	}
}

func TestScan_SchemeValidation(t *testing.T) {
	s := NewScanner()
	if _, err := s.Scan(context.Background(), "ftp", "h", 80, Options{}); err == nil {
		t.Fatalf("expected error on ftp scheme")
	}
	if _, err := s.Scan(context.Background(), "http", "", 80, Options{}); err == nil {
		t.Fatalf("expected error on empty host")
	}
	if _, err := s.Scan(context.Background(), "http", "h", 0, Options{}); err == nil {
		t.Fatalf("expected error on port 0")
	}
	if _, err := s.Scan(context.Background(), "http", "h", 70000, Options{}); err == nil {
		t.Fatalf("expected error on port >65535")
	}
}

func TestCompositeResult_TotalFingerprintsNilSafe(t *testing.T) {
	var r *CompositeResult
	if r.TotalFingerprints() != 0 {
		t.Fatalf("nil receiver must return 0")
	}
}

// Helpers — narrow accessors against each sub-package's Fingerprint
// shape so the tests stay readable.

func hasHeaderProduct(fps []headerfingerprint.Fingerprint, product string) bool {
	for _, f := range fps {
		if f.Product == product {
			return true
		}
	}
	return false
}
func hasJSProduct(fps []jsfingerprint.Fingerprint, product string) bool {
	for _, f := range fps {
		if f.Product == product {
			return true
		}
	}
	return false
}
func hasAPIProduct(fps []apifingerprint.Fingerprint, product string) bool {
	for _, f := range fps {
		if f.Product == product {
			return true
		}
	}
	return false
}
func hasFilePath(fs []filefingerprint.Finding, path string) bool {
	for _, f := range fs {
		if f.Path == path {
			return true
		}
	}
	return false
}
