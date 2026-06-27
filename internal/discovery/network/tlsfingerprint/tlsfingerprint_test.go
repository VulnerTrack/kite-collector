package tlsfingerprint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"testing"
	"time"
)

// genCert creates a self-signed cert that matches the supplied
// Subject/Issuer/SANs spec. Used to drive tlstest servers so we can
// exercise the matcher without hitting the real internet.
type certSpec struct {
	NotBefore time.Time
	NotAfter  time.Time
	SubjectCN string
	IssuerCN  string
	IssuerOrg []string
	SANs      []string
}

func generateCert(t *testing.T, spec certSpec) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	if spec.NotBefore.IsZero() {
		spec.NotBefore = time.Now().Add(-time.Hour)
	}
	if spec.NotAfter.IsZero() {
		spec.NotAfter = time.Now().Add(24 * time.Hour)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: spec.SubjectCN},
		Issuer: pkix.Name{
			CommonName:   spec.IssuerCN,
			Organization: spec.IssuerOrg,
		},
		NotBefore:             spec.NotBefore,
		NotAfter:              spec.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              spec.SANs,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        parsed,
	}, parsed
}

// startTLSServer returns the host and port a tls.Listener bound to it
// is listening on. The listener serves the supplied cert and accepts
// connections in a goroutine that closes them immediately after the
// handshake.
func startTLSServer(t *testing.T, cert tls.Certificate) (string, int, func()) {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Force the handshake so the client receives the cert,
			// then close.
			tlsConn, _ := c.(*tls.Conn)
			if tlsConn != nil {
				_ = tlsConn.HandshakeContext(context.Background())
			}
			_ = c.Close()
		}
	}()
	addrStr := ln.Addr().String()
	host, portStr, _ := net.SplitHostPort(addrStr)
	port, _ := strconv.Atoi(portStr)
	stop := func() { _ = ln.Close() }
	return host, port, stop
}

func TestScan_DetectsSupabaseSANSuffix(t *testing.T) {
	cert, _ := generateCert(t, certSpec{
		SubjectCN: "xxxxxxxxxxxxxxxxxxxxxxxx.supabase.co",
		IssuerCN:  "Test Root",
		SANs:      []string{"xxxxxxxxxxxxxxxxxxxxxxxx.supabase.co", "*.supabase.co"},
	})
	host, port, stop := startTLSServer(t, cert)
	defer stop()

	s := NewScanner(nil)
	res, err := s.Scan(context.Background(), host, port, ScanOptions{SNI: "x.supabase.co"})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if !hasVendor(res.Fingerprints, "Supabase") {
		t.Fatalf("expected Supabase fingerprint, got %+v", res.Fingerprints)
	}
}

func TestScan_DetectsCloudfrontAndAWSStorage(t *testing.T) {
	cert, _ := generateCert(t, certSpec{
		SubjectCN: "d1234abcdef.cloudfront.net",
		IssuerCN:  "Amazon RSA 2048 M01",
		IssuerOrg: []string{"Amazon"},
		SANs:      []string{"d1234abcdef.cloudfront.net"},
	})
	host, port, stop := startTLSServer(t, cert)
	defer stop()

	s := NewScanner(nil)
	res, _ := s.Scan(context.Background(), host, port, ScanOptions{SNI: "x.cloudfront.net"})
	if !hasVendor(res.Fingerprints, "Amazon") {
		t.Fatalf("expected Amazon fingerprint, got %+v", res.Fingerprints)
	}
	products := vendorProducts(res.Fingerprints, "Amazon")
	if len(products) < 1 {
		t.Fatalf("expected at least one Amazon product, got %v", products)
	}
}

func TestScan_DetectsVercelStatic(t *testing.T) {
	cert, _ := generateCert(t, certSpec{
		SubjectCN: "myapp.vercel.app",
		IssuerCN:  "Let's Encrypt R3",
		SANs:      []string{"myapp.vercel.app"},
	})
	host, port, stop := startTLSServer(t, cert)
	defer stop()

	s := NewScanner(nil)
	res, _ := s.Scan(context.Background(), host, port, ScanOptions{SNI: "myapp.vercel.app"})
	if !hasVendor(res.Fingerprints, "Vercel") {
		t.Fatalf("expected Vercel, got %+v", res.Fingerprints)
	}
	// Note: self-signed test certs have Issuer==Subject, so the
	// Let's Encrypt issuer signature is not exercised here. See
	// TestMatchPattern_IssuerRegex for direct coverage.
}

func TestScan_ReturnsCertSummaryOnNoMatch(t *testing.T) {
	cert, _ := generateCert(t, certSpec{
		SubjectCN: "example.test",
		IssuerCN:  "Test Internal CA",
		SANs:      []string{"example.test", "www.example.test"},
	})
	host, port, stop := startTLSServer(t, cert)
	defer stop()

	s := NewScanner(nil)
	res, _ := s.Scan(context.Background(), host, port, ScanOptions{SNI: "example.test"})
	if len(res.Fingerprints) != 0 {
		t.Fatalf("expected no fingerprints, got %+v", res.Fingerprints)
	}
	if res.Cert.SubjectCN != "example.test" {
		t.Fatalf("expected subject CN captured, got %q", res.Cert.SubjectCN)
	}
	if len(res.Cert.SANs) != 2 {
		t.Fatalf("expected 2 SANs captured, got %d", len(res.Cert.SANs))
	}
	if res.ClientJA3 == "" {
		t.Fatalf("expected ClientJA3 populated")
	}
}

func TestScan_InvalidPortErrors(t *testing.T) {
	s := NewScanner(nil)
	if _, err := s.Scan(context.Background(), "h", 0, ScanOptions{}); err == nil {
		t.Fatalf("expected error on port=0")
	}
	if _, err := s.Scan(context.Background(), "h", 70000, ScanOptions{}); err == nil {
		t.Fatalf("expected error on port>65535")
	}
}

func TestScan_EmptyHostErrors(t *testing.T) {
	s := NewScanner(nil)
	if _, err := s.Scan(context.Background(), "", 443, ScanOptions{}); err == nil {
		t.Fatalf("expected error on empty host")
	}
}

func TestScan_DialFailureSurfacesError(t *testing.T) {
	// 1 is reserved, never listening. Tight deadline to keep test fast.
	s := NewScanner(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := s.Scan(ctx, "127.0.0.1", 1, ScanOptions{DialTimeout: 100 * time.Millisecond})
	if err == nil {
		t.Fatalf("expected dial error")
	}
}

func TestMatchPattern_SANSuffix(t *testing.T) {
	cs := CertSummary{SANs: []string{"abc.supabase.co", "*.supabase.co"}}
	p := Pattern{Name: "supabase-co", SANSuffix: ".supabase.co", Kind: SignalSANSuffix, Confidence: ConfidenceHigh}
	ok, ev := MatchPattern(p, cs)
	if !ok {
		t.Fatalf("expected match")
	}
	if ev == "" {
		t.Fatalf("expected non-empty evidence")
	}
}

func TestMatchPattern_IssuerRegex(t *testing.T) {
	cs := CertSummary{IssuerJoined: "R3 — Let's Encrypt"}
	for _, sig := range DefaultCatalog() {
		if sig.Vendor != "Let's Encrypt" {
			continue
		}
		ok, _ := MatchPattern(sig.Patterns[0], cs)
		if !ok {
			t.Fatalf("expected Let's Encrypt issuer match on %q", cs.IssuerJoined)
		}
	}
}

func TestSummariseCert_RoundTrip(t *testing.T) {
	cert, parsed := generateCert(t, certSpec{
		SubjectCN: "x.example",
		IssuerCN:  "Test CA",
		IssuerOrg: []string{"Test Org"},
		SANs:      []string{"x.example", "y.example"},
	})
	_ = cert
	cs := SummariseCert(parsed)
	if cs.SubjectCN != "x.example" {
		t.Errorf("subject: got %q", cs.SubjectCN)
	}
	if len(cs.SANs) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(cs.SANs))
	}
	if cs.IssuerJoined == "" {
		t.Errorf("expected IssuerJoined populated")
	}
}

func TestDefaultCatalog_AllPatternsHaveOneMatcher(t *testing.T) {
	for _, sig := range DefaultCatalog() {
		if sig.Vendor == "" || sig.Product == "" {
			t.Errorf("empty vendor/product: %+v", sig)
		}
		for i, p := range sig.Patterns {
			count := 0
			if p.SANSuffix != "" {
				count++
			}
			if p.IssuerRegex != nil {
				count++
			}
			if p.SubjectRegex != nil {
				count++
			}
			if p.OCSPHost != "" {
				count++
			}
			if count != 1 {
				t.Errorf("%s/%s pattern[%d] %q: expected exactly one matcher, got %d",
					sig.Vendor, sig.Product, i, p.Name, count)
			}
			if p.Name == "" {
				t.Errorf("%s/%s pattern[%d]: empty name", sig.Vendor, sig.Product, i)
			}
			if p.Kind == "" {
				t.Errorf("%s/%s pattern[%d] %q: empty kind", sig.Vendor, sig.Product, i, p.Name)
			}
		}
	}
}

// Ensure URL parsing works for the endpoint string format.
func TestScan_EndpointHasTLSScheme(t *testing.T) {
	cert, _ := generateCert(t, certSpec{
		SubjectCN: "x.example", IssuerCN: "T",
		SANs: []string{"x.example"},
	})
	host, port, stop := startTLSServer(t, cert)
	defer stop()
	s := NewScanner(nil)
	res, _ := s.Scan(context.Background(), host, port, ScanOptions{SNI: "x.example"})
	u, err := url.Parse(res.Endpoint)
	if err != nil {
		t.Fatalf("endpoint not a URL: %v", err)
	}
	if u.Scheme != "https" {
		t.Errorf("expected scheme=https, got %q", u.Scheme)
	}
}

// Helpers

func hasVendor(fps []Fingerprint, vendor string) bool {
	for _, f := range fps {
		if f.Vendor == vendor {
			return true
		}
	}
	return false
}

func vendorProducts(fps []Fingerprint, vendor string) []string {
	out := make([]string, 0)
	for _, f := range fps {
		if f.Vendor == vendor {
			out = append(out, f.Product)
		}
	}
	return out
}
