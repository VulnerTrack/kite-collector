package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(StoreSystemRoot), "system-root"},
		{string(StoreSystemIntermediate), "system-intermediate"},
		{string(StoreUserRoot), "user-root"},
		{string(StoreUserIntermediate), "user-intermediate"},
		{string(StoreCodeSigning), "code-signing"},
		{string(StoreMDM), "mdm"},
		{string(StoreWebhost), "webhost"},
		{string(StoreOther), "other"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestParsePEMBundleSkipsNonCertBlocks(t *testing.T) {
	rsaCert := mintSelfSignedRSA(t, 2048, "test-root")
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaCert.Raw})
	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("not a real key but should be skipped"),
	})
	bundle := append(pemCert, pemKey...)
	bundle = append(bundle, pemCert...) // duplicate cert in same bundle

	got := ParsePEMBundle(bundle)
	if len(got) != 2 {
		t.Fatalf("want 2 certs (key block skipped), got %d", len(got))
	}
}

func TestFromX509RSACert(t *testing.T) {
	x := mintSelfSignedRSA(t, 2048, "rsa-root")
	c := FromX509(x, StoreSystemRoot, "/etc/ssl/certs/rsa-root.pem")

	if c.Store != StoreSystemRoot {
		t.Fatalf("store=%q", c.Store)
	}
	if !c.IsCA {
		t.Fatalf("must be CA")
	}
	if !c.IsSelfSigned {
		t.Fatalf("must be self-signed (issuer == subject + sig verifies)")
	}
	if c.KeyAlgorithm != "RSA-2048" {
		t.Fatalf("key_algorithm=%q, want RSA-2048", c.KeyAlgorithm)
	}
	if len(c.FingerprintSHA256) != 64 {
		t.Fatalf("fingerprint not sha256 hex: %q", c.FingerprintSHA256)
	}
	if len(c.FingerprintSHA1) != 40 {
		t.Fatalf("sha1 fingerprint length: %d", len(c.FingerprintSHA1))
	}
	if c.NotBefore == "" || c.NotAfter == "" {
		t.Fatalf("timestamps missing: %+v", c)
	}
}

func TestFromX509ECDSACert(t *testing.T) {
	x := mintSelfSignedECDSA(t, "ecdsa-root")
	c := FromX509(x, StoreSystemRoot, "/etc/ssl/certs/ecdsa-root.pem")
	if c.KeyAlgorithm != "ECDSA-P-256" {
		t.Fatalf("key_algorithm=%q, want ECDSA-P-256", c.KeyAlgorithm)
	}
}

func TestFromX509SerialFingerprintAreLowercaseHex(t *testing.T) {
	x := mintSelfSignedRSA(t, 2048, "case-test")
	c := FromX509(x, StoreSystemRoot, "/dev/null")
	for _, s := range []string{c.SerialHex, c.FingerprintSHA256, c.FingerprintSHA1} {
		for _, r := range s {
			if (r >= 'A' && r <= 'F') || (r >= 'G' && r <= 'Z') {
				t.Fatalf("hex must be lowercase: %q", s)
			}
		}
	}
}

func TestIsWeakDetectsObsoleteCrypto(t *testing.T) {
	cases := []struct {
		c    Certificate
		want bool
	}{
		// SHA-1 signature → weak
		{Certificate{SignatureAlgo: "SHA1-RSA", KeyAlgorithm: "RSA-2048"}, true},
		{Certificate{SignatureAlgo: "MD5-RSA", KeyAlgorithm: "RSA-2048"}, true},
		// RSA-1024 → weak (regardless of signature alg)
		{Certificate{SignatureAlgo: "SHA256-RSA", KeyAlgorithm: "RSA-1024"}, true},
		{Certificate{SignatureAlgo: "SHA256-RSA", KeyAlgorithm: "RSA-512"}, true},
		// Healthy combos
		{Certificate{SignatureAlgo: "SHA256-RSA", KeyAlgorithm: "RSA-2048"}, false},
		{Certificate{SignatureAlgo: "ECDSA-SHA256", KeyAlgorithm: "ECDSA-P-256"}, false},
		{Certificate{SignatureAlgo: "Ed25519", KeyAlgorithm: "Ed25519"}, false},
		// Empty / unknown → not weak (no signal)
		{Certificate{SignatureAlgo: "", KeyAlgorithm: ""}, false},
	}
	for i, tc := range cases {
		if got := IsWeak(tc.c); got != tc.want {
			t.Fatalf("case %d: IsWeak(%+v) = %v, want %v",
				i, tc.c, got, tc.want)
		}
	}
}

func TestSortCertificatesDeterministic(t *testing.T) {
	in := []Certificate{
		{Store: StoreSystemRoot, FingerprintSHA256: "z"},
		{Store: StoreUserRoot, FingerprintSHA256: "a"},
		{Store: StoreSystemRoot, FingerprintSHA256: "a"},
		{Store: StoreCodeSigning, FingerprintSHA256: "m"},
	}
	SortCertificates(in)
	want := []struct {
		s  Store
		fp string
	}{
		{StoreCodeSigning, "m"},
		{StoreSystemRoot, "a"},
		{StoreSystemRoot, "z"},
		{StoreUserRoot, "a"},
	}
	for i, c := range in {
		if c.Store != want[i].s || c.FingerprintSHA256 != want[i].fp {
			t.Fatalf("pos %d: got (%q,%q), want (%q,%q)",
				i, c.Store, c.FingerprintSHA256, want[i].s, want[i].fp)
		}
	}
}

func TestLooksLikeCertFile(t *testing.T) {
	cases := map[string]bool{
		"/etc/ssl/certs/foo.pem":           true,
		"/etc/ssl/certs/Foo.CRT":           true,
		"/etc/ssl/certs/bar.cer":           true,
		"/etc/ssl/certs/ca-bundle.crt":     true,
		"/etc/pki/tls/certs/ca-bundle.crt": true,
		"/etc/ssl/certs/12345678.0":        true, // OpenSSL subject-hash symlink
		"/etc/ssl/certs/deadbeef.1":        true,
		"/etc/ssl/certs/README":            false,
		"/etc/ssl/certs/foo.key":           false,
		"/etc/ssl/certs/ghihijkl.0":        false, // 'g' is not hex
		"/etc/ssl/certs/12345.0":           false, // too short for subject-hash
	}
	for in, want := range cases {
		if got := looksLikeCertFile(in); got != want {
			t.Fatalf("looksLikeCertFile(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsHex(t *testing.T) {
	for in, want := range map[string]bool{
		"":         false,
		"0":        true,
		"abcdef":   true,
		"ABCDEF":   false, // we only accept lowercase
		"123g":     false,
		"deadbeef": true,
	} {
		if got := isHex(in); got != want {
			t.Fatalf("isHex(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestPEMCollectorDedupesAndClassifies(t *testing.T) {
	root := mintSelfSignedRSA(t, 2048, "root")
	intermediate := mintSelfSignedRSA(t, 2048, "intermediate-also-root-in-fixture")

	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.pem")
	dupePath := filepath.Join(dir, "12345678.0") // symlink-style duplicate
	bundlePath := filepath.Join(dir, "ca-bundle.crt")

	writePEM(t, rootPath, root)
	writePEM(t, dupePath, root) // same fingerprint as root.pem
	writeBundlePEM(t, bundlePath, root, intermediate)

	c := &pemCollector{
		readFile: os.ReadFile,
		walkDir:  filepath.WalkDir,
		roots:    []pemRoot{{path: dir, store: StoreSystemRoot}},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 2 unique fingerprints (root duplicated 3 times across 3 files → 1 row).
	if len(got) != 2 {
		t.Fatalf("want 2 unique certs (dedup by fingerprint), got %d", len(got))
	}
	for _, cert := range got {
		if cert.Store != StoreSystemRoot {
			t.Fatalf("store not stamped: %q", cert.Store)
		}
		if cert.FingerprintSHA256 == "" {
			t.Fatalf("fingerprint missing")
		}
	}
}

func TestPEMCollectorSkipsMissingRoot(t *testing.T) {
	c := &pemCollector{
		readFile: os.ReadFile,
		walkDir:  filepath.WalkDir,
		roots:    []pemRoot{{path: "/does/not/exist/anywhere", store: StoreSystemRoot}},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing root must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestPEMCollectorRespectsMaxCertificates(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: generates MaxCertificates+5 RSA-1024 keys")
	}
	// Build one bundle with MaxCertificates+5 unique certs. The cap stops
	// the walk mid-bundle. We rely on the real walker but inject a fake
	// readFile to avoid the per-cert key generation cost (still real x509
	// parsing — that's the path under test).
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "ca-bundle.crt")
	if err := os.WriteFile(bundlePath, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	// Pre-generate enough unique certs once; bundle them.
	var bundle []byte
	for i := 0; i < MaxCertificates+5; i++ {
		c := mintSelfSignedRSA(t, 1024, "cap-fixture-"+itoa(i)) // 1024 for speed
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	c := &pemCollector{
		readFile: func(_ string) ([]byte, error) { return bundle, nil },
		walkDir:  filepath.WalkDir,
		roots:    []pemRoot{{path: dir, store: StoreSystemRoot}},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != MaxCertificates {
		t.Fatalf("want exactly %d (cap), got %d", MaxCertificates, len(got))
	}
}

// -- helpers --------------------------------------------------------------

// mintSelfSignedRSA builds a real self-signed RSA cert in-memory so the
// tests exercise the actual x509 parsing path (no fixture files).
func mintSelfSignedRSA(t *testing.T, bits int, cn string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("gen rsa key: %v", err)
	}
	return mintSelfSigned(t, cn, key, &key.PublicKey)
}

func mintSelfSignedECDSA(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ecdsa key: %v", err)
	}
	return mintSelfSigned(t, cn, key, &key.PublicKey)
}

func mintSelfSigned(t *testing.T, cn string, priv any, pub any) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		Issuer:                pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func writePEM(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeBundlePEM(t *testing.T, path string, certs ...*x509.Certificate) {
	t.Helper()
	out := make([]byte, 0, len(certs)*1024) // PEM-encoded cert ≈ 1KB
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write bundle %s: %v", path, err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [11]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
