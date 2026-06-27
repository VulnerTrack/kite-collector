package winafipwsaa

import (
	"context"
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

// -- enum / helper pinning -----------------------------------------

func TestArtifactKindAndEndpointStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ArtifactCert), "cert"},
		{string(ArtifactPrivateKey), "private-key"},
		{string(ArtifactPKCS12), "pkcs12"},
		{string(ArtifactTAXML), "ta-xml"},
		{string(ArtifactTRACMS), "tra-cms"},
		{string(ArtifactWSAAConfig), "wsaa-config"},
		{string(ArtifactUnknown), "unknown"},
		{string(EndpointProduction), "production"},
		{string(EndpointHomologatio), "homologation"},
		{string(EndpointUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("body"))
	b := HashContents([]byte("body"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsValidCuitEntityPrefix(t *testing.T) {
	yes := []string{"20", "23", "24", "27", "30", "33", "34"}
	no := []string{"", "11", "50", "99"}
	for _, v := range yes {
		if !IsValidCuitEntityPrefix(v) {
			t.Fatalf("expected valid: %q", v)
		}
	}
	for _, v := range no {
		if IsValidCuitEntityPrefix(v) {
			t.Fatalf("expected invalid: %q", v)
		}
	}
}

func TestIsAfipPath(t *testing.T) {
	yes := []string{
		`C:\Users\alice\AppData\Roaming\afip\produccion.crt`,
		"/home/alice/.pyafipws/cert.key",
		"/opt/wsaa/wsfev1/config.ini",
		"/home/bob/Documents/ARCA/factura.xml",
	}
	no := []string{
		"/home/alice/.ssh/id_rsa",
		"/etc/ssl/certs/ca.pem",
		"",
	}
	for _, v := range yes {
		if !IsAfipPath(v) {
			t.Fatalf("expected AFIP path: %q", v)
		}
	}
	for _, v := range no {
		if IsAfipPath(v) {
			t.Fatalf("expected NOT AFIP path: %q", v)
		}
	}
}

func TestDetectEndpointEnv(t *testing.T) {
	cases := map[string]EndpointEnv{
		"/home/u/afip/produccion/cert.crt":        EndpointProduction,
		"/home/u/afip/homologacion/cert.crt":      EndpointHomologatio,
		"/home/u/afip/wsaahomo/cache.xml":         EndpointHomologatio,
		"/home/u/afip/cert.crt":                   EndpointUnknown,
		"/srv/integrations/afip/prod/wsfe.key":    EndpointProduction,
		"/srv/integrations/afip/test/wsfe.key":    EndpointHomologatio,
		"/srv/integrations/afip/prod-test/wsfe.k": EndpointUnknown,
	}
	for in, want := range cases {
		if got := DetectEndpointEnv(in); got != want {
			t.Fatalf("DetectEndpointEnv(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyByExtension(t *testing.T) {
	cases := map[string]ArtifactKind{
		"a.crt":  ArtifactCert,
		"a.pem":  ArtifactCert,
		"a.cer":  ArtifactCert,
		"a.key":  ArtifactPrivateKey,
		"a.p12":  ArtifactPKCS12,
		"a.pfx":  ArtifactPKCS12,
		"a.cms":  ArtifactTRACMS,
		"a.xml":  ArtifactUnknown, // disambiguated by content
		"a.ini":  ArtifactWSAAConfig,
		"a.json": ArtifactWSAAConfig,
		"a.bin":  ArtifactUnknown,
	}
	for in, want := range cases {
		if got := ClassifyByExtension(in); got != want {
			t.Fatalf("ClassifyByExtension(%q)=%q want %q", in, got, want)
		}
	}
}

// -- CUIT fingerprint extraction -----------------------------------

func TestCuitFingerprintFromText(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"CUIT 30-71234567-8", "30", "5678"},
		{"serialNumber=CUIT 20-12345678-9", "20", "6789"},
		{"30712345678", "30", "5678"},
		{"no cuit here", "", ""},
		{"CUIT 11-12345678-9", "", ""}, // invalid prefix
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprintFromText(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprintFromText(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

// -- AnnotateSecurity branches -------------------------------------

func TestAnnotatePrivateKeyExposed(t *testing.T) {
	a := Artifact{ArtifactKind: ArtifactPrivateKey, IsPrivateKeyUnencrypted: true, FileMode: 0o644}
	AnnotateSecurity(&a)
	if !a.IsWorldReadable {
		t.Fatal("0o644 must flag world-readable")
	}
	if !a.IsCredentialExposureRisk {
		t.Fatal("unencrypted key + world-readable must flag exposure")
	}
}

func TestAnnotatePrivateKey0600Clean(t *testing.T) {
	a := Artifact{ArtifactKind: ArtifactPrivateKey, IsPrivateKeyUnencrypted: true, FileMode: 0o600}
	AnnotateSecurity(&a)
	if a.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateTaLiveTokenExposed(t *testing.T) {
	a := Artifact{ArtifactKind: ArtifactTAXML, IsTaTokenPresent: true, IsTaExpired: false, FileMode: 0o644}
	AnnotateSecurity(&a)
	if !a.IsCredentialExposureRisk {
		t.Fatal("live TA + world-readable must flag exposure")
	}
}

func TestAnnotateTaExpiredClean(t *testing.T) {
	a := Artifact{ArtifactKind: ArtifactTAXML, IsTaTokenPresent: true, IsTaExpired: true, FileMode: 0o644}
	AnnotateSecurity(&a)
	if a.IsCredentialExposureRisk {
		t.Fatal("expired TA must NOT flag exposure")
	}
}

// -- ParseTicketAcceso ---------------------------------------------

func TestParseTicketAccesoLive(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<loginTicketResponse version="1.0">
  <header>
    <source>CN=wsaa, O=AFIP, C=AR, SERIALNUMBER=CUIT 33-99999999-9</source>
    <destination>SERIALNUMBER=CUIT 30-71234567-8</destination>
    <generationTime>2026-06-23T08:00:00.000-03:00</generationTime>
    <expirationTime>2026-06-23T20:00:00.000-03:00</expirationTime>
  </header>
  <credentials>
    <token>opaque-token-bytes</token>
    <sign>opaque-sign</sign>
  </credentials>
</loginTicketResponse>`)
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	ta, ok := ParseTicketAcceso(body, now)
	if !ok {
		t.Fatal("typical TA must parse")
	}
	if !ta.IsTokenPresent || ta.IsExpired {
		t.Fatalf("token=%v expired=%v", ta.IsTokenPresent, ta.IsExpired)
	}
	if ta.SourceCuitPfx != "33" || ta.SourceCuitSfx4 != "9999" {
		t.Fatalf("source cuit: %q %q", ta.SourceCuitPfx, ta.SourceCuitSfx4)
	}
	if ta.DestCuitPfx != "30" || ta.DestCuitSfx4 != "5678" {
		t.Fatalf("dest cuit: %q %q", ta.DestCuitPfx, ta.DestCuitSfx4)
	}
}

func TestParseTicketAccesoExpired(t *testing.T) {
	body := []byte(`<loginTicketResponse><header>
<expirationTime>2026-06-23T08:00:00.000-03:00</expirationTime></header>
<credentials><token>x</token></credentials></loginTicketResponse>`)
	now := time.Date(2026, 6, 23, 23, 0, 0, 0, time.UTC)
	ta, ok := ParseTicketAcceso(body, now)
	if !ok {
		t.Fatal("must parse")
	}
	if !ta.IsExpired {
		t.Fatal("must flag expired")
	}
}

func TestParseTicketAccesoMalformedRejected(t *testing.T) {
	_, ok := ParseTicketAcceso([]byte("not xml"), time.Now())
	if ok {
		t.Fatal("malformed must NOT parse")
	}
}

// -- AnalyzePrivateKey ---------------------------------------------

func TestAnalyzePrivateKeyUnencrypted(t *testing.T) {
	body := makeUnencryptedKeyPEM(t)
	k, ok := AnalyzePrivateKey(body)
	if !ok {
		t.Fatal("PEM must parse")
	}
	if !k.IsUnencrypted {
		t.Fatal("plain key must flag unencrypted")
	}
}

func TestAnalyzePrivateKeyEncryptedHeader(t *testing.T) {
	body := []byte(`-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,1234567890ABCDEF1234567890ABCDEF

aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsbw==
-----END RSA PRIVATE KEY-----`)
	k, ok := AnalyzePrivateKey(body)
	if !ok {
		t.Fatal("PEM must parse")
	}
	if k.IsUnencrypted {
		t.Fatal("Proc-Type: 4,ENCRYPTED must NOT flag unencrypted")
	}
}

func TestAnalyzePrivateKeyNotKey(t *testing.T) {
	_, ok := AnalyzePrivateKey([]byte("nothing here"))
	if ok {
		t.Fatal("non-PEM must NOT parse")
	}
}

// -- AnalyzeCert ---------------------------------------------------

func TestAnalyzeCertExtractsCN(t *testing.T) {
	body := makeCertPEM(t)
	c, ok := AnalyzeCert(body)
	if !ok {
		t.Fatal("cert must parse")
	}
	if c.SubjectCN != "fixture-cn" {
		t.Fatalf("cn=%q", c.SubjectCN)
	}
	if c.CuitEntityPrefix != "30" || c.CuitSuffix4 != "5678" {
		t.Fatalf("cuit pfx=%q sfx=%q", c.CuitEntityPrefix, c.CuitSuffix4)
	}
}

// -- collector end-to-end -----------------------------------------

func TestFileCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")

	// alice has an unencrypted AFIP key + a live TA cache.
	aliceDir := filepath.Join(usersBase, "alice", "pyafipws")
	must(t, os.MkdirAll(aliceDir, 0o755))

	keyPath := filepath.Join(aliceDir, "produccion.key")
	must(t, os.WriteFile(keyPath, makeUnencryptedKeyPEM(t), 0o644))

	certPath := filepath.Join(aliceDir, "produccion.crt")
	must(t, os.WriteFile(certPath, makeCertPEM(t), 0o644))

	taPath := filepath.Join(aliceDir, "wsfe.ta.xml")
	must(t, os.WriteFile(taPath, []byte(`<loginTicketResponse><header>
<source>SERIALNUMBER=CUIT 33-99999999-9</source>
<destination>SERIALNUMBER=CUIT 30-71234567-8</destination>
<expirationTime>2026-06-23T20:00:00.000-03:00</expirationTime>
</header><credentials><token>live-token</token></credentials></loginTicketResponse>`), 0o644))

	// bob has a non-AFIP key — must be ignored.
	bobDir := filepath.Join(usersBase, "bob", ".ssh")
	must(t, os.MkdirAll(bobDir, 0o755))
	must(t, os.WriteFile(filepath.Join(bobDir, "id_rsa"),
		makeUnencryptedKeyPEM(t), 0o600))

	// Public profile must be skipped.
	pubDir := filepath.Join(usersBase, "Public", "afip")
	must(t, os.MkdirAll(pubDir, 0o755))
	must(t, os.WriteFile(filepath.Join(pubDir, "produccion.key"),
		makeUnencryptedKeyPEM(t), 0o644))

	c := &fileCollector{
		usersBases: []string{usersBase},
		getenv:     func(string) string { return "" },
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
		now:        func() time.Time { return time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 (alice key+cert+ta), got %d: %+v", len(got), got)
	}

	var aliceKey, aliceCert, aliceTa Artifact
	for _, a := range got {
		switch a.FilePath {
		case keyPath:
			aliceKey = a
		case certPath:
			aliceCert = a
		case taPath:
			aliceTa = a
		}
	}
	if aliceKey.FilePath == "" || aliceCert.FilePath == "" || aliceTa.FilePath == "" {
		t.Fatalf("missing expected files: %+v", got)
	}
	if !aliceKey.IsPrivateKeyUnencrypted || !aliceKey.IsCredentialExposureRisk {
		t.Fatalf("alice key must flag: %+v", aliceKey)
	}
	if aliceKey.EndpointEnv != EndpointProduction {
		t.Fatalf("alice key env=%q want production", aliceKey.EndpointEnv)
	}
	if aliceCert.SubjectCN != "fixture-cn" {
		t.Fatalf("alice cert CN=%q", aliceCert.SubjectCN)
	}
	if aliceCert.CuitEntityPrefix != "30" || aliceCert.CuitSuffix4 != "5678" {
		t.Fatalf("alice cert cuit: %+v", aliceCert)
	}
	if !aliceTa.IsTaTokenPresent || aliceTa.IsTaExpired {
		t.Fatalf("alice TA: %+v", aliceTa)
	}
	if !aliceTa.IsCredentialExposureRisk {
		t.Fatalf("alice TA + world-readable must flag exposure: %+v", aliceTa)
	}
	if aliceTa.CuitEntityPrefix != "33" {
		t.Fatalf("alice TA source cuit pfx=%q", aliceTa.CuitEntityPrefix)
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		usersBases: []string{"/nope-users"},
		getenv:     func(string) string { return "" },
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
		now:        func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortArtifactsDeterministic(t *testing.T) {
	in := []Artifact{
		{FilePath: "z", ArtifactKind: ArtifactCert},
		{FilePath: "a", ArtifactKind: ArtifactPrivateKey},
		{FilePath: "a", ArtifactKind: ArtifactCert},
	}
	SortArtifacts(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != ArtifactCert {
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

func makeUnencryptedKeyPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

func makeCertPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "fixture-cn",
			SerialNumber: "CUIT 30-71234567-8",
			Organization: []string{"AFIP-Fixture"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
