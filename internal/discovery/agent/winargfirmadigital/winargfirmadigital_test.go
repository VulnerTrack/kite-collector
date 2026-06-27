package winargfirmadigital

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

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindSoftPFX), "soft-cert-pfx"},
		{string(KindSoftP12), "soft-cert-p12"},
		{string(KindX509PEM), "x509-pem"},
		{string(KindX509DER), "x509-der"},
		{string(KindCACert), "ca-cert"},
		{string(KindKeyOnly), "key-only"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(IssuerONTI), "onti"},
		{string(IssuerACModernizacion), "ac-modernizacion"},
		{string(IssuerACRaizRepArg), "ac-raiz-republica-argentina"},
		{string(IssuerACARCA), "ac-arca"},
		{string(IssuerACAFIP), "ac-afip"},
		{string(IssuerACCamerfirma), "ac-camerfirma"},
		{string(IssuerACEncode), "ac-encode"},
		{string(IssuerOther), "other"},
		{string(IssuerUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsAfipWsaaPath(t *testing.T) {
	yes := []string{
		`C:\Users\alice\afip\produccion.crt`,
		"/home/u/.pyafipws/cert.pfx",
		"/srv/wsaa/cert.pem",
	}
	no := []string{
		`C:\FirmaDigital\firma_natanael.pfx`,
		"/opt/firma-digital/cert.pem",
		"",
	}
	for _, v := range yes {
		if !IsAfipWsaaPath(v) {
			t.Fatalf("expected AFIP-WSAA path: %q", v)
		}
	}
	for _, v := range no {
		if IsAfipWsaaPath(v) {
			t.Fatalf("expected NOT AFIP-WSAA path: %q", v)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"firma_digital_natanael.pfx",
		"firmadigital_juan.p12",
		"onti_cert.pem",
		"ac_modernizacion_acme.cer",
		"ac-raiz.crt",
		"cert_firma_alice.p12",
		"certificado_2024.pem",
	}
	no := []string{"", "factura.pdf", "cv.docx"}
	for _, v := range yes {
		if !IsCandidateName(v) {
			t.Fatalf("expected candidate: %q", v)
		}
	}
	for _, v := range no {
		if IsCandidateName(v) {
			t.Fatalf("expected NOT candidate: %q", v)
		}
	}
}

func TestIsCandidateExt(t *testing.T) {
	yes := []string{"a.pfx", "a.p12", "a.cer", "a.crt", "a.pem", "a.der", "a.key"}
	no := []string{"a.txt", "a.pdf", "", "a.docx"}
	for _, v := range yes {
		if !IsCandidateExt(v) {
			t.Fatalf("expected cert ext: %q", v)
		}
	}
	for _, v := range no {
		if IsCandidateExt(v) {
			t.Fatalf("expected NOT cert ext: %q", v)
		}
	}
}

func TestCertKindFromExt(t *testing.T) {
	cases := map[string]CertKind{
		"a.pfx": KindSoftPFX,
		"a.p12": KindSoftP12,
		"a.pem": KindX509PEM,
		"a.crt": KindX509PEM,
		"a.cer": KindX509DER,
		"a.der": KindX509DER,
		"a.key": KindKeyOnly,
		"a.bin": KindUnknown,
	}
	for in, want := range cases {
		if got := CertKindFromExt(in); got != want {
			t.Fatalf("CertKindFromExt(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIssuerCAFromText(t *testing.T) {
	cases := map[string]IssuerCA{
		"CN=AC-Raíz República Argentina, O=ONTI":             IssuerACRaizRepArg,
		"CN=AC-Modernización, O=Ministerio de Modernización": IssuerACModernizacion,
		"CN=AC-ARCA, O=ARCA":                                 IssuerACARCA,
		"CN=AC-AFIP, O=AFIP":                                 IssuerACAFIP,
		"CN=AC-ONTI v3, O=ONTI":                              IssuerONTI,
		"CN=AC Camerfirma":                                   IssuerACCamerfirma,
		"CN=Encode":                                          IssuerACEncode,
		"CN=Random CA":                                       IssuerOther,
		"":                                                   IssuerUnknown,
	}
	for in, want := range cases {
		if got := IssuerCAFromText(in); got != want {
			t.Fatalf("IssuerCAFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsONTIAccreditedIssuer(t *testing.T) {
	yes := []IssuerCA{
		IssuerONTI, IssuerACModernizacion, IssuerACRaizRepArg,
		IssuerACARCA, IssuerACAFIP,
	}
	no := []IssuerCA{
		IssuerACCamerfirma, IssuerACEncode, IssuerOther, IssuerUnknown,
	}
	for _, v := range yes {
		if !IsONTIAccreditedIssuer(v) {
			t.Fatalf("expected accredited: %q", v)
		}
	}
	for _, v := range no {
		if IsONTIAccreditedIssuer(v) {
			t.Fatalf("expected NOT accredited: %q", v)
		}
	}
}

func TestCuitFingerprintFromText(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"CUIT 30-71234567-8", "30", "5678"},
		{"CUIL 20-12345678-9", "20", "6789"},
		{"serialNumber=CUIT 30-71234567-8, CN=Natanael", "30", "5678"},
		{"CN=Random, O=Foo, 30712345678", "30", "5678"},
		{"no cuit", "", ""},
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

func TestSubjectSerialNumberFromDN(t *testing.T) {
	cases := map[string]string{
		"CN=Foo, SERIALNUMBER=CUIT 30-71234567-8, O=ACME": "CUIT 30-71234567-8",
		"CN=Foo, serialNumber=CUIT 20-12345678-9":         "CUIT 20-12345678-9",
		"CN=Foo, O=ACME": "",
	}
	for in, want := range cases {
		if got := SubjectSerialNumberFromDN(in); got != want {
			t.Fatalf("SubjectSerialNumberFromDN(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateExpiringSoon(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC) }
	r := Row{
		CertKind:  KindSoftPFX,
		IssuerCA:  IssuerACModernizacion,
		ValidFrom: "2024-06-15T00:00:00Z",
		ValidTo:   "2026-06-30T00:00:00Z",
		FileMode:  0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsExpiringSoon {
		t.Fatalf("15d-to-expiry must flag expiring-soon: %+v", r)
	}
	if r.IsExpired {
		t.Fatal("not expired yet")
	}
	if !r.IsONTIAccredited {
		t.Fatal("AC-Modernización must flag accredited")
	}
	if !r.IsLegallyBinding {
		t.Fatal("accredited + not-expired must flag legally-binding")
	}
}

func TestAnnotateExpired(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC) }
	r := Row{
		CertKind: KindSoftPFX,
		IssuerCA: IssuerACARCA,
		ValidTo:  "2024-06-30T00:00:00Z",
		FileMode: 0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsExpired {
		t.Fatal("past valid_to must flag expired")
	}
	if r.IsLegallyBinding {
		t.Fatal("expired must NOT flag legally-binding")
	}
}

func TestAnnotateSoftCertExposure(t *testing.T) {
	r := Row{
		CertKind: KindSoftPFX,
		IssuerCA: IssuerACModernizacion,
		FileMode: 0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsSoftCertWithKey {
		t.Fatal("PFX must flag soft-cert-with-key")
	}
	if !r.IsWorldReadable {
		t.Fatal("0o644 must flag world-readable")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("PFX + readable = T1552.004 exposure")
	}
}

func TestAnnotateNonAccredited(t *testing.T) {
	now := func() time.Time { return time.Now() }
	r := Row{
		CertKind: KindSoftPFX,
		IssuerCA: IssuerACCamerfirma,
		ValidTo:  "2030-01-01T00:00:00Z",
		FileMode: 0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsONTIAccredited {
		t.Fatal("Camerfirma is NOT ONTI-accredited")
	}
	if r.IsLegallyBinding {
		t.Fatal("non-accredited must NOT flag legally-binding")
	}
}

// -- ParseCertPEM --------------------------------------------------

func TestParseCertPEMExtractsCN(t *testing.T) {
	body := makeCertPEM(t, "Natanael Test", "CUIT 30-71234567-8",
		"AC-Modernización", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	f, ok := ParseCertPEM(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.SubjectCN != "Natanael Test" {
		t.Fatalf("CN=%q", f.SubjectCN)
	}
	if f.IssuerDN == "" {
		t.Fatal("issuer DN missing")
	}
}

func TestParseCertPEMRejectsNonPEM(t *testing.T) {
	if _, ok := ParseCertPEM([]byte("not a cert")); ok {
		t.Fatal("non-PEM must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "FirmaDigital")
	must(t, os.MkdirAll(dir, 0o755))

	// PEM cert from AC-Modernización, valid → legally-binding.
	pemPath := filepath.Join(dir, "firma_digital_alice.pem")
	must(t, os.WriteFile(pemPath, makeCertPEM(t, "Alice", "CUIT 30-71234567-8",
		"AC-Modernización", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour)), 0o600))

	// PFX (soft cert) world-readable → T1552.004 exposure.
	pfxPath := filepath.Join(dir, "firma_digital_bob.pfx")
	must(t, os.WriteFile(pfxPath, []byte("fake pfx body"), 0o644))

	// AFIP-path cert — must be SKIPPED (covered by iter 88).
	afipDir := filepath.Join(usersBase, "alice", "Documents", "FirmaDigital", "afip")
	must(t, os.MkdirAll(afipDir, 0o755))
	must(t, os.WriteFile(filepath.Join(afipDir, "afip_cert.crt"),
		makeCertPEM(t, "AFIP", "", "AC-AFIP", time.Now(), time.Now().Add(time.Hour)), 0o600))

	// Random file ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"), []byte("x"), 0o644))

	// Public — skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "FirmaDigital")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "skip.pfx"), []byte("x"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (pem+pfx), got %d: %+v", len(got), got)
	}

	var pemRow, pfxRow Row
	for _, r := range got {
		switch r.FilePath {
		case pemPath:
			pemRow = r
		case pfxPath:
			pfxRow = r
		}
	}
	if pemRow.IssuerCA != IssuerACModernizacion {
		t.Fatalf("pem issuer=%q", pemRow.IssuerCA)
	}
	if !pemRow.IsLegallyBinding {
		t.Fatalf("pem must flag legally-binding: %+v", pemRow)
	}
	if pemRow.SubjectCuitPrefix != "30" || pemRow.SubjectCuitSuffix4 != "5678" {
		t.Fatalf("pem CUIT: %+v", pemRow)
	}

	if !pfxRow.IsSoftCertWithKey {
		t.Fatalf("pfx must flag soft-cert-with-key: %+v", pfxRow)
	}
	if !pfxRow.IsCredentialExposureRisk {
		t.Fatalf("pfx + readable = exposure: %+v", pfxRow)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-fd")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "firma_digital_alice.pfx"),
		[]byte("fake"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "FIRMA_DIGITAL_DIR" {
				return envDir
			}
			return ""
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
		now:      func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || !got[0].IsSoftCertWithKey {
		t.Fatalf("env-supplied: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-fd"},
		usersBases:   []string{"/nope-users"},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Now() },
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
		{FilePath: "z", IssuerCA: IssuerACModernizacion, SubjectCN: "a"},
		{FilePath: "a", IssuerCA: IssuerACRaizRepArg, SubjectCN: "z"},
		{FilePath: "a", IssuerCA: IssuerACModernizacion, SubjectCN: "z"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].IssuerCA != IssuerACModernizacion {
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

func makeCertPEM(t *testing.T, cn, serial, issuerCN string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	// Build a CA → leaf chain so Issuer != Subject (self-
	// signed certs would otherwise inherit Subject as Issuer).
	caPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: issuerCN},
		NotBefore:             notBefore.Add(-time.Hour),
		NotAfter:              notAfter.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn, SerialNumber: serial},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
}
