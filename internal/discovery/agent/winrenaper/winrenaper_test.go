package winrenaper

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindDNIIndividual), "dni-individual"},
		{string(KindDNIBatch), "dni-batch"},
		{string(KindAuditLog), "audit-log"},
		{string(KindPhotoCache), "photo-cache"},
		{string(KindBiometric), "biometric"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"renaper_consulta_30712345.json",
		"consulta_dni_12345678.xml",
		"kyc_batch_2024.csv",
		"renaper_audit_202506.jsonl",
		"verificacion_identidad_alice.json",
		"biometric_huella_001.bin",
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

func TestConsultationKindFromName(t *testing.T) {
	cases := map[string]ConsultationKind{
		"biometric_huella_001.bin":       KindBiometric,
		"biometria_iris.dat":             KindBiometric,
		"renaper_foto_30712345.jpg":      KindPhotoCache,
		"renaper_audit_202506.jsonl":     KindAuditLog,
		"renaper_log_2024.txt":           KindAuditLog,
		"kyc_batch_2024.csv":             KindDNIBatch,
		"lote_kyc_2024.txt":              KindDNIBatch,
		"consulta_dni_12345678.xml":      KindDNIIndividual,
		"renaper_consulta_30712345.json": KindDNIIndividual,
		"kyc_general.txt":                KindOther,
		"random.json":                    KindUnknown,
		"":                               KindUnknown,
	}
	for in, want := range cases {
		if got := ConsultationKindFromName(in); got != want {
			t.Fatalf("ConsultationKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDniSuffix4(t *testing.T) {
	cases := map[string]string{
		"consulta_dni_12345678.xml": "5678",
		"renaper_30712345.json":     "2345",
		"random.txt":                "",
		"":                          "",
		"dni_123.txt":               "", // too short
	}
	for in, want := range cases {
		if got := DniSuffix4(in); got != want {
			t.Fatalf("DniSuffix4(%q)=%q want %q", in, got, want)
		}
	}
}

func TestContainsPhoto(t *testing.T) {
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}
	if !ContainsPhoto(jpeg) {
		t.Fatal("JPEG header must be detected")
	}
	png := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	if !ContainsPhoto(png) {
		t.Fatal("PNG header must be detected")
	}
	json := []byte(`{"foto":"AAAA"}`)
	if !ContainsPhoto(json) {
		t.Fatal(`"foto":… key must be detected`)
	}
	if ContainsPhoto([]byte("hello world")) {
		t.Fatal("plain text must NOT trigger photo")
	}
	if ContainsPhoto([]byte("")) {
		t.Fatal("empty must NOT trigger photo")
	}
}

func TestContainsBiometric(t *testing.T) {
	yes := [][]byte{
		[]byte(`{"huella":"AAAA"}`),
		[]byte(`{"fingerprint":"data"}`),
		[]byte(`{"biometric":true}`),
		[]byte(`some text mentioning WSQ format`),
	}
	no := [][]byte{
		[]byte(""),
		[]byte("nothing here"),
		[]byte(`{"foto":"only"}`),
	}
	for _, b := range yes {
		if !ContainsBiometric(b) {
			t.Fatalf("expected biometric in: %q", b)
		}
	}
	for _, b := range no {
		if ContainsBiometric(b) {
			t.Fatalf("expected NOT biometric in: %q", b)
		}
	}
}

func TestContainsDomicilio(t *testing.T) {
	yes := [][]byte{
		[]byte(`{"domicilio":"Av. Corrientes"}`),
		[]byte(`{"calle":"Av. Corrientes"}`),
		[]byte(`{"direccion":"..."}`),
		[]byte(`<domicilio>x</domicilio>`),
	}
	no := [][]byte{[]byte(""), []byte("hello"), []byte(`{"foto":"x"}`)}
	for _, b := range yes {
		if !ContainsDomicilio(b) {
			t.Fatalf("expected domicilio in: %q", b)
		}
	}
	for _, b := range no {
		if ContainsDomicilio(b) {
			t.Fatalf("expected NOT domicilio in: %q", b)
		}
	}
}

func TestCountLinesAsLog(t *testing.T) {
	cases := map[string]int{
		"":          0,
		"a":         1,
		"a\n":       1,
		"a\nb":      2,
		"a\nb\n":    2,
		"a\nb\nc\n": 3,
	}
	for in, want := range cases {
		if got := CountLinesAsLog([]byte(in)); got != want {
			t.Fatalf("CountLinesAsLog(%q)=%d want %d", in, got, want)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ConsultationKind: KindDNIIndividual,
		HasPhoto:         true,
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable RENAPER + photo = critical exposure")
	}
}

func TestAnnotateBatchFlag(t *testing.T) {
	r := Row{
		ConsultationKind:  KindAuditLog,
		ConsultationCount: 100,
		FileMode:          0o600,
	}
	AnnotateSecurity(&r)
	if !r.IsAuditLog {
		t.Fatal("audit-log kind must flag is_audit_log")
	}
	if !r.IsBatch {
		t.Fatal("count > BatchThreshold must flag is_batch")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateUnknownKindReadableNoExposure(t *testing.T) {
	r := Row{ConsultationKind: "", FileMode: 0o644}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("empty consultation kind must NOT flag exposure")
	}
}

func TestAnnotateGroupReadable(t *testing.T) {
	r := Row{ConsultationKind: KindDNIIndividual, FileMode: 0o640}
	AnnotateSecurity(&r)
	if !r.IsGroupReadable || r.IsWorldReadable {
		t.Fatalf("0o640 must flag group only: %+v", r)
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("group-readable RENAPER must flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "KYC", "RENAPER")
	must(t, os.MkdirAll(dir, 0o755))

	// Photo-bearing JSON, world-readable → CRITICAL exposure.
	photoPath := filepath.Join(dir, "renaper_consulta_30712345.json")
	must(t, os.WriteFile(photoPath, []byte(`{"dni":"30712345","foto":"data:image/jpeg;base64,AAAA","huella":"X"}`), 0o644))

	// Audit log, batch, locked-down.
	auditPath := filepath.Join(dir, "renaper_audit_202506.jsonl")
	must(t, os.WriteFile(auditPath, []byte("{}\n{}\n{}\n{}\n{}\n{}\n"), 0o600))

	// Random — ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.json"),
		[]byte(`{}`), 0o644))

	// Public — skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "KYC", "RENAPER")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "renaper_consulta_skip.json"),
		[]byte("{}"), 0o644))

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
		t.Fatalf("want 2 (photo+audit), got %d: %+v", len(got), got)
	}

	var photo, audit Row
	for _, r := range got {
		switch r.FilePath {
		case photoPath:
			photo = r
		case auditPath:
			audit = r
		}
	}
	if !photo.HasPhoto {
		t.Fatalf("photo must flag has_photo: %+v", photo)
	}
	if !photo.HasBiometric {
		t.Fatalf("photo body has huella → must flag biometric: %+v", photo)
	}
	if photo.ConsultationKind != KindBiometric {
		t.Fatalf("biometric trump: %+v", photo)
	}
	if !photo.IsCredentialExposureRisk {
		t.Fatalf("RENAPER + readable = critical exposure: %+v", photo)
	}
	if photo.TargetDniSuffix4 != "2345" {
		t.Fatalf("photo dni suffix=%q", photo.TargetDniSuffix4)
	}

	if !audit.IsAuditLog {
		t.Fatalf("audit must flag is_audit_log: %+v", audit)
	}
	if !audit.IsBatch {
		t.Fatalf("audit 6 lines > BatchThreshold(5) must flag is_batch: %+v", audit)
	}
	if audit.ConsultationCount != 6 {
		t.Fatalf("audit count=%d want 6", audit.ConsultationCount)
	}
	if audit.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag exposure: %+v", audit)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-renaper")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "renaper_consulta_30712345.json"),
		[]byte(`{"foto":"x"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "RENAPER_DIR" {
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
	if len(got) != 1 || !got[0].HasPhoto || !got[0].IsCredentialExposureRisk {
		t.Fatalf("env-supplied: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-renaper"},
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
		{FilePath: "z", ConsultationKind: KindAuditLog, TargetDniSuffix4: "1234"},
		{FilePath: "a", ConsultationKind: KindBiometric, TargetDniSuffix4: "5678"},
		{FilePath: "a", ConsultationKind: KindAuditLog, TargetDniSuffix4: "1111"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ConsultationKind != KindAuditLog {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
