package winafipsicore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindSICOREDDJJ), "sicore-ddjj"},
		{string(KindF744XML), "f744-xml"},
		{string(KindRetencionesCSV), "retenciones-csv"},
		{string(KindPercepcionesCSV), "percepciones-csv"},
		{string(KindPagosCSV), "pagos-csv"},
		{string(KindSIRECGS), "sire-cgs"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(RegimenGananciasR6), "ganancias-r6"},
		{string(RegimenIVAR1), "iva-r1"},
		{string(RegimenIVAR2), "iva-r2"},
		{string(RegimenSSocialR5), "ssocial-r5"},
		{string(RegimenIIBBCM), "iibb-cm"},
		{string(RegimenMonotributo), "monotributo"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"SICORE_DDJJ_202506_30712345678.txt",
		"F744_202506.xml",
		"retenciones_202506.csv",
		"percepciones_202506.csv",
		"pagos_retenciones_202506.csv",
		"SIRE_CGS_30712345678_202506.txt",
		"ddjj_retenciones_acme.xml",
	}
	no := []string{"", "factura.xml", "cv.docx", "random.csv"}
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

func TestArtifactKindFromName(t *testing.T) {
	cases := map[string]ArtifactKind{
		"F744_202506.xml":              KindF744XML,
		"SIRE_CGS_30000000007.txt":     KindSIRECGS,
		"pagos_retenciones_202506.csv": KindPagosCSV,
		"percepciones_202506.csv":      KindPercepcionesCSV,
		"retenciones_202506.csv":       KindRetencionesCSV,
		"SICORE_DDJJ_202506.txt":       KindSICOREDDJJ,
		"ddjj_retenciones_acme.xml":    KindSICOREDDJJ,
		"random.csv":                   KindOther,
		"":                             KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestRegimenFromText(t *testing.T) {
	cases := map[string]RegimenKind{
		"ganancias":             RegimenGananciasR6,
		"R6":                    RegimenGananciasR6,
		"IVA R1":                RegimenIVAR1,
		"IVA R-2":               RegimenIVAR2,
		"IVA":                   RegimenIVAR1,
		"R5":                    RegimenSSocialR5,
		"seguridad social":      RegimenSSocialR5,
		"R10":                   RegimenSUSSR10,
		"IIBB":                  RegimenIIBBCM,
		"convenio multilateral": RegimenIIBBCM,
		"monotributo":           RegimenMonotributo,
		"":                      RegimenUnknown,
		"other régimen":         RegimenOther,
	}
	for in, want := range cases {
		if got := RegimenFromText(in); got != want {
			t.Fatalf("RegimenFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	cases := map[string]string{
		"SICORE_DDJJ_202506_30712345678.txt": "202506",
		"F744_202506.xml":                    "202506",
		"random.csv":                         "",
	}
	for in, want := range cases {
		if got := PeriodFromFilename(in); got != want {
			t.Fatalf("PeriodFromFilename(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"SICORE_DDJJ_202506_30712345678.txt", "30", "5678"},
		{"agent 30-71234567-8", "30", "5678"},
		{"no cuit", "", ""},
		{"11-12345678-9", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestIsNaturalPersonPrefix(t *testing.T) {
	yes := []string{"20", "23", "24", "27"}
	no := []string{"30", "33", "34", "", "11"}
	for _, v := range yes {
		if !IsNaturalPersonPrefix(v) {
			t.Fatalf("expected natural-person: %q", v)
		}
	}
	for _, v := range no {
		if IsNaturalPersonPrefix(v) {
			t.Fatalf("expected NOT natural-person: %q", v)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateHighVolume(t *testing.T) {
	r := Row{
		ArtifactKind:    KindRetencionesCSV,
		AgentCuitPrefix: "30",
		RetainedCount:   2000,
		FileMode:        0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHighVolume {
		t.Fatal("2000 retenciones must flag high-volume")
	}
}

func TestAnnotateLargeTotal(t *testing.T) {
	r := Row{
		ArtifactKind:           KindRetencionesCSV,
		AgentCuitPrefix:        "30",
		TotalRetentionARSCents: 20_000_000_000, // 200 M ARS
		FileMode:               0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasLargeRetentionTotal {
		t.Fatal("200M ARS must flag large total")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("agent CUIT + large total + readable = exposure")
	}
}

func TestAnnotateNaturalPersonExposure(t *testing.T) {
	r := Row{
		ArtifactKind:               KindRetencionesCSV,
		AgentCuitPrefix:            "30",
		AgentCuitSuffix4:           "5678",
		RetainedCount:              50,
		NaturalPersonRetainedCount: 25,
		FileMode:                   0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasNaturalPersonRetained {
		t.Fatal("natural person count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("agent CUIT + natural person + readable = exposure")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:               KindRetencionesCSV,
		AgentCuitPrefix:            "30",
		NaturalPersonRetainedCount: 25,
		FileMode:                   0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoAgentNoExposure(t *testing.T) {
	r := Row{
		ArtifactKind:               KindRetencionesCSV,
		NaturalPersonRetainedCount: 25,
		FileMode:                   0o644,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("no agent CUIT must NOT flag exposure")
	}
}

// -- ParseSicore --------------------------------------------------

func TestParseSicoreF744XML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<f744>
  <cuit_agente>30712345678</cuit_agente>
  <periodo>202506</periodo>
  <regimen>ganancias</regimen>
  <detalle>
    <cuit_retenido>20111111119</cuit_retenido>
    <importe>50000.00</importe>
  </detalle>
  <detalle>
    <cuit_retenido>27222222227</cuit_retenido>
    <importe>75000.00</importe>
  </detalle>
  <detalle>
    <cuit_retenido>30333333334</cuit_retenido>
    <importe>100000.00</importe>
  </detalle>
</f744>`)
	sum, ok := ParseSicore(body)
	if !ok {
		t.Fatal("must parse")
	}
	if sum.AgentCuitRaw != "30712345678" {
		t.Fatalf("agent=%q", sum.AgentCuitRaw)
	}
	if sum.RegimenHint != "ganancias" {
		t.Fatalf("regimen=%q", sum.RegimenHint)
	}
	if sum.RetainedCount != 3 {
		t.Fatalf("retained count=%d", sum.RetainedCount)
	}
	if sum.NaturalPersonRetainedCount != 2 {
		t.Fatalf("natural person count=%d", sum.NaturalPersonRetainedCount)
	}
	if sum.TotalRetentionARSCents != 22_500_000 {
		t.Fatalf("total=%d", sum.TotalRetentionARSCents)
	}
	if sum.MaxRetentionARSCents != 10_000_000 {
		t.Fatalf("max=%d", sum.MaxRetentionARSCents)
	}
}

func TestParseSicoreCSV(t *testing.T) {
	body := []byte(`cuit_retenido,razon_social,importe
20111111119,Juan Perez,50000.00
27222222227,Maria Lopez,75000.00
30333333334,Acme SA,100000.00
`)
	sum, ok := ParseSicore(body)
	if !ok {
		t.Fatal("must parse")
	}
	if sum.RetainedCount != 3 {
		t.Fatalf("retained=%d", sum.RetainedCount)
	}
	if sum.NaturalPersonRetainedCount != 2 {
		t.Fatalf("natural=%d", sum.NaturalPersonRetainedCount)
	}
}

func TestParseSicoreEmpty(t *testing.T) {
	if _, ok := ParseSicore([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "AFIP", "SICORE")
	must(t, os.MkdirAll(dir, 0o755))

	// F744 with natural-person retenidos, world-readable.
	f744Path := filepath.Join(dir, "F744_202506_30712345678.xml")
	must(t, os.WriteFile(f744Path, []byte(`<?xml version="1.0"?>
<f744>
<cuit_agente>30712345678</cuit_agente>
<periodo>202506</periodo>
<regimen>ganancias</regimen>
<detalle><cuit_retenido>20111111119</cuit_retenido><importe>500000.00</importe></detalle>
<detalle><cuit_retenido>27222222227</cuit_retenido><importe>750000.00</importe></detalle>
</f744>`), 0o644))

	// Retenciones CSV, locked down.
	retPath := filepath.Join(dir, "retenciones_iva_202506.csv")
	must(t, os.WriteFile(retPath, []byte(`cuit_retenido,importe
30000000007,5000.00
30000000015,6000.00
`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.xml"),
		[]byte(`<x/>`), 0o644))

	// Public profile skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "AFIP", "SICORE")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "F744_skip.xml"),
		[]byte(`<f744/>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (f744 + ret), got %d: %+v", len(got), got)
	}

	var f744, ret Row
	for _, r := range got {
		switch r.FilePath {
		case f744Path:
			f744 = r
		case retPath:
			ret = r
		}
	}
	if f744.ArtifactKind != KindF744XML {
		t.Fatalf("f744 kind=%q", f744.ArtifactKind)
	}
	if f744.RegimenKind != RegimenGananciasR6 {
		t.Fatalf("f744 regimen=%q", f744.RegimenKind)
	}
	if f744.AgentCuitPrefix != "30" || f744.AgentCuitSuffix4 != "5678" {
		t.Fatalf("f744 agent: %+v", f744)
	}
	if f744.NaturalPersonRetainedCount != 2 {
		t.Fatalf("f744 natural=%d", f744.NaturalPersonRetainedCount)
	}
	if !f744.HasNaturalPersonRetained {
		t.Fatalf("must flag natural person: %+v", f744)
	}
	if !f744.IsCredentialExposureRisk {
		t.Fatalf("agent + natural + readable = exposure: %+v", f744)
	}
	if f744.PeriodYYYYMM != "202506" {
		t.Fatalf("f744 period=%q", f744.PeriodYYYYMM)
	}

	if ret.ArtifactKind != KindRetencionesCSV {
		t.Fatalf("ret kind=%q", ret.ArtifactKind)
	}
	if ret.RegimenKind != RegimenIVAR1 {
		t.Fatalf("ret regimen=%q (expect IVA R1)", ret.RegimenKind)
	}
	if ret.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", ret)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-sicore")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "F744_202506.xml"),
		[]byte(`<f744><cuit_agente>30712345678</cuit_agente></f744>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SICORE_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindF744XML {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-sicore"},
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
		{FilePath: "z", ArtifactKind: KindF744XML},
		{FilePath: "a", ArtifactKind: KindRetencionesCSV},
		{FilePath: "a", ArtifactKind: KindF744XML},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindF744XML {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
