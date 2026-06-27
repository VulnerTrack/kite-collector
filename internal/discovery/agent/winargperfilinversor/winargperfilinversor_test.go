package winargperfilinversor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindPerfilPDF), "perfil-pdf"},
		{string(KindPerfilQuestionnaire), "perfil-questionnaire"},
		{string(KindPerfilDeclaration), "perfil-declaration"},
		{string(KindPerfilCategory), "perfil-category"},
		{string(KindPerfilUpdateLog), "perfil-update-log"},
		{string(KindPerfilRevision), "perfil-revision"},
		{string(KindInstaller), "perfil-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(CategoryConservadora), "conservadora"},
		{string(CategoryModerada), "moderada"},
		{string(CategoryAgresiva), "agresiva"},
		{string(CategorySofisticada), "sofisticada"},
		{string(CategoryInversorCalificado), "inversor-calificado"},
		{string(CategoryOther), "other"},
		{string(CategoryUnknown), "unknown"},
		{string(AgenteALYC), "alyc"},
		{string(AgenteAAG), "aag"},
		{string(AgenteACOTG), "acotg"},
		{string(AgenteACODI), "acodi"},
		{string(AgenteOther), "other"},
		{string(AgenteUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"perfil_inversor_27111111114.pdf",
		"cuestionario_27111111114.xml",
		"declaracion_cliente_27111111114.xml",
		"categoria_inversor_27111111114.json",
		"update_perfil_27111111114.csv",
		"revision_perfil_27111111114.xml",
		"perfil-inversor-27111111114.pdf",
	}
	no := []string{"", "factura.pdf", "random.xml"}
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
		"perfil_inversor_27111111114.pdf":     KindPerfilPDF,
		"cuestionario_27111111114.xml":        KindPerfilQuestionnaire,
		"declaracion_cliente_27111111114.xml": KindPerfilDeclaration,
		"categoria_inversor_27111111114.json": KindPerfilCategory,
		"update_perfil_27111111114.csv":       KindPerfilUpdateLog,
		"revision_perfil_27111111114.xml":     KindPerfilRevision,
		"perfil_v8_installer.msi":             KindInstaller,
		"":                                    KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAgenteClassFromPath(t *testing.T) {
	cases := map[string]AgenteClass{
		`C:\Compliance\ALYC\perfil_001.pdf`:  AgenteALYC,
		`C:\Compliance\AAG\perfil_001.pdf`:   AgenteAAG,
		`C:\Compliance\ACOTG\perfil_001.pdf`: AgenteACOTG,
		`C:\Compliance\ACODI\perfil_001.pdf`: AgenteACODI,
		`C:\Compliance\perfil\generic.pdf`:   AgenteOther,
		`C:\Random\path.pdf`:                 AgenteUnknown,
		"":                                   AgenteUnknown,
	}
	for in, want := range cases {
		if got := AgenteClassFromPath(in); got != want {
			t.Fatalf("AgenteClassFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNormalizeRiskCategory(t *testing.T) {
	cases := map[string]RiskCategory{
		"conservadora":        CategoryConservadora,
		"moderada":            CategoryModerada,
		"agresiva":            CategoryAgresiva,
		"sofisticada":         CategorySofisticada,
		"inversor calificado": CategoryInversorCalificado,
		"qualified investor":  CategoryInversorCalificado,
		"random":              CategoryUnknown,
		"":                    CategoryUnknown,
	}
	for in, want := range cases {
		if got := NormalizeRiskCategory(in); got != want {
			t.Fatalf("NormalizeRiskCategory(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsHighRiskCategory(t *testing.T) {
	yes := []RiskCategory{
		CategoryAgresiva, CategorySofisticada,
		CategoryInversorCalificado,
	}
	no := []RiskCategory{
		CategoryConservadora, CategoryModerada,
		CategoryOther, CategoryUnknown,
	}
	for _, v := range yes {
		if !IsHighRiskCategory(v) {
			t.Fatalf("expected high-risk: %q", v)
		}
	}
	for _, v := range no {
		if IsHighRiskCategory(v) {
			t.Fatalf("expected NOT high-risk: %q", v)
		}
	}
}

func TestHasComplexInstrument(t *testing.T) {
	yes := []string{
		"futuros,opciones,acciones",
		"futures-financial",
		"derivados-fx",
		"crypto-margin trading",
		"caucion-leveraged operations",
		"CFDs only",
	}
	no := []string{
		"acciones,bonos",
		"fci",
		"renta fija",
		"",
	}
	for _, v := range yes {
		if !HasComplexInstrument(v) {
			t.Fatalf("expected complex: %q", v)
		}
	}
	for _, v := range no {
		if HasComplexInstrument(v) {
			t.Fatalf("expected NOT complex: %q", v)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"cliente 27-11111111-4", "27", "1114"},
		{"empresa 30-71234567-8", "30", "5678"},
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

func TestMatriculaFromText(t *testing.T) {
	cases := map[string]string{
		"matricula 338":        "338",
		"broker_matricula 999": "999",
		"aag_matricula 88":     "88",
		"no matricula":         "",
	}
	for in, want := range cases {
		if got := MatriculaFromText(in); got != want {
			t.Fatalf("MatriculaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("perfil_202506.xml") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.xml") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsProfileOverdue(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		date string
		want bool
	}{
		{"2025-12-01", false}, // <365d
		{"2024-12-01", true},  // >365d
		{"2026-06-01", false}, // recent
		{"", false},
		{"garbage", false},
	}
	for _, c := range cases {
		if got := IsProfileOverdue(c.date, now); got != c.want {
			t.Fatalf("IsProfileOverdue(%q)=%v want %v", c.date, got, c.want)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateCategoryMismatch(t *testing.T) {
	r := Row{
		ArtifactKind:        KindPerfilCategory,
		RiskCategory:        CategoryConservadora,
		InstrumentClassList: "acciones,futuros,opciones",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCategoryMismatch {
		t.Fatal("conservative + derivatives must flag mismatch")
	}
}

func TestAnnotateHighRiskLowIncome(t *testing.T) {
	r := Row{
		ArtifactKind:              KindPerfilCategory,
		RiskCategory:              CategoryAgresiva,
		DeclaredAnnualIncomeCents: 6_000_000_000, // 600k ARS
		FileMode:                  0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHighRiskLowIncome {
		t.Fatal("aggressive + 600k ARS income must flag")
	}
}

func TestAnnotateClientePIIExposure(t *testing.T) {
	r := Row{
		ArtifactKind:       KindPerfilCategory,
		RiskCategory:       CategoryModerada,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + cliente + category = exposure")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:              KindPerfilCategory,
		RiskCategory:              CategoryAgresiva,
		ClienteCuitPrefix:         "27",
		DeclaredAnnualIncomeCents: 6_000_000_000,
		FileMode:                  0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParsePerfilArtifact ------------------------------------------

func TestParsePerfilArtifactCategory(t *testing.T) {
	body := []byte(`{
  "matricula": "338",
  "cliente_cuit": "27-11111111-4",
  "risk_category": "agresiva",
  "last_review_date": "2024-12-01",
  "annual_income": "5000000.00",
  "net_worth": "20000000.00",
  "instrument_classes": "acciones, futuros, opciones"
}`)
	f := ParsePerfilArtifact(body)
	if f.BrokerMatricula != "338" {
		t.Fatalf("matricula=%q", f.BrokerMatricula)
	}
	if f.RiskCategory != CategoryAgresiva {
		t.Fatalf("category=%q", f.RiskCategory)
	}
	if f.LastReviewDate != "2024-12-01" {
		t.Fatalf("last review=%q", f.LastReviewDate)
	}
	if f.DeclaredAnnualIncome != 500_000_000 {
		t.Fatalf("income=%d", f.DeclaredAnnualIncome)
	}
	if f.DeclaredNetWorth != 2_000_000_000 {
		t.Fatalf("net worth=%d", f.DeclaredNetWorth)
	}
	if f.InstrumentClassList == "" {
		t.Fatal("instrument list missing")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParsePerfilArtifactMissingSignature(t *testing.T) {
	body := []byte(`{
  "matricula": "338",
  "signature_missing": true,
  "risk_category": "moderada"
}`)
	f := ParsePerfilArtifact(body)
	if !f.HasMissingSignature {
		t.Fatal("missing signature must flag")
	}
}

func TestParsePerfilArtifactNoKYC(t *testing.T) {
	body := []byte(`{
  "matricula": "338",
  "kyc_missing": true
}`)
	f := ParsePerfilArtifact(body)
	if !f.HasNoKYCLink {
		t.Fatal("kyc missing must flag")
	}
}

func TestParsePerfilArtifactEmpty(t *testing.T) {
	f := ParsePerfilArtifact(nil)
	if f.RiskCategory != CategoryUnknown {
		t.Fatalf("empty must be unknown: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "Compliance", "Perfil")
	must(t, os.MkdirAll(dir, 0o755))

	// Aggressive category with low income + outdated review.
	catPath := filepath.Join(dir, "categoria_inversor_27111111114.json")
	must(t, os.WriteFile(catPath, []byte(`{
  "matricula": "338",
  "cliente_cuit": "27-11111111-4",
  "risk_category": "agresiva",
  "last_review_date": "2024-12-01",
  "annual_income": "5000000.00",
  "instrument_classes": "acciones,futuros,opciones"
}`), 0o644))

	// Conservative profile with complex instruments (mismatch).
	misPath := filepath.Join(dir, "perfil_inversor_30712345678.pdf")
	must(t, os.WriteFile(misPath, []byte(`%PDF-binary-blob`), 0o600))

	// Questionnaire JSON, signature missing.
	qPath := filepath.Join(dir, "cuestionario_27222222222.xml")
	must(t, os.WriteFile(qPath, []byte(`<?xml version="1.0"?>
<perfil>
  <matricula>338</matricula>
  <cliente_cuit>27-22222222-2</cliente_cuit>
  <risk_category>moderada</risk_category>
  <signature_missing>true</signature_missing>
</perfil>`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "Compliance", "Perfil")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "perfil_inversor_skip.pdf"),
		[]byte(`x`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 (cat+mis+q), got %d: %+v", len(got), got)
	}

	var cat, mis, q Row
	for _, r := range got {
		switch r.FilePath {
		case catPath:
			cat = r
		case misPath:
			mis = r
		case qPath:
			q = r
		}
	}

	if cat.ArtifactKind != KindPerfilCategory {
		t.Fatalf("cat kind=%q", cat.ArtifactKind)
	}
	if cat.RiskCategory != CategoryAgresiva {
		t.Fatalf("cat category=%q", cat.RiskCategory)
	}
	if !cat.HasOutdatedProfile {
		t.Fatalf("cat 2024-12-01 must flag overdue: %+v", cat)
	}
	if !cat.HasHighRiskLowIncome {
		t.Fatalf("cat aggressive + 50k ARS income must flag low: %+v", cat)
	}
	if !cat.HasClienteCuit {
		t.Fatalf("cat must flag cliente: %+v", cat)
	}
	if !cat.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente + category = exposure: %+v", cat)
	}

	if mis.ArtifactKind != KindPerfilPDF {
		t.Fatalf("mis kind=%q", mis.ArtifactKind)
	}
	if mis.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", mis)
	}

	if q.ArtifactKind != KindPerfilQuestionnaire {
		t.Fatalf("q kind=%q", q.ArtifactKind)
	}
	if !q.HasMissingSignature {
		t.Fatalf("q must flag signature: %+v", q)
	}
	if q.RiskCategory != CategoryModerada {
		t.Fatalf("q category=%q", q.RiskCategory)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-perfil")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "perfil_inversor_001.pdf"),
		[]byte(`%PDF`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "PERFIL_INVERSOR_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindPerfilPDF {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-perfil"},
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
		{FilePath: "z", ArtifactKind: KindPerfilCategory},
		{FilePath: "a", ArtifactKind: KindPerfilPDF},
		{FilePath: "a", ArtifactKind: KindPerfilCategory},
	}
	SortRows(in)
	// "perfil-category" sorts before "perfil-pdf".
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindPerfilCategory {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashContents(t *testing.T) {
	a := HashContents([]byte("perfil"))
	b := HashContents([]byte("perfil"))
	c := HashContents([]byte("PERFIL"))
	if a != b {
		t.Fatal("hash drift")
	}
	if a == c {
		t.Fatal("hash collision case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
