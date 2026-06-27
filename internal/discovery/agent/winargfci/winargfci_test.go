package winargfci

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindNAVDiario), "nav-diario"},
		{string(KindComposicionCart), "composicion-cartera"},
		{string(KindCuotapartistas), "cuotapartistas"},
		{string(KindProspecto), "prospecto"},
		{string(KindRegimenInformativo), "regimen-informativo"},
		{string(KindCDAAccount), "cda-account"},
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
		"FCI_69_20240615_NAV.csv",
		"composicion_FCI_69_20240615.xml",
		"cuotapartistas_FCI_69.xml",
		"prospecto_FCI_69.pdf",
		"regimen_informativo_fci_202506.xml",
		"sociedad_gerente_acme.xml",
		"caja_de_valores_account.cda",
		"fondo_comun_general.xml",
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

func TestArtifactKindFromName(t *testing.T) {
	cases := map[string]ArtifactKind{
		"FCI_69_20240615_NAV.csv":            KindNAVDiario,
		"valor_cuotaparte_2024.csv":          KindNAVDiario,
		"composicion_FCI_69.xml":             KindComposicionCart,
		"cartera_FCI_69.xml":                 KindComposicionCart,
		"cuotapartistas_FCI_69.xml":          KindCuotapartistas,
		"prospecto_FCI_69.pdf":               KindProspecto,
		"regimen_informativo_fci_202506.xml": KindRegimenInformativo,
		"cuenta_caja_valores.cda":            KindCDAAccount,
		"fondo_comun_general.xml":            KindOther,
		"fci_69.xml":                         KindOther,
		"random.xml":                         KindUnknown,
		"":                                   KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestJuridicalCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"30-71234567-8", "30", "5678"}, // juridical ✓
		{"33-71234567-8", "33", "5678"}, // juridical ✓
		{"34-71234567-8", "34", "5678"}, // juridical ✓
		{"20-71234567-8", "", ""},       // natural-person REJECTED
		{"27-71234567-8", "", ""},       // natural-person REJECTED
		{"no-cuit", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := JuridicalCuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("JuridicalCuitFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestMatriculaFromText(t *testing.T) {
	cases := map[string]string{
		"matricula FCI 69": "69",
		"matrícula: 69":    "69",
		"FCI N° 69":        "69",
		"fci_matricula=69": "69",
		"no matricula":     "",
		"":                 "",
	}
	for in, want := range cases {
		if got := MatriculaFromText(in); got != want {
			t.Fatalf("MatriculaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestFechaNAVFromName(t *testing.T) {
	cases := map[string]string{
		"FCI_69_20240615_NAV.csv": "2024-06-15",
		"nav_20240101.csv":        "2024-01-01",
		"no-fecha.csv":            "",
		"FCI_69_20241332.csv":     "", // invalid month
	}
	for in, want := range cases {
		if got := FechaNAVFromName(in); got != want {
			t.Fatalf("FechaNAVFromName(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateConcentrationExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindCuotapartistas,
		CuotapartistasCount: 50,
		MaxCuotapartistaPct: 35,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHighConcentration {
		t.Fatal("35% must flag high concentration (>10%)")
	}
	if !r.HasCuotapartistasList {
		t.Fatal("cuotapartistas kind must flag list")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("list + readable = exposure")
	}
}

func TestAnnotateForeignDominated(t *testing.T) {
	r := Row{
		ArtifactKind:             KindComposicionCart,
		ForeignCurrencyWeightPct: 75,
		FileMode:                 0o600,
	}
	AnnotateSecurity(&r)
	if !r.HasForeignDominatedPortfolio {
		t.Fatal("75% USD must flag foreign-dominated")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateLowConcentrationClean(t *testing.T) {
	r := Row{
		ArtifactKind:        KindCuotapartistas,
		CuotapartistasCount: 100,
		MaxCuotapartistaPct: 5,
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if r.HasHighConcentration {
		t.Fatal("5% must NOT flag concentration")
	}
}

func TestAnnotateNAVNoCuotapartistasList(t *testing.T) {
	r := Row{ArtifactKind: KindNAVDiario, FileMode: 0o644}
	AnnotateSecurity(&r)
	if r.HasCuotapartistasList {
		t.Fatal("NAV file should NOT flag cuotapartistas list")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("NAV without investor PII must NOT flag exposure")
	}
}

// -- ParseFCIArtifact ----------------------------------------------

func TestParseFCIArtifactXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<fci_disclosure>
  <fci_matricula>69</fci_matricula>
  <fci_denominacion>ACME Renta Mixta FCI</fci_denominacion>
  <cuit_sociedad_gerente>30712345678</cuit_sociedad_gerente>
  <cuit_sociedad_depositaria>33712345670</cuit_sociedad_depositaria>
  <nav>1234.56</nav>
  <aum>10000000.00</aum>
  <cuotapartistas>
    <cuotapartista>
      <cuit>27111111114</cuit>
      <valor_cuotaparte>2500000.00</valor_cuotaparte>
    </cuotapartista>
    <cuotapartista>
      <cuit>20222222220</cuit>
      <valor_cuotaparte>1500000.00</valor_cuotaparte>
    </cuotapartista>
    <cuotapartista>
      <cuit>27333333330</cuit>
      <valor_cuotaparte>500000.00</valor_cuotaparte>
    </cuotapartista>
  </cuotapartistas>
  <composicion>
    <activo><moneda>USD</moneda><peso>60</peso></activo>
    <activo><moneda>ARS</moneda><peso>40</peso></activo>
  </composicion>
</fci_disclosure>`)
	f, ok := ParseFCIArtifact(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.FciMatricula != "69" {
		t.Fatalf("matricula=%q", f.FciMatricula)
	}
	if f.SociedadGerenteCuitRaw != "30712345678" {
		t.Fatalf("gerente=%q", f.SociedadGerenteCuitRaw)
	}
	if f.NavARSCents != 123456 {
		t.Fatalf("nav=%d want 123456", f.NavARSCents)
	}
	if f.AumARSCents != 1000000000 {
		t.Fatalf("aum=%d", f.AumARSCents)
	}
	if f.CuotapartistasCount != 3 {
		t.Fatalf("cuotapartistas=%d want 3", f.CuotapartistasCount)
	}
	// Max = 2.5M / 10M = 25%
	if f.MaxCuotapartistaPct < 20 || f.MaxCuotapartistaPct > 30 {
		t.Fatalf("max pct=%d want ~25", f.MaxCuotapartistaPct)
	}
	// 60% USD weight
	if f.ForeignCurrencyWeightPct < 50 || f.ForeignCurrencyWeightPct > 70 {
		t.Fatalf("foreign pct=%d want ~60", f.ForeignCurrencyWeightPct)
	}
}

func TestParseFCIArtifactCSV(t *testing.T) {
	body := []byte(`# NAV diario FCI 69
matricula: 69
NAV: 1234.56
AUM: 10000000.00
`)
	f, ok := ParseFCIArtifact(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.FciMatricula != "69" {
		t.Fatalf("matricula=%q", f.FciMatricula)
	}
	if f.NavARSCents != 123456 {
		t.Fatalf("nav=%d", f.NavARSCents)
	}
}

func TestParseFCIArtifactEmpty(t *testing.T) {
	if _, ok := ParseFCIArtifact([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "FCI")
	must(t, os.MkdirAll(dir, 0o755))

	// Cuotapartistas list with high concentration + foreign portfolio, readable.
	cuotapartistasPath := filepath.Join(dir, "cuotapartistas_FCI_69_202506.xml")
	must(t, os.WriteFile(cuotapartistasPath, []byte(`<fci_disclosure>
<fci_matricula>69</fci_matricula>
<fci_denominacion>ACME Renta Fija FCI</fci_denominacion>
<cuit_sociedad_gerente>30712345678</cuit_sociedad_gerente>
<aum>10000000.00</aum>
<cuotapartistas>
<cuotapartista><cuit>27111111114</cuit><valor_cuotaparte>5000000</valor_cuotaparte></cuotapartista>
<cuotapartista><cuit>20222222220</cuit><valor_cuotaparte>2000000</valor_cuotaparte></cuotapartista>
</cuotapartistas>
<composicion>
<activo><moneda>USD</moneda><peso>75</peso></activo>
<activo><moneda>ARS</moneda><peso>25</peso></activo>
</composicion>
</fci_disclosure>`), 0o644))

	// NAV CSV locked-down.
	navPath := filepath.Join(dir, "FCI_69_20240615_NAV.csv")
	must(t, os.WriteFile(navPath, []byte(`matricula: 69
NAV: 1234.56
`), 0o600))

	// Random — ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.csv"),
		[]byte("a,b\n"), 0o644))

	// Public — skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "FCI")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "fci_skip.xml"),
		[]byte(`<fci_disclosure/>`), 0o644))

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
		t.Fatalf("want 2 (cuotapartistas+nav), got %d: %+v", len(got), got)
	}

	var cuot, nav Row
	for _, r := range got {
		switch r.FilePath {
		case cuotapartistasPath:
			cuot = r
		case navPath:
			nav = r
		}
	}
	if cuot.FciMatricula != "69" {
		t.Fatalf("cuot matricula=%q", cuot.FciMatricula)
	}
	if cuot.SociedadGerenteCuitPrefix != "30" {
		t.Fatalf("cuot gerente cuit: %+v", cuot)
	}
	if !cuot.HasHighConcentration {
		t.Fatalf("cuot 50%% must flag concentration: %+v", cuot)
	}
	if !cuot.HasForeignDominatedPortfolio {
		t.Fatalf("cuot 75%% USD must flag foreign: %+v", cuot)
	}
	if !cuot.HasCuotapartistasList {
		t.Fatalf("cuot must flag cuotapartistas list: %+v", cuot)
	}
	if !cuot.IsCredentialExposureRisk {
		t.Fatalf("cuot + readable = exposure: %+v", cuot)
	}

	if nav.ArtifactKind != KindNAVDiario {
		t.Fatalf("nav kind=%q", nav.ArtifactKind)
	}
	if nav.IsCredentialExposureRisk {
		t.Fatalf("nav 0o600 must NOT flag: %+v", nav)
	}
	if nav.FechaNAV != "2024-06-15" {
		t.Fatalf("nav fecha=%q", nav.FechaNAV)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-fci")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "FCI_69_NAV.csv"),
		[]byte("matricula: 69\nNAV: 100\n"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "FCI_DIR" {
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
	if len(got) != 1 || got[0].FciMatricula != "69" {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-fci"},
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
		{FilePath: "z", FciMatricula: "69", PeriodYYYYMM: "202506"},
		{FilePath: "a", FciMatricula: "70", PeriodYYYYMM: "202506"},
		{FilePath: "a", FciMatricula: "69", PeriodYYYYMM: "202507"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].FciMatricula != "69" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
