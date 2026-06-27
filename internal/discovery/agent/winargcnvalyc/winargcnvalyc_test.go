package winargcnvalyc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindRITenencias), "ri-tenencias"},
		{string(KindRIOperaciones), "ri-operaciones"},
		{string(KindEstadosPatrimoniales), "estados-patrimoniales"},
		{string(KindCustodiaMensual), "custodia-mensual"},
		{string(KindRegimenIIR), "regimen-iir"},
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
		"alyc_338_tenencias_202506.xml",
		"RI_Agentes_338_202506.xml",
		"R-IIR_338_202506.xml",
		"tenencias_alyc_202506.xml",
		"custodia_mensual_338.xml",
		"estados_patrimoniales_338.xml",
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

func TestFilingKindFromName(t *testing.T) {
	cases := map[string]FilingKind{
		"tenencias_alyc_202506.xml":         KindRITenencias,
		"alyc_338_tenencias.xml":            KindRITenencias,
		"alyc_338_operaciones_especies.xml": KindRIOperaciones,
		"estados_patrimoniales_338.xml":     KindEstadosPatrimoniales,
		"custodia_mensual_338.xml":          KindCustodiaMensual,
		"R-IIR_338_202506.xml":              KindRegimenIIR,
		"alyc_338_general.xml":              KindOther,
		"RI_Agentes_338.xml":                KindOther,
		"random.xml":                        KindUnknown,
		"":                                  KindUnknown,
	}
	for in, want := range cases {
		if got := FilingKindFromName(in); got != want {
			t.Fatalf("FilingKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"alyc_30712345678_202506.xml", "30", "5678"},
		{"30-71234567-8", "30", "5678"},
		{"no-cuit", "", ""},
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
		"matricula CNV 338":  "338",
		"matrícula: 338":     "338",
		"alyc_matricula=338": "338",
		"mat.CNV 12345":      "12345",
		"no matricula":       "",
		"":                   "",
	}
	for in, want := range cases {
		if got := MatriculaFromText(in); got != want {
			t.Fatalf("MatriculaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPeriodFromName(t *testing.T) {
	cases := map[string]string{
		"alyc_338_tenencias_202506.xml": "202506",
		"R-IIR_338_2025-06.xml":         "202506",
		"no-period.xml":                 "",
		"2025-13.xml":                   "", // invalid month
	}
	for in, want := range cases {
		if got := PeriodFromName(in); got != want {
			t.Fatalf("PeriodFromName(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateExposureFromClientList(t *testing.T) {
	r := Row{
		FilingKind:  KindRITenencias,
		ClientCount: 100,
		FileMode:    0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatal("client list + readable = exposure")
	}
}

func TestAnnotateHighConcentration(t *testing.T) {
	r := Row{FilingKind: KindCustodiaMensual, MaxClientPct: 75, FileMode: 0o600}
	AnnotateSecurity(&r)
	if !r.HasHighConcentration {
		t.Fatal("75% must flag high concentration")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateLowConcentrationNoFlag(t *testing.T) {
	r := Row{FilingKind: KindCustodiaMensual, MaxClientPct: 30, FileMode: 0o600}
	AnnotateSecurity(&r)
	if r.HasHighConcentration {
		t.Fatal("30% must NOT flag high concentration")
	}
}

// -- ParseALYCDisclosure -------------------------------------------

func TestParseALYCDisclosureTenencias(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<regimen_informativo>
  <cuit_agente>30712345678</cuit_agente>
  <denominacion_agente>ACME ALYC S.A.</denominacion_agente>
  <matricula>338</matricula>
  <periodo>202506</periodo>
  <tenencias>
    <tenencia>
      <cuit_cliente>20111111110</cuit_cliente>
      <monto>500000.00</monto>
      <moneda>ARS</moneda>
    </tenencia>
    <tenencia>
      <cuit_cliente>20222222220</cuit_cliente>
      <monto>2000000.00</monto>
      <moneda>USD</moneda>
    </tenencia>
    <tenencia>
      <cuit_cliente>27333333330</cuit_cliente>
      <monto>50000.00</monto>
      <moneda>ARS</moneda>
    </tenencia>
  </tenencias>
  <especies>
    <especie>GGAL</especie>
    <especie>YPFD</especie>
  </especies>
  <total_aum>2550000.00</total_aum>
</regimen_informativo>`)
	f, ok := ParseALYCDisclosure(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.AlycCuitRaw != "30712345678" {
		t.Fatalf("alyc cuit=%q", f.AlycCuitRaw)
	}
	if f.AlycMatricula != "338" {
		t.Fatalf("matricula=%q", f.AlycMatricula)
	}
	if f.ClientCount != 3 {
		t.Fatalf("client_count=%d want 3", f.ClientCount)
	}
	if f.SpecieCount != 2 {
		t.Fatalf("specie_count=%d want 2", f.SpecieCount)
	}
	if !f.HasForeignCustody {
		t.Fatal("USD tenencia must flag foreign custody")
	}
	if f.TotalAUMARSCents != 255000000 {
		t.Fatalf("total aum=%d want 255000000", f.TotalAUMARSCents)
	}
	// Max client = 2000000 / 2550000 ≈ 78%
	if f.MaxClientPct < 70 || f.MaxClientPct > 90 {
		t.Fatalf("max client pct=%d want ~78", f.MaxClientPct)
	}
}

func TestParseALYCDisclosureRejectsNonXML(t *testing.T) {
	if _, ok := ParseALYCDisclosure([]byte("nope")); ok {
		t.Fatal("non-XML must NOT parse")
	}
}

func TestParseALYCDisclosureEmpty(t *testing.T) {
	if _, ok := ParseALYCDisclosure([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "CNV", "Agentes")
	must(t, os.MkdirAll(dir, 0o755))

	// Tenencias world-readable, high concentration.
	tenPath := filepath.Join(dir, "alyc_338_tenencias_202506.xml")
	must(t, os.WriteFile(tenPath, []byte(`<regimen_informativo>
<cuit_agente>30712345678</cuit_agente>
<matricula>338</matricula>
<periodo>202506</periodo>
<tenencias>
<tenencia><cuit_cliente>20111111110</cuit_cliente><monto>800000.00</monto><moneda>USD</moneda></tenencia>
<tenencia><cuit_cliente>20222222220</cuit_cliente><monto>200000.00</monto><moneda>ARS</moneda></tenencia>
</tenencias>
<total_aum>1000000.00</total_aum>
</regimen_informativo>`), 0o644))

	// Custodia locked-down.
	custPath := filepath.Join(dir, "custodia_mensual_338_202506.xml")
	must(t, os.WriteFile(custPath, []byte(`<regimen_informativo>
<cuit_agente>30712345678</cuit_agente>
<matricula>338</matricula>
<total_aum>500000.00</total_aum>
</regimen_informativo>`), 0o600))

	// Random — ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.xml"),
		[]byte(`<root/>`), 0o644))

	// Public — skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "CNV", "Agentes")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "alyc_skip.xml"),
		[]byte(`<regimen_informativo><cuit_agente>30712345678</cuit_agente></regimen_informativo>`), 0o644))

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
		t.Fatalf("want 2 (ten+cust), got %d: %+v", len(got), got)
	}

	var ten, cust Row
	for _, r := range got {
		switch r.FilePath {
		case tenPath:
			ten = r
		case custPath:
			cust = r
		}
	}
	if ten.FilingKind != KindRITenencias {
		t.Fatalf("ten kind=%q", ten.FilingKind)
	}
	if !ten.HasForeignCurrencyCustody {
		t.Fatalf("USD tenencia must flag foreign: %+v", ten)
	}
	if !ten.HasHighConcentration {
		t.Fatalf("80%% client must flag high concentration: %+v", ten)
	}
	if !ten.IsCredentialExposureRisk {
		t.Fatalf("clients + readable = exposure: %+v", ten)
	}
	if ten.AlycMatricula != "338" {
		t.Fatalf("ten matricula=%q", ten.AlycMatricula)
	}
	if cust.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", cust)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-alyc")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "alyc_338_tenencias_202506.xml"),
		[]byte(`<regimen_informativo>
<cuit_agente>30712345678</cuit_agente>
<matricula>338</matricula>
</regimen_informativo>`), 0o600))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "CNV_ALYC_DIR" {
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
	if len(got) != 1 || got[0].AlycMatricula != "338" {
		t.Fatalf("env-supplied: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-alyc"},
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
		{FilePath: "z", AlycCuitPrefix: "30", PeriodYYYYMM: "202506"},
		{FilePath: "a", AlycCuitPrefix: "30", PeriodYYYYMM: "202507"},
		{FilePath: "a", AlycCuitPrefix: "20", PeriodYYYYMM: "202506"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].AlycCuitPrefix != "20" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
