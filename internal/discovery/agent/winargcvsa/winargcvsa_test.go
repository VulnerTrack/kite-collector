package winargcvsa

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindCuentaComitente), "cuenta-comitente"},
		{string(KindTenenciasBroker), "tenencias-broker"},
		{string(KindSaldosClientes), "saldos-clientes"},
		{string(KindLiquidacionTitulo), "liquidacion-titulos"},
		{string(KindTransferenciaDVP), "transferencia-dvp"},
		{string(KindDRRRestringidas), "drr-restringidas"},
		{string(KindTitulares), "titulares"},
		{string(KindCDAArchive), "cda-archive"},
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
		"cuenta_comitente_12345_BR338.xml",
		"tenencias_BR338_202506.xml",
		"saldos_clientes_202506.csv",
		"liquidacion_titulos_202506.csv",
		"transferencia_dvp_001.xml",
		"DRR_202506.xml",
		"titulares_12345.xml",
		"cvsa_export.xml",
		"caja_valores_dump.csv",
		"archive.cda",
	}
	no := []string{"", "factura.xml", "random.txt"}
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
		"cuenta_comitente_12345.xml":     KindCuentaComitente,
		"comitente_12345.xml":            KindCuentaComitente,
		"tenencias_BR338_202506.xml":     KindTenenciasBroker,
		"saldos_clientes_202506.csv":     KindSaldosClientes,
		"liquidacion_titulos_202506.csv": KindLiquidacionTitulo,
		"transferencia_dvp_001.xml":      KindTransferenciaDVP,
		"DRR_202506.xml":                 KindDRRRestringidas,
		"titulares_12345.xml":            KindTitulares,
		"archive.cda":                    KindCDAArchive,
		"cvsa_export.xml":                KindOther,
		"":                               KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"cuenta_comitente_12345_30712345678.xml", "30", "5678"},
		{"30-71234567-8", "30", "5678"},
		{"cliente 27-11111111-4", "27", "1114"},
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

func TestIsBrokerCuitPrefix(t *testing.T) {
	yes := []string{"30", "33", "34"}
	no := []string{"20", "27", "23", "24", "", "11"}
	for _, v := range yes {
		if !IsBrokerCuitPrefix(v) {
			t.Fatalf("expected broker: %q", v)
		}
	}
	for _, v := range no {
		if IsBrokerCuitPrefix(v) {
			t.Fatalf("expected NOT broker: %q", v)
		}
	}
}

func TestMatriculaFromText(t *testing.T) {
	cases := map[string]string{
		"matricula 338":         "338",
		"matrícula 999":         "999",
		"alyc_matricula 88":     "88",
		"broker_matricula 1234": "1234",
		"no matricula here":     "",
		"":                      "",
	}
	for in, want := range cases {
		if got := MatriculaFromText(in); got != want {
			t.Fatalf("MatriculaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuentaSuffix4(t *testing.T) {
	cases := map[string]string{
		"comitente 12345":  "2345",
		"comitente N°7777": "7777",
		"cuenta: 9999":     "9999",
		"no comitente":     "",
		"":                 "",
	}
	for in, want := range cases {
		if got := CuentaSuffix4(in); got != want {
			t.Fatalf("CuentaSuffix4(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("tenencias_BR338_202506.xml") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.xml") != "" {
		t.Fatal("non-period must be empty")
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateLargeHoldings(t *testing.T) {
	r := Row{
		ArtifactKind:          KindCuentaComitente,
		ClienteCuitPrefix:     "27",
		ClienteCuitSuffix4:    "1114",
		InstrumentCount:       5,
		TotalPositionARSCents: 20_000_000_000, // 200 M ARS
		FileMode:              0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasLargeHoldings {
		t.Fatal("200M ARS must flag large")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("cliente CUIT + holdings + readable = exposure: %+v", r)
	}
}

func TestAnnotateHighConcentration(t *testing.T) {
	r := Row{
		ArtifactKind:   KindCuentaComitente,
		MaxPositionPct: 75,
		FileMode:       0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHighConcentration {
		t.Fatal("75% must flag concentration")
	}
}

func TestAnnotateCotitulares(t *testing.T) {
	r := Row{
		ArtifactKind:     KindTitulares,
		CotitularesCount: 3,
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCotitulares {
		t.Fatal("3 cotitulares must flag")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:          KindCuentaComitente,
		ClienteCuitPrefix:     "27",
		InstrumentCount:       5,
		TotalPositionARSCents: 20_000_000_000,
		FileMode:              0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseCVSAArtifact --------------------------------------------

func TestParseCuentaComitenteXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<cuenta_comitente>
  <broker_matricula>338</broker_matricula>
  <broker_cuit>30712345678</broker_cuit>
  <numero_cuenta>12345</numero_cuenta>
  <cliente_cuit>27111111114</cliente_cuit>
  <residencia>EXTERIOR</residencia>
  <periodo>202506</periodo>
  <tenencia>
    <ticker>GGAL</ticker>
    <valor_mercado>5000000.00</valor_mercado>
  </tenencia>
  <tenencia>
    <ticker>AL30</ticker>
    <valor_mercado>2000000.00</valor_mercado>
  </tenencia>
  <cotitular><nombre>X</nombre></cotitular>
  <cotitular><nombre>Y</nombre></cotitular>
</cuenta_comitente>`)
	f, ok := ParseCVSAArtifact(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.BrokerMatricula != "338" {
		t.Fatalf("matricula=%q", f.BrokerMatricula)
	}
	if f.BrokerCuitRaw != "30712345678" {
		t.Fatalf("broker=%q", f.BrokerCuitRaw)
	}
	if f.ClienteCuitRaw != "27111111114" {
		t.Fatalf("cliente=%q", f.ClienteCuitRaw)
	}
	if f.CuentaComitenteID != "12345" {
		t.Fatalf("cuenta=%q", f.CuentaComitenteID)
	}
	if !f.HasForeignOwner {
		t.Fatal("EXTERIOR must flag foreign")
	}
	if f.InstrumentCount != 2 {
		t.Fatalf("instr=%d", f.InstrumentCount)
	}
	if f.TotalCents != 700_000_000 {
		t.Fatalf("total=%d", f.TotalCents)
	}
	if f.MaxPositionCents != 500_000_000 {
		t.Fatalf("max=%d", f.MaxPositionCents)
	}
	if f.CotitularesCount != 2 {
		t.Fatalf("cotitulares=%d", f.CotitularesCount)
	}
}

func TestParseEmpty(t *testing.T) {
	if _, ok := ParseCVSAArtifact([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

func TestParseNonXML(t *testing.T) {
	if _, ok := ParseCVSAArtifact([]byte("cuit,monto\n123,456")); ok {
		t.Fatal("CSV is out-of-scope for structured parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "CajadeValores")
	must(t, os.MkdirAll(dir, 0o755))

	// High-value cuenta comitente, foreign owner, world-readable.
	cuentaPath := filepath.Join(dir, "cuenta_comitente_12345_BR338.xml")
	must(t, os.WriteFile(cuentaPath, []byte(`<?xml version="1.0"?>
<cuenta_comitente>
<broker_matricula>338</broker_matricula>
<broker_cuit>30712345678</broker_cuit>
<numero_cuenta>12345</numero_cuenta>
<cliente_cuit>27111111114</cliente_cuit>
<residencia>EXTERIOR</residencia>
<periodo>202506</periodo>
<tenencia><ticker>GGAL</ticker><valor_mercado>150000000.00</valor_mercado></tenencia>
<tenencia><ticker>AL30</ticker><valor_mercado>20000000.00</valor_mercado></tenencia>
</cuenta_comitente>`), 0o644))

	// Tenencias broker dump, locked down.
	tenPath := filepath.Join(dir, "tenencias_BR338_202506.xml")
	must(t, os.WriteFile(tenPath, []byte(`<tenencias>
<broker_matricula>338</broker_matricula>
<tenencia><valor_mercado>10000000.00</valor_mercado></tenencia>
</tenencias>`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.xml"),
		[]byte(`<x/>`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "CajadeValores")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "cuenta_comitente_skip.xml"),
		[]byte(`<cuenta_comitente/>`), 0o644))

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
		t.Fatalf("want 2 (cuenta+tenencias), got %d: %+v", len(got), got)
	}

	var cuenta, ten Row
	for _, r := range got {
		switch r.FilePath {
		case cuentaPath:
			cuenta = r
		case tenPath:
			ten = r
		}
	}
	if cuenta.ArtifactKind != KindCuentaComitente {
		t.Fatalf("cuenta kind=%q", cuenta.ArtifactKind)
	}
	if cuenta.BrokerMatricula != "338" {
		t.Fatalf("cuenta broker matricula=%q", cuenta.BrokerMatricula)
	}
	if cuenta.ClienteCuitPrefix != "27" || cuenta.ClienteCuitSuffix4 != "1114" {
		t.Fatalf("cuenta cliente: %+v", cuenta)
	}
	if !cuenta.HasForeignOwner {
		t.Fatalf("EXTERIOR must flag foreign: %+v", cuenta)
	}
	if !cuenta.HasLargeHoldings {
		t.Fatalf("170M ARS must flag large: %+v", cuenta)
	}
	if !cuenta.HasHighConcentration {
		t.Fatalf("150/170 = 88%% must flag concentration: pct=%d", cuenta.MaxPositionPct)
	}
	if !cuenta.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente + holdings = exposure: %+v", cuenta)
	}
	if cuenta.PeriodYYYYMM != "202506" {
		t.Fatalf("period=%q", cuenta.PeriodYYYYMM)
	}

	if ten.ArtifactKind != KindTenenciasBroker {
		t.Fatalf("ten kind=%q", ten.ArtifactKind)
	}
	if ten.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", ten)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-cvsa")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "cuenta_comitente_12345.xml"),
		[]byte(`<cuenta_comitente><cliente_cuit>27111111114</cliente_cuit></cuenta_comitente>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "CVSA_CUSTODY_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindCuentaComitente {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-cvsa"},
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
		{FilePath: "z", ArtifactKind: KindCuentaComitente},
		{FilePath: "a", ArtifactKind: KindTenenciasBroker},
		{FilePath: "a", ArtifactKind: KindCuentaComitente},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindCuentaComitente {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
