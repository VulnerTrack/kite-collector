package winargpymebursatil

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindChPDAvalado), "chpd-avalado"},
		{string(KindPagareBursatil), "pagare-bursatil"},
		{string(KindONPyME), "on-pyme"},
		{string(KindFCEMiPyME), "fce-mipyme"},
		{string(KindLetraTesoro), "letra-tesoro"},
		{string(KindNegociacionMensual), "negociacion-mensual"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(MonedaARS), "ars"},
		{string(MonedaUSD), "usd"},
		{string(MonedaEUR), "eur"},
		{string(MonedaBRL), "brl"},
		{string(MonedaOther), "other"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"ChPD_SGR12_30712345678.xml",
		"cheque_pago_diferido_001.xml",
		"pagare_bursatil_acme.xml",
		"ON_PyME_acme_serie1.pdf",
		"FCE_mipyme_30712345678.xml",
		"FCE_30712345678_27111111114.xml",
		"factura_credito_electronica_001.xml",
		"letra_tesoro_provincial_BA.xml",
		"sgr_aval_acme.xml",
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

func TestInstrumentKindFromName(t *testing.T) {
	cases := map[string]InstrumentKind{
		"ChPD_001.xml":                    KindChPDAvalado,
		"cheque_pago_diferido_001.xml":    KindChPDAvalado,
		"pagare_bursatil_acme.xml":        KindPagareBursatil,
		"on_pyme_acme.xml":                KindONPyME,
		"obligacion_negociable_pyme.xml":  KindONPyME,
		"fce_mipyme_001.xml":              KindFCEMiPyME,
		"FCE_30712345678.xml":             KindFCEMiPyME,
		"factura_credito_electronica.xml": KindFCEMiPyME,
		"letra_tesoro_provincial.xml":     KindLetraTesoro,
		"negociacion_pyme_202506.csv":     KindNegociacionMensual,
		"pyme_bursatil_general.xml":       KindOther,
		"sgr_001.xml":                     KindOther,
		"random.xml":                      KindUnknown,
		"":                                KindUnknown,
	}
	for in, want := range cases {
		if got := InstrumentKindFromName(in); got != want {
			t.Fatalf("InstrumentKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMonedaFromText(t *testing.T) {
	cases := map[string]Moneda{
		"ARS": MonedaARS,
		"PES": MonedaARS,
		"USD": MonedaUSD,
		"DOL": MonedaUSD,
		"EUR": MonedaEUR,
		"BRL": MonedaBRL,
		"":    MonedaEmpty,
		"XYZ": MonedaOther,
	}
	for in, want := range cases {
		if got := MonedaFromText(in); got != want {
			t.Fatalf("MonedaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"FCE_30712345678.xml", "30", "5678"},
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

func TestSgrMatriculaFromText(t *testing.T) {
	cases := map[string]string{
		"sgr matricula 12": "12",
		"SGR 999":          "999",
		"matricula sgr 88": "88",
		"no sgr":           "",
		"":                 "",
	}
	for in, want := range cases {
		if got := SgrMatriculaFromText(in); got != want {
			t.Fatalf("SgrMatriculaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateDefaultRisk(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC) }
	r := Row{
		InstrumentKind:    KindChPDAvalado,
		EmisorCuitPrefix:  "30",
		EmisorCuitSuffix4: "5678",
		FechaVencimiento:  "2024-06-30",
		FileMode:          0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasDefaultRisk {
		t.Fatal("past vencimiento must flag default risk")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("emisor CUIT + readable = exposure")
	}
}

func TestAnnotateHighValueForeign(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC) }
	r := Row{
		InstrumentKind:   KindONPyME,
		EmisorCuitPrefix: "30",
		MontoARSCents:    5_000_000_000, // 50M ARS
		Moneda:           MonedaUSD,
		FechaVencimiento: "2027-01-01",
		FileMode:         0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsHighValue {
		t.Fatal("50M ARS must flag high-value")
	}
	if !r.IsForeignCurrency {
		t.Fatal("USD must flag foreign")
	}
	if r.HasDefaultRisk {
		t.Fatal("future vencimiento must NOT flag default")
	}
}

func TestAnnotateNoCuitNoExposure(t *testing.T) {
	r := Row{InstrumentKind: KindPagareBursatil, FileMode: 0o644}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("no CUIT must NOT flag exposure")
	}
}

func TestAnnotateARSDomesticClean(t *testing.T) {
	r := Row{InstrumentKind: KindChPDAvalado, Moneda: MonedaARS, FileMode: 0o600}
	AnnotateSecurity(&r)
	if r.IsForeignCurrency {
		t.Fatal("ARS must NOT flag foreign")
	}
}

// -- ParsePyMEInstrument -------------------------------------------

func TestParsePyMEInstrumentXMLChPD(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<chpd>
  <cuit_emisor>30712345678</cuit_emisor>
  <cuit_receptor>27111111114</cuit_receptor>
  <sgr_matricula>12</sgr_matricula>
  <sgr_aval>true</sgr_aval>
  <monto>500000.00</monto>
  <moneda>ARS</moneda>
  <fecha_emision>2024-06-15</fecha_emision>
  <fecha_vencimiento>2024-12-15</fecha_vencimiento>
</chpd>`)
	f, ok := ParsePyMEInstrument(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.EmisorCuitRaw != "30712345678" {
		t.Fatalf("emisor=%q", f.EmisorCuitRaw)
	}
	if f.ReceptorCuitRaw != "27111111114" {
		t.Fatalf("receptor=%q", f.ReceptorCuitRaw)
	}
	if f.SgrMatricula != "12" {
		t.Fatalf("sgr matricula=%q", f.SgrMatricula)
	}
	if !f.HasSgrAval {
		t.Fatal("sgr_aval=true must flag")
	}
	if f.MontoARSCents != 50000000 {
		t.Fatalf("monto=%d", f.MontoARSCents)
	}
}

func TestParsePyMEInstrumentNarrativeSGR(t *testing.T) {
	body := []byte(`<chpd>
<cuit_emisor>30712345678</cuit_emisor>
<descripcion>cheque avalada por SGR Garantizar</descripcion>
</chpd>`)
	f, ok := ParsePyMEInstrument(body)
	if !ok {
		t.Fatal("must parse")
	}
	if !f.HasSgrAval {
		t.Fatal("narrative SGR aval must flag")
	}
}

func TestParsePyMEInstrumentEmpty(t *testing.T) {
	if _, ok := ParsePyMEInstrument([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "PyMEBursatil")
	must(t, os.MkdirAll(dir, 0o755))

	// ChPD with SGR aval, past vencimiento (default risk), world-readable.
	chpdPath := filepath.Join(dir, "ChPD_SGR12_30712345678.xml")
	must(t, os.WriteFile(chpdPath, []byte(`<chpd>
<cuit_emisor>30712345678</cuit_emisor>
<cuit_receptor>27111111114</cuit_receptor>
<sgr_matricula>12</sgr_matricula>
<sgr_aval>true</sgr_aval>
<monto>500000.00</monto>
<moneda>ARS</moneda>
<fecha_vencimiento>2024-06-30</fecha_vencimiento>
</chpd>`), 0o644))

	// ON-PyME USD, locked-down.
	onPath := filepath.Join(dir, "ON_PyME_acme_30000000007.xml")
	must(t, os.WriteFile(onPath, []byte(`<on_pyme>
<cuit_emisor>30000000007</cuit_emisor>
<monto>50000000.00</monto>
<moneda>USD</moneda>
<fecha_vencimiento>2030-01-01</fecha_vencimiento>
</on_pyme>`), 0o600))

	// Random — ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.xml"),
		[]byte(`<root/>`), 0o644))

	// Public — skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "PyMEBursatil")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "ChPD_skip.xml"),
		[]byte(`<chpd/>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (chpd+on), got %d: %+v", len(got), got)
	}

	var chpd, on Row
	for _, r := range got {
		switch r.FilePath {
		case chpdPath:
			chpd = r
		case onPath:
			on = r
		}
	}
	if chpd.InstrumentKind != KindChPDAvalado {
		t.Fatalf("chpd kind=%q", chpd.InstrumentKind)
	}
	if !chpd.HasSgrAval {
		t.Fatalf("chpd must flag SGR aval: %+v", chpd)
	}
	if !chpd.HasDefaultRisk {
		t.Fatalf("chpd past vencimiento must flag default: %+v", chpd)
	}
	if !chpd.IsCredentialExposureRisk {
		t.Fatalf("chpd CUIT + readable = exposure: %+v", chpd)
	}
	if chpd.EmisorCuitPrefix != "30" || chpd.EmisorCuitSuffix4 != "5678" {
		t.Fatalf("chpd emisor: %+v", chpd)
	}
	if chpd.ReceptorCuitPrefix != "27" {
		t.Fatalf("chpd receptor: %+v", chpd)
	}

	if on.InstrumentKind != KindONPyME {
		t.Fatalf("on kind=%q", on.InstrumentKind)
	}
	if !on.IsHighValue {
		t.Fatalf("50M ARS must flag high-value: %+v", on)
	}
	if !on.IsForeignCurrency {
		t.Fatalf("USD must flag foreign: %+v", on)
	}
	if on.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", on)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-pyme")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "ChPD_001.xml"),
		[]byte(`<chpd><cuit_emisor>30712345678</cuit_emisor></chpd>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "PYME_BURSATIL_DIR" {
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
	if len(got) != 1 || got[0].InstrumentKind != KindChPDAvalado {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-pyme"},
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
		{FilePath: "z", InstrumentKind: KindChPDAvalado, EmisorCuitSuffix4: "5678"},
		{FilePath: "a", InstrumentKind: KindONPyME, EmisorCuitSuffix4: "1111"},
		{FilePath: "a", InstrumentKind: KindChPDAvalado, EmisorCuitSuffix4: "9999"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].InstrumentKind != KindChPDAvalado {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
