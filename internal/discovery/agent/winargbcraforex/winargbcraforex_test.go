package winargbcraforex

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(DeclMULCOperacion), "mulc-operacion"},
		{string(DeclCCLOperacion), "ccl-operacion"},
		{string(DeclMEPOperacion), "mep-operacion"},
		{string(DeclLiquidacionDivisas), "liquidacion-divisas"},
		{string(DeclDolarSoja), "dolar-soja"},
		{string(DeclRIPCAA), "ripcaa"},
		{string(DeclOther), "other"},
		{string(DeclUnknown), "unknown"},
		{string(OpAtesoramiento), "atesoramiento"},
		{string(OpTurismoExterior), "turismo-exterior"},
		{string(OpLiquidacionExportacion), "liquidacion-exportacion"},
		{string(OpPagoImportacion), "pago-importacion"},
		{string(MonedaARS), "ars"},
		{string(MonedaUSD), "usd"},
		{string(MonedaEUR), "eur"},
		{string(MonedaBRL), "brl"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"mulc_declaracion_001.xml",
		"CCL_AL30_202506.xml",
		"mep_bonar_202506.csv",
		"liquidacion_divisas_30712345678.xml",
		"dolar_soja_202506.xml",
		"ripcaa_pago_exterior.xml",
		"declaracion_cambiaria_001.xml",
		"pago_importacion_USD.xml",
		"cobro_exportacion_BRA.xml",
		"forex_bcra_dump.json",
	}
	no := []string{"", "factura.xml", "cv.pdf", "random.xml"}
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

func TestDeclarationKindFromName(t *testing.T) {
	cases := map[string]DeclarationKind{
		"mulc_declaracion_001.xml":          DeclMULCOperacion,
		"CCL_AL30_202506.xml":               DeclCCLOperacion,
		"mep_bonar.xml":                     DeclMEPOperacion,
		"liquidacion_divisas_30000000007.x": DeclLiquidacionDivisas,
		"dolar_soja_202506.xml":             DeclDolarSoja,
		"ripcaa_pago_exterior.xml":          DeclRIPCAA,
		"declaracion_cambiaria_001.xml":     DeclOther,
		"forex_bcra_dump.json":              DeclOther,
		"random.xml":                        DeclUnknown,
		"":                                  DeclUnknown,
	}
	for in, want := range cases {
		if got := DeclarationKindFromName(in); got != want {
			t.Fatalf("DeclarationKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestOperacionTypeFromText(t *testing.T) {
	cases := map[string]OperacionType{
		"atesoramiento":              OpAtesoramiento,
		"turismo exterior":           OpTurismoExterior,
		"viajes exterior":            OpTurismoExterior,
		"dividendos exterior":        OpDividendosExterior,
		"intereses exterior":         OpInteresesExterior,
		"liquidacion de exportacion": OpLiquidacionExportacion,
		"pago de importacion":        OpPagoImportacion,
		"transferencia":              OpTransferencia,
		"compra de divisas":          OpCompra,
		"venta de divisas":           OpVenta,
		"":                           OpUnknown,
		"other text":                 OpOther,
	}
	for in, want := range cases {
		if got := OperacionTypeFromText(in); got != want {
			t.Fatalf("OperacionTypeFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsSpeculativeOperacion(t *testing.T) {
	if !IsSpeculativeOperacion(OpAtesoramiento) {
		t.Fatal("atesoramiento must flag speculative")
	}
	if !IsSpeculativeOperacion(OpTurismoExterior) {
		t.Fatal("turismo-exterior must flag speculative")
	}
	if IsSpeculativeOperacion(OpLiquidacionExportacion) {
		t.Fatal("liquidacion-exportacion is hedger not speculative")
	}
	if IsSpeculativeOperacion(OpUnknown) {
		t.Fatal("unknown must NOT flag")
	}
}

func TestIsSpeculativeConcepto(t *testing.T) {
	yes := []string{"A01", "a01", "S04", "S15", "S22"}
	no := []string{"", "Z99", "B12"}
	for _, v := range yes {
		if !IsSpeculativeConcepto(v) {
			t.Fatalf("expected speculative: %q", v)
		}
	}
	for _, v := range no {
		if IsSpeculativeConcepto(v) {
			t.Fatalf("expected NOT speculative: %q", v)
		}
	}
}

func TestMonedaFromText(t *testing.T) {
	cases := map[string]Moneda{
		"ARS":  MonedaARS,
		"PES":  MonedaARS,
		"USD":  MonedaUSD,
		"EUR":  MonedaEUR,
		"BRL":  MonedaBRL,
		"":     MonedaEmpty,
		"XYZ":  MonedaOther,
		"REAL": MonedaBRL,
	}
	for in, want := range cases {
		if got := MonedaFromText(in); got != want {
			t.Fatalf("MonedaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsFatfGreyCountry(t *testing.T) {
	yes := []string{"VEN", "VNM", "SYR", "NGA"}
	no := []string{"USA", "ARG", "BRA", "", "X"}
	for _, v := range yes {
		if !IsFatfGreyCountry(v) {
			t.Fatalf("expected FATF grey: %q", v)
		}
	}
	for _, v := range no {
		if IsFatfGreyCountry(v) {
			t.Fatalf("expected NOT FATF grey: %q", v)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"liquidacion_divisas_30712345678.xml", "30", "5678"},
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
		"matricula 338":     "338",
		"matrícula CNV 338": "338",
		"mat.cnv 999":       "999",
		"alyc_matricula 88": "88",
		"no matricula here": "",
		"":                  "",
	}
	for in, want := range cases {
		if got := MatriculaFromText(in); got != want {
			t.Fatalf("MatriculaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateHighValueUSD(t *testing.T) {
	r := Row{
		DeclarationKind:     DeclMULCOperacion,
		OperacionType:       OpCompra,
		DeclarantCuitPrefix: "30",
		MontoUSDCents:       200_000_000, // 2M USD > 1M threshold
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsHighValueUSD {
		t.Fatal("2M USD must flag high-value")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("CUIT + monetary + readable = exposure")
	}
}

func TestAnnotateFatfGreyDestination(t *testing.T) {
	r := Row{
		DeclarationKind:     DeclLiquidacionDivisas,
		OperacionType:       OpTransferencia,
		CounterpartyCountry: "VEN",
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if !r.IsFatfGreyDestination {
		t.Fatal("VEN counterparty must flag FATF grey")
	}
}

func TestAnnotateSpeculativeConcepto(t *testing.T) {
	r := Row{
		DeclarationKind: DeclMULCOperacion,
		OperacionType:   OpCompra,
		ConceptoBCRA:    "A01",
		FileMode:        0o600,
	}
	AnnotateSecurity(&r)
	if !r.HasConceptoSpeculative {
		t.Fatal("A01 concepto must flag speculative")
	}
}

func TestAnnotateSpeculativeOperacion(t *testing.T) {
	r := Row{
		DeclarationKind: DeclMULCOperacion,
		OperacionType:   OpAtesoramiento,
		FileMode:        0o600,
	}
	AnnotateSecurity(&r)
	if !r.HasConceptoSpeculative {
		t.Fatal("atesoramiento op must flag speculative")
	}
}

func TestAnnotateARSCleanNoExposure(t *testing.T) {
	r := Row{
		DeclarationKind: DeclMULCOperacion,
		Moneda:          MonedaARS,
		FileMode:        0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("no CUIT + no monetary must NOT flag exposure")
	}
	if r.IsHighValueUSD {
		t.Fatal("0 USD must NOT flag high-value")
	}
}

// -- ParseBCRAForex ------------------------------------------------

func TestParseBCRAForexMULCXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<mulc>
  <cuit_declarante>30712345678</cuit_declarante>
  <broker_matricula>338</broker_matricula>
  <pais_contraparte>USA</pais_contraparte>
  <moneda>USD</moneda>
  <concepto_bcra>A01</concepto_bcra>
  <operacion>compra de divisas</operacion>
  <monto_usd>2500000.00</monto_usd>
  <monto_ars>2500000000.00</monto_ars>
  <fecha_operacion>2026-06-15</fecha_operacion>
</mulc>`)
	f, ok := ParseBCRAForex(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.DeclarantCuitRaw != "30712345678" {
		t.Fatalf("declarant=%q", f.DeclarantCuitRaw)
	}
	if f.BrokerMatricula != "338" {
		t.Fatalf("matricula=%q", f.BrokerMatricula)
	}
	if f.CounterpartyCountry != "USA" {
		t.Fatalf("country=%q", f.CounterpartyCountry)
	}
	if f.MonedaText != "USD" {
		t.Fatalf("moneda=%q", f.MonedaText)
	}
	if f.ConceptoBCRA != "A01" {
		t.Fatalf("concepto=%q", f.ConceptoBCRA)
	}
	if f.OperacionText != "compra de divisas" {
		t.Fatalf("operacion=%q", f.OperacionText)
	}
	if f.MontoUSDCents != 250_000_000 {
		t.Fatalf("monto USD=%d", f.MontoUSDCents)
	}
	if f.FechaOperacion != "2026-06-15" {
		t.Fatalf("fecha=%q", f.FechaOperacion)
	}
}

func TestParseBCRAForexEmpty(t *testing.T) {
	if _, ok := ParseBCRAForex([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

func TestParseBCRAForexMalformed(t *testing.T) {
	if _, ok := ParseBCRAForex([]byte("<not-xml")); ok {
		t.Fatal("malformed XML must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "BCRA", "MULC")
	must(t, os.MkdirAll(dir, 0o755))

	// High-value MULC USD, world-readable.
	mulcPath := filepath.Join(dir, "mulc_declaracion_30712345678.xml")
	must(t, os.WriteFile(mulcPath, []byte(`<mulc>
<cuit_declarante>30712345678</cuit_declarante>
<broker_matricula>338</broker_matricula>
<moneda>USD</moneda>
<concepto_bcra>A02</concepto_bcra>
<operacion>compra de divisas</operacion>
<monto_usd>2500000.00</monto_usd>
<fecha_operacion>2026-06-15</fecha_operacion>
</mulc>`), 0o644))

	// CCL to FATF-grey, locked down.
	cclDir := filepath.Join(usersBase, "alice", "Documents", "BCRA", "Forex")
	must(t, os.MkdirAll(cclDir, 0o755))
	cclPath := filepath.Join(cclDir, "CCL_AL30_VEN_202506.xml")
	must(t, os.WriteFile(cclPath, []byte(`<ccl>
<cuit_declarante>30000000007</cuit_declarante>
<pais_contraparte>VEN</pais_contraparte>
<moneda>USD</moneda>
<operacion>transferencia</operacion>
<monto_usd>500000.00</monto_usd>
<fecha_operacion>2026-06-15</fecha_operacion>
</ccl>`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.xml"),
		[]byte(`<root/>`), 0o644))

	// Public profile skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "BCRA", "MULC")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "mulc_skip.xml"),
		[]byte(`<mulc/>`), 0o644))

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
		t.Fatalf("want 2, got %d: %+v", len(got), got)
	}

	var mulc, ccl Row
	for _, r := range got {
		switch r.FilePath {
		case mulcPath:
			mulc = r
		case cclPath:
			ccl = r
		}
	}
	if mulc.DeclarationKind != DeclMULCOperacion {
		t.Fatalf("mulc kind=%q", mulc.DeclarationKind)
	}
	if !mulc.IsHighValueUSD {
		t.Fatalf("mulc 2.5M USD must flag high-value: %+v", mulc)
	}
	if !mulc.HasConceptoSpeculative {
		t.Fatalf("A02 concepto must flag speculative: %+v", mulc)
	}
	if !mulc.IsCredentialExposureRisk {
		t.Fatalf("mulc CUIT + monetary + readable = exposure: %+v", mulc)
	}
	if mulc.DeclarantCuitPrefix != "30" || mulc.DeclarantCuitSuffix4 != "5678" {
		t.Fatalf("mulc declarant: %+v", mulc)
	}
	if mulc.BrokerMatricula != "338" {
		t.Fatalf("mulc broker: %+v", mulc)
	}

	if ccl.DeclarationKind != DeclCCLOperacion {
		t.Fatalf("ccl kind=%q", ccl.DeclarationKind)
	}
	if !ccl.IsFatfGreyDestination {
		t.Fatalf("VEN counterparty must flag FATF grey: %+v", ccl)
	}
	if ccl.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag exposure: %+v", ccl)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-forex")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "mulc_001.xml"),
		[]byte(`<mulc><cuit_declarante>30712345678</cuit_declarante></mulc>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "BCRA_FOREX_DIR" {
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
	if len(got) != 1 || got[0].DeclarationKind != DeclMULCOperacion {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-forex"},
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
		{FilePath: "z", DeclarationKind: DeclMULCOperacion},
		{FilePath: "a", DeclarationKind: DeclCCLOperacion},
		{FilePath: "a", DeclarationKind: DeclMULCOperacion},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].DeclarationKind != DeclCCLOperacion {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
