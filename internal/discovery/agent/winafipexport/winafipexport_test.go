package winafipexport

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(WSMtxca), "wsmtxca"},
		{string(WSCT), "wsct"},
		{string(WSBfev1), "wsbfev1"},
		{string(WSOther), "other"},
		{string(WSUnknown), "unknown"},
		{string(IncoFOB), "fob"},
		{string(IncoCIF), "cif"},
		{string(IncoEXW), "exw"},
		{string(IncoFAS), "fas"},
		{string(IncoCFR), "cfr"},
		{string(IncoCPT), "cpt"},
		{string(IncoCIP), "cip"},
		{string(IncoDAP), "dap"},
		{string(IncoDPU), "dpu"},
		{string(IncoDDP), "ddp"},
		{string(IncoFCA), "fca"},
		{string(IncoOther), "other"},
		{string(IncoUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"WSMTXCA_30712345678_202506.xml",
		"wsct_001.xml",
		"factura_e_202506.xml",
		"comprobante_e_001.xml",
		"export_afip_2024.xml",
		"factura-exportacion-001.xml",
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

func TestWSKindFromName(t *testing.T) {
	cases := map[string]WSKind{
		"WSMTXCA_001.xml":        WSMtxca,
		"wsmtx_001.xml":          WSMtxca,
		"WSCT_001.xml":           WSCT,
		"wsbfev1_001.xml":        WSBfev1,
		"bonos_fiscales_001.xml": WSBfev1,
		"factura_e_001.xml":      WSMtxca,
		"comprobante-e-001.xml":  WSMtxca,
		"export_general.xml":     WSOther,
		"random.xml":             WSUnknown,
		"":                       WSUnknown,
	}
	for in, want := range cases {
		if got := WSKindFromName(in); got != want {
			t.Fatalf("WSKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIncotermFromText(t *testing.T) {
	cases := map[string]Incoterm{
		"FOB": IncoFOB, "fob": IncoFOB,
		"CIF": IncoCIF, "cfr": IncoCFR,
		"EXW": IncoEXW, "FAS": IncoFAS,
		"CPT": IncoCPT, "CIP": IncoCIP,
		"DAP": IncoDAP, "DPU": IncoDPU,
		"DDP": IncoDDP, "FCA": IncoFCA,
		"":    IncoUnknown,
		"DAT": IncoOther, // deprecated 2010 term
	}
	for in, want := range cases {
		if got := IncotermFromText(in); got != want {
			t.Fatalf("IncotermFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCifCfrIncoterm(t *testing.T) {
	yes := []Incoterm{IncoCIF, IncoCFR, IncoCIP, IncoCPT}
	no := []Incoterm{IncoFOB, IncoEXW, IncoFAS, IncoDDP, IncoUnknown}
	for _, v := range yes {
		if !IsCifCfrIncoterm(v) {
			t.Fatalf("expected CIF/CFR class: %q", v)
		}
	}
	for _, v := range no {
		if IsCifCfrIncoterm(v) {
			t.Fatalf("expected NOT CIF/CFR class: %q", v)
		}
	}
}

func TestCountryCodeFromText(t *testing.T) {
	cases := map[string]string{
		"USA":     "USA",
		"usa":     "USA",
		"  bra  ": "BRA",
		"":        "",
		"USA1":    "",
		"US":      "",
		"abcd":    "",
	}
	for in, want := range cases {
		if got := CountryCodeFromText(in); got != want {
			t.Fatalf("CountryCodeFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsFatfGreyCountry(t *testing.T) {
	yes := []string{"VEN", "ven", "SYR", "MMR"}
	no := []string{"USA", "BRA", "DEU", "", "ZZZ"}
	for _, v := range yes {
		if !IsFatfGreyCountry(v) {
			t.Fatalf("expected grey: %q", v)
		}
	}
	for _, v := range no {
		if IsFatfGreyCountry(v) {
			t.Fatalf("expected NOT grey: %q", v)
		}
	}
}

func TestIsExportCbteTipo(t *testing.T) {
	yes := []int{19, 20, 21, 22}
	no := []int{1, 6, 11, 51, 0, 100}
	for _, v := range yes {
		if !IsExportCbteTipo(v) {
			t.Fatalf("expected export: %d", v)
		}
	}
	for _, v := range no {
		if IsExportCbteTipo(v) {
			t.Fatalf("expected NOT export: %d", v)
		}
	}
}

func TestNormaliseDestino(t *testing.T) {
	cases := map[string]string{
		"USA":            "USA",
		"BRA":            "BRA",
		"212":            "USA",
		"200":            "BRA",
		"203":            "CHL",
		"999":            "",
		"Estados Unidos": "",
		"":               "",
	}
	for in, want := range cases {
		if got := NormaliseDestino(in); got != want {
			t.Fatalf("NormaliseDestino(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateHighValueExposure(t *testing.T) {
	r := Row{
		WSKind:           WSMtxca,
		CaeCode:          "75123456789012",
		CbteTipo:         19, // Factura E
		Incoterm:         IncoCIF,
		DestinoCountry:   "USA",
		Moneda:           "DOL",
		ImpTotalUSDCents: 500_000_000, // 5M USD
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsExportFactura {
		t.Fatal("CbteTipo 19 must flag export")
	}
	if !r.IsHighValueUSD {
		t.Fatal("5M USD must flag high-value")
	}
	if !r.IsIncotermCifCfr {
		t.Fatal("CIF must flag cif-cfr class")
	}
	if r.IsFatfGreyCountry {
		t.Fatal("USA must NOT flag FATF-grey")
	}
	if !r.IsCaePresent || !r.IsCredentialExposureRisk {
		t.Fatalf("CAE + readable must flag exposure: %+v", r)
	}
}

func TestAnnotateFatfGrey(t *testing.T) {
	r := Row{
		WSKind:           WSMtxca,
		CaeCode:          "75999999999999",
		CbteTipo:         19,
		Incoterm:         IncoFOB,
		DestinoCountry:   "VEN",
		ImpTotalUSDCents: 50_000_000, // 500k USD
		FileMode:         0o600,
	}
	AnnotateSecurity(&r)
	if !r.IsFatfGreyCountry {
		t.Fatal("VEN must flag FATF-grey")
	}
	if r.IsHighValueUSD {
		t.Fatal("500k USD must NOT flag high-value (<1M USD)")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoCAEClean(t *testing.T) {
	r := Row{WSKind: WSMtxca, CbteTipo: 1, FileMode: 0o644}
	AnnotateSecurity(&r)
	if r.IsCaePresent {
		t.Fatal("empty CAE must NOT flag is_cae_present")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("no CAE must NOT flag exposure")
	}
}

// -- ParseExportInvoice --------------------------------------------

func TestParseExportInvoiceXMLFOB(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<FECAEDetResponse>
  <CuitEmisor>30712345678</CuitEmisor>
  <CAE>75999999999999</CAE>
  <CbteTipo>19</CbteTipo>
  <CbteFch>20240615</CbteFch>
  <PtoVta>3</PtoVta>
  <CbteDesde>12345</CbteDesde>
  <Incoterm>FOB</Incoterm>
  <Dst_cmp>USA</Dst_cmp>
  <MonId>DOL</MonId>
  <MonCotiz>900.50</MonCotiz>
  <ImpTotal>50000.00</ImpTotal>
  <IdiomaCbte>es</IdiomaCbte>
</FECAEDetResponse>`)
	f, ok := ParseExportInvoice(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.CuitEmisorRaw != "30712345678" {
		t.Fatalf("emisor=%q", f.CuitEmisorRaw)
	}
	if f.CAE != "75999999999999" {
		t.Fatalf("cae=%q", f.CAE)
	}
	if f.CbteTipo != 19 {
		t.Fatalf("tipo=%d", f.CbteTipo)
	}
	if f.IncotermRaw != "FOB" {
		t.Fatalf("incoterm=%q", f.IncotermRaw)
	}
	if f.DestinoCountry != "USA" {
		t.Fatalf("destino=%q", f.DestinoCountry)
	}
	if f.Moneda != "DOL" {
		t.Fatalf("moneda=%q", f.Moneda)
	}
	if f.CotizacionARS != 90050 {
		t.Fatalf("cotiz=%d", f.CotizacionARS)
	}
	if f.ImpTotalCents != 5000000 {
		t.Fatalf("imp=%d", f.ImpTotalCents)
	}
	// Moneda=DOL → ImpTotalUSDCents == ImpTotalCents (already USD).
	if f.ImpTotalUSDCents != 5000000 {
		t.Fatalf("usd cents=%d want 5000000", f.ImpTotalUSDCents)
	}
}

func TestParseExportInvoiceRejectsNonXML(t *testing.T) {
	if _, ok := ParseExportInvoice([]byte("nope")); ok {
		t.Fatal("non-XML must NOT parse")
	}
	if _, ok := ParseExportInvoice([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "AFIP", "FacturaExportacion")
	must(t, os.MkdirAll(dir, 0o755))

	// High-value CIF to USA — world-readable.
	highPath := filepath.Join(dir, "WSMTXCA_30712345678_202506.xml")
	must(t, os.WriteFile(highPath, []byte(`<FECAEDetResponse>
<CuitEmisor>30712345678</CuitEmisor>
<CAE>75999999999999</CAE>
<CbteTipo>19</CbteTipo>
<PtoVta>1</PtoVta><CbteDesde>1</CbteDesde>
<Incoterm>CIF</Incoterm><Dst_cmp>USA</Dst_cmp>
<MonId>DOL</MonId><ImpTotal>2000000.00</ImpTotal>
</FECAEDetResponse>`), 0o644))

	// Low-value FOB to Venezuela (FATF grey) — locked-down.
	venPath := filepath.Join(dir, "factura_e_30000000007_202506.xml")
	must(t, os.WriteFile(venPath, []byte(`<FECAEDetResponse>
<CuitEmisor>30000000007</CuitEmisor>
<CAE>75111111111111</CAE>
<CbteTipo>19</CbteTipo>
<PtoVta>1</PtoVta><CbteDesde>2</CbteDesde>
<Incoterm>FOB</Incoterm><Dst_cmp>VEN</Dst_cmp>
<MonId>DOL</MonId><ImpTotal>50000.00</ImpTotal>
</FECAEDetResponse>`), 0o600))

	// Random XML, ignored by name gate.
	must(t, os.WriteFile(filepath.Join(dir, "random.xml"),
		[]byte(`<root/>`), 0o644))

	// Public — skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "AFIP", "FacturaExportacion")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "WSMTXCA_skip.xml"),
		[]byte(`<FECAEDetResponse/>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (high+ven), got %d: %+v", len(got), got)
	}

	var high, ven Row
	for _, r := range got {
		switch r.FilePath {
		case highPath:
			high = r
		case venPath:
			ven = r
		}
	}
	if !high.IsExportFactura || !high.IsHighValueUSD || !high.IsIncotermCifCfr {
		t.Fatalf("high flags: %+v", high)
	}
	if !high.IsCredentialExposureRisk {
		t.Fatalf("high + world-readable must flag exposure: %+v", high)
	}
	if high.CuitEmisorPrefix != "30" || high.CuitEmisorSuffix4 != "5678" {
		t.Fatalf("high cuit: %+v", high)
	}
	if high.DestinoCountry != "USA" {
		t.Fatalf("high destino=%q", high.DestinoCountry)
	}

	if !ven.IsFatfGreyCountry {
		t.Fatalf("VEN must flag FATF-grey: %+v", ven)
	}
	if ven.IsIncotermCifCfr {
		t.Fatalf("FOB must NOT flag CIF/CFR: %+v", ven)
	}
	if ven.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag exposure: %+v", ven)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-export")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "WSMTXCA_30712345678.xml"),
		[]byte(`<FECAEDetResponse>
<CuitEmisor>30712345678</CuitEmisor><CAE>x</CAE>
<CbteTipo>19</CbteTipo><PtoVta>1</PtoVta><CbteDesde>1</CbteDesde>
<Incoterm>CIF</Incoterm><Dst_cmp>USA</Dst_cmp>
<MonId>DOL</MonId><ImpTotal>5000000</ImpTotal>
</FECAEDetResponse>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "AFIP_EXPORT_DIR" {
				return envDir
			}
			return ""
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || !got[0].IsHighValueUSD {
		t.Fatalf("env-supplied high-value: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-export"},
		usersBases:   []string{"/nope-users"},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
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
		{FilePath: "z", PtoVta: 1, CbteNro: 1},
		{FilePath: "a", PtoVta: 2, CbteNro: 1},
		{FilePath: "a", PtoVta: 1, CbteNro: 5},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].PtoVta != 1 || in[0].CbteNro != 5 {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
