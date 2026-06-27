package winafipcae

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(CbteA), "A"},
		{string(CbteB), "B"},
		{string(CbteC), "C"},
		{string(CbteE), "E"},
		{string(CbteM), "M"},
		{string(CbteUnknown), "X"},
		{string(DocCUIT), "cuit"},
		{string(DocCUIL), "cuil"},
		{string(DocDNI), "dni"},
		{string(DocPasaporte), "pasaporte"},
		{string(DocCDI), "cdi"},
		{string(DocLE), "le"},
		{string(DocLC), "lc"},
		{string(DocOther), "other"},
		{string(DocUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestLetterFromCbteTipo(t *testing.T) {
	cases := map[int]CbteLetter{
		1: CbteA, 2: CbteA, 3: CbteA, 4: CbteA, 5: CbteA,
		6: CbteB, 7: CbteB, 8: CbteB, 9: CbteB, 10: CbteB,
		11: CbteC, 12: CbteC, 13: CbteC, 15: CbteC,
		19: CbteE, 20: CbteE, 21: CbteE, 22: CbteE,
		51: CbteM, 52: CbteM, 53: CbteM,
		0:   CbteUnknown,
		99:  CbteUnknown,
		100: CbteUnknown,
	}
	for in, want := range cases {
		if got := LetterFromCbteTipo(in); got != want {
			t.Fatalf("LetterFromCbteTipo(%d)=%q want %q", in, got, want)
		}
	}
}

func TestDocTipoLabel(t *testing.T) {
	cases := map[int]DocTipoLabel{
		80: DocCUIT,
		86: DocCUIL,
		96: DocDNI,
		94: DocPasaporte,
		87: DocCDI,
		89: DocLE,
		90: DocLC,
		0:  DocUnknown,
		99: DocUnknown,
		77: DocOther,
	}
	for in, want := range cases {
		if got := DocTipoLabelFromCode(in); got != want {
			t.Fatalf("DocTipoLabelFromCode(%d)=%q want %q", in, got, want)
		}
	}
}

func TestSuffix4(t *testing.T) {
	cases := map[string]string{
		"30712345678": "5678",
		"12345":       "2345",
		"abc":         "",
		"":            "",
		"1234":        "1234",
	}
	for in, want := range cases {
		if got := Suffix4(in); got != want {
			t.Fatalf("Suffix4(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsAfipPath(t *testing.T) {
	yes := []string{
		`C:\Users\alice\Documents\Facturas\factura-001.xml`,
		"/home/alice/afip/cae/2026-06.xml",
		"/home/bob/Documents/comprobantes/0001-00012345.xml",
	}
	no := []string{
		"/home/alice/Documents/random.xml",
		"",
	}
	for _, v := range yes {
		if !IsAfipPath(v) {
			t.Fatalf("expected AFIP path: %q", v)
		}
	}
	for _, v := range no {
		if IsAfipPath(v) {
			t.Fatalf("expected NOT AFIP path: %q", v)
		}
	}
}

// -- AnnotateSecurity branches -------------------------------------

func TestAnnotateHighValueForeignCurrency(t *testing.T) {
	r := Receipt{
		CaeCode:       "75123456789012",
		CbteTipo:      1,
		ImpTotalCents: 2_500_000_000, // 25M ARS-equivalent
		MonID:         "DOL",
		FileMode:      0o600,
	}
	AnnotateSecurity(&r)
	if !r.IsCaePresent || !r.IsForeignCurrency || !r.IsHighValue {
		t.Fatalf("expected high+foreign+cae: %+v", r)
	}
	if r.CbteLetter != CbteA {
		t.Fatalf("letter=%q", r.CbteLetter)
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateFacturaMExposure(t *testing.T) {
	r := Receipt{
		CaeCode:       "75999999999999",
		CbteTipo:      51,
		ImpTotalCents: 100_00,
		MonID:         "PES",
		FileMode:      0o644,
		DocTipo:       96,
		DocNroSuffix4: "5678",
	}
	AnnotateSecurity(&r)
	if r.CbteLetter != CbteM || !r.IsFacturaM {
		t.Fatalf("factura M not flagged: %+v", r)
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("0o644 + CAE must flag PII exposure")
	}
	if r.DocTipoLabel != DocDNI {
		t.Fatalf("doc label=%q", r.DocTipoLabel)
	}
}

func TestAnnotateNoCAEClean(t *testing.T) {
	r := Receipt{CaeCode: "", CbteTipo: 1, FileMode: 0o644}
	AnnotateSecurity(&r)
	if r.IsCaePresent || r.IsCredentialExposureRisk {
		t.Fatalf("no CAE must NOT flag: %+v", r)
	}
}

// -- ParseCAEReceipt -----------------------------------------------

func TestParseCAEReceiptTypical(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<FECAEDetResponse>
  <CAE>75123456789012</CAE>
  <CAEFchVto>20260630</CAEFchVto>
  <CbteTipo>1</CbteTipo>
  <CbteFch>20260615</CbteFch>
  <PtoVta>3</PtoVta>
  <CbteDesde>12345</CbteDesde>
  <DocTipo>80</DocTipo>
  <DocNro>30712345678</DocNro>
  <ImpTotal>123456.78</ImpTotal>
  <MonId>PES</MonId>
</FECAEDetResponse>`)
	r, ok := ParseCAEReceipt(body)
	if !ok {
		t.Fatal("must parse")
	}
	if r.CaeCode != "75123456789012" {
		t.Fatalf("cae=%q", r.CaeCode)
	}
	if r.CbteTipo != 1 || r.CbteFch != "20260615" {
		t.Fatalf("tipo/fch: %+v", r)
	}
	if r.PtoVta != 3 || r.CbteNro != 12345 {
		t.Fatalf("pto/nro: %+v", r)
	}
	if r.DocTipo != 80 || r.DocNroSuffix4 != "5678" {
		t.Fatalf("doc: %+v", r)
	}
	if r.ImpTotalCents != 12345678 {
		t.Fatalf("imp cents=%d want 12345678", r.ImpTotalCents)
	}
	if r.MonID != "PES" {
		t.Fatalf("mon=%q", r.MonID)
	}
}

func TestParseCAEReceiptSOAPWrapped(t *testing.T) {
	body := []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <FECAESolicitarResponse>
      <FECAESolicitarResult>
        <FeDetResp>
          <FECAEDetResponse>
            <CAE>75999999999999</CAE>
            <CbteTipo>19</CbteTipo>
            <PtoVta>5</PtoVta>
            <CbteDesde>9876</CbteDesde>
            <ImpTotal>50000.00</ImpTotal>
            <MonId>DOL</MonId>
          </FECAEDetResponse>
        </FeDetResp>
      </FECAESolicitarResult>
    </FECAESolicitarResponse>
  </soap:Body>
</soap:Envelope>`)
	r, ok := ParseCAEReceipt(body)
	if !ok {
		t.Fatal("soap-wrapped must parse")
	}
	if r.CaeCode != "75999999999999" || r.CbteTipo != 19 {
		t.Fatalf("cae/tipo: %+v", r)
	}
	if r.MonID != "DOL" {
		t.Fatalf("mon=%q", r.MonID)
	}
	if r.ImpTotalCents != 5000000 {
		t.Fatalf("imp=%d", r.ImpTotalCents)
	}
}

func TestParseCAEReceiptRejectsNonCAE(t *testing.T) {
	body := []byte(`<foo><bar>x</bar></foo>`)
	if _, ok := ParseCAEReceipt(body); ok {
		t.Fatal("non-CAE must NOT parse")
	}
}

func TestParseCAEReceiptBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte(`<FECAEDetResponse><CAE>75000000000001</CAE><PtoVta>1</PtoVta><CbteDesde>1</CbteDesde></FECAEDetResponse>`)...)
	r, ok := ParseCAEReceipt(body)
	if !ok {
		t.Fatal("BOM must be tolerated")
	}
	if r.CaeCode != "75000000000001" {
		t.Fatalf("cae=%q", r.CaeCode)
	}
}

// -- collector end-to-end -----------------------------------------

func TestFileCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")

	// alice has a high-value foreign-currency receipt + a regular one.
	aliceDir := filepath.Join(usersBase, "alice", "Documents", "Facturas")
	must(t, os.MkdirAll(aliceDir, 0o755))

	dolPath := filepath.Join(aliceDir, "factura-dol-001.xml")
	must(t, os.WriteFile(dolPath, []byte(`<FECAEDetResponse>
<CAE>75999999999999</CAE><CbteTipo>1</CbteTipo>
<PtoVta>1</PtoVta><CbteDesde>1</CbteDesde>
<DocTipo>80</DocTipo><DocNro>30712345678</DocNro>
<ImpTotal>15000000.00</ImpTotal><MonId>DOL</MonId>
</FECAEDetResponse>`), 0o644))

	pesPath := filepath.Join(aliceDir, "factura-pes-001.xml")
	must(t, os.WriteFile(pesPath, []byte(`<FECAEDetResponse>
<CAE>75111111111111</CAE><CbteTipo>6</CbteTipo>
<PtoVta>1</PtoVta><CbteDesde>2</CbteDesde>
<DocTipo>96</DocTipo><DocNro>11223344</DocNro>
<ImpTotal>1500.00</ImpTotal><MonId>PES</MonId>
</FECAEDetResponse>`), 0o600))

	// bob has an unrelated XML — must be ignored.
	bobDir := filepath.Join(usersBase, "bob", "Documents")
	must(t, os.MkdirAll(bobDir, 0o755))
	must(t, os.WriteFile(filepath.Join(bobDir, "notes.xml"),
		[]byte(`<root><x/></root>`), 0o644))

	// Public profile must be skipped.
	pubDir := filepath.Join(usersBase, "Public", "Facturas")
	must(t, os.MkdirAll(pubDir, 0o755))
	must(t, os.WriteFile(filepath.Join(pubDir, "factura-skip.xml"),
		[]byte(`<FECAEDetResponse><CAE>x</CAE><PtoVta>1</PtoVta><CbteDesde>1</CbteDesde></FECAEDetResponse>`), 0o644))

	c := &fileCollector{
		usersBases: []string{usersBase},
		getenv:     func(string) string { return "" },
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (alice DOL + PES), got %d: %+v", len(got), got)
	}

	var dol, pes Receipt
	for _, r := range got {
		if r.FilePath == dolPath {
			dol = r
		}
		if r.FilePath == pesPath {
			pes = r
		}
	}
	if dol.FilePath == "" || pes.FilePath == "" {
		t.Fatalf("missing receipts: %+v", got)
	}
	if !dol.IsForeignCurrency || !dol.IsHighValue {
		t.Fatalf("DOL must flag foreign+high: %+v", dol)
	}
	if !dol.IsCredentialExposureRisk {
		t.Fatalf("DOL world-readable + CAE must flag exposure: %+v", dol)
	}
	if dol.DocTipoLabel != DocCUIT || dol.DocNroSuffix4 != "5678" {
		t.Fatalf("DOL doc: %+v", dol)
	}
	if pes.IsForeignCurrency || pes.IsHighValue || pes.IsCredentialExposureRisk {
		t.Fatalf("PES 0o600 small-value local must NOT flag: %+v", pes)
	}
	if pes.DocTipoLabel != DocDNI || pes.DocNroSuffix4 != "3344" {
		t.Fatalf("PES doc: %+v", pes)
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		usersBases: []string{"/nope-users"},
		getenv:     func(string) string { return "" },
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortReceiptsDeterministic(t *testing.T) {
	in := []Receipt{
		{FilePath: "z", PtoVta: 1, CbteNro: 2},
		{FilePath: "a", PtoVta: 2, CbteNro: 1},
		{FilePath: "a", PtoVta: 1, CbteNro: 5},
	}
	SortReceipts(in)
	if in[0].FilePath != "a" || in[0].PtoVta != 1 || in[0].CbteNro != 5 {
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
