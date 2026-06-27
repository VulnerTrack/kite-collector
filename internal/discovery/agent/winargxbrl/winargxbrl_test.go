package winargxbrl

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(FilingXBRLInstance), "xbrl-instance"},
		{string(FilingXBRLSchema), "xbrl-schema"},
		{string(FilingXBRLLinkbase), "xbrl-linkbase"},
		{string(FilingXBRLZip), "xbrl-zip"},
		{string(FilingUnknown), "unknown"},
		{string(TaxonomyCNVAIF), "cnv-aif"},
		{string(TaxonomyIGJ), "igj"},
		{string(TaxonomyIFRS), "ifrs"},
		{string(TaxonomyARIFRS), "ar-ifrs"},
		{string(TaxonomyUSGAAP), "us-gaap"},
		{string(TaxonomyOther), "other"},
		{string(TaxonomyUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("xbrl"))
	b := HashContents([]byte("xbrl"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"30712345678", "30", "5678"},
		{"30-71234567-8", "30", "5678"},
		{"20-12345678-9", "20", "6789"},
		{"", "", ""},
		{"123", "", ""},
		{"11111111111", "", ""}, // invalid prefix
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestCurrencyFromMeasure(t *testing.T) {
	cases := map[string]string{
		"iso4217:ARS":  "ARS",
		"iso4217:USD":  "USD",
		"iso4217:EUR":  "EUR",
		"ARS":          "ARS",
		"":             "",
		"iso4217:XYZ1": "",
		"shares":       "",
	}
	for in, want := range cases {
		if got := CurrencyFromMeasure(in); got != want {
			t.Fatalf("CurrencyFromMeasure(%q)=%q want %q", in, got, want)
		}
	}
}

func TestTaxonomyLabelFromSchemaRef(t *testing.T) {
	cases := map[string]TaxonomyLabel{
		"https://aif.cnv.gov.ar/taxonomy/2024/cnv-aif.xsd":    TaxonomyCNVAIF,
		"https://www.cnv.gov.ar/xbrl/taxonomy.xsd":            TaxonomyCNVAIF,
		"https://igj.gov.ar/xbrl/igj.xsd":                     TaxonomyIGJ,
		"https://xbrl.ifrs.org/taxonomy/2021/full_ifrs.xsd":   TaxonomyIFRS,
		"https://fasb.org/us-gaap/2024/elts/us-gaap-2024.xsd": TaxonomyUSGAAP,
		"https://example.com/random.xsd":                      TaxonomyOther,
		"":                                                    TaxonomyUnknown,
	}
	for in, want := range cases {
		if got := TaxonomyLabelFromSchemaRef(in); got != want {
			t.Fatalf("TaxonomyLabelFromSchemaRef(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyByExtension(t *testing.T) {
	cases := map[string]FilingKind{
		"a.xbrl": FilingXBRLInstance,
		"a.xsd":  FilingXBRLSchema,
		"a.zip":  FilingXBRLZip,
		"a.xml":  FilingUnknown,
		"a.bin":  FilingUnknown,
	}
	for in, want := range cases {
		if got := ClassifyByExtension(in); got != want {
			t.Fatalf("ClassifyByExtension(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsXBRLCandidatePath(t *testing.T) {
	yes := []string{
		"/home/alice/xbrl/2024/acme.xbrl",
		"/home/bob/Documents/CNV/balance.xbrl",
		"/srv/aif/igj/consolid-2025.xml",
		"/home/u/estados-contables/eecc-2024.xml",
	}
	no := []string{
		"/home/alice/Documents/random.xml",
		"",
	}
	for _, v := range yes {
		if !IsXBRLCandidatePath(v) {
			t.Fatalf("expected candidate: %q", v)
		}
	}
	for _, v := range no {
		if IsXBRLCandidatePath(v) {
			t.Fatalf("expected NOT candidate: %q", v)
		}
	}
}

func TestTruncateDenominacion(t *testing.T) {
	short := "ACME S.A."
	if TruncateDenominacion(short) != short {
		t.Fatal("short must pass through")
	}
	long := strings.Repeat("a", 200)
	got := TruncateDenominacion(long)
	if len(got) != MaxDenominationChars {
		t.Fatalf("len=%d want %d", len(got), MaxDenominationChars)
	}
}

// -- AnnotateSecurity branches -------------------------------------

func TestAnnotateCNVListed(t *testing.T) {
	f := Filing{
		FilingKind:        FilingXBRLInstance,
		TaxonomyLabel:     TaxonomyCNVAIF,
		ReportingCurrency: "ARS",
		FilePath:          "/home/a/xbrl/acme.xbrl",
		FileMode:          0o600,
	}
	AnnotateSecurity(&f)
	if !f.IsCnvPubliclyListed {
		t.Fatal("CNV taxonomy must flag publicly-listed")
	}
	if f.IsForeignCurrencyFacts || f.IsCredentialExposureRisk {
		t.Fatalf("ARS + 0o600 must NOT flag: %+v", f)
	}
}

func TestAnnotateForeignAndExposure(t *testing.T) {
	f := Filing{
		FilingKind:        FilingXBRLInstance,
		ReportingCurrency: "USD",
		FilePath:          "/home/a/xbrl/eecc-consolid-acme.xbrl",
		FileMode:          0o644,
	}
	AnnotateSecurity(&f)
	if !f.IsForeignCurrencyFacts {
		t.Fatal("USD must flag foreign currency")
	}
	if !f.IsConsolidatedStatement {
		t.Fatal("path containing 'consolid' must flag consolidated")
	}
	if !f.IsCredentialExposureRisk {
		t.Fatal("XBRL + world-readable must flag exposure")
	}
}

// -- ParseXBRLInstance ---------------------------------------------

func TestParseXBRLInstanceTypical(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<xbrli:xbrl
  xmlns:xbrli="http://www.xbrl.org/2003/instance"
  xmlns:link="http://www.xbrl.org/2003/linkbase"
  xmlns:xlink="http://www.w3.org/1999/xlink"
  xmlns:ar-ifrs="https://aif.cnv.gov.ar/taxonomy/2024/ar-ifrs"
  xmlns:iso4217="http://www.xbrl.org/2003/iso4217">
  <link:schemaRef xlink:href="https://aif.cnv.gov.ar/taxonomy/2024/cnv-aif.xsd"/>
  <xbrli:context id="C-2025">
    <xbrli:entity>
      <xbrli:identifier scheme="http://www.cnv.gov.ar/cuit">30-71234567-8</xbrli:identifier>
    </xbrli:entity>
    <xbrli:period>
      <xbrli:startDate>2025-01-01</xbrli:startDate>
      <xbrli:endDate>2025-12-31</xbrli:endDate>
    </xbrli:period>
  </xbrli:context>
  <xbrli:unit id="U-ARS">
    <xbrli:measure>iso4217:ARS</xbrli:measure>
  </xbrli:unit>
  <ar-ifrs:EntityRegistrantName contextRef="C-2025">ACME S.A.</ar-ifrs:EntityRegistrantName>
  <ar-ifrs:Equity contextRef="C-2025" unitRef="U-ARS" decimals="0">1000000</ar-ifrs:Equity>
</xbrli:xbrl>`)
	f, ok := ParseXBRLInstance(body)
	if !ok {
		t.Fatal("typical XBRL must parse")
	}
	if f.FilingKind != FilingXBRLInstance {
		t.Fatalf("kind=%q", f.FilingKind)
	}
	if f.TaxonomyLabel != TaxonomyCNVAIF {
		t.Fatalf("taxonomy=%q", f.TaxonomyLabel)
	}
	if f.EntityCuitPrefix != "30" || f.EntityCuitSuffix4 != "5678" {
		t.Fatalf("cuit: %+v", f)
	}
	if f.PeriodStart != "2025-01-01" || f.PeriodEnd != "2025-12-31" {
		t.Fatalf("period: %+v", f)
	}
	if f.ReportingCurrency != "ARS" {
		t.Fatalf("currency=%q", f.ReportingCurrency)
	}
	if f.EntityDenominacion != "ACME S.A." {
		t.Fatalf("denom=%q", f.EntityDenominacion)
	}
	if f.FactCount < 2 {
		t.Fatalf("factCount=%d want >=2 (EntityRegistrantName + Equity)", f.FactCount)
	}
}

func TestParseXBRLInstanceRejectsNonXBRL(t *testing.T) {
	body := []byte(`<root><x/></root>`)
	if _, ok := ParseXBRLInstance(body); ok {
		t.Fatal("non-xbrl must NOT parse")
	}
}

func TestParseXBRLInstanceBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte(`<xbrli:xbrl xmlns:xbrli="http://www.xbrl.org/2003/instance"></xbrli:xbrl>`)...)
	if _, ok := ParseXBRLInstance(body); !ok {
		t.Fatal("BOM must be tolerated")
	}
}

// -- collector end-to-end -----------------------------------------

func TestFileCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")

	aliceDir := filepath.Join(usersBase, "alice", "Documents", "xbrl")
	must(t, os.MkdirAll(aliceDir, 0o755))

	cnvPath := filepath.Join(aliceDir, "acme-2025.xbrl")
	must(t, os.WriteFile(cnvPath, []byte(`<xbrli:xbrl
  xmlns:xbrli="http://www.xbrl.org/2003/instance"
  xmlns:link="http://www.xbrl.org/2003/linkbase"
  xmlns:xlink="http://www.w3.org/1999/xlink">
  <link:schemaRef xlink:href="https://aif.cnv.gov.ar/cnv-aif.xsd"/>
  <xbrli:context id="C-2025">
    <xbrli:entity>
      <xbrli:identifier scheme="http://www.cnv.gov.ar/cuit">30712345678</xbrli:identifier>
    </xbrli:entity>
    <xbrli:period>
      <xbrli:startDate>2025-01-01</xbrli:startDate>
      <xbrli:endDate>2025-12-31</xbrli:endDate>
    </xbrli:period>
  </xbrli:context>
  <xbrli:unit id="U-USD"><xbrli:measure>iso4217:USD</xbrli:measure></xbrli:unit>
</xbrli:xbrl>`), 0o644))

	// Public profile must be skipped.
	pubDir := filepath.Join(usersBase, "Public", "xbrl")
	must(t, os.MkdirAll(pubDir, 0o755))
	must(t, os.WriteFile(filepath.Join(pubDir, "skip.xbrl"),
		[]byte(`<xbrli:xbrl xmlns:xbrli="http://www.xbrl.org/2003/instance"/>`), 0o644))

	// bob has an unrelated XML — must be ignored (not under xbrl/ path).
	bobDir := filepath.Join(usersBase, "bob", "Documents")
	must(t, os.MkdirAll(bobDir, 0o755))
	must(t, os.WriteFile(filepath.Join(bobDir, "notes.xml"),
		[]byte(`<root><x/></root>`), 0o644))

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
	if len(got) != 1 {
		t.Fatalf("want 1 (alice CNV), got %d: %+v", len(got), got)
	}
	a := got[0]
	if a.FilePath != cnvPath {
		t.Fatalf("path=%q", a.FilePath)
	}
	if !a.IsCnvPubliclyListed {
		t.Fatalf("CNV schema must flag publicly listed: %+v", a)
	}
	if !a.IsForeignCurrencyFacts {
		t.Fatalf("USD measure must flag foreign currency: %+v", a)
	}
	if !a.IsCredentialExposureRisk {
		t.Fatalf("0o644 + XBRL must flag exposure: %+v", a)
	}
	if a.EntityCuitPrefix != "30" || a.EntityCuitSuffix4 != "5678" {
		t.Fatalf("alice cuit: %+v", a)
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

func TestSortFilingsDeterministic(t *testing.T) {
	in := []Filing{
		{FilePath: "z", EntityCuitPrefix: "30", PeriodEnd: "2024"},
		{FilePath: "a", EntityCuitPrefix: "30", PeriodEnd: "2025"},
		{FilePath: "a", EntityCuitPrefix: "20", PeriodEnd: "2025"},
	}
	SortFilings(in)
	if in[0].FilePath != "a" || in[0].EntityCuitPrefix != "20" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
