package winargcrs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindCRSXMLBody), "crs-xml-body"},
		{string(KindFATCAXMLBody), "fatca-xml-body"},
		{string(KindCompetentAuthoritySend), "competent-authority-transmission"},
		{string(KindAccountHolderRecord), "account-holder-record"},
		{string(KindW8BENForm), "w8ben-form"},
		{string(KindW9Form), "w9-form"},
		{string(KindAFIPRG4056Receipt), "afip-rg4056-receipt"},
		{string(RegimeCRS), "crs"},
		{string(RegimeFATCA), "fatca"},
		{string(RegimeRG4056), "rg4056"},
		{string(InstitutionInvestmentEntity), "investment-entity"},
		{string(InstitutionCustodial), "custodial-institution"},
		{string(InstitutionALYC), "aly-c-alyc"},
		{string(HolderUSPerson), "us-person"},
		{string(HolderForeignIndividual), "foreign-individual"},
		{string(HolderHighNetWorth), "high-net-worth"},
		{string(CAAFIP), "afip"},
		{string(CAIRS), "irs"},
		{string(CAHMRC), "hmrc"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"crs_body.xml",
		"fatca_body.xml",
		"ca_transmission.xml",
		"competent_authority_irs.xml",
		"account_holder_30-12345678-9.json",
		"reportable_account_2026.csv",
		"self_certification_27-11111111-4.pdf",
		"w8ben_27-11111111-4.pdf",
		"w-9_30-12345678-9.pdf",
		"balance_report_202606.csv",
		"income_report_2026.xml",
		"afip_rg4056_2025.xml",
		"afip_rg-3826_2025.xml",
		"afip_rg_4838_2025.xml",
		"afip_crs_config.json",
	}
	no := []string{"", "factura.xml", "random.bin", "report.pdf", "notes.txt"}
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
		"crs_body.xml":                         KindCRSXMLBody,
		"fatca_body.xml":                       KindFATCAXMLBody,
		"ca_transmission.xml":                  KindCompetentAuthoritySend,
		"competent_authority_irs.xml":          KindCompetentAuthoritySend,
		"account_holder_30-12345678-9.json":    KindAccountHolderRecord,
		"reportable_account_2026.csv":          KindAccountHolderRecord,
		"self_certification_27-11111111-4.pdf": KindSelfCertification,
		"w8ben_27-11111111-4.pdf":              KindW8BENForm,
		"w-9_30-12345678-9.pdf":                KindW9Form,
		"balance_report_202606.csv":            KindBalanceReport,
		"income_report_2026.xml":               KindIncomeReport,
		"afip_rg4056_2025.xml":                 KindAFIPRG4056Receipt,
		"afip_rg-3826_2025.xml":                KindAFIPRG3826Receipt,
		"afip_rg_4838_2025.xml":                KindAFIPRG4838Receipt,
		"afip_crs_config.json":                 KindCRSConfig,
		"credentials.json":                     KindCRSCredentials,
		"afip_taxit_setup.msi":                 KindInstaller,
		"":                                     KindUnknown,
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
		{"cliente 27-11111111-4", "27", "1114"},
		{"empresa 30-71234567-8", "30", "5678"},
		{"no cuit", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	cases := map[string]string{
		"balance_report_202606.csv": "202606",
		"afip_rg4056_2025.xml":      "2025",
		"crs_body.xml":              "",
	}
	for in, want := range cases {
		if got := PeriodFromFilename(in); got != want {
			t.Fatalf("PeriodFromFilename(%q)=%q want %q", in, got, want)
		}
	}
}

func TestOECDReportableCountry(t *testing.T) {
	yes := []string{"US", "UY", "BR", "CL", "ES", "PA", "KY"}
	no := []string{"", "AR", "ZZ", "XX"}
	for _, v := range yes {
		if !IsOECDReportableCountry(v) {
			t.Fatalf("expected reportable: %q", v)
		}
	}
	for _, v := range no {
		if IsOECDReportableCountry(v) {
			t.Fatalf("expected NOT reportable: %q", v)
		}
	}
}

func TestTaxHavenCountry(t *testing.T) {
	yes := []string{"PA", "KY", "VG", "LU", "LI"}
	no := []string{"", "US", "AR", "BR"}
	for _, v := range yes {
		if !IsTaxHavenCountry(v) {
			t.Fatalf("expected tax-haven: %q", v)
		}
	}
	for _, v := range no {
		if IsTaxHavenCountry(v) {
			t.Fatalf("expected NOT tax-haven: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindCRSXMLBody, KindFATCAXMLBody, KindCompetentAuthoritySend,
		KindAccountHolderRecord, KindSelfCertification,
		KindW8BENForm, KindW9Form, KindBalanceReport, KindIncomeReport,
		KindAFIPRG4056Receipt, KindAFIPRG3826Receipt, KindAFIPRG4838Receipt,
		KindCRSConfig, KindCRSCredentials,
	}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected cred kind: %q", k)
		}
	}
	for _, k := range []ArtifactKind{KindInstaller, KindOther, KindUnknown} {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT cred kind: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindCRSXMLBody,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.HasCRSXMLBody {
		t.Fatal("crs-xml-body kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + cliente = exposure")
	}
}

func TestAnnotateCrossBorderPIIRisk(t *testing.T) {
	r := Row{
		ArtifactKind:          KindAccountHolderRecord,
		ForeignTINCountryCode: "US",
		FileMode:              0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasForeignTIN {
		t.Fatal("foreign TIN country must flag")
	}
	if !r.IsCrossBorderPIIRisk {
		t.Fatal("readable + holder + foreign TIN = cross-border PII risk")
	}
}

func TestAnnotateW8BEN(t *testing.T) {
	r := Row{ArtifactKind: KindW8BENForm}
	AnnotateSecurity(&r)
	if !r.HasW8BENAttestation {
		t.Fatal("w8ben kind must flag")
	}
}

func TestAnnotateW9(t *testing.T) {
	r := Row{ArtifactKind: KindW9Form}
	AnnotateSecurity(&r)
	if !r.HasW9Attestation {
		t.Fatal("w9 kind must flag")
	}
}

func TestAnnotateInstitutionalVolume(t *testing.T) {
	r := Row{
		ArtifactKind:       KindCRSXMLBody,
		AccountHolderCount: InstitutionalAccountHolderThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasInstitutionalVolume {
		t.Fatal("> 100 holders must flag institutional volume")
	}
}

func TestAnnotateHighNetWorth(t *testing.T) {
	r := Row{
		ArtifactKind:             KindBalanceReport,
		BalanceTotalUSDThousands: HighNetWorthBalanceUSDThousands + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasHighNetWorthAccount {
		t.Fatal("> $250k USD must flag HNW")
	}
}

func TestParseCRSBody(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<crs:CRS_OECD xmlns:crs="urn:oecd:ties:crs:v2">
  <crs:CrsBody>
    <crs:AccountReport>
      <crs:AccountNumber>123-456-789</crs:AccountNumber>
      <crs:AccountHolder>
        <crs:Individual>
          <crs:ResCountryCode>US</crs:ResCountryCode>
          <crs:ResCountryCode>PA</crs:ResCountryCode>
          <crs:TIN issuedBy="US">123-45-6789</crs:TIN>
        </crs:Individual>
      </crs:AccountHolder>
      <crs:AccountBalance currCode="USD">500000.00</crs:AccountBalance>
    </crs:AccountReport>
    <crs:AccountReport>
      <crs:AccountNumber>987-654-321</crs:AccountNumber>
      <crs:AccountBalance currCode="USD">100000.00</crs:AccountBalance>
    </crs:AccountReport>
    <crs:cliente_cuit>30-71234567-8</crs:cliente_cuit>
  </crs:CrsBody>
</crs:CRS_OECD>`)
	f := ParseCRSBody(body)
	if !f.HasCRSXML {
		t.Fatal("crs xml must flag")
	}
	if f.AccountHolderCount != 2 {
		t.Fatalf("holder count=%d want 2", f.AccountHolderCount)
	}
	if f.ForeignTIN == "" {
		t.Fatal("foreign TIN must extract")
	}
	if f.ForeignTINCountryCode != "US" {
		t.Fatalf("country=%q want US", f.ForeignTINCountryCode)
	}
	if f.BalanceTotalUSDThousands != 600 {
		t.Fatalf("balance=%d want 600 (500k+100k)/1k", f.BalanceTotalUSDThousands)
	}
	if f.ReportableJurisdictions < 2 {
		t.Fatalf("juris=%d want >=2", f.ReportableJurisdictions)
	}
	if !f.HasMultiResidence {
		t.Fatal("multi-residence with PA tax haven must flag")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cuit must extract")
	}
}

func TestParseFATCABody(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<fatca:FATCA_OECD xmlns:fatca="urn:fatca:idesschemaisfa:v1.1">
  <fatca:FATCAFI>
    <fatca:AccountReport>
      <fatca:AccountNumber>US-001</fatca:AccountNumber>
      <fatca:AccountBalance currCode="USD">300000.00</fatca:AccountBalance>
    </fatca:AccountReport>
  </fatca:FATCAFI>
</fatca:FATCA_OECD>`)
	f := ParseFATCABody(body)
	if !f.HasFATCAXML {
		t.Fatal("fatca xml must flag")
	}
	if f.AccountHolderCount != 1 {
		t.Fatalf("holder count=%d", f.AccountHolderCount)
	}
	if f.BalanceTotalUSDThousands != 300 {
		t.Fatalf("balance=%d want 300", f.BalanceTotalUSDThousands)
	}
}

func TestParseCompetentAuthority(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<CA_Transmission destination="IRS">
  <Endpoint>irs.gov/idesfis</Endpoint>
</CA_Transmission>`)
	f := ParseCompetentAuthority(body)
	if f.CompetentAuthority != CAIRS {
		t.Fatalf("CA=%q want irs", f.CompetentAuthority)
	}
}

func TestParseAccountHolderJSON(t *testing.T) {
	body := []byte(`{
  "name": "Doe, John",
  "dob": "1980-05-15",
  "tin": "123-45-6789",
  "tin_country": "US",
  "balance_usd": "750000.00",
  "cliente_cuit": "27-11111111-4"
}`)
	f := ParseAccountHolder(body)
	if f.ForeignTIN == "" {
		t.Fatal("TIN must extract")
	}
	if f.ForeignTINCountryCode != "US" {
		t.Fatalf("country=%q", f.ForeignTINCountryCode)
	}
	if f.BalanceTotalUSDThousands != 750 {
		t.Fatalf("balance=%d", f.BalanceTotalUSDThousands)
	}
}

func TestParseAFIPReceipt(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<Receipt>
  <AFIP_Receipt>AFIP-20260615-001234567</AFIP_Receipt>
  <Period>2025</Period>
</Receipt>`)
	f := ParseAFIPReceipt(body)
	if f.AFIPReceiptID == "" {
		t.Fatalf("receipt id=%q", f.AFIPReceiptID)
	}
}

func TestDetectCompetentAuthority(t *testing.T) {
	cases := map[string]CompetentAuthority{
		`<dest>AFIP</dest>`:    CAAFIP,
		`<dest>IRS</dest>`:     CAIRS,
		`<dest>HMRC</dest>`:    CAHMRC,
		`<dest>ATO</dest>`:     CAATO,
		`<dest>BZSt</dest>`:    CABZSt,
		`<dest>Unknown</dest>`: CAUnknown,
	}
	for in, want := range cases {
		got := detectCompetentAuthority([]byte(in))
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyInstitution(t *testing.T) {
	if got := classifyInstitution(Row{HasAFIPFilingReceipt: true}); got != InstitutionComplianceOfficer {
		t.Fatalf("receipt -> compliance, got %q", got)
	}
	if got := classifyInstitution(Row{HasCompetentAuthority: true}); got != InstitutionComplianceOfficer {
		t.Fatalf("ca -> compliance, got %q", got)
	}
	if got := classifyInstitution(Row{HasCRSXMLBody: true}); got != InstitutionInvestmentEntity {
		t.Fatalf("crs -> investment-entity, got %q", got)
	}
	if got := classifyInstitution(Row{HasFATCAXMLBody: true}); got != InstitutionCustodial {
		t.Fatalf("fatca -> custodial, got %q", got)
	}
	if got := classifyInstitution(Row{HasAccountHolderRecord: true, ClienteCuitPrefix: "30"}); got != InstitutionALYC {
		t.Fatalf("holder+cuit -> alyc, got %q", got)
	}
	if got := classifyInstitution(Row{ArtifactKind: KindCRSConfig}); got != InstitutionAPI {
		t.Fatalf("config -> api, got %q", got)
	}
	if got := classifyInstitution(Row{}); got != InstitutionUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyAccountHolder(t *testing.T) {
	if got := classifyAccountHolder(Row{HasHighNetWorthAccount: true}); got != HolderHighNetWorth {
		t.Fatalf("hnw -> high-net-worth, got %q", got)
	}
	if got := classifyAccountHolder(Row{HasW9Attestation: true}); got != HolderUSPerson {
		t.Fatalf("w9 -> us-person, got %q", got)
	}
	if got := classifyAccountHolder(Row{HasW8BENAttestation: true, ForeignTINCountryCode: "UY"}); got != HolderForeignIndividual {
		t.Fatalf("w8ben+uy -> foreign-individual, got %q", got)
	}
	if got := classifyAccountHolder(Row{ClienteCuitPrefix: "30"}); got != HolderAREntity {
		t.Fatalf("30 -> ar-entity, got %q", got)
	}
	if got := classifyAccountHolder(Row{ClienteCuitPrefix: "27"}); got != HolderARIndividual {
		t.Fatalf("27 -> ar-individual, got %q", got)
	}
	if got := classifyAccountHolder(Row{HasForeignTIN: true, ForeignTINCountryCode: "US"}); got != HolderUSPerson {
		t.Fatalf("us tin -> us-person, got %q", got)
	}
	if got := classifyAccountHolder(Row{HasAccountHolderRecord: true}); got != HolderPassiveNFFE {
		t.Fatalf("holder -> passive-nffe, got %q", got)
	}
	if got := classifyAccountHolder(Row{}); got != HolderUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	roaming := filepath.Join(usersBase, "alice", "AppData", "Roaming", "AFIP CRS")
	yearDir := filepath.Join(roaming, "2025")
	w8Dir := filepath.Join(roaming, "w8ben")
	receiptDir := filepath.Join(roaming, "receipt")
	must(t, os.MkdirAll(yearDir, 0o755))
	must(t, os.MkdirAll(w8Dir, 0o755))
	must(t, os.MkdirAll(receiptDir, 0o755))

	crsPath := filepath.Join(yearDir, "crs_body.xml")
	must(t, os.WriteFile(crsPath, []byte(`<?xml version="1.0"?>
<crs:CRS_OECD xmlns:crs="urn:oecd:ties:crs:v2">
  <crs:CrsBody>
    <crs:AccountReport>
      <crs:AccountNumber>123</crs:AccountNumber>
      <crs:AccountHolder>
        <crs:Individual>
          <crs:ResCountryCode>US</crs:ResCountryCode>
          <crs:TIN issuedBy="US">123-45-6789</crs:TIN>
        </crs:Individual>
      </crs:AccountHolder>
      <crs:AccountBalance currCode="USD">500000.00</crs:AccountBalance>
    </crs:AccountReport>
  </crs:CrsBody>
</crs:CRS_OECD>`), 0o644))

	w8Path := filepath.Join(w8Dir, "w8ben_27-11111111-4.pdf")
	must(t, os.WriteFile(w8Path, []byte(`W-8BEN form
Name: Doe, John
TIN: 123-45-6789
Country: US
cliente_cuit: 27-11111111-4
`), 0o644))

	receiptPath := filepath.Join(receiptDir, "afip_rg4056_2025.xml")
	must(t, os.WriteFile(receiptPath, []byte(`<?xml version="1.0"?>
<Receipt>
  <afip_receipt>AFIP-2025-0001234</afip_receipt>
</Receipt>`), 0o644))

	must(t, os.WriteFile(filepath.Join(yearDir, "random.txt"),
		[]byte(`nope`), 0o644))

	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming",
		"AFIP CRS")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "crs_body.xml"),
		[]byte(`<crs:CRS_OECD/>`), 0o644))

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
		t.Fatalf("want 3 (crs+w8+receipt), got %d: %+v", len(got), got)
	}

	var crs, w8, receipt Row
	for _, r := range got {
		switch r.FilePath {
		case crsPath:
			crs = r
		case w8Path:
			w8 = r
		case receiptPath:
			receipt = r
		}
	}

	if crs.ArtifactKind != KindCRSXMLBody {
		t.Fatalf("crs kind=%q", crs.ArtifactKind)
	}
	if !crs.HasCRSXMLBody {
		t.Fatalf("crs must flag xml body: %+v", crs)
	}
	if crs.ForeignTINCountryCode != "US" {
		t.Fatalf("crs foreign TIN country=%q", crs.ForeignTINCountryCode)
	}
	if !crs.HasHighNetWorthAccount {
		t.Fatalf("crs must flag HNW (500k USD): %+v", crs)
	}
	if crs.InstitutionClass != InstitutionInvestmentEntity {
		t.Fatalf("crs should classify as investment-entity, got %q", crs.InstitutionClass)
	}
	if !crs.IsCrossBorderPIIRisk {
		t.Fatalf("crs must flag cross-border PII (holder + US TIN + readable): %+v", crs)
	}

	if w8.ArtifactKind != KindW8BENForm {
		t.Fatalf("w8 kind=%q", w8.ArtifactKind)
	}
	if !w8.HasW8BENAttestation {
		t.Fatalf("w8 must flag: %+v", w8)
	}
	if !w8.HasClienteCuit {
		t.Fatalf("w8 must flag cliente cuit: %+v", w8)
	}

	if receipt.ArtifactKind != KindAFIPRG4056Receipt {
		t.Fatalf("receipt kind=%q", receipt.ArtifactKind)
	}
	if !receipt.HasAFIPFilingReceipt {
		t.Fatalf("receipt must flag: %+v", receipt)
	}
	if receipt.InstitutionClass != InstitutionComplianceOfficer {
		t.Fatalf("receipt should classify as compliance-officer, got %q", receipt.InstitutionClass)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-crs")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "afip_crs_config.json"),
		[]byte(`{"password":"hello"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "AFIP_CRS_DIR" {
				return custom
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
	if len(got) != 1 {
		t.Fatalf("want 1 from env-override, got %d", len(got))
	}
	if !got[0].HasPasswordInConfig {
		t.Fatalf("env-override row must flag password")
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-crs"},
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
	rs := []Row{
		{FilePath: "/b", ArtifactKind: KindCRSXMLBody},
		{FilePath: "/a", ArtifactKind: KindFATCAXMLBody},
		{FilePath: "/a", ArtifactKind: KindCRSXMLBody},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindCRSXMLBody {
		t.Fatalf("sort drift: %+v", rs)
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("abc")
	b := HashSecret("ABC")
	if a != b {
		t.Fatal("hash must be case-insensitive")
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
