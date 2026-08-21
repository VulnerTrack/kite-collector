package winargallaria

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// coverClock is the FIXED clock mandated for collectors built here.
func coverClock() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }

// -- constructor / identity ---------------------------------------

func TestNewCollectorName(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
	if got := c.Name(); got != "winargallaria" {
		t.Fatalf("Name()=%q want winargallaria", got)
	}
}

func TestDefaultPathSets(t *testing.T) {
	if got := len(DefaultInstallRoots()); got != 10 {
		t.Fatalf("DefaultInstallRoots len=%d want 10", got)
	}
	if got := len(DefaultUsersBases()); got != 3 {
		t.Fatalf("DefaultUsersBases len=%d want 3", got)
	}
}

// -- classifiers / small helpers ----------------------------------

func TestIsCandidateExtBranches(t *testing.T) {
	yes := []string{
		"x.xml", "x.json", "x.ini", "x.cfg", "x.conf",
		"x.yaml", "x.yml", "x.csv", "x.tsv", "x.xlsx", "x.xls",
		"x.log", "x.txt", "x.msi", "x.exe", "x.pkg", "x.dmg", "X.JSON",
	}
	no := []string{"x.pdf", "x.docx", "noext", "", "x.zip"}
	for _, v := range yes {
		if !IsCandidateExt(v) {
			t.Fatalf("expected candidate ext: %q", v)
		}
	}
	for _, v := range no {
		if IsCandidateExt(v) {
			t.Fatalf("expected NOT candidate ext: %q", v)
		}
	}
}

func TestMatriculaFromTextBranches(t *testing.T) {
	if got := MatriculaFromText("matricula: 117"); got != "117" {
		t.Fatalf("matricula=%q want 117", got)
	}
	if got := MatriculaFromText("<matricula>200</matricula>"); got != "200" {
		t.Fatalf("xml matricula=%q want 200", got)
	}
	if got := MatriculaFromText("no matricula token here"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestHashSecretEmpty(t *testing.T) {
	if got := HashSecret(""); got != "" {
		t.Fatalf("empty secret must hash empty, got %q", got)
	}
	if got := HashSecret("   "); got != "" {
		t.Fatalf("whitespace secret must hash empty, got %q", got)
	}
	if got := HashSecret("Token"); len(got) != 64 {
		t.Fatalf("non-empty secret hash len=%d", len(got))
	}
}

func TestMax64BothArms(t *testing.T) {
	if got := max64(7, 3); got != 7 {
		t.Fatalf("max64(7,3)=%d want 7", got)
	}
	if got := max64(2, 9); got != 9 {
		t.Fatalf("max64(2,9)=%d want 9", got)
	}
	if got := max64(4, 4); got != 4 {
		t.Fatalf("max64(4,4)=%d want 4", got)
	}
}

func TestDecimalToCents(t *testing.T) {
	cases := map[string]int64{
		"":             0,
		"   ":          0,
		"0":            0,
		"1234":         123400,
		"1234.56":      123456,
		"1234,56":      123456,
		"1.234,56":     123456,
		"1.234.567,89": 123456789,
		"1.500":        150, // single dot treated as decimal
		"-5.00":        0,
		"abc":          0,
		"  2500.00  ":  250000,
		"1000000.00":   100000000,
	}
	for in, want := range cases {
		if got := decimalToCents(in); got != want {
			t.Fatalf("decimalToCents(%q)=%d want %d", in, got, want)
		}
	}
}

func TestCsvDataRowCount(t *testing.T) {
	if got := csvDataRowCount(nil); got != 0 {
		t.Fatalf("nil=%d want 0", got)
	}
	if got := csvDataRowCount([]byte("no_delimiter_header_line")); got != 0 {
		t.Fatalf("no-delim=%d want 0", got)
	}
	// Delimited but header not block/bloque/trade shaped.
	if got := csvDataRowCount([]byte("foo,bar\n1,2\n3,4\n")); got != 0 {
		t.Fatalf("non-block header=%d want 0", got)
	}
	// Block-shaped header, empty line skipped.
	body := []byte("block_id,notional_usd\n1,100\n\n2,200\n3,300\n")
	if got := csvDataRowCount(body); got != 3 {
		t.Fatalf("block csv=%d want 3", got)
	}
	// "trade" token also qualifies as a block-trade shaped header.
	if got := csvDataRowCount([]byte("trade_id,x\nA,1\nB,2\n")); got != 2 {
		t.Fatalf("trade csv=%d want 2", got)
	}
}

func TestCountBlockTradesCSVAware(t *testing.T) {
	// CSV path.
	csv := []byte("block_id,notional_usd\n1,100\n2,200\n3,300\n")
	if got := countBlockTradesCSVAware(csv); got != 3 {
		t.Fatalf("csv path=%d want 3", got)
	}
	// Regex per-row entry path (spaces only, no CSV delimiter).
	entries := []byte("trade_id X block_id Y operacion_id Z bloque_id W")
	if got := countBlockTradesCSVAware(entries); got != 4 {
		t.Fatalf("entry path=%d want 4", got)
	}
	// Marker fallback path (no id entries, but a block-trade marker).
	if got := countBlockTradesCSVAware([]byte("off-book pre-arranged execution")); got != 1 {
		t.Fatalf("marker path=%d want 1", got)
	}
	// Nothing at all.
	if got := countBlockTradesCSVAware([]byte("nothing interesting here")); got != 0 {
		t.Fatalf("none=%d want 0", got)
	}
}

func TestMaxUSDAmountRegexPath(t *testing.T) {
	// Non-CSV body → regex path chooses the peak row.
	body := []byte("importe_usd=1000.00\nimporte_usd=3000.50\nimporte_usd=2000.00\n")
	if got := maxUSDAmount(body); got != 300050 {
		t.Fatalf("maxUSDAmount=%d want 300050", got)
	}
	if got := sumUSDAmounts(body); got != 600050 {
		t.Fatalf("sumUSDAmounts=%d want 600050", got)
	}
	// Malformed / no amounts → zero.
	if got := maxUSDAmount([]byte("no amounts here")); got != 0 {
		t.Fatalf("maxUSDAmount(none)=%d want 0", got)
	}
}

func TestCollectSymbolsBothForms(t *testing.T) {
	// INI/JSON `symbol=` form + XML `<ticker>` form, deduplicated,
	// uppercased.
	body := []byte("symbol=tx26\nticker=al30\n<especie>TX26</especie>\n")
	syms := collectSymbols(body)
	if len(syms) != 2 {
		t.Fatalf("distinct symbols=%d want 2: %v", len(syms), syms)
	}
	seen := map[string]bool{}
	for _, s := range syms {
		seen[s] = true
	}
	if !seen["TX26"] || !seen["AL30"] {
		t.Fatalf("symbols=%v want TX26+AL30", syms)
	}
}

// -- Parse* exact-value coverage ----------------------------------

func TestParseAllariaPositionsExact(t *testing.T) {
	body := []byte("symbol=TX26\nsymbol=AL30\nvalor_usd=1000000.00\n" +
		"cliente_cuit=30-71234567-8\n")
	f := ParseAllariaPositions(body)
	if f.DistinctSymbols != 2 {
		t.Fatalf("distinct=%d want 2", f.DistinctSymbols)
	}
	if f.CERUVAPositionCount != 1 {
		t.Fatalf("ceruva=%d want 1 (TX26)", f.CERUVAPositionCount)
	}
	if f.LetrasPositionCount != 2 {
		t.Fatalf("letras=%d want 2 (TX26,AL30)", f.LetrasPositionCount)
	}
	if f.PortfolioAUMUSDCents != 100000000 {
		t.Fatalf("aum=%d want 100000000", f.PortfolioAUMUSDCents)
	}
	if f.ClienteCuitRaw != "30-71234567-8" {
		t.Fatalf("cuit=%q", f.ClienteCuitRaw)
	}
	// Orders delegates to Positions → identical output.
	if ParseAllariaOrders(body) != f {
		t.Fatal("ParseAllariaOrders must equal ParseAllariaPositions")
	}
}

func TestParseAllariaPositionsEmpty(t *testing.T) {
	if f := ParseAllariaPositions(nil); f.DistinctSymbols != 0 {
		t.Fatalf("empty positions non-zero: %+v", f)
	}
	if f := ParseAllariaOrders(nil); f.DistinctSymbols != 0 {
		t.Fatalf("empty orders non-zero: %+v", f)
	}
}

func TestParseAllariaCustodyReportExact(t *testing.T) {
	body := []byte("<custody_report>" +
		"<matricula>117</matricula>" +
		"<symbol>TX26</symbol>" +
		"<symbol>GD30</symbol>" +
		"<cliente_cuit>27-11111111-4</cliente_cuit>" +
		"</custody_report>")
	f := ParseAllariaCustodyReport(body)
	if f.BrokerMatricula != "117" {
		t.Fatalf("matricula=%q want 117", f.BrokerMatricula)
	}
	if f.DistinctSymbols != 2 {
		t.Fatalf("distinct=%d want 2", f.DistinctSymbols)
	}
	if f.CERUVAPositionCount != 1 {
		t.Fatalf("ceruva=%d want 1 (TX26)", f.CERUVAPositionCount)
	}
	if f.LetrasPositionCount != 2 {
		t.Fatalf("letras=%d want 2 (TX26,GD30)", f.LetrasPositionCount)
	}
	if f.ClienteCuitRaw != "27-11111111-4" {
		t.Fatalf("cuit=%q want 27-11111111-4", f.ClienteCuitRaw)
	}
	if f.PortfolioAUMUSDCents != 0 {
		t.Fatalf("aum=%d want 0 (xml usd not summed)", f.PortfolioAUMUSDCents)
	}
}

func TestParseAllariaCustodyReportEmpty(t *testing.T) {
	if f := ParseAllariaCustodyReport(nil); f.DistinctSymbols != 0 {
		t.Fatalf("empty custody report non-zero: %+v", f)
	}
}

func TestParseAllariaCredentialsINIForm(t *testing.T) {
	body := []byte("access_token=aBcDeFgHiJkLmNoPqRsTuVwX12345\n" +
		"username=bob@allaria.com.ar\n" +
		"password=secret\n" +
		"matricula=200\n" +
		"cliente_cuit=27-11111111-4\n")
	f := ParseAllariaCredentials(body)
	if f.BearerToken != "aBcDeFgHiJkLmNoPqRsTuVwX12345" {
		t.Fatalf("bearer=%q", f.BearerToken)
	}
	if f.Username != "bob@allaria.com.ar" {
		t.Fatalf("username=%q", f.Username)
	}
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.BrokerMatricula != "200" {
		t.Fatalf("matricula=%q want 200", f.BrokerMatricula)
	}
	if f.ClienteCuitRaw != "27-11111111-4" {
		t.Fatalf("cuit=%q", f.ClienteCuitRaw)
	}
}

func TestParseAllariaCredentialsNoSecrets(t *testing.T) {
	// Non-empty body with none of the tokens → every extractor
	// returns its empty branch.
	f := ParseAllariaCredentials([]byte("just some plain text without markers"))
	if f.BearerToken != "" {
		t.Fatalf("bearer=%q want empty", f.BearerToken)
	}
	if f.Username != "" {
		t.Fatalf("username=%q want empty", f.Username)
	}
	if f.HasPassword {
		t.Fatal("must not flag password")
	}
	if f.ClienteCuitRaw != "" {
		t.Fatalf("cuit=%q want empty", f.ClienteCuitRaw)
	}
	if f.BrokerMatricula != "" {
		t.Fatalf("matricula=%q want empty", f.BrokerMatricula)
	}
}

func TestParseAllariaCustodyReconMarkerFallback(t *testing.T) {
	// No recon_id / fci_id entries, but a depositaria marker → 1.
	body := []byte("<recon><sociedad_depositaria>Allaria Ledesma" +
		"</sociedad_depositaria></recon>")
	f := ParseAllariaCustodyRecon(body)
	if f.FCICustodyReconCount != 1 {
		t.Fatalf("recon count=%d want 1 (marker fallback)", f.FCICustodyReconCount)
	}
}

func TestParseAllariaCustodyReconEmpty(t *testing.T) {
	if f := ParseAllariaCustodyRecon(nil); f.FCICustodyReconCount != 0 {
		t.Fatalf("empty recon non-zero: %+v", f)
	}
}

func TestParseAllariaSSNHoldingsBareTokenFallback(t *testing.T) {
	// No `<symbol>` tags — letras/CER stems appear only as bare
	// tokens, exercising the scanLetrasPresence / scanCERUVAPresence
	// fallbacks.
	body := []byte("<holdings><aseguradora>La Caja</aseguradora>" +
		"cartera incluye LECAP y TX26 tokens</holdings>")
	f := ParseAllariaSSNHoldings(body)
	// "aseguradora" appears in both the opening and closing XML tags.
	if f.InsuranceCount != 2 {
		t.Fatalf("insurance=%d want 2", f.InsuranceCount)
	}
	if f.LetrasPositionCount != 2 {
		t.Fatalf("letras=%d want 2 (LECAP,TX26)", f.LetrasPositionCount)
	}
	if f.CERUVAPositionCount != 1 {
		t.Fatalf("ceruva=%d want 1 (TX26)", f.CERUVAPositionCount)
	}
}

func TestParseAllariaSSNHoldingsEmpty(t *testing.T) {
	if f := ParseAllariaSSNHoldings(nil); f.InsuranceCount != 0 {
		t.Fatalf("empty ssn non-zero: %+v", f)
	}
}

func TestParseAllariaANSeSFlowsWithCuit(t *testing.T) {
	body := []byte("anses cliente_cuit=30-71234567-8 LECAP " +
		"importe_usd=10000000.00")
	f := ParseAllariaANSeSFlows(body)
	if f.PensionFundCount != 1 {
		t.Fatalf("pension=%d want 1", f.PensionFundCount)
	}
	if f.LetrasPositionCount != 1 {
		t.Fatalf("letras=%d want 1 (LECAP)", f.LetrasPositionCount)
	}
	if f.CERUVAPositionCount != 0 {
		t.Fatalf("ceruva=%d want 0", f.CERUVAPositionCount)
	}
	if f.PortfolioAUMUSDCents != 1000000000 {
		t.Fatalf("aum=%d want 1000000000", f.PortfolioAUMUSDCents)
	}
	if f.ClienteCuitRaw != "30-71234567-8" {
		t.Fatalf("cuit=%q", f.ClienteCuitRaw)
	}
}

func TestParseAllariaANSeSFlowsEmpty(t *testing.T) {
	if f := ParseAllariaANSeSFlows(nil); f.PensionFundCount != 0 {
		t.Fatalf("empty anses non-zero: %+v", f)
	}
}

// -- SortRows tie-break on period ---------------------------------

func TestSortRowsPeriodTieBreak(t *testing.T) {
	in := []Row{
		{FilePath: "a", ArtifactKind: KindConfig, PeriodYYYYMM: "202508"},
		{FilePath: "a", ArtifactKind: KindConfig, PeriodYYYYMM: "202501"},
	}
	SortRows(in)
	if in[0].PeriodYYYYMM != "202501" {
		t.Fatalf("earlier period must sort first: %+v", in)
	}
}

// -- ownerUID non-Stat_t branch -----------------------------------

type fakeFileInfo struct{}

func (fakeFileInfo) Name() string       { return "fake" }
func (fakeFileInfo) Size() int64        { return 0 }
func (fakeFileInfo) Mode() os.FileMode  { return 0o644 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool        { return false }
func (fakeFileInfo) Sys() any           { return nil }

func TestOwnerUIDNonStat(t *testing.T) {
	if got := ownerUID(fakeFileInfo{}); got != 0 {
		t.Fatalf("ownerUID(non-Stat_t)=%d want 0", got)
	}
}

// -- collector: mergeFields switch arms + skipBody + KindOther ----

func TestCollectorMergeFieldsAllKinds(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Allaria")
	must(t, os.MkdirAll(root, 0o755))

	write := func(name, body string) string {
		p := filepath.Join(root, name)
		must(t, os.WriteFile(p, []byte(body), 0o644))
		return p
	}

	posPath := write("allaria_positions_202506.json",
		"symbol=TX26\nsymbol=AL30\nvalor_usd=1000000.00\ncliente_cuit=30-71234567-8\n")
	ordPath := write("allaria_orders_202506.json",
		"symbol=GD30\nimporte_usd=2000000.00\n")
	credPath := write("allaria_credentials.json",
		"access_token=aBcDeFgHiJkLmNoPqRsTuVwX12345\nusername=bob@allaria.com.ar\npassword=secret\nmatricula=200\n")
	repPath := write("custody_report_202506.xml",
		"<custody_report><matricula>117</matricula><symbol>TX26</symbol><symbol>GD30</symbol><cliente_cuit>27-11111111-4</cliente_cuit></custody_report>")
	ssnPath := write("ssn_holdings_202506.xml",
		"<holdings><aseguradora>La Caja</aseguradora><symbol>TX26</symbol></holdings>")
	msiPath := write("allaria_installer.msi", "MZ fake installer binary payload")
	otherPath := write("allaria_notes.txt", "just notes about allaria nothing structured")

	c := &fileCollector{
		installRoots: []string{root},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          coverClock,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 7 {
		t.Fatalf("want 7 rows, got %d", len(got))
	}
	by := map[string]Row{}
	for _, r := range got {
		by[r.FilePath] = r
	}

	pos := by[posPath]
	if pos.ArtifactKind != KindPositionsCache {
		t.Fatalf("pos kind=%q", pos.ArtifactKind)
	}
	if pos.DistinctSymbolsCount != 2 || pos.CERUVAPositionCount != 1 ||
		pos.LetrasPositionCount != 2 {
		t.Fatalf("pos counts: %+v", pos)
	}
	if pos.PortfolioAUMUSDCents != 100000000 {
		t.Fatalf("pos aum=%d want 100000000", pos.PortfolioAUMUSDCents)
	}
	if pos.ClienteCuitPrefix != "30" || pos.ClienteCuitSuffix4 != "5678" {
		t.Fatalf("pos cuit=(%q,%q)", pos.ClienteCuitPrefix, pos.ClienteCuitSuffix4)
	}
	if !pos.HasCERUVAHoldings || !pos.HasLetrasTesoro {
		t.Fatalf("pos flags: %+v", pos)
	}

	ord := by[ordPath]
	if ord.ArtifactKind != KindOrdersCache {
		t.Fatalf("ord kind=%q", ord.ArtifactKind)
	}
	if ord.PortfolioAUMUSDCents != 200000000 {
		t.Fatalf("ord aum=%d want 200000000", ord.PortfolioAUMUSDCents)
	}
	if ord.LetrasPositionCount != 1 {
		t.Fatalf("ord letras=%d want 1 (GD30)", ord.LetrasPositionCount)
	}

	cred := by[credPath]
	if cred.ArtifactKind != KindCredentials {
		t.Fatalf("cred kind=%q", cred.ArtifactKind)
	}
	if !cred.HasBearerToken || cred.BearerTokenHash == "" {
		t.Fatalf("cred must flag bearer: %+v", cred)
	}
	if !cred.HasPasswordInConfig || cred.UsernameHash == "" {
		t.Fatalf("cred password/username: %+v", cred)
	}
	if cred.BrokerMatricula != "200" {
		t.Fatalf("cred matricula=%q", cred.BrokerMatricula)
	}

	rep := by[repPath]
	if rep.ArtifactKind != KindCustodyReport {
		t.Fatalf("rep kind=%q", rep.ArtifactKind)
	}
	if rep.BrokerMatricula != "117" {
		t.Fatalf("rep matricula=%q", rep.BrokerMatricula)
	}
	if !rep.HasCustodyBankRole {
		t.Fatalf("custody-report implies custody-bank role: %+v", rep)
	}
	if rep.AccountClass != AccountFCIManager {
		t.Fatalf("rep account=%q want fci-manager", rep.AccountClass)
	}

	ssn := by[ssnPath]
	if ssn.ArtifactKind != KindSSNHoldings {
		t.Fatalf("ssn kind=%q", ssn.ArtifactKind)
	}
	if !ssn.HasInsuranceAccount {
		t.Fatalf("ssn must flag insurance: %+v", ssn)
	}
	if ssn.AccountClass != AccountInsurance {
		t.Fatalf("ssn account=%q want insurance", ssn.AccountClass)
	}

	msi := by[msiPath]
	if msi.ArtifactKind != KindInstaller {
		t.Fatalf("msi kind=%q", msi.ArtifactKind)
	}
	if msi.FileHash == "" {
		t.Fatal("installer hash-only path must populate hash")
	}
	if msi.HasBearerToken || msi.BrokerMatricula != "" {
		t.Fatalf("installer must not parse fields: %+v", msi)
	}

	other := by[otherPath]
	if other.ArtifactKind != KindOther {
		t.Fatalf("other kind=%q", other.ArtifactKind)
	}
	if other.FileHash == "" {
		t.Fatal("other kind still hashed")
	}
	if other.AccountClass != AccountUnknown {
		t.Fatalf("other account=%q want unknown", other.AccountClass)
	}
}

// -- collector: consider dedup / stat error / read error ----------

func TestCollectorDedupSameRootTwice(t *testing.T) {
	tmp := t.TempDir()
	must(t, os.WriteFile(filepath.Join(tmp, "allaria_config.xml"),
		[]byte("<Allaria><matricula>117</matricula></Allaria>"), 0o644))
	c := &fileCollector{
		installRoots: []string{tmp, tmp}, // same dir twice → dedup path
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          coverClock,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("dedup: want 1 row, got %d", len(got))
	}
}

func TestCollectorStatError(t *testing.T) {
	tmp := t.TempDir()
	must(t, os.WriteFile(filepath.Join(tmp, "allaria_config.xml"),
		[]byte("<Allaria/>"), 0o644))
	c := &fileCollector{
		installRoots: []string{tmp},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     func(string) (os.FileInfo, error) { return nil, errors.New("stat boom") },
		now:          coverClock,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("stat error must drop row, got %d", len(got))
	}
}

func TestCollectorReadFileError(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "allaria_config.xml")
	must(t, os.WriteFile(p, []byte("<Allaria><matricula>117</matricula></Allaria>"), 0o644))
	c := &fileCollector{
		installRoots: []string{tmp},
		getenv:       func(string) string { return "" },
		readFile:     func(string) ([]byte, error) { return nil, errors.New("read boom") },
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          coverClock,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 row, got %d", len(got))
	}
	if got[0].ArtifactKind != KindConfig {
		t.Fatalf("kind=%q", got[0].ArtifactKind)
	}
	if got[0].FileHash != "" {
		t.Fatalf("read error must leave hash empty, got %q", got[0].FileHash)
	}
	if got[0].BrokerMatricula != "" {
		t.Fatalf("read error must skip mergeFields, matricula=%q", got[0].BrokerMatricula)
	}
}

// -- collector: ALINVEST_DIR env override -------------------------

func TestCollectorRespectsAlinvestEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "alinvest-home")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "alinvest_settings.json"),
		[]byte(`{"matricula":"117"}`), 0o644))
	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "ALINVEST_DIR" {
				return envDir
			}
			return ""
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
		now:      coverClock,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || got[0].ArtifactKind != KindConfig {
		t.Fatalf("alinvest env: %+v", got)
	}
}

// -- collector: walk depth guard ----------------------------------

func TestCollectorWalkDepthGuard(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Allaria")
	// f is at depth 6 (processed); g is at depth 7 (skipped).
	deepF := filepath.Join(root, "a", "b", "c", "d", "e", "f")
	deepG := filepath.Join(deepF, "g")
	must(t, os.MkdirAll(deepG, 0o755))
	must(t, os.WriteFile(filepath.Join(deepF, "allaria_config.xml"),
		[]byte("<Allaria/>"), 0o644))
	must(t, os.WriteFile(filepath.Join(deepG, "allaria_config.xml"),
		[]byte("<Allaria/>"), 0o644))
	c := &fileCollector{
		installRoots: []string{root},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          coverClock,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("depth guard: want 1 (f only), got %d", len(got))
	}
	if got[0].FilePath != filepath.Join(deepF, "allaria_config.xml") {
		t.Fatalf("unexpected collected path %q", got[0].FilePath)
	}
}
