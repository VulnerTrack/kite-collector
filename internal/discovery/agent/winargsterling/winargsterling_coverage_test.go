package winargsterling

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixedClock at 2026-06-16 UTC — matches the reference collectors.
func fixedClock() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }

// newStCollector wires a collector to injectable functions with
// hermetic defaults (fixed clock, no env).
func newStCollector(installRoots, usersBases []string) *fileCollector {
	return &fileCollector{
		installRoots: installRoots,
		usersBases:   usersBases,
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          fixedClock,
	}
}

// fakeInfo is an os.FileInfo whose Sys() is caller-controlled, used
// to drive the ownerUID non-syscall fallback.
type fakeInfo struct {
	sys any
}

func (fakeInfo) Name() string       { return "fake" }
func (fakeInfo) Size() int64        { return 0 }
func (fakeInfo) Mode() os.FileMode  { return 0o644 }
func (fakeInfo) ModTime() time.Time { return time.Time{} }
func (fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any         { return f.sys }

// -- constructor / identity ---------------------------------------

func TestCovNewCollectorName(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
	if got := c.Name(); got != "winargsterling" {
		t.Fatalf("Name()=%q want winargsterling", got)
	}
}

func TestCovDefaultPathSets(t *testing.T) {
	if got := len(DefaultInstallRoots()); got != 6 {
		t.Fatalf("install roots=%d want 6", got)
	}
	if got := len(DefaultUsersBases()); got != 3 {
		t.Fatalf("users bases=%d want 3", got)
	}
}

// -- constants ----------------------------------------------------

func TestCovConstants(t *testing.T) {
	if MaxRows != 16384 {
		t.Fatalf("MaxRows=%d want 16384", MaxRows)
	}
	if MaxFileBytes != 16<<20 {
		t.Fatalf("MaxFileBytes=%d want %d", MaxFileBytes, 16<<20)
	}
	if RecentlyWindow != 90*24*time.Hour {
		t.Fatalf("RecentlyWindow=%v", RecentlyWindow)
	}
	if HighVolumeTraderDailyFills != 1000 {
		t.Fatalf("HighVolumeTraderDailyFills=%d", HighVolumeTraderDailyFills)
	}
	if PatternDayTraderDailyFills != 4 {
		t.Fatalf("PatternDayTraderDailyFills=%d", PatternDayTraderDailyFills)
	}
	if MaxWalkDepth != 6 {
		t.Fatalf("MaxWalkDepth=%d want 6", MaxWalkDepth)
	}
}

// -- classifiers --------------------------------------------------

func TestCovIsCandidateExt(t *testing.T) {
	yes := []string{"x.cfg", "layout.STX", "X.CSV", "a.log", "b.msi", "c.exe"}
	no := []string{"file.pdf", "noext", "x.docx", ""}
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

func TestCovIsValidCuitEntityPrefix(t *testing.T) {
	if len(CuitEntityPrefixes()) != 7 {
		t.Fatalf("prefixes=%d", len(CuitEntityPrefixes()))
	}
	for _, p := range []string{"20", "23", "24", "27", "30", "33", "34"} {
		if !IsValidCuitEntityPrefix(p) {
			t.Fatalf("expected valid prefix %q", p)
		}
	}
	for _, p := range []string{"99", "00", ""} {
		if IsValidCuitEntityPrefix(p) {
			t.Fatalf("expected invalid prefix %q", p)
		}
	}
}

func TestCovIsCredentialKindFalse(t *testing.T) {
	for _, k := range []ArtifactKind{KindInstaller, KindOther, KindUnknown} {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT cred kind: %q", k)
		}
	}
	if !IsCredentialKind(KindConfig) {
		t.Fatal("KindConfig must be cred kind")
	}
}

// -- SortRows: all comparator branches ----------------------------

func TestCovSortRows(t *testing.T) {
	in := []Row{
		{FilePath: "z", ArtifactKind: KindConfig, PeriodYYYYMM: "202601"},
		{FilePath: "a", ArtifactKind: KindLayout, PeriodYYYYMM: "202602"},
		{FilePath: "a", ArtifactKind: KindLayout, PeriodYYYYMM: "202601"},
		{FilePath: "a", ArtifactKind: KindConfig, PeriodYYYYMM: "202699"},
	}
	SortRows(in)
	// FilePath "a" < "z"; among "a" rows KindConfig ("sterling-config")
	// < KindLayout ("sterling-layout"); among equal path+kind the
	// earlier period wins.
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v", in[0])
	}
	if in[1].ArtifactKind != KindLayout || in[1].PeriodYYYYMM != "202601" {
		t.Fatalf("second=%+v", in[1])
	}
	if in[2].ArtifactKind != KindLayout || in[2].PeriodYYYYMM != "202602" {
		t.Fatalf("third=%+v", in[2])
	}
	if in[3].FilePath != "z" {
		t.Fatalf("last=%+v", in[3])
	}
}

// -- classifyProduct: all branches --------------------------------

func TestCovClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{HasOptionsChain: true, HasUSEquity: true}); got != ProductMultiAsset {
		t.Fatalf("multi-asset, got %q", got)
	}
	if got := classifyProduct(Row{HasOptionsChain: true}); got != ProductUSOptions {
		t.Fatalf("us-options, got %q", got)
	}
	if got := classifyProduct(Row{HasUSEquity: true}); got != ProductUSEquity {
		t.Fatalf("us-equity, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

// -- detectPropFirm: remaining branches ---------------------------

func TestCovDetectPropFirmExtra(t *testing.T) {
	cases := map[string]PropFirm{
		"cfg great_point capital":  PropFirmGreatPoint,
		"cfg great-point capital":  PropFirmGreatPoint,
		"cfg great point capital":  PropFirmGreatPoint,
		"cfg kershner trading grp": PropFirmKershner,
		"[prop_firm] custom":       PropFirmCustom,
	}
	for in, want := range cases {
		if got := detectPropFirm([]byte(in)); got != want {
			t.Fatalf("detectPropFirm(%q)=%q want %q", in, got, want)
		}
	}
}

// -- classifySymbols: equity + options ----------------------------

func TestCovClassifySymbols(t *testing.T) {
	body := []byte("symbol=AAPL\nsymbol=MSFT\nsymbol=DLR\nAAPL_240419P00170000\n")
	us, opts, total := classifySymbols(body)
	if us != 2 {
		t.Fatalf("us=%d want 2 (AAPL,MSFT)", us)
	}
	if opts != 1 {
		t.Fatalf("opts=%d want 1", opts)
	}
	if total != 4 {
		t.Fatalf("total=%d want 4", total)
	}
	// Empty body → all zero.
	if u, o, tt := classifySymbols(nil); u != 0 || o != 0 || tt != 0 {
		t.Fatalf("empty=(%d,%d,%d)", u, o, tt)
	}
}

// -- Parse* direct exact-value coverage ---------------------------

func TestCovParseSterlingCredentials(t *testing.T) {
	body := []byte("sterling_username=bob@example.com\n" +
		"sterling_password=pw12345\n" +
		"sterling_api_key=ABCDEFGHIJKLMNOP1234\n")
	f := ParseSterlingCredentials(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey != "ABCDEFGHIJKLMNOP1234" {
		t.Fatalf("api key=%q", f.APIKey)
	}
	if f.Username != "bob@example.com" {
		t.Fatalf("username=%q", f.Username)
	}
}

func TestCovParseSterlingLayout(t *testing.T) {
	f := ParseSterlingLayout([]byte("symbol=SPY\nAAPL_240419P00170000\n"))
	if f.USEquitySymbolsCount != 1 {
		t.Fatalf("us=%d want 1", f.USEquitySymbolsCount)
	}
	if f.OptionsSymbolsCount != 1 {
		t.Fatalf("opts=%d want 1", f.OptionsSymbolsCount)
	}
}

func TestCovParseSterlingChartDef(t *testing.T) {
	f := ParseSterlingChartDef([]byte("symbol=AAPL\nsymbol=MSFT\n"))
	if f.USEquitySymbolsCount != 2 {
		t.Fatalf("us=%d want 2", f.USEquitySymbolsCount)
	}
	if f.DistinctSymbols != 2 {
		t.Fatalf("distinct=%d want 2", f.DistinctSymbols)
	}
}

func TestCovParseSterlingDMARoute(t *testing.T) {
	f := ParseSterlingDMARoute([]byte("route=NYSE\nsymbol=AAPL\n"))
	if f.HasPassword {
		t.Fatal("no password expected")
	}
	if f.USEquitySymbolsCount != 1 {
		t.Fatalf("us=%d want 1", f.USEquitySymbolsCount)
	}
}

func TestCovParseSterlingBranchConfig(t *testing.T) {
	f := ParseSterlingBranchConfig([]byte("branch_id=B09\nprop_firm=SMB Capital\n"))
	if f.SterlingBranchID != "B09" {
		t.Fatalf("branch=%q want B09", f.SterlingBranchID)
	}
	if f.PropFirm != PropFirmSMBCapital {
		t.Fatalf("prop=%q", f.PropFirm)
	}
}

func TestCovParseSterlingClearingConfig(t *testing.T) {
	f := ParseSterlingClearingConfig([]byte("clearing_password=topsecret\n"))
	if !f.HasPassword {
		t.Fatal("clearing password must flag")
	}
}

func TestCovParseSterlingShortLocateLog(t *testing.T) {
	body := []byte("short_locate AAPL 100\nlocate_id 55\ntrader_id=A123\nsymbol=AAPL\n")
	f := ParseSterlingShortLocateLog(body)
	if f.ShortLocateCount != 2 {
		t.Fatalf("short locate=%d want 2", f.ShortLocateCount)
	}
	if f.SterlingTraderID != "A123" {
		t.Fatalf("trader=%q", f.SterlingTraderID)
	}
	if f.USEquitySymbolsCount != 1 {
		t.Fatalf("us=%d want 1", f.USEquitySymbolsCount)
	}
	// Empty body → zero.
	if e := ParseSterlingShortLocateLog(nil); e.ShortLocateCount != 0 {
		t.Fatalf("empty short locate=%d", e.ShortLocateCount)
	}
}

func TestCovParseSterlingFIXRoute(t *testing.T) {
	body := []byte("SenderCompID=NYSEARCA\nfix_password=\"secret1\"\n")
	f := ParseSterlingFIXRoute(body)
	if !f.HasPassword {
		t.Fatal("fix password must flag")
	}
	// A FIX body without any password stays clean.
	g := ParseSterlingFIXRoute([]byte("SenderCompID=NYSEARCA\n"))
	if g.HasPassword {
		t.Fatal("no password expected")
	}
}

func TestCovParseSterlingConfigEmpty(t *testing.T) {
	if f := ParseSterlingConfig(nil); f.HasPassword || f.APIKey != "" {
		t.Fatalf("empty config non-zero: %+v", f)
	}
	if f := ParseSterlingHotKeys(nil); f.HotKeyCount != 0 {
		t.Fatalf("empty hotkeys=%d", f.HotKeyCount)
	}
	if f := ParseSterlingOrderLog(nil); f.FillCount != 0 {
		t.Fatalf("empty orderlog=%d", f.FillCount)
	}
}

// -- ownerUID fallback --------------------------------------------

func TestCovOwnerUIDNonStat(t *testing.T) {
	if got := ownerUID(fakeInfo{sys: nil}); got != 0 {
		t.Fatalf("ownerUID non-syscall fallback=%d want 0", got)
	}
	if got := ownerUID(fakeInfo{sys: "not-a-stat"}); got != 0 {
		t.Fatalf("ownerUID wrong-type fallback=%d want 0", got)
	}
}

// -- collector end-to-end covering all artifact kinds -------------

func TestCovCollectorInstallTreeKinds(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Sterling Trader")
	must(t, os.MkdirAll(root, 0o755))

	files := []struct{ name, body string }{
		{"sterling_installer.msi", "MZ fake installer body"},
		{"sterling.txt", "just some unstructured junk text"},
		{"dma_route_nyse.cfg", "route=NYSE\nSenderCompID=ARCA\n"},
		{"clearing.cfg", "clearing_password=topsecret\ncliente_cuit=30-71234567-8\n"},
		{"branch.cfg", "branch_id=B09\nprop_firm=Great Point\n"},
		{"trader_risk_limits.cfg", "daily_loss_limit=$3000\nmax_position=$25000\ntrader_id=A777\n"},
		{"shortlocate_20260615.log", "short_locate AAPL 100\nlocate_id 55\n"},
		{"sterling_fix_route.cfg", "SenderCompID=NYSEARCA\nfix_password=\"secret1\"\n"},
		{"chartdef.cfg", "symbol=AAPL\nsymbol=MSFT\n"},
		{"my_layout.stx", "symbol=SPY\nAAPL_240419P00170000\n"},
		{"sterling_credentials.cfg", "sterling_username=bob@example.com\nsterling_password=pw\nsterling_api_key=ABCDEFGHIJKLMNOP1234\n"},
		{"sterling.cfg", "cliente_cuit: 24-99887766-5\nsymbol=NVDA\n"},
		{"sterling_27-11111111-4.cfg", "symbol=TSLA\n"},
		// Non-candidates: bad ext, and candidate ext but no token.
		{"random.pdf", "ignored"},
		{"random.cfg", "ignored"},
	}
	for _, f := range files {
		must(t, os.WriteFile(filepath.Join(root, f.name), []byte(f.body), 0o644))
	}

	c := newStCollector([]string{root}, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 13 {
		t.Fatalf("want 13 rows, got %d", len(got))
	}

	by := map[string]Row{}
	for _, r := range got {
		by[filepath.Base(r.FilePath)] = r
	}

	if r := by["sterling_installer.msi"]; r.ArtifactKind != KindInstaller || len(r.FileHash) != 64 {
		t.Fatalf("installer: kind=%q hashlen=%d", r.ArtifactKind, len(r.FileHash))
	}
	if r := by["sterling.txt"]; r.ArtifactKind != KindOther || len(r.FileHash) != 64 {
		t.Fatalf("other: kind=%q hashlen=%d", r.ArtifactKind, len(r.FileHash))
	}
	if r := by["clearing.cfg"]; !r.HasClearingCredentials || !r.HasPasswordInConfig ||
		!r.HasClienteCuit || !r.IsCredentialExposureRisk {
		t.Fatalf("clearing: %+v", r)
	}
	if r := by["branch.cfg"]; r.PropFirm != PropFirmGreatPoint || r.SterlingBranchID != "B09" ||
		!r.HasBranchHierarchy || r.AccountClass != AccountBranchAdmin {
		t.Fatalf("branch: %+v", r)
	}
	if r := by["trader_risk_limits.cfg"]; r.DailyLossLimitUSD != 3000 ||
		r.MaxPositionUSD != 25000 || !r.HasTraderRiskLimits {
		t.Fatalf("trader risk: %+v", r)
	}
	if r := by["shortlocate_20260615.log"]; r.ShortLocateCount != 2 || !r.HasShortLocateLog {
		t.Fatalf("shortlocate: %+v", r)
	}
	if r := by["sterling_fix_route.cfg"]; r.ArtifactKind != KindFIXRoute ||
		!r.HasPasswordInConfig || !r.HasDMARouteConfig {
		t.Fatalf("fix: %+v", r)
	}
	if r := by["chartdef.cfg"]; !r.HasUSEquity || r.USEquitySymbolsCount != 2 ||
		r.ProductClass != ProductUSEquity {
		t.Fatalf("chartdef: %+v", r)
	}
	if r := by["my_layout.stx"]; !r.HasUSEquity || !r.HasOptionsChain ||
		r.ProductClass != ProductMultiAsset {
		t.Fatalf("layout: %+v", r)
	}
	if r := by["sterling_credentials.cfg"]; !r.HasPasswordInConfig ||
		r.APIKeyHash == "" || r.UsernameHash == "" {
		t.Fatalf("credentials: %+v", r)
	}
	if r := by["sterling.cfg"]; r.ClienteCuitPrefix != "24" || r.ClienteCuitSuffix4 != "7665" {
		t.Fatalf("cuit-from-body: (%q,%q)", r.ClienteCuitPrefix, r.ClienteCuitSuffix4)
	}
	if r := by["sterling_27-11111111-4.cfg"]; r.ClienteCuitPrefix != "27" {
		t.Fatalf("cuit-from-filename prefix=%q want 27", r.ClienteCuitPrefix)
	}
}

// -- collector: env override --------------------------------------

func TestCovCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-sterling")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "sterling.cfg"),
		[]byte("trader_id=A123\n"), 0o644))

	c := newStCollector(nil, nil)
	c.getenv = func(k string) string {
		if k == "STERLING_DIR" {
			return envDir
		}
		return ""
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || got[0].ArtifactKind != KindConfig {
		t.Fatalf("env override: %+v", got)
	}
	if got[0].SterlingTraderID != "A123" {
		t.Fatalf("trader=%q", got[0].SterlingTraderID)
	}
}

// -- collector: dedup across duplicate roots ----------------------

func TestCovCollectorDedup(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Sterling Trader")
	must(t, os.MkdirAll(root, 0o755))
	must(t, os.WriteFile(filepath.Join(root, "sterling.cfg"),
		[]byte("trader_id=A123\n"), 0o644))

	// Same root twice → the second walk hits the consider dedup guard.
	c := newStCollector([]string{root, root}, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("dedup: want 1, got %d", len(got))
	}
}

// -- collector: stat error skips the file -------------------------

func TestCovConsiderStatError(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Sterling Trader")
	must(t, os.MkdirAll(root, 0o755))
	must(t, os.WriteFile(filepath.Join(root, "sterling.cfg"),
		[]byte("trader_id=A123\n"), 0o644))

	c := newStCollector([]string{root}, nil)
	c.statFile = func(string) (os.FileInfo, error) {
		return nil, errors.New("stat boom")
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("stat error must skip: got %d", len(got))
	}
}

// -- collector: readFile error still emits a hash-less row --------

func TestCovConsiderReadFileError(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Sterling Trader")
	must(t, os.MkdirAll(root, 0o755))
	must(t, os.WriteFile(filepath.Join(root, "sterling.cfg"),
		[]byte("trader_id=A123\n"), 0o644))

	c := newStCollector([]string{root}, nil)
	c.readFile = func(string) ([]byte, error) {
		return nil, errors.New("read boom")
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("read error should still emit row: got %d", len(got))
	}
	if got[0].FileHash != "" {
		t.Fatalf("unreadable file must have empty hash, got %q", got[0].FileHash)
	}
}

// -- collector: walk depth guard ----------------------------------

func TestCovWalkDepthGuard(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Sterling Trader")
	// Shallow candidate — found.
	must(t, os.MkdirAll(root, 0o755))
	must(t, os.WriteFile(filepath.Join(root, "sterling.cfg"),
		[]byte("trader_id=A123\n"), 0o644))

	// A file nested beyond MaxWalkDepth (6) is never reached.
	deep := filepath.Join(root, "d1", "d2", "d3", "d4", "d5", "d6", "d7")
	must(t, os.MkdirAll(deep, 0o755))
	must(t, os.WriteFile(filepath.Join(deep, "sterling_deep.cfg"),
		[]byte("trader_id=Z999\n"), 0o644))

	c := newStCollector([]string{root}, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("depth guard: want 1 (shallow only), got %d", len(got))
	}
	if filepath.Base(got[0].FilePath) != "sterling.cfg" {
		t.Fatalf("unexpected path %q", got[0].FilePath)
	}
}
