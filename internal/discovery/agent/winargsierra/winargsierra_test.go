package winargsierra

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "sierra-config"},
		{string(KindCredentials), "sierra-credentials"},
		{string(KindWorkspace), "sierra-workspace"},
		{string(KindChartbook), "sierra-chartbook"},
		{string(KindSCIDTick), "sierra-scid-tick"},
		{string(KindDLYDaily), "sierra-dly-daily"},
		{string(KindACSILSource), "sierra-acsil-source"},
		{string(KindACSILModule), "sierra-acsil-module"},
		{string(KindSpreadsheet), "sierra-spreadsheet"},
		{string(KindTradingActivity), "sierra-trading-activity"},
		{string(KindDTCLog), "sierra-dtc-log"},
		{string(KindInstaller), "sierra-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountProFutures), "pro-futures"},
		{string(AccountPropTrader), "prop-trader"},
		{string(AccountArbitrageur), "arbitrageur"},
		{string(AccountHFT), "hft"},
		{string(AccountQuantResearch), "quant-research"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(ProductCMEFutures), "cme-futures"},
		{string(ProductMATbaRofex), "matba-rofex"},
		{string(ProductGlobalFutures), "global-futures"},
		{string(ProductMultiVenue), "multi-venue"},
		{string(ProductOptions), "options"},
		{string(ProductHFTExecution), "hft-execution"},
		{string(ProductOther), "other"},
		{string(ProductUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"sierra.config",
		"sierra_config.ini",
		"DLR-202506.scid",
		"ES-202506.dly",
		"my_chart.cht",
		"workspace.cwsp",
		"my_study.scss",
		"my_study.spreadsheet",
		"tradingactivity.txt",
		"trading_activity_202506.csv",
		"dtc_session_202506.log",
		"sierrachart_installer.msi",
		"sierra_credentials.json",
		"acsil_study.cpp",
	}
	no := []string{"", "factura.xml", "random.txt", "report.pdf"}
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
		"sierra.config":               KindConfig,
		"sierra_credentials.json":     KindCredentials,
		"sierra_api_token.json":       KindCredentials,
		"workspace.cwsp":              KindWorkspace,
		"my_chart.cht":                KindChartbook,
		"DLR-202506.scid":             KindSCIDTick,
		"ES-202506.dly":               KindDLYDaily,
		"my_study.scss":               KindACSILSource,
		"acsil_study.cpp":             KindACSILSource,
		"sierra_study.dll":            KindACSILModule,
		"my_strat.spreadsheet":        KindSpreadsheet,
		"tradingactivity.txt":         KindTradingActivity,
		"trading_activity_202506.csv": KindTradingActivity,
		"dtc_session_202506.log":      KindDTCLog,
		"sierrachart_installer.msi":   KindInstaller,
		"":                            KindUnknown,
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

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("dtc_session_202506.log") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.log") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsMATbaRofexSymbol(t *testing.T) {
	yes := []string{
		"DLR", "DOM", "ROS-DLR", "MTR-USD",
		"SOJ", "MAI", "TRI", "CER", "UVA", "MERV",
	}
	no := []string{"", "ES", "CL", "GC", "AAPL"}
	for _, v := range yes {
		if !IsMATbaRofexSymbol(v) {
			t.Fatalf("expected MATba: %q", v)
		}
	}
	for _, v := range no {
		if IsMATbaRofexSymbol(v) {
			t.Fatalf("expected NOT MATba: %q", v)
		}
	}
}

func TestIsCMEFuturesSymbol(t *testing.T) {
	yes := []string{
		"ES", "NQ", "YM", "CL", "NG", "GC", "SI",
		"ZC", "ZN", "6E", "DXY", "BTC", "ETH",
	}
	no := []string{"", "DLR", "SOJ", "AAPL"}
	for _, v := range yes {
		if !IsCMEFuturesSymbol(v) {
			t.Fatalf("expected CME: %q", v)
		}
	}
	for _, v := range no {
		if IsCMEFuturesSymbol(v) {
			t.Fatalf("expected NOT CME: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindWorkspace, KindChartbook,
		KindACSILSource, KindACSILModule, KindSpreadsheet,
		KindTradingActivity, KindDTCLog,
	}
	no := []ArtifactKind{
		KindSCIDTick, KindDLYDaily,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected cred kind: %q", k)
		}
	}
	for _, k := range no {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT cred kind: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindConfig,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + cliente = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:        KindConfig,
		HasPasswordInConfig: true,
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateCrossVenueArb(t *testing.T) {
	r := Row{
		ArtifactKind:      KindDTCLog,
		MATbaSymbolsCount: 2,
		CMESymbolsCount:   3,
	}
	AnnotateSecurity(&r)
	if !r.HasMATbaRofexRouting {
		t.Fatal("MATba count must flag")
	}
	if !r.HasCMEFutures {
		t.Fatal("CME count must flag")
	}
	if !r.HasCrossVenueArb {
		t.Fatal("both must flag cross-venue arb")
	}
}

func TestAnnotateACSILAuto(t *testing.T) {
	r := Row{ArtifactKind: KindACSILModule}
	AnnotateSecurity(&r)
	if !r.HasACSILNativeModule {
		t.Fatal("ACSIL module kind must auto-flag")
	}
}

func TestAnnotateTradingActivityAuto(t *testing.T) {
	r := Row{ArtifactKind: KindTradingActivity}
	AnnotateSecurity(&r)
	if !r.HasTradingActivityExport {
		t.Fatal("trading activity kind must auto-flag")
	}
}

func TestAnnotateHighMsgRate(t *testing.T) {
	r := Row{
		ArtifactKind:  KindDTCLog,
		PeakMsgPerSec: 1500,
	}
	AnnotateSecurity(&r)
	if !r.HasHighMessageRate {
		t.Fatal("1500/s must flag HFT")
	}
}

func TestAnnotateLargeTickCache(t *testing.T) {
	r := Row{
		ArtifactKind: KindSCIDTick,
		FileSize:     LargeTickCacheBytes + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasLargeTickCache {
		t.Fatal("large .scid must flag")
	}
	if r.TickCacheBytes != r.FileSize {
		t.Fatalf("TickCacheBytes=%d want %d", r.TickCacheBytes, r.FileSize)
	}
}

func TestParseSierraConfig(t *testing.T) {
	body := []byte(`[Sierra]
sierra_username=alice@example.com
sierra_password=secret123
sierra_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
sierra_account=ACME-FUTURES-001
dtc_server=dtc.stage5trading.com:11099
symbol=DLR
symbol=ES
cliente_cuit=27-11111111-4
`)
	f := ParseSierraConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.SierraAccountID == "" {
		t.Fatalf("account=%q", f.SierraAccountID)
	}
	if !f.HasDTCServerURL {
		t.Fatal("DTC server URL must flag")
	}
	if f.DTCServerHost == "" {
		t.Fatalf("dtc host=%q", f.DTCServerHost)
	}
	if f.DTCServerPort != 11099 {
		t.Fatalf("dtc port=%d want 11099", f.DTCServerPort)
	}
	if f.MATbaSymbolsCount < 1 {
		t.Fatalf("matba=%d", f.MATbaSymbolsCount)
	}
	if f.CMESymbolsCount < 1 {
		t.Fatalf("cme=%d", f.CMESymbolsCount)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseSierraSpreadsheetAutotrade(t *testing.T) {
	body := []byte(`<spreadsheet>
<symbol>DLR/JUN26</symbol>
AutoTradeEnabled=true
</spreadsheet>`)
	f := ParseSierraSpreadsheet(body)
	if !f.HasAutotrade {
		t.Fatal("autotrade must flag")
	}
	if f.MATbaSymbolsCount < 1 {
		t.Fatalf("matba=%d", f.MATbaSymbolsCount)
	}
}

func TestParseSierraDTCLog(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 DTC LogonRequest server=dtc.optimusfutures.com:11099
2026-06-15 09:30:02 DTC EncodingResponse OK
2026-06-15 09:30:02 MarketDataUpdateTrade symbol=DLR
2026-06-15 09:30:03 MarketDataUpdateTrade symbol=ES
2026-06-15 09:30:03 MarketDataUpdateBidAsk symbol=MTR-USD
`)
	f := ParseSierraDTCLog(body)
	if !f.HasDTCSession {
		t.Fatal("DTC session must flag")
	}
	if !f.HasDTCServerURL {
		t.Fatal("DTC URL must flag")
	}
	if f.DTCServerHost == "" {
		t.Fatalf("dtc host=%q", f.DTCServerHost)
	}
	if f.MATbaSymbolsCount < 1 {
		t.Fatalf("matba=%d", f.MATbaSymbolsCount)
	}
	if f.CMESymbolsCount < 1 {
		t.Fatalf("cme=%d", f.CMESymbolsCount)
	}
}

func TestParseSierraTradingActivity(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 OrderFilled symbol=DLR/JUN26 qty=5 px=1234.5
2026-06-15 09:30:02 OrderFilled symbol=ES/JUN26 qty=2 px=5400.25
2026-06-15 09:30:03 OrderFilled symbol=MTR-USD/JUN26 qty=1 px=900
account_id=ACME-001
`)
	f := ParseSierraTradingActivity(body)
	if f.FillCount < 3 {
		t.Fatalf("fills=%d", f.FillCount)
	}
	if f.SierraAccountID == "" {
		t.Fatalf("account=%q", f.SierraAccountID)
	}
}

func TestParseSierraEmpty(t *testing.T) {
	f := ParseSierraConfig(nil)
	if f.HasPassword || f.APIKey != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestClassifyProduct(t *testing.T) {
	if classifyProduct(Row{PeakMsgPerSec: HighMessageRateThreshold + 1}) != ProductHFTExecution {
		t.Fatal("high msg rate -> hft-execution")
	}
	if classifyProduct(Row{MATbaSymbolsCount: 1, CMESymbolsCount: 1}) != ProductMultiVenue {
		t.Fatal("both -> multi-venue")
	}
	if classifyProduct(Row{MATbaSymbolsCount: 1}) != ProductMATbaRofex {
		t.Fatal("matba -> matba-rofex")
	}
	if classifyProduct(Row{CMESymbolsCount: 1}) != ProductCMEFutures {
		t.Fatal("cme -> cme-futures")
	}
	if classifyProduct(Row{}) != ProductUnknown {
		t.Fatal("unknown")
	}
}

func TestClassifyAccount(t *testing.T) {
	if classifyAccount(Row{HasACSILNativeModule: true}) != AccountHFT {
		t.Fatal("ACSIL module -> hft")
	}
	if classifyAccount(Row{PeakMsgPerSec: HighMessageRateThreshold + 1}) != AccountHFT {
		t.Fatal("high msg rate -> hft")
	}
	if classifyAccount(Row{HasSpreadsheetAutotrade: true}) != AccountPropTrader {
		t.Fatal("autotrade -> prop-trader")
	}
	if classifyAccount(Row{MATbaSymbolsCount: 1, CMESymbolsCount: 1}) != AccountArbitrageur {
		t.Fatal("cross-venue -> arbitrageur")
	}
	if classifyAccount(Row{ArtifactKind: KindACSILSource}) != AccountQuantResearch {
		t.Fatal("ACSIL source -> quant-research")
	}
	if classifyAccount(Row{MATbaSymbolsCount: 1}) != AccountProFutures {
		t.Fatal("matba -> pro-futures")
	}
	if classifyAccount(Row{}) != AccountUnknown {
		t.Fatal("unknown")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "SierraChart")
	must(t, os.MkdirAll(filepath.Join(dir, "logs"), 0o755))

	cfgPath := filepath.Join(dir, "sierra.config")
	must(t, os.WriteFile(cfgPath, []byte(`[Sierra]
sierra_username=alice@example.com
sierra_password=secret123
sierra_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
sierra_account=ACME-FUTURES-001
dtc_server=dtc.stage5trading.com:11099
cliente_cuit=27-11111111-4
`), 0o644))

	dtcPath := filepath.Join(dir, "logs", "dtc_session_202506.log")
	must(t, os.WriteFile(dtcPath, []byte(`2026-06-15 09:30:01 DTC LogonRequest server=dtc.optimusfutures.com:11099
2026-06-15 09:30:02 DTC EncodingResponse OK
2026-06-15 09:30:02 MarketDataUpdateTrade symbol=DLR
2026-06-15 09:30:03 MarketDataUpdateTrade symbol=ES
2026-06-15 09:30:03 MarketDataUpdateBidAsk symbol=MTR-USD
`), 0o644))

	taPath := filepath.Join(dir, "tradingactivity.txt")
	must(t, os.WriteFile(taPath, []byte(`2026-06-15 09:30:01 OrderFilled symbol=DLR/JUN26 qty=5 px=1234.5
2026-06-15 09:30:02 OrderFilled symbol=ES/JUN26 qty=2 px=5400.25
account_id=ACME-001
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "SierraChart")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "sierra.config"),
		[]byte(`[Sierra]`), 0o644))

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
		t.Fatalf("want 3 (cfg+dtc+ta), got %d: %+v", len(got), got)
	}

	var cfg, dtc, ta Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case dtcPath:
			dtc = r
		case taPath:
			ta = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if cfg.SierraAccountID == "" {
		t.Fatalf("cfg account=%q", cfg.SierraAccountID)
	}
	if !cfg.HasDTCServerURL {
		t.Fatalf("cfg must flag DTC server URL: %+v", cfg)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cliente = exposure: %+v", cfg)
	}

	if dtc.ArtifactKind != KindDTCLog {
		t.Fatalf("dtc kind=%q want dtc-log", dtc.ArtifactKind)
	}
	if !dtc.HasDTCSession {
		t.Fatalf("dtc must flag DTC session: %+v", dtc)
	}
	if !dtc.HasMATbaRofexRouting {
		t.Fatalf("dtc must flag MATba: %+v", dtc)
	}
	if !dtc.HasCMEFutures {
		t.Fatalf("dtc must flag CME: %+v", dtc)
	}
	if !dtc.HasCrossVenueArb {
		t.Fatalf("dtc must flag cross-venue: %+v", dtc)
	}
	if dtc.AccountClass != AccountArbitrageur {
		t.Fatalf("dtc account=%q want arbitrageur", dtc.AccountClass)
	}
	if dtc.ProductClass != ProductMultiVenue {
		t.Fatalf("dtc product=%q want multi-venue", dtc.ProductClass)
	}

	if ta.ArtifactKind != KindTradingActivity {
		t.Fatalf("ta kind=%q want trading-activity", ta.ArtifactKind)
	}
	if !ta.HasTradingActivityExport {
		t.Fatalf("ta must auto-flag: %+v", ta)
	}
	if ta.FillCount < 2 {
		t.Fatalf("ta fills=%d", ta.FillCount)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-sierra")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "sierra.config"),
		[]byte(`[Sierra]
sierra_account=ACME
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SIERRA_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindConfig {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-sierra"},
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
		{FilePath: "z", ArtifactKind: KindConfig},
		{FilePath: "a", ArtifactKind: KindDTCLog},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,sierra-config)", in[0])
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("abc")
	b := HashSecret("abc")
	c := HashSecret("ABC")
	if a != b {
		t.Fatal("hash drift")
	}
	if a != c {
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
