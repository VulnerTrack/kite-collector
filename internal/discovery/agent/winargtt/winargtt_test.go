package winargtt

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "tt-config"},
		{string(KindCredentials), "tt-credentials"},
		{string(KindDesktopConfig), "tt-desktop-config"},
		{string(KindFIXAdapterConfig), "tt-fix-adapter-config"},
		{string(KindADLStrategy), "tt-adl-strategy"},
		{string(KindAlgoSEStrategy), "tt-algo-se-strategy"},
		{string(KindAuroraConfig), "tt-aurora-config"},
		{string(KindScoreReport), "tt-score-report"},
		{string(KindAPIScript), "tt-api-script"},
		{string(KindSessionLog), "tt-session-log"},
		{string(KindInstaller), "tt-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountProFutures), "pro-futures"},
		{string(AccountPropTrader), "prop-trader"},
		{string(AccountArbitrageur), "arbitrageur"},
		{string(AccountInstitutional), "institutional"},
		{string(AccountAPI), "api"},
		{string(AccountHFT), "hft"},
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
		"tt_config.xml",
		"tt_desktop_workspace.json",
		"tt_credentials.json",
		"tt_fix_adapter.cfg",
		"tt_adl_strategy.adl",
		"tt_algo_se_strategy.tt",
		"tt_aurora_config.json",
		"tt_score_report.score",
		"tt_api_script.py",
		"tt_session.log",
		"tradingtechnologies_installer.msi",
		"ttas.cfg",
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
		"tt_config.xml":            KindConfig,
		"tt_credentials.json":      KindCredentials,
		"tt_api_token.json":        KindCredentials,
		"tt_desktop_workspace.xml": KindDesktopConfig,
		"tt_fix_adapter.cfg":       KindFIXAdapterConfig,
		"my_strat.adl":             KindADLStrategy,
		"tt_adl_strategy.xml":      KindADLStrategy,
		"server_strategy.tt":       KindAlgoSEStrategy,
		"tt_algo_se_strategy.json": KindAlgoSEStrategy,
		"tt_aurora_config.json":    KindAuroraConfig,
		"tt_score_report.score":    KindScoreReport,
		"tt_score_202506.json":     KindScoreReport,
		"tt_api_script.py":         KindAPIScript,
		"tt_rest_quant.ipynb":      KindAPIScript,
		"tt_session_202506.log":    KindSessionLog,
		"tradingtechnologies.msi":  KindInstaller,
		"tt_desktop_installer.msi": KindInstaller,
		"":                         KindUnknown,
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
	if PeriodFromFilename("tt_session_202506.log") != "202506" {
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
		KindConfig, KindCredentials, KindDesktopConfig,
		KindFIXAdapterConfig, KindADLStrategy, KindAlgoSEStrategy,
		KindAuroraConfig, KindScoreReport, KindAPIScript, KindSessionLog,
	}
	no := []ArtifactKind{KindInstaller, KindOther, KindUnknown}
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
		ArtifactKind:       KindConfig,
		HasAPICredentials:  true,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + api + cliente = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:      KindConfig,
		HasAPICredentials: true,
		FileMode:          0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateCrossVenueArb(t *testing.T) {
	r := Row{
		ArtifactKind:      KindSessionLog,
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

func TestAnnotateADLAuto(t *testing.T) {
	r := Row{ArtifactKind: KindADLStrategy}
	AnnotateSecurity(&r)
	if !r.HasADLVisualAlgo {
		t.Fatal("ADL kind must auto-flag")
	}
}

func TestAnnotateAlgoSEAuto(t *testing.T) {
	r := Row{ArtifactKind: KindAlgoSEStrategy}
	AnnotateSecurity(&r)
	if !r.HasAlgoSEStrategy {
		t.Fatal("Algo SE kind must auto-flag")
	}
}

func TestAnnotateAuroraAuto(t *testing.T) {
	r := Row{ArtifactKind: KindAuroraConfig}
	AnnotateSecurity(&r)
	if !r.HasAuroraHFT {
		t.Fatal("Aurora kind must auto-flag")
	}
}

func TestAnnotateScoreAuto(t *testing.T) {
	r := Row{ArtifactKind: KindScoreReport}
	AnnotateSecurity(&r)
	if !r.HasScoreAudit {
		t.Fatal("Score kind must auto-flag")
	}
}

func TestAnnotateHighMsgRate(t *testing.T) {
	r := Row{
		ArtifactKind:  KindSessionLog,
		PeakMsgPerSec: 1500,
	}
	AnnotateSecurity(&r)
	if !r.HasHighMessageRate {
		t.Fatal("1500/s must flag HFT")
	}
}

func TestParseTTConfig(t *testing.T) {
	body := []byte(`<TT>
tt_username=alice@example.com
tt_password=secret123
tt_app_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
tt_account=ACME-TT-001
symbol=DLR/JUN26
symbol=ES
cliente_cuit=27-11111111-4
ttas=true
</TT>`)
	f := ParseTTConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.TTAccountID == "" {
		t.Fatalf("account=%q", f.TTAccountID)
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
	if !f.HasTTASMarker {
		t.Fatal("ttas marker must flag")
	}
}

func TestParseTTFIXAdapterConfig(t *testing.T) {
	body := []byte(`[FIX]
BeginString=FIX.4.4
SenderCompID=ACME_TRADER
TargetCompID=TT_GATEWAY
ConnectionType=initiator
tt_fix=true
`)
	f := ParseTTFIXAdapterConfig(body)
	if !f.HasTTFIXSession {
		t.Fatal("TT FIX must flag")
	}
	if f.FIXSenderCompID == "" {
		t.Fatalf("sender=%q", f.FIXSenderCompID)
	}
	if f.FIXTargetCompID == "" {
		t.Fatalf("target=%q", f.FIXTargetCompID)
	}
}

func TestParseTTADLStrategy(t *testing.T) {
	body := []byte(`<adl_strategy name="cross-venue-arb">
<block type="quote" symbol_1="MTR-USD/JUN26"/>
<block type="quote" symbol_2="ES"/>
<api_key>"aBcDeFgHiJkLmNoPqRsTuVwX12345"</api_key>
</adl_strategy>`)
	f := ParseTTADLStrategy(body)
	if !f.HasADLMarker {
		t.Fatal("ADL marker must flag")
	}
	if f.MATbaSymbolsCount < 1 {
		t.Fatalf("matba=%d", f.MATbaSymbolsCount)
	}
	if f.CMESymbolsCount < 1 {
		t.Fatalf("cme=%d", f.CMESymbolsCount)
	}
}

func TestParseTTAlgoSEStrategy(t *testing.T) {
	body := []byte(`# Algo SE strategy for cross-venue arb
strategy_engine.run("mtr-usd-dxy-arb")
symbol_1=MTR-USD/JUN26
symbol_2=DXY
api_key="aBcDeFgHiJkLmNoPqRsTuVwX12345"
`)
	f := ParseTTAlgoSEStrategy(body)
	if !f.HasAlgoSEMarker {
		t.Fatal("Algo SE marker must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if f.MATbaSymbolsCount < 1 {
		t.Fatalf("matba=%d", f.MATbaSymbolsCount)
	}
	if f.CMESymbolsCount < 1 {
		t.Fatalf("cme=%d", f.CMESymbolsCount)
	}
}

func TestParseTTAuroraConfig(t *testing.T) {
	body := []byte(`<TT_Aurora>
<aurora_engine name="hft-cl-es"/>
symbol=CL/JUN26
</TT_Aurora>`)
	f := ParseTTAuroraConfig(body)
	if !f.HasAuroraMarker {
		t.Fatal("Aurora marker must flag")
	}
}

func TestParseTTScoreReport(t *testing.T) {
	body := []byte(`{
"tt_score_report": "algo_audit_202506",
"account_id": "ACME-001",
"symbol": "ES/JUN26"
}`)
	f := ParseTTScoreReport(body)
	if !f.HasScoreMarker {
		t.Fatal("Score marker must flag")
	}
	if f.TTAccountID == "" {
		t.Fatalf("account=%q", f.TTAccountID)
	}
}

func TestParseTTSessionLog(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 8=FIX.4.4|9=120|35=W|49=ACME_TRADER|56=TT_GATEWAY|TargetSubID=DROP|55=DLR
2026-06-15 09:30:02 8=FIX.4.4|9=80|35=8|49=ACME_TRADER|56=TT_GATEWAY|TargetSubID=DROP|55=ES TradeCaptureReport
2026-06-15 09:30:02 8=FIX.4.4|9=80|35=8|49=ACME_TRADER|56=TT_GATEWAY|TargetSubID=DROP|55=ES TradeCaptureReport
`)
	f := ParseTTSessionLog(body)
	if !f.HasTTFIXSession {
		t.Fatal("TT FIX session must flag")
	}
	if !f.HasFIXDropCopy {
		t.Fatal("drop copy must flag")
	}
	if f.MATbaSymbolsCount < 1 {
		t.Fatalf("matba=%d", f.MATbaSymbolsCount)
	}
	if f.CMESymbolsCount < 1 {
		t.Fatalf("cme=%d", f.CMESymbolsCount)
	}
}

func TestParseTTEmpty(t *testing.T) {
	f := ParseTTConfig(nil)
	if f.HasPassword || f.APIKey != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{ArtifactKind: KindAuroraConfig},
		TTFields{HasAuroraMarker: true}); got != ProductHFTExecution {
		t.Fatalf("aurora -> hft-execution, got %q", got)
	}
	if got := classifyProduct(Row{PeakMsgPerSec: HighMessageRateThreshold + 1},
		TTFields{}); got != ProductHFTExecution {
		t.Fatalf("high msg rate -> hft-execution, got %q", got)
	}
	if got := classifyProduct(Row{},
		TTFields{MATbaSymbolsCount: 1, CMESymbolsCount: 1}); got != ProductMultiVenue {
		t.Fatalf("both -> multi-venue, got %q", got)
	}
	if got := classifyProduct(Row{},
		TTFields{MATbaSymbolsCount: 1}); got != ProductMATbaRofex {
		t.Fatalf("matba -> matba-rofex, got %q", got)
	}
	if got := classifyProduct(Row{},
		TTFields{CMESymbolsCount: 1}); got != ProductCMEFutures {
		t.Fatalf("cme -> cme-futures, got %q", got)
	}
	if got := classifyProduct(Row{}, TTFields{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{ArtifactKind: KindAuroraConfig},
		TTFields{HasAuroraMarker: true}); got != AccountHFT {
		t.Fatalf("aurora -> hft, got %q", got)
	}
	if got := classifyAccount(Row{PeakMsgPerSec: HighMessageRateThreshold + 1},
		TTFields{}); got != AccountHFT {
		t.Fatalf("high msg rate -> hft, got %q", got)
	}
	if got := classifyAccount(Row{ArtifactKind: KindAPIScript},
		TTFields{}); got != AccountAPI {
		t.Fatalf("py -> api, got %q", got)
	}
	if got := classifyAccount(Row{}, TTFields{HasTTFIXSession: true}); got != AccountInstitutional {
		t.Fatalf("TT FIX -> institutional, got %q", got)
	}
	if got := classifyAccount(Row{},
		TTFields{MATbaSymbolsCount: 1, CMESymbolsCount: 1}); got != AccountArbitrageur {
		t.Fatalf("cross-venue -> arbitrageur, got %q", got)
	}
	if got := classifyAccount(Row{},
		TTFields{MATbaSymbolsCount: 1}); got != AccountProFutures {
		t.Fatalf("matba -> pro-futures, got %q", got)
	}
	if got := classifyAccount(Row{}, TTFields{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "TT")
	must(t, os.MkdirAll(filepath.Join(dir, "FIX"), 0o755))

	cfgPath := filepath.Join(dir, "tt_config.xml")
	must(t, os.WriteFile(cfgPath, []byte(`<TT>
tt_username=alice@example.com
tt_password=secret123
tt_app_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
tt_account=ACME-TT-001
cliente_cuit=27-11111111-4
</TT>`), 0o644))

	fixPath := filepath.Join(dir, "FIX", "tt_fix_session.log")
	must(t, os.WriteFile(fixPath, []byte(`2026-06-15 09:30:01 8=FIX.4.4|9=120|35=W|49=ACME_TRADER|56=TT_GATEWAY|55=DLR/JUN26
2026-06-15 09:30:02 8=FIX.4.4|9=80|35=8|49=ACME_TRADER|56=TT_GATEWAY|55=ES TradeCaptureReport
2026-06-15 09:30:03 8=FIX.4.4|9=80|35=8|49=ACME_TRADER|56=TT_GATEWAY|55=MTR-USD/JUN26
`), 0o644))

	stratPath := filepath.Join(usersBase, "alice", "projects", "tt", "my_strat.adl")
	must(t, os.MkdirAll(filepath.Dir(stratPath), 0o755))
	must(t, os.WriteFile(stratPath, []byte(`<adl_strategy name="dlr-es-arb">
<block type="quote" symbol_1="DLR/JUN26"/>
<block type="quote" symbol_2="ES"/>
</adl_strategy>`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "TT")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "tt_config.xml"),
		[]byte(`<x/>`), 0o644))

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
		t.Fatalf("want 3 (cfg+fix+strat), got %d: %+v", len(got), got)
	}

	var cfg, fix, strat Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case fixPath:
			fix = r
		case stratPath:
			strat = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if !cfg.HasAPICredentials {
		t.Fatalf("cfg must flag api: %+v", cfg)
	}
	if cfg.TTAccountID == "" {
		t.Fatalf("cfg account=%q", cfg.TTAccountID)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + api + cliente = exposure: %+v", cfg)
	}

	if fix.ArtifactKind != KindSessionLog {
		t.Fatalf("fix kind=%q want session-log", fix.ArtifactKind)
	}
	if !fix.HasTTFIXSession {
		t.Fatalf("fix must flag TT FIX: %+v", fix)
	}
	if !fix.HasMATbaRofexRouting {
		t.Fatalf("fix must flag MATba: %+v", fix)
	}
	if !fix.HasCMEFutures {
		t.Fatalf("fix must flag CME: %+v", fix)
	}
	if !fix.HasCrossVenueArb {
		t.Fatalf("fix must flag cross-venue: %+v", fix)
	}
	if fix.AccountClass != AccountInstitutional {
		t.Fatalf("fix account=%q want institutional", fix.AccountClass)
	}
	if fix.ProductClass != ProductMultiVenue {
		t.Fatalf("fix product=%q want multi-venue", fix.ProductClass)
	}

	if strat.ArtifactKind != KindADLStrategy {
		t.Fatalf("strat kind=%q want adl-strategy", strat.ArtifactKind)
	}
	if !strat.HasADLVisualAlgo {
		t.Fatalf("strat must flag ADL: %+v", strat)
	}
	if strat.AccountClass != AccountAPI {
		t.Fatalf("strat account=%q want api", strat.AccountClass)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-tt")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "tt_config.xml"),
		[]byte(`<TT><tt_account>ACME</tt_account></TT>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "TT_DIR" {
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
		installRoots: []string{"/nope-tt"},
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
		{FilePath: "a", ArtifactKind: KindSessionLog},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,tt-config)", in[0])
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
