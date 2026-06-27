package winargcqg

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "cqg-config"},
		{string(KindCredentials), "cqg-credentials"},
		{string(KindICConfig), "cqg-ic-config"},
		{string(KindQTraderConfig), "cqg-qtrader-config"},
		{string(KindContinuumConfig), "cqg-continuum-config"},
		{string(KindAlgoSEStrategy), "cqg-algo-se-strategy"},
		{string(KindAPIScript), "cqg-api-script"},
		{string(KindSessionLog), "cqg-session-log"},
		{string(KindPositions), "cqg-positions"},
		{string(KindOrders), "cqg-orders"},
		{string(KindFIXLog), "cqg-fix-log"},
		{string(KindInstaller), "cqg-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountProFutures), "pro-futures"},
		{string(AccountPropTrader), "prop-trader"},
		{string(AccountArbitrageur), "arbitrageur"},
		{string(AccountInstitutional), "institutional"},
		{string(AccountAPI), "api"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(ProductCMEFutures), "cme-futures"},
		{string(ProductMATbaRofex), "matba-rofex"},
		{string(ProductGlobalFutures), "global-futures"},
		{string(ProductMultiVenue), "multi-venue"},
		{string(ProductOptions), "options"},
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
		"cqg_config.xml",
		"cqg_credentials.json",
		"qtrader_workspace.xml",
		"continuum_fix.cfg",
		"algo_se_strategy.cqg",
		"cqg_api_script.py",
		"cqg_session.log",
		"fix.fix",
		"cqg_installer.msi",
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
		"cqg_config.xml":           KindConfig,
		"cqg_credentials.json":     KindCredentials,
		"cqg_api_token.json":       KindCredentials,
		"qtrader_workspace.xml":    KindQTraderConfig,
		"q_trader_blocks.csv":      KindQTraderConfig,
		"continuum_fix.cfg":        KindContinuumConfig,
		"algo_se_strategy.cqg":     KindAlgoSEStrategy,
		"algose_btcusd.cqg":        KindAlgoSEStrategy,
		"cqg_api_script.py":        KindAPIScript,
		"cqg_quant.ipynb":          KindAPIScript,
		"cqg_session_202506.log":   KindSessionLog,
		"cqg_positions_202506.csv": KindPositions,
		"cqg_orders_202506.csv":    KindOrders,
		"fix.fix":                  KindFIXLog,
		"fix_drop_copy.log":        KindFIXLog,
		"cqg_installer.msi":        KindInstaller,
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
	if PeriodFromFilename("cqg_session_202506.log") != "202506" {
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
		KindConfig, KindCredentials, KindICConfig,
		KindQTraderConfig, KindContinuumConfig,
		KindAlgoSEStrategy, KindAPIScript,
		KindSessionLog, KindPositions, KindOrders, KindFIXLog,
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
		ArtifactKind:      KindFIXLog,
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

func TestAnnotateBlockQTrader(t *testing.T) {
	r := Row{
		ArtifactKind:    KindQTraderConfig,
		BlockTradeCount: 5,
	}
	AnnotateSecurity(&r)
	if !r.HasBlockQTrader {
		t.Fatal("QTrader kind must flag")
	}
}

func TestAnnotateAlgoSE(t *testing.T) {
	r := Row{ArtifactKind: KindAlgoSEStrategy}
	AnnotateSecurity(&r)
	if !r.HasAlgoSEStrategy {
		t.Fatal("Algo SE kind must auto-flag")
	}
}

func TestAnnotateHighMsgRate(t *testing.T) {
	r := Row{
		ArtifactKind:  KindFIXLog,
		PeakMsgPerSec: 1500,
	}
	AnnotateSecurity(&r)
	if !r.HasHighMessageRate {
		t.Fatal("1500/s must flag HFT")
	}
}

func TestParseCQGConfig(t *testing.T) {
	body := []byte(`<CQG>
cqg_username=alice@example.com
cqg_password=secret123
cqg_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
cqg_account=ACME-FUTURES-001
symbol=DLR/JUN26
symbol=ES
cliente_cuit=27-11111111-4
</CQG>`)
	f := ParseCQGConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.CQGAccountID == "" {
		t.Fatalf("account=%q", f.CQGAccountID)
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

func TestParseCQGContinuumConfig(t *testing.T) {
	body := []byte(`[FIX]
BeginString=FIX.4.4
SenderCompID=ACME_TRADER
TargetCompID=CQG_CONTINUUM
ConnectionType=initiator
continuum_session=true
`)
	f := ParseCQGContinuumConfig(body)
	if !f.HasFIXContinuum {
		t.Fatal("FIX continuum must flag")
	}
	if f.FIXSenderCompID == "" {
		t.Fatalf("sender=%q", f.FIXSenderCompID)
	}
	if f.FIXTargetCompID == "" {
		t.Fatalf("target=%q", f.FIXTargetCompID)
	}
}

func TestParseCQGAlgoSEStrategy(t *testing.T) {
	body := []byte(`# AlgoSE strategy for cross-venue arb
strategy_engine.run("mtr-usd-dxy-arb")
symbol_1=MTR-USD/JUN26
symbol_2=DXY
api_key="aBcDeFgHiJkLmNoPqRsTuVwX12345"
`)
	f := ParseCQGAlgoSEStrategy(body)
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

func TestParseCQGQTraderConfig(t *testing.T) {
	body := []byte(`<QTrader>
<workspace name="DLR-block">
<block_id>B-001</block_id>
<symbol>DLR/JUN26</symbol>
<negotiated_cross>true</negotiated_cross>
</workspace>
</QTrader>`)
	f := ParseCQGQTraderConfig(body)
	if !f.HasQTraderMarker {
		t.Fatal("QTrader marker must flag")
	}
	if f.BlockTradeCount < 1 {
		t.Fatalf("blocks=%d", f.BlockTradeCount)
	}
}

func TestParseCQGFIXLog(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 8=FIX.4.4|9=120|35=W|49=CQG|56=ACME|TargetSubID=DROP|55=DLR
2026-06-15 09:30:02 8=FIX.4.4|9=80|35=8|49=CQG|56=ACME|TargetSubID=DROP|55=ES TradeCaptureReport
`)
	f := ParseCQGFIXLog(body)
	if !f.HasFIXContinuum {
		t.Fatal("FIX continuum must flag")
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

func TestParseCQGEmpty(t *testing.T) {
	f := ParseCQGConfig(nil)
	if f.HasPassword || f.APIKey != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestClassifyProduct(t *testing.T) {
	if classifyProduct(CQGFields{MATbaSymbolsCount: 1, CMESymbolsCount: 1}) != ProductMultiVenue {
		t.Fatal("both -> multi-venue")
	}
	if classifyProduct(CQGFields{MATbaSymbolsCount: 1}) != ProductMATbaRofex {
		t.Fatal("matba -> matba-rofex")
	}
	if classifyProduct(CQGFields{CMESymbolsCount: 1}) != ProductCMEFutures {
		t.Fatal("cme -> cme-futures")
	}
	if classifyProduct(CQGFields{}) != ProductUnknown {
		t.Fatal("unknown")
	}
}

func TestClassifyAccount(t *testing.T) {
	if classifyAccount(Row{ArtifactKind: KindAPIScript}, CQGFields{}) != AccountAPI {
		t.Fatal("py -> api")
	}
	if classifyAccount(Row{}, CQGFields{HasFIXContinuum: true}) != AccountInstitutional {
		t.Fatal("FIX continuum -> institutional")
	}
	if classifyAccount(Row{}, CQGFields{MATbaSymbolsCount: 1, CMESymbolsCount: 1}) != AccountArbitrageur {
		t.Fatal("cross-venue -> arbitrageur")
	}
	if classifyAccount(Row{}, CQGFields{MATbaSymbolsCount: 1}) != AccountProFutures {
		t.Fatal("matba -> pro-futures")
	}
	if classifyAccount(Row{}, CQGFields{}) != AccountUnknown {
		t.Fatal("unknown")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "CQG")
	must(t, os.MkdirAll(filepath.Join(dir, "Continuum"), 0o755))

	cfgPath := filepath.Join(dir, "cqg_config.xml")
	must(t, os.WriteFile(cfgPath, []byte(`<CQG>
cqg_username=alice@example.com
cqg_password=secret123
cqg_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
cqg_account=ACME-FUTURES-001
cliente_cuit=27-11111111-4
</CQG>`), 0o644))

	fixPath := filepath.Join(dir, "Continuum", "fix.fix")
	must(t, os.WriteFile(fixPath, []byte(`2026-06-15 09:30:01 8=FIX.4.4|9=120|35=W|49=ACME_TRADER|56=CQG_CONTINUUM|55=DLR/JUN26
2026-06-15 09:30:02 8=FIX.4.4|9=80|35=8|49=ACME_TRADER|56=CQG_CONTINUUM|55=ES TradeCaptureReport
2026-06-15 09:30:03 8=FIX.4.4|9=80|35=8|49=ACME_TRADER|56=CQG_CONTINUUM|55=MTR-USD/JUN26
`), 0o644))

	stratPath := filepath.Join(usersBase, "alice", "projects", "cqg", "algo_se_strategy.cqg")
	must(t, os.MkdirAll(filepath.Dir(stratPath), 0o755))
	must(t, os.WriteFile(stratPath, []byte(`# AlgoSE strategy
strategy_engine.run("dlr-es-arb")
symbol_1=DLR/JUN26
symbol_2=ES
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "CQG")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "cqg_config.xml"),
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
	if cfg.CQGAccountID == "" {
		t.Fatalf("cfg account=%q", cfg.CQGAccountID)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + api + cliente = exposure: %+v", cfg)
	}

	if fix.ArtifactKind != KindFIXLog {
		t.Fatalf("fix kind=%q", fix.ArtifactKind)
	}
	if !fix.HasContinuumFIXSession {
		t.Fatalf("fix must flag continuum: %+v", fix)
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

	if strat.ArtifactKind != KindAlgoSEStrategy {
		t.Fatalf("strat kind=%q", strat.ArtifactKind)
	}
	if !strat.HasAlgoSEStrategy {
		t.Fatalf("strat must flag: %+v", strat)
	}
	if strat.AccountClass != AccountAPI {
		t.Fatalf("strat account=%q want api", strat.AccountClass)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-cqg")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "cqg_config.xml"),
		[]byte(`<CQG><cqg_account>ACME</cqg_account></CQG>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "CQG_DIR" {
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
		installRoots: []string{"/nope-cqg"},
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
		{FilePath: "a", ArtifactKind: KindFIXLog},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,cqg-config)", in[0])
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
