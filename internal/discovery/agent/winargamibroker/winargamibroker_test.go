package winargamibroker

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "ami-config"},
		{string(KindCredentials), "ami-credentials"},
		{string(KindAFLFormula), "ami-afl-formula"},
		{string(KindAPXProject), "ami-apx-project"},
		{string(KindADATDatabase), "ami-adat-database"},
		{string(KindWorkspace), "ami-workspace"},
		{string(KindBrokerPlugin), "ami-broker-plugin"},
		{string(KindAutotradeConfig), "ami-autotrade-config"},
		{string(KindBacktestReport), "ami-backtest-report"},
		{string(KindTradeLog), "ami-trade-log"},
		{string(KindLayout), "ami-layout"},
		{string(KindInstaller), "ami-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountEquityDaytrader), "equity-daytrader"},
		{string(AccountAlgotrader), "algotrader"},
		{string(AccountBacktestResearcher), "backtest-researcher"},
		{string(AccountPropTrader), "prop-trader"},
		{string(AccountAPI), "api"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(ProductBYMAEquity), "byma-equity"},
		{string(ProductMERVIndex), "merv-index"},
		{string(ProductARBonds), "ar-bonds"},
		{string(ProductARCEDEARs), "ar-cedears"},
		{string(ProductMultiAsset), "multi-asset"},
		{string(ProductCrypto), "crypto"},
		{string(ProductForex), "forex"},
		{string(ProductOther), "other"},
		{string(ProductUnknown), "unknown"},
		{string(PluginIB), "ib"},
		{string(PluginIOL), "iol"},
		{string(PluginCocos), "cocos"},
		{string(PluginBYMA), "byma"},
		{string(PluginROFEX), "rofex"},
		{string(PluginTWS), "tws"},
		{string(PluginCustom), "custom"},
		{string(PluginNone), "none"},
		{string(PluginUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"broker.txt",
		"my_strategy.afl",
		"my_project.apx",
		"GGAL_intraday.adat",
		"my_workspace.awx",
		"autotrade.ini",
		"trade_log_202506.csv",
		"backtest_report.csv",
		"amibroker_installer.msi",
		"amibroker_ib.dll",
		"ami_credentials.json",
	}
	no := []string{"", "factura.xml", "random.bin", "report.pdf"}
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
		"broker.txt":              KindConfig,
		"ami_credentials.json":    KindCredentials,
		"ami_api_token.json":      KindCredentials,
		"my_strategy.afl":         KindAFLFormula,
		"my_project.apx":          KindAPXProject,
		"GGAL_intraday.adat":      KindADATDatabase,
		"my_workspace.awx":        KindWorkspace,
		"my_chart.cdl":            KindLayout,
		"autotrade.ini":           KindAutotradeConfig,
		"auto_trade_cfg.json":     KindAutotradeConfig,
		"trade_log_202506.csv":    KindTradeLog,
		"backtest_report.csv":     KindBacktestReport,
		"amibroker_ib.dll":        KindBrokerPlugin,
		"amibroker_installer.msi": KindInstaller,
		"":                        KindUnknown,
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
	if PeriodFromFilename("trade_log_202506.csv") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.csv") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsBYMAEquityTicker(t *testing.T) {
	yes := []string{"GGAL", "YPFD", "PAMP", "EDN", "TXAR", "BMA", "ALUA"}
	no := []string{"", "AAPL", "ES", "AL30"}
	for _, v := range yes {
		if !IsBYMAEquityTicker(v) {
			t.Fatalf("expected BYMA: %q", v)
		}
	}
	for _, v := range no {
		if IsBYMAEquityTicker(v) {
			t.Fatalf("expected NOT BYMA: %q", v)
		}
	}
}

func TestIsMERVIndexSymbol(t *testing.T) {
	yes := []string{"MERV", "MERVAL", "MERVAL25"}
	no := []string{"", "GGAL", "AAPL"}
	for _, v := range yes {
		if !IsMERVIndexSymbol(v) {
			t.Fatalf("expected MERV: %q", v)
		}
	}
	for _, v := range no {
		if IsMERVIndexSymbol(v) {
			t.Fatalf("expected NOT MERV: %q", v)
		}
	}
}

func TestIsARBondTicker(t *testing.T) {
	yes := []string{"AL30", "GD30", "AE38", "AL30D", "GD35D", "BONCER"}
	no := []string{"", "GGAL", "MERV"}
	for _, v := range yes {
		if !IsARBondTicker(v) {
			t.Fatalf("expected bond: %q", v)
		}
	}
	for _, v := range no {
		if IsARBondTicker(v) {
			t.Fatalf("expected NOT bond: %q", v)
		}
	}
}

func TestIsCEDEARTicker(t *testing.T) {
	yes := []string{"AAPLD", "MSFTD", "TSLAD", "AMZNC"}
	no := []string{"", "GGAL", "AL30", "ES"}
	for _, v := range yes {
		if !IsCEDEARTicker(v) {
			t.Fatalf("expected CEDEAR: %q", v)
		}
	}
	for _, v := range no {
		if IsCEDEARTicker(v) {
			t.Fatalf("expected NOT CEDEAR: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindAFLFormula, KindAPXProject,
		KindWorkspace, KindBrokerPlugin, KindAutotradeConfig,
		KindBacktestReport, KindTradeLog, KindLayout,
	}
	no := []ArtifactKind{
		KindADATDatabase, KindInstaller, KindOther, KindUnknown,
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

func TestAnnotatePluginDLL(t *testing.T) {
	r := Row{ArtifactKind: KindBrokerPlugin}
	AnnotateSecurity(&r)
	if !r.HasPluginDLL {
		t.Fatal("plug-in kind must auto-flag")
	}
}

func TestAnnotateLargeADATCache(t *testing.T) {
	r := Row{
		ArtifactKind: KindADATDatabase,
		FileSize:     LargeADATCacheBytes + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasLargeADATCache {
		t.Fatal("large .adat must flag")
	}
}

func TestAnnotateAFLWithOrders(t *testing.T) {
	r := Row{
		ArtifactKind:        KindAFLFormula,
		OrderStatementCount: 3,
	}
	AnnotateSecurity(&r)
	if !r.HasAFLWithOrders {
		t.Fatal("AFL with orders must flag")
	}
}

func TestAnnotateLiveTradeLog(t *testing.T) {
	r := Row{
		ArtifactKind: KindTradeLog,
		FillCount:    5,
	}
	AnnotateSecurity(&r)
	if !r.HasLiveTradeLog {
		t.Fatal("trade log with fills must flag live")
	}
}

func TestAnnotateBYMACounts(t *testing.T) {
	r := Row{
		ArtifactKind:       KindAFLFormula,
		BYMATickersCount:   3,
		CEDEARTickersCount: 2,
		ARBondTickersCount: 1,
	}
	AnnotateSecurity(&r)
	if !r.HasBYMAEquity {
		t.Fatal("BYMA count must flag")
	}
	if !r.HasCEDEAR {
		t.Fatal("CEDEAR count must flag")
	}
	if !r.HasARBond {
		t.Fatal("AR bond count must flag")
	}
}

func TestParseAmiConfig(t *testing.T) {
	body := []byte(`# Broker.txt
[IB]
tws_port=7497
tws_username=alice
broker_password=secret123
ami_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
cliente_cuit=27-11111111-4
`)
	f := ParseAmiConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if !f.HasBrokerPluginCreds {
		t.Fatal("plug-in creds must flag")
	}
	if f.BrokerPlugin != PluginIB {
		t.Fatalf("plugin=%q want ib", f.BrokerPlugin)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseAmiAFLFormula(t *testing.T) {
	body := []byte(`// Strategy for GGAL momentum
Buy = (Symbol() == "GGAL") AND Cross(MACD(), Signal());
Sell = (RSI(14) > 70);
BuyPrice = Open;
SellPrice = Close;
PositionSize = 100;
`)
	f := ParseAmiAFLFormula(body)
	if f.OrderStatementCount < 3 {
		t.Fatalf("orders=%d want >=3", f.OrderStatementCount)
	}
	if f.BYMATickersCount < 1 {
		t.Fatalf("byma=%d", f.BYMATickersCount)
	}
}

func TestParseAmiAutotradeConfig(t *testing.T) {
	body := []byte(`<AutoTrade>
AutoTradeEnabled=1
[IB]
tws_port=7497
tws_username=alice
Symbol("GGAL")
AddSymbol("YPFD")
</AutoTrade>
`)
	f := ParseAmiAutotradeConfig(body)
	if !f.HasAutotradeArmed {
		t.Fatal("autotrade armed must flag")
	}
	if !f.HasBrokerPluginCreds {
		t.Fatal("plug-in creds must flag")
	}
	if f.BYMATickersCount < 2 {
		t.Fatalf("byma=%d", f.BYMATickersCount)
	}
}

func TestParseAmiTradeLog(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 OrderFilled symbol=GGAL qty=100 px=1234.5
2026-06-15 09:30:02 OrderFilled symbol=YPFD qty=200 px=5400.25
2026-06-15 09:30:03 OrderFilled symbol=AAPLD qty=50 px=180.5
2026-06-15 09:30:04 FillEvent symbol=AL30 qty=10000 px=58
`)
	f := ParseAmiTradeLog(body)
	if f.FillCount < 4 {
		t.Fatalf("fills=%d", f.FillCount)
	}
	if f.BYMATickersCount < 2 {
		t.Fatalf("byma=%d", f.BYMATickersCount)
	}
	if f.CEDEARTickersCount < 1 {
		t.Fatalf("cedear=%d", f.CEDEARTickersCount)
	}
	if f.ARBondTickersCount < 1 {
		t.Fatalf("bond=%d", f.ARBondTickersCount)
	}
}

func TestParseAmiBrokerPlugin(t *testing.T) {
	f := ParseAmiBrokerPlugin(nil, "amibroker_iol.dll")
	if f.PluginDLLName == "" {
		t.Fatal("dll name must extract")
	}
	if f.BrokerPlugin != PluginIOL {
		t.Fatalf("plugin=%q want iol", f.BrokerPlugin)
	}
}

func TestDetectBrokerPluginFromName(t *testing.T) {
	cases := map[string]BrokerPlugin{
		"amibroker_ib.dll":    PluginIB,
		"amibroker_iol.dll":   PluginIOL,
		"amibroker_cocos.dll": PluginCocos,
		"amibroker_byma.dll":  PluginBYMA,
		"amibroker_rofex.dll": PluginROFEX,
		"tws_plugin.dll":      PluginTWS,
		"my_plugin.dll":       PluginCustom,
		"nothing.dll":         PluginUnknown,
	}
	for in, want := range cases {
		got := detectBrokerPluginFromName(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseAmiEmpty(t *testing.T) {
	f := ParseAmiConfig(nil)
	if f.HasPassword || f.APIKey != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{BYMATickersCount: 1, ARBondTickersCount: 1}); got != ProductMultiAsset {
		t.Fatalf("multi -> multi-asset, got %q", got)
	}
	if got := classifyProduct(Row{HasMERVStrategy: true}); got != ProductMERVIndex {
		t.Fatalf("merv -> merv-index, got %q", got)
	}
	if got := classifyProduct(Row{BYMATickersCount: 1}); got != ProductBYMAEquity {
		t.Fatalf("byma -> byma-equity, got %q", got)
	}
	if got := classifyProduct(Row{CEDEARTickersCount: 1}); got != ProductARCEDEARs {
		t.Fatalf("cedear -> ar-cedears, got %q", got)
	}
	if got := classifyProduct(Row{ARBondTickersCount: 1}); got != ProductARBonds {
		t.Fatalf("bond -> ar-bonds, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{
		HasAutotradeArmed: true,
		HasAFLWithOrders:  true,
	}); got != AccountAlgotrader {
		t.Fatalf("armed + orders -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{HasAutotradeArmed: true}); got != AccountAlgotrader {
		t.Fatalf("armed -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{
		ArtifactKind:        KindAFLFormula,
		OrderStatementCount: 3,
	}); got != AccountAlgotrader {
		t.Fatalf("afl orders -> algotrader, got %q", got)
	}
	if got := classifyAccount(Row{ArtifactKind: KindBacktestReport}); got != AccountBacktestResearcher {
		t.Fatalf("backtest -> researcher, got %q", got)
	}
	if got := classifyAccount(Row{HasLiveTradeLog: true}); got != AccountEquityDaytrader {
		t.Fatalf("live -> daytrader, got %q", got)
	}
	if got := classifyAccount(Row{BYMATickersCount: 1, HasBYMAEquity: true}); got != AccountEquityDaytrader {
		t.Fatalf("byma -> daytrader, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	formulas := filepath.Join(usersBase, "alice", "Documents", "AmiBroker", "Formulas")
	must(t, os.MkdirAll(formulas, 0o755))

	brokerPath := filepath.Join(usersBase, "alice", "Documents", "AmiBroker", "broker.txt")
	must(t, os.WriteFile(brokerPath, []byte(`[IB]
tws_port=7497
tws_username=alice
broker_password=secret123
ami_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
cliente_cuit=27-11111111-4
`), 0o644))

	aflPath := filepath.Join(formulas, "ggal_momentum.afl")
	must(t, os.WriteFile(aflPath, []byte(`// Strategy for GGAL momentum
Buy = (Symbol() == "GGAL") AND Cross(MACD(), Signal());
Sell = (RSI(14) > 70);
BuyPrice = Open;
SellPrice = Close;
PositionSize = 100;
`), 0o644))

	autotradePath := filepath.Join(usersBase, "alice", "Documents", "AmiBroker", "autotrade.ini")
	must(t, os.WriteFile(autotradePath, []byte(`<AutoTrade>
AutoTradeEnabled=1
[IB]
tws_port=7497
tws_username=alice
Symbol("GGAL")
AddSymbol("YPFD")
</AutoTrade>
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(formulas, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "AmiBroker")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "broker.txt"),
		[]byte(`[IB]`), 0o644))

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
		t.Fatalf("want 3 (broker+afl+autotrade), got %d: %+v", len(got), got)
	}

	var bk, afl, at Row
	for _, r := range got {
		switch r.FilePath {
		case brokerPath:
			bk = r
		case aflPath:
			afl = r
		case autotradePath:
			at = r
		}
	}

	if bk.ArtifactKind != KindConfig {
		t.Fatalf("broker kind=%q", bk.ArtifactKind)
	}
	if !bk.HasPasswordInConfig {
		t.Fatalf("broker must flag password: %+v", bk)
	}
	if !bk.HasBrokerPluginCredentials {
		t.Fatalf("broker must flag plug-in creds: %+v", bk)
	}
	if bk.BrokerPlugin != PluginIB {
		t.Fatalf("broker plugin=%q want ib", bk.BrokerPlugin)
	}
	if !bk.HasClienteCuit {
		t.Fatalf("broker must flag cliente cuit: %+v", bk)
	}
	if !bk.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cliente = exposure: %+v", bk)
	}

	if afl.ArtifactKind != KindAFLFormula {
		t.Fatalf("afl kind=%q", afl.ArtifactKind)
	}
	if !afl.HasAFLWithOrders {
		t.Fatalf("afl must flag orders: %+v", afl)
	}
	if !afl.HasBYMAEquity {
		t.Fatalf("afl must flag BYMA: %+v", afl)
	}
	if afl.AccountClass != AccountAlgotrader {
		t.Fatalf("afl account=%q want algotrader", afl.AccountClass)
	}

	if at.ArtifactKind != KindAutotradeConfig {
		t.Fatalf("autotrade kind=%q", at.ArtifactKind)
	}
	if !at.HasAutotradeArmed {
		t.Fatalf("autotrade must flag armed: %+v", at)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-ami")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "broker.txt"),
		[]byte(`[IB]
tws_username=alice
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "AMIBROKER_DIR" {
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
		installRoots: []string{"/nope-ami"},
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
		{FilePath: "a", ArtifactKind: KindTradeLog},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,ami-config)", in[0])
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
