package winargdas

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "das-config"},
		{string(KindCredentials), "das-credentials"},
		{string(KindLayout), "das-layout"},
		{string(KindHotKeys), "das-hotkeys"},
		{string(KindScript), "das-script"},
		{string(KindRoute), "das-route"},
		{string(KindClearingConfig), "das-clearing-config"},
		{string(KindOrderLog), "das-orderlog"},
		{string(KindShortLocateLog), "das-short-locate-log"},
		{string(KindAPIToken), "das-api-token"},
		{string(KindMobileToken), "das-mobile-token"},
		{string(KindInstaller), "das-installer"},
		{string(AccountPropFirmTrainee), "prop-firm-trainee"},
		{string(AccountPatternDayTrader), "pattern-day-trader"},
		{string(AccountScalper), "scalper"},
		{string(AccountComplianceOfficer), "compliance-officer"},
		{string(ProductUSEquity), "us-equity"},
		{string(ProductUSOptions), "us-options"},
		{string(ProductMultiAsset), "multi-asset"},
		{string(ClearingStratos), "stratos"},
		{string(ClearingCenterpoint), "centerpoint"},
		{string(ClearingAllianceTrader), "alliance-trader"},
		{string(PropFirmBearBullTraders), "bear-bull-traders"},
		{string(PropFirmInvestorsUnderground), "investors-underground"},
		{string(PropFirmWarriorTrading), "warrior-trading"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"das_trader.cfg",
		"my_layout.das",
		"HotKeys.cfg",
		"orderlog_20260615.csv",
		"shortlocate_20260615.log",
		"stratos.cfg",
		"centerpoint.cfg",
		"alliance_trader.cfg",
		"clearing.cfg",
		"das_api.token",
		"das_mobile.token",
		"my_script.script",
		"strategy.dasscript",
		"dasinet_route_arca.cfg",
		"das_trader_installer.msi",
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
		"das_trader.cfg":           KindConfig,
		"my_layout.das":            KindLayout,
		"hotkeys.cfg":              KindHotKeys,
		"my_strategy.script":       KindScript,
		"momentum.dasscript":       KindScript,
		"dasinet_route_arca.cfg":   KindRoute,
		"stratos.cfg":              KindClearingConfig,
		"centerpoint.cfg":          KindClearingConfig,
		"clearing.cfg":             KindClearingConfig,
		"orderlog_20260615.csv":    KindOrderLog,
		"shortlocate_20260615.log": KindShortLocateLog,
		"das_api_token.json":       KindAPIToken,
		"das_mobile_token.json":    KindMobileToken,
		"das_trader_installer.msi": KindInstaller,
		"credentials.json":         KindCredentials,
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
		"orderlog_20260615.csv":    "202606",
		"shortlocate_20260615.log": "202606",
		"das_trader.cfg":           "",
	}
	for in, want := range cases {
		if got := PeriodFromFilename(in); got != want {
			t.Fatalf("PeriodFromFilename(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsUSEquityStem(t *testing.T) {
	yes := []string{"AAPL", "MSFT", "SPY"}
	no := []string{"", "DLR", "ES"}
	for _, v := range yes {
		if !IsUSEquityStem(v) {
			t.Fatalf("expected US: %q", v)
		}
	}
	for _, v := range no {
		if IsUSEquityStem(v) {
			t.Fatalf("expected NOT US: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindLayout, KindHotKeys,
		KindScript, KindRoute, KindClearingConfig,
		KindOrderLog, KindShortLocateLog,
		KindAPIToken, KindMobileToken,
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
		ArtifactKind:        KindClearingConfig,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.HasClearingCredentials {
		t.Fatal("clearing kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + cliente = exposure")
	}
}

func TestAnnotateScriptAuto(t *testing.T) {
	r := Row{ArtifactKind: KindScript, ScriptSendOrderCount: 3}
	AnnotateSecurity(&r)
	if !r.HasDASScript {
		t.Fatal("script kind must flag DASScript")
	}
}

func TestAnnotateAPITokenAuto(t *testing.T) {
	r := Row{ArtifactKind: KindAPIToken}
	AnnotateSecurity(&r)
	if !r.HasAPICredentials {
		t.Fatal("api token kind must flag API creds")
	}
	r2 := Row{ArtifactKind: KindMobileToken}
	AnnotateSecurity(&r2)
	if !r2.HasAPICredentials {
		t.Fatal("mobile token kind must flag API creds")
	}
}

func TestAnnotateRouteAuto(t *testing.T) {
	r := Row{ArtifactKind: KindRoute}
	AnnotateSecurity(&r)
	if !r.HasDASInetRouting {
		t.Fatal("route kind must flag DAS Inet routing")
	}
}

func TestAnnotatePDT(t *testing.T) {
	r := Row{ArtifactKind: KindOrderLog, FillCount: 10}
	AnnotateSecurity(&r)
	if !r.HasPatternDayTrader {
		t.Fatal("≥4 fills in orderlog must flag PDT")
	}
	if !r.HasOrderLogExport {
		t.Fatal("orderlog kind must flag export")
	}
}

func TestAnnotateHighVolume(t *testing.T) {
	r := Row{
		ArtifactKind: KindOrderLog,
		FillCount:    HighVolumeTraderDailyFills + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasHighVolumeTrader {
		t.Fatal("> 1000 fills must flag high-volume")
	}
}

func TestParseDASConfig(t *testing.T) {
	body := []byte(`[DAS]
das_username=alice@example.com
das_password=secret123
das_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
trader_id=AABC1
clearing=Stratos
prop_firm=Bear Bull Traders
symbol=AAPL
symbol=MSFT
cliente_cuit=27-11111111-4
`)
	f := ParseDASConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.DASTraderID != "AABC1" {
		t.Fatalf("trader=%q", f.DASTraderID)
	}
	if f.ClearingFirm != ClearingStratos {
		t.Fatalf("clearing=%q want stratos", f.ClearingFirm)
	}
	if f.PropFirm != PropFirmBearBullTraders {
		t.Fatalf("prop firm=%q want bear-bull-traders", f.PropFirm)
	}
	if f.USEquitySymbolsCount < 2 {
		t.Fatalf("us=%d", f.USEquitySymbolsCount)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cuit must extract")
	}
}

func TestParseDASScript(t *testing.T) {
	body := []byte(`# DASScript momentum strategy
DEFSYM:AAPL
IF AAPL.Price > AAPL.PrevClose THEN
  SEND_ORDER(BUY, AAPL, 100, MARKET);
  SUBMIT_ORDER(SELL, AAPL, 100, LIMIT, 200.50);
  PLACE_ORDER(SHORT, MSFT, 50, MARKET);
ENDIF
`)
	f := ParseDASScript(body)
	if f.ScriptSendOrderCount < 3 {
		t.Fatalf("send-order count=%d want >=3", f.ScriptSendOrderCount)
	}
}

func TestParseDASHotKeys(t *testing.T) {
	body := []byte(`# HotKeys
Ctrl+1=BUY
Ctrl+3=SHORT
Ctrl+5=COVER
F2=CANCEL
Alt+F=FLATTEN
Ctrl-Alt-1=BUY
Ctrl-Alt-3=SHORT
`)
	f := ParseDASHotKeys(body)
	if f.HotKeyCount < 5 {
		t.Fatalf("hotkeys=%d", f.HotKeyCount)
	}
	if f.ChordHotKeyCount < 2 {
		t.Fatalf("chord hotkeys=%d", f.ChordHotKeyCount)
	}
}

func TestParseDASOrderLog(t *testing.T) {
	body := []byte(`Time,OrderID,Symbol,Side,Qty,Price
09:30:01,123,AAPL,BUY,100,200.50
09:30:02,124,MSFT,SHORT,50,425.10
09:30:03,125,TSLA,COVER,50,250.75
09:30:04,126,NVDA,BUY,100,900.00
09:30:05,127,SPY,SELL,50,500.00
trader_id=AABC1
`)
	f := ParseDASOrderLog(body)
	if f.FillCount < 5 {
		t.Fatalf("fills=%d", f.FillCount)
	}
	if f.DASTraderID != "AABC1" {
		t.Fatalf("trader=%q", f.DASTraderID)
	}
	if f.USEquitySymbolsCount < 1 {
		t.Fatalf("us=%d", f.USEquitySymbolsCount)
	}
}

func TestParseDASRoute(t *testing.T) {
	body := []byte(`[DASInet]
route=ARCA
exchange=NSDQ
`)
	f := ParseDASRoute(body)
	if !f.HasDASInetRoute {
		t.Fatal("route body must flag DAS Inet route")
	}
}

func TestDetectClearingFirm(t *testing.T) {
	cases := map[string]ClearingFirm{
		`clearing=Stratos`:                ClearingStratos,
		`clearing=Centerpoint`:            ClearingCenterpoint,
		`clearing=Centerpoint Securities`: ClearingCenterpointSecurities,
		`clearing=Alliance Trader`:        ClearingAllianceTrader,
		`clearing=Velocity`:               ClearingVelocity,
		`clearing=Ironbeam`:               ClearingIronbeam,
		`clearing=SureTrader`:             ClearingSureTrader,
		`clearing=DAS Clearing`:           ClearingDAS,
		`# generic config`:                ClearingUnknown,
	}
	for in, want := range cases {
		got := detectClearingFirm([]byte(in))
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectPropFirm(t *testing.T) {
	cases := map[string]PropFirm{
		`prop_firm=Bear Bull Traders`:     PropFirmBearBullTraders,
		`prop_firm=Investors Underground`: PropFirmInvestorsUnderground,
		`prop_firm=Warrior Trading`:       PropFirmWarriorTrading,
		`prop_firm=Simpler Trading`:       PropFirmSimplerTrading,
		`prop_firm=TradeNet Strategies`:   PropFirmTradeNetStrategies,
		`prop_firm=Maverick Trading`:      PropFirmMaverickTrading,
		`# generic config`:                PropFirmUnknown,
	}
	for in, want := range cases {
		got := detectPropFirm([]byte(in))
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{HasPatternDayTrader: true}); got != AccountPatternDayTrader {
		t.Fatalf("PDT -> pattern-day-trader, got %q", got)
	}
	if got := classifyAccount(Row{HasClearingCredentials: true}); got != AccountComplianceOfficer {
		t.Fatalf("clearing -> compliance, got %q", got)
	}
	if got := classifyAccount(Row{ChordHotKeyCount: 3}); got != AccountScalper {
		t.Fatalf("chord -> scalper, got %q", got)
	}
	if got := classifyAccount(Row{HasHighVolumeTrader: true}); got != AccountScalper {
		t.Fatalf("high-volume -> scalper, got %q", got)
	}
	if got := classifyAccount(Row{HasDASScript: true}); got != AccountPropTrader {
		t.Fatalf("script -> prop-trader, got %q", got)
	}
	if got := classifyAccount(Row{PropFirm: PropFirmBearBullTraders}); got != AccountPropFirmTrainee {
		t.Fatalf("bbt -> prop-firm-trainee, got %q", got)
	}
	if got := classifyAccount(Row{HasOrderLogExport: true}); got != AccountUSEquityDaytrader {
		t.Fatalf("orderlog -> us-equity-daytrader, got %q", got)
	}
	if got := classifyAccount(Row{HasDASInetRouting: true}); got != AccountPropTrader {
		t.Fatalf("dasinet -> prop-trader, got %q", got)
	}
	if got := classifyAccount(Row{HasAPICredentials: true}); got != AccountAPI {
		t.Fatalf("api -> api, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{HasUSEquity: true, HasOptionsChain: true}); got != ProductMultiAsset {
		t.Fatalf("us+opt -> multi-asset, got %q", got)
	}
	if got := classifyProduct(Row{HasOptionsChain: true}); got != ProductUSOptions {
		t.Fatalf("opt -> us-options, got %q", got)
	}
	if got := classifyProduct(Row{HasUSEquity: true}); got != ProductUSEquity {
		t.Fatalf("us -> us-equity, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "DAS Trader")
	must(t, os.MkdirAll(dir, 0o755))

	cfgPath := filepath.Join(dir, "das_trader.cfg")
	must(t, os.WriteFile(cfgPath, []byte(`das_username=alice@example.com
das_password=secret123
trader_id=AABC1
clearing=Stratos
prop_firm=Bear Bull Traders
symbol=AAPL
cliente_cuit=27-11111111-4
`), 0o644))

	hkPath := filepath.Join(dir, "HotKeys.cfg")
	must(t, os.WriteFile(hkPath, []byte(`Ctrl+1=BUY
Ctrl-Alt-1=BUY
Ctrl-Alt-3=SHORT
`), 0o644))

	scriptPath := filepath.Join(dir, "momentum.dasscript")
	must(t, os.WriteFile(scriptPath, []byte(`IF AAPL.Price > AAPL.PrevClose THEN
  SEND_ORDER(BUY, AAPL, 100, MARKET);
ENDIF
`), 0o644))

	olPath := filepath.Join(dir, "orderlog_20260615.csv")
	must(t, os.WriteFile(olPath, []byte(`Time,OrderID,Symbol,Side,Qty,Price
09:30:01,123,AAPL,BUY,100,200.50
09:30:02,124,MSFT,SHORT,50,425.10
09:30:03,125,TSLA,COVER,50,250.75
09:30:04,126,NVDA,BUY,100,900.00
09:30:05,127,SPY,SELL,50,500.00
`), 0o644))

	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	pub := filepath.Join(usersBase, "Public", "DAS Trader")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "das_trader.cfg"),
		[]byte(`# public`), 0o644))

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
	if len(got) != 4 {
		t.Fatalf("want 4 (cfg+hk+script+ol), got %d: %+v", len(got), got)
	}

	var cfg, hk, sc, ol Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case hkPath:
			hk = r
		case scriptPath:
			sc = r
		case olPath:
			ol = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if cfg.ClearingFirm != ClearingStratos {
		t.Fatalf("cfg clearing=%q want stratos", cfg.ClearingFirm)
	}
	if cfg.PropFirm != PropFirmBearBullTraders {
		t.Fatalf("cfg prop=%q want bear-bull-traders", cfg.PropFirm)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cliente = exposure: %+v", cfg)
	}

	if hk.ArtifactKind != KindHotKeys {
		t.Fatalf("hk kind=%q", hk.ArtifactKind)
	}
	if !hk.HasHotKeyOneClick {
		t.Fatalf("hk must flag: %+v", hk)
	}
	if hk.ChordHotKeyCount < 2 {
		t.Fatalf("hk chord count=%d", hk.ChordHotKeyCount)
	}
	if hk.AccountClass != AccountScalper {
		t.Fatalf("hk should classify as scalper (chord), got %q", hk.AccountClass)
	}

	if sc.ArtifactKind != KindScript {
		t.Fatalf("sc kind=%q", sc.ArtifactKind)
	}
	if !sc.HasDASScript {
		t.Fatalf("sc must flag DASScript: %+v", sc)
	}
	if sc.ScriptSendOrderCount < 1 {
		t.Fatalf("sc send-order count=%d", sc.ScriptSendOrderCount)
	}

	if ol.ArtifactKind != KindOrderLog {
		t.Fatalf("ol kind=%q", ol.ArtifactKind)
	}
	if !ol.HasOrderLogExport {
		t.Fatalf("ol must auto-flag: %+v", ol)
	}
	if !ol.HasPatternDayTrader {
		t.Fatalf("ol must flag PDT: %+v", ol)
	}
	if ol.AccountClass != AccountPatternDayTrader {
		t.Fatalf("ol should classify as pattern-day-trader, got %q", ol.AccountClass)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-das")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "das_trader.cfg"),
		[]byte(`das_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "DAS_DIR" {
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
		installRoots: []string{"/nope-das"},
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
		{FilePath: "/b", ArtifactKind: KindConfig},
		{FilePath: "/a", ArtifactKind: KindOrderLog},
		{FilePath: "/a", ArtifactKind: KindConfig},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindConfig {
		t.Fatalf("sort drift: %+v", rs)
	}
	if rs[1].FilePath != "/a" || rs[1].ArtifactKind != KindOrderLog {
		t.Fatalf("sort drift: %+v", rs)
	}
	if rs[2].FilePath != "/b" {
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
