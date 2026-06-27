package winargsterling

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "sterling-config"},
		{string(KindLayout), "sterling-layout"},
		{string(KindHotKeys), "sterling-hotkeys"},
		{string(KindOrderLog), "sterling-orderlog"},
		{string(AccountPropFirmTrainee), "prop-firm-trainee"},
		{string(AccountPatternDayTrader), "pattern-day-trader"},
		{string(ProductUSEquity), "us-equity"},
		{string(PropFirmSMBCapital), "smb-capital"},
		{string(PropFirmSterlingEquities), "sterling-equities"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"sterling.cfg",
		"my_layout.stx",
		"HotKeys.cfg",
		"orderlog_20260615.csv",
		"branch.cfg",
		"trader_risk_limits.cfg",
		"shortlocate_20260615.log",
		"dma_route_nyse.cfg",
		"sterling_installer.msi",
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
		"sterling.cfg":             KindConfig,
		"my_layout.stx":            KindLayout,
		"hotkeys.cfg":              KindHotKeys,
		"chartdef.cfg":             KindChartDef,
		"dma_route_nyse.cfg":       KindDMARoute,
		"branch.cfg":               KindBranchConfig,
		"trader_risk_limits.cfg":   KindTraderRiskLimits,
		"clearing.cfg":             KindClearingConfig,
		"orderlog_20260615.csv":    KindOrderLog,
		"shortlocate_20260615.log": KindShortLocateLog,
		"fix_route_nasdaq.cfg":     KindFIXRoute,
		"sterling_installer.msi":   KindInstaller,
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
		KindChartDef, KindDMARoute, KindBranchConfig,
		KindTraderRiskLimits, KindClearingConfig,
		KindOrderLog, KindShortLocateLog, KindFIXRoute,
	}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected cred kind: %q", k)
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

func TestAnnotateHotKeyAuto(t *testing.T) {
	r := Row{ArtifactKind: KindHotKeys, HotKeyCount: 5}
	AnnotateSecurity(&r)
	if !r.HasHotKeyOneClick {
		t.Fatal("hotkey count must flag")
	}
}

func TestAnnotateDMAAuto(t *testing.T) {
	r := Row{ArtifactKind: KindDMARoute}
	AnnotateSecurity(&r)
	if !r.HasDMARouteConfig {
		t.Fatal("DMA route kind must auto-flag")
	}
}

func TestAnnotatePDT(t *testing.T) {
	r := Row{ArtifactKind: KindOrderLog, FillCount: 10}
	AnnotateSecurity(&r)
	if !r.HasPatternDayTrader {
		t.Fatal("≥4 fills in orderlog must flag PDT")
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

func TestParseSterlingConfig(t *testing.T) {
	body := []byte(`[Sterling]
sterling_username=alice@example.com
sterling_password=secret123
sterling_api_key=aBcDeFgHiJkLmNoPqRsTuVwX12345
trader_id=A123
branch_id=B05
prop_firm=SMB Capital
symbol=AAPL
symbol=MSFT
cliente_cuit=27-11111111-4
`)
	f := ParseSterlingConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.SterlingTraderID != "A123" {
		t.Fatalf("trader=%q", f.SterlingTraderID)
	}
	if f.SterlingBranchID != "B05" {
		t.Fatalf("branch=%q", f.SterlingBranchID)
	}
	if f.PropFirm != PropFirmSMBCapital {
		t.Fatalf("prop firm=%q want smb-capital", f.PropFirm)
	}
	if f.USEquitySymbolsCount < 2 {
		t.Fatalf("us=%d", f.USEquitySymbolsCount)
	}
}

func TestParseSterlingHotKeys(t *testing.T) {
	body := []byte(`# HotKeys
Ctrl+1=BUY
Ctrl+3=SHORT
Ctrl+5=COVER
F2=CANCEL
Alt+F=FLATTEN
`)
	f := ParseSterlingHotKeys(body)
	if f.HotKeyCount < 5 {
		t.Fatalf("hotkeys=%d", f.HotKeyCount)
	}
}

func TestParseSterlingTraderRiskLimits(t *testing.T) {
	body := []byte(`trader_id=A123
daily_loss_limit=$5000
max_position=$50000
`)
	f := ParseSterlingTraderRiskLimits(body)
	if f.DailyLossLimitUSD != 5000 {
		t.Fatalf("daily loss=%d want 5000", f.DailyLossLimitUSD)
	}
	if f.MaxPositionUSD != 50000 {
		t.Fatalf("max pos=%d want 50000", f.MaxPositionUSD)
	}
}

func TestParseSterlingOrderLog(t *testing.T) {
	body := []byte(`OrdID,Symbol,Side,Qty,Px,FillTime
123,AAPL,BUY,100,200.50,09:30:01
124,MSFT,SHORT,50,425.10,09:30:02
125,TSLA,COVER,50,250.75,09:30:03
trader_id=A123
`)
	f := ParseSterlingOrderLog(body)
	if f.FillCount < 3 {
		t.Fatalf("fills=%d", f.FillCount)
	}
	if f.SterlingTraderID != "A123" {
		t.Fatalf("trader=%q", f.SterlingTraderID)
	}
	if f.USEquitySymbolsCount < 1 {
		t.Fatalf("us=%d", f.USEquitySymbolsCount)
	}
}

func TestDetectPropFirm(t *testing.T) {
	cases := map[string]PropFirm{
		`prop_firm=SMB Capital`:       PropFirmSMBCapital,
		`prop_firm=T3 Live`:           PropFirmT3Live,
		`prop_firm=CenterPoint`:       PropFirmCenterPoint,
		`prop_firm=Bright Trading`:    PropFirmBrightTrading,
		`prop_firm=Hold Brothers`:     PropFirmHoldBrothers,
		`prop_firm=Sterling Equities`: PropFirmSterlingEquities,
		`# generic config`:            PropFirmUnknown,
	}
	for in, want := range cases {
		got := detectPropFirm([]byte(in))
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{
		ArtifactKind:       KindBranchConfig,
		HasBranchHierarchy: true,
	}); got != AccountBranchAdmin {
		t.Fatalf("branch -> branch-admin, got %q", got)
	}
	if got := classifyAccount(Row{HasPatternDayTrader: true}); got != AccountPatternDayTrader {
		t.Fatalf("PDT -> pattern-day-trader, got %q", got)
	}
	if got := classifyAccount(Row{HasHotKeyOneClick: true}); got != AccountScalper {
		t.Fatalf("hotkey -> scalper, got %q", got)
	}
	if got := classifyAccount(Row{PropFirm: PropFirmSMBCapital}); got != AccountPropFirmTrainee {
		t.Fatalf("smb -> prop-firm-trainee, got %q", got)
	}
	if got := classifyAccount(Row{HasClearingCredentials: true}); got != AccountComplianceOfficer {
		t.Fatalf("clearing -> compliance, got %q", got)
	}
	if got := classifyAccount(Row{HasDMARouteConfig: true}); got != AccountPropTrader {
		t.Fatalf("dma -> prop-trader, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Sterling Trader")
	must(t, os.MkdirAll(dir, 0o755))

	cfgPath := filepath.Join(dir, "sterling.cfg")
	must(t, os.WriteFile(cfgPath, []byte(`sterling_username=alice@example.com
sterling_password=secret123
trader_id=A123
branch_id=B05
prop_firm=SMB Capital
symbol=AAPL
cliente_cuit=27-11111111-4
`), 0o644))

	hkPath := filepath.Join(dir, "HotKeys.cfg")
	must(t, os.WriteFile(hkPath, []byte(`Ctrl+1=BUY
Ctrl+3=SHORT
`), 0o644))

	olPath := filepath.Join(dir, "orderlog_20260615.csv")
	must(t, os.WriteFile(olPath, []byte(`OrdID,Symbol,Side,Qty,Px,FillTime
123,AAPL,BUY,100,200.50,09:30:01
124,MSFT,SHORT,50,425.10,09:30:02
125,TSLA,COVER,50,250.75,09:30:03
126,NVDA,BUY,100,900.00,09:30:04
127,SPY,SELL,50,500.00,09:30:05
`), 0o644))

	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	pub := filepath.Join(usersBase, "Public", "Sterling Trader")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "sterling.cfg"),
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
	if len(got) != 3 {
		t.Fatalf("want 3 (cfg+hk+ol), got %d: %+v", len(got), got)
	}

	var cfg, hk, ol Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case hkPath:
			hk = r
		case olPath:
			ol = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if cfg.PropFirm != PropFirmSMBCapital {
		t.Fatalf("cfg prop=%q want smb-capital", cfg.PropFirm)
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

	if ol.ArtifactKind != KindOrderLog {
		t.Fatalf("ol kind=%q", ol.ArtifactKind)
	}
	if !ol.HasOrderLogExport {
		t.Fatalf("ol must auto-flag: %+v", ol)
	}
	if !ol.HasPatternDayTrader {
		t.Fatalf("ol must flag PDT: %+v", ol)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-sterling"},
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
