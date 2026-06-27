package winargoms

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindOrderBlotter), "oms-order-blotter"},
		{string(KindFillReport), "oms-fill-report"},
		{string(KindBestExReport), "oms-best-ex-report"},
		{string(KindAllocation), "oms-allocation"},
		{string(KindTCAReport), "oms-tca-report"},
		{string(KindBrokerList), "oms-broker-list"},
		{string(KindOrderAuditTrail), "oms-order-audit-trail"},
		{string(KindPreTradeCompliance), "oms-pre-trade-compliance"},
		{string(KindRestrictedList), "oms-restricted-list"},
		{string(KindWatchList), "oms-watch-list"},
		{string(KindBlockTrade), "oms-block-trade"},
		{string(KindCrossTrade), "oms-cross-trade"},
		{string(KindCNVRG731Report), "oms-cnv-rg731-report"},
		{string(KindFIXSessionConfig), "oms-fix-session-config"},
		{string(PlatformCharlesRiver), "charles-river"},
		{string(PlatformBloombergAIM), "bloomberg-aim"},
		{string(PlatformEze), "eze"},
		{string(RolePortfolioManager), "portfolio-manager"},
		{string(RoleHeadTrader), "head-trader"},
		{string(RoleCCO), "cco"},
		{string(SideBuy), "buy"},
		{string(SideShortSell), "short-sell"},
		{string(TypeVWAP), "vwap"},
		{string(TypeDarkPool), "dark-pool"},
		{string(VenueBYMA), "byma"},
		{string(VenueMATbaRofex), "matba-rofex"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"order_blotter_20260624.csv",
		"fill_report_20260624.csv",
		"best_ex_report_2026q2.pdf",
		"allocation_FCI_PESOS_20260624.csv",
		"tca_report_BCBA_2026q2.pdf",
		"broker_list.json",
		"order_audit_trail_20260624.csv",
		"pre_trade_compliance.json",
		"restricted_list_202606.csv",
		"watch_list_202606.csv",
		"block_trade_20260624.csv",
		"cross_trade_20260624.csv",
		"cnv_rg731_report_2026.xml",
		"fix_session.cfg",
		"oms_config.ini",
		"charles_river_export.csv",
		"fidessa_blotter.fid",
		"bloomberg_aim_export.aim",
		"eze_oms_blotter.eze",
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
		"order_blotter_20260624.csv":     KindOrderBlotter,
		"fill_report_20260624.csv":       KindFillReport,
		"best_ex_report_2026q2.pdf":      KindBestExReport,
		"allocation_FCI_PESOS.csv":       KindAllocation,
		"tca_report_BCBA_2026q2.pdf":     KindTCAReport,
		"broker_list.json":               KindBrokerList,
		"order_audit_trail_20260624.csv": KindOrderAuditTrail,
		"oat_20260624.csv":               KindOrderAuditTrail,
		"pre_trade_compliance.json":      KindPreTradeCompliance,
		"restricted_list_202606.csv":     KindRestrictedList,
		"watch_list_202606.csv":          KindWatchList,
		"block_trade_20260624.csv":       KindBlockTrade,
		"cross_trade_20260624.csv":       KindCrossTrade,
		"cnv_rg731_report_2026.xml":      KindCNVRG731Report,
		"fix_session.cfg":                KindFIXSessionConfig,
		"oms_config.ini":                 KindConfig,
		"credentials.json":               KindCredentials,
		"charles_river_setup.msi":        KindInstaller,
		"":                               KindUnknown,
		"random_unrelated.txt":           KindOther,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestOMSPlatformFromName(t *testing.T) {
	cases := map[string]OMSPlatform{
		"charles_river_export.csv":  PlatformCharlesRiver,
		"crims_blotter.csv":         PlatformCharlesRiver,
		"fidessa_blotter.fid":       PlatformFidessa,
		"bloomberg_aim_export.aim":  PlatformBloombergAIM,
		"bloomberg_emsx_orders.csv": PlatformBloombergEMSX,
		"flextrade_fills.csv":       PlatformFlexTrade,
		"eze_oms_blotter.eze":       PlatformEze,
		"itiviti_export.csv":        PlatformItiviti,
		"tradingscreen_blotter.csv": PlatformTradingScreen,
		"imatch_orders.csv":         PlatformIMatch,
		"portware_executions.csv":   PlatformPortware,
		"random.txt":                PlatformUnknown,
	}
	for in, want := range cases {
		if got := OMSPlatformFromName(in); got != want {
			t.Fatalf("OMSPlatformFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectOrderSide(t *testing.T) {
	cases := map[string]OrderSide{
		"buy":        SideBuy,
		"sell":       SideSell,
		"short":      SideShortSell,
		"short sell": SideShortSell,
		"short_sell": SideShortSell,
		"cover":      SideBuyCover,
		"buy cover":  SideBuyCover,
		"random":     SideUnknown,
	}
	for in, want := range cases {
		if got := detectOrderSide(in); got != want {
			t.Fatalf("detectOrderSide(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectOrderType(t *testing.T) {
	cases := map[string]OrderType{
		"market":     TypeMarket,
		"mkt":        TypeMarket,
		"limit":      TypeLimit,
		"lmt":        TypeLimit,
		"stop":       TypeStop,
		"stop_limit": TypeStopLimit,
		"vwap":       TypeVWAP,
		"twap":       TypeTWAP,
		"pegged":     TypePegged,
		"iceberg":    TypeIceberg,
		"dark_pool":  TypeDarkPool,
		"random":     TypeUnknown,
	}
	for in, want := range cases {
		if got := detectOrderType(in); got != want {
			t.Fatalf("detectOrderType(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectExecutionVenue(t *testing.T) {
	cases := map[string]ExecutionVenue{
		"byma":        VenueBYMA,
		"bcba":        VenueBYMA,
		"mae":         VenueMAE,
		"matba_rofex": VenueMATbaRofex,
		"matba":       VenueMATbaRofex,
		"rofex":       VenueMATbaRofex,
		"mav":         VenueMAV,
		"nyse":        VenueNYSE,
		"nasdaq":      VenueNASDAQ,
		"arca":        VenueARCA,
		"bats":        VenueBATS,
		"dark_pool":   VenueDarkPool,
		"otc":         VenueOTC,
		"random":      VenueUnknown,
	}
	for in, want := range cases {
		if got := detectExecutionVenue(in); got != want {
			t.Fatalf("detectExecutionVenue(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectOMSPlatform(t *testing.T) {
	cases := map[string]OMSPlatform{
		"Charles River": PlatformCharlesRiver,
		"CRIMS":         PlatformCharlesRiver,
		"Fidessa":       PlatformFidessa,
		"Bloomberg AIM": PlatformBloombergAIM,
		"EMSX":          PlatformBloombergEMSX,
		"FlexTrade":     PlatformFlexTrade,
		"Eze":           PlatformEze,
		"random":        PlatformUnknown,
	}
	for in, want := range cases {
		if got := detectOMSPlatform(in); got != want {
			t.Fatalf("detectOMSPlatform(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindOrderBlotter, KindFillReport,
		KindBestExReport, KindAllocation,
		KindTCAReport, KindBrokerList,
		KindOrderAuditTrail, KindPreTradeCompliance,
		KindRestrictedList, KindWatchList,
		KindBlockTrade, KindCrossTrade,
		KindCNVRG731Report, KindFIXSessionConfig,
		KindConfig, KindCredentials,
	}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected cred: %q", k)
		}
	}
	for _, k := range []ArtifactKind{KindInstaller, KindOther, KindUnknown} {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT cred: %q", k)
		}
	}
}

func TestIsBestExecutionDisclosureKind(t *testing.T) {
	yes := []ArtifactKind{
		KindBestExReport, KindTCAReport, KindBrokerList,
	}
	for _, k := range yes {
		if !IsBestExecutionDisclosureKind(k) {
			t.Fatalf("expected best-ex: %q", k)
		}
	}
	for _, k := range []ArtifactKind{
		KindOrderBlotter, KindFillReport, KindAllocation,
		KindOrderAuditTrail, KindPreTradeCompliance,
		KindRestrictedList, KindWatchList,
		KindBlockTrade, KindCrossTrade,
		KindCNVRG731Report, KindFIXSessionConfig,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown,
	} {
		if IsBestExecutionDisclosureKind(k) {
			t.Fatalf("expected NOT best-ex: %q", k)
		}
	}
}

func TestIsInsiderInformationKind(t *testing.T) {
	yes := []ArtifactKind{
		KindRestrictedList, KindWatchList,
		KindCrossTrade, KindPreTradeCompliance,
	}
	for _, k := range yes {
		if !IsInsiderInformationKind(k) {
			t.Fatalf("expected insider: %q", k)
		}
	}
}

func TestIsOrderAuditTrailKind(t *testing.T) {
	yes := []ArtifactKind{
		KindOrderAuditTrail, KindOrderBlotter,
		KindFillReport, KindAllocation, KindCNVRG731Report,
	}
	for _, k := range yes {
		if !IsOrderAuditTrailKind(k) {
			t.Fatalf("expected OAT: %q", k)
		}
	}
}

func TestAnnotateBestExecutionDisclosure(t *testing.T) {
	r := Row{
		ArtifactKind: KindBestExReport,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasBestExReport {
		t.Fatal("best-ex kind must flag")
	}
	if !r.IsBestExecutionDisclosureRisk {
		t.Fatal("readable + best-ex = disclosure risk")
	}
}

func TestAnnotateInsiderInformation(t *testing.T) {
	r := Row{
		ArtifactKind: KindRestrictedList,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasRestrictedList {
		t.Fatal("restricted-list must flag")
	}
	if !r.IsInsiderInformationRisk {
		t.Fatal("readable + restricted = insider risk")
	}
}

func TestAnnotateOrderAuditTrailLeak(t *testing.T) {
	r := Row{
		ArtifactKind: KindOrderAuditTrail,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasOrderAuditTrail {
		t.Fatal("OAT must flag")
	}
	if !r.IsOrderAuditTrailLeak {
		t.Fatal("readable + OAT = audit trail leak")
	}
}

func TestAnnotateCredentialExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindFIXSessionConfig,
		FileMode:            0o644,
		HasPasswordInConfig: true,
	}
	AnnotateSecurity(&r)
	if !r.HasFIXSessionConfig {
		t.Fatal("FIX session must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + FIX + password = credential exposure risk")
	}
}

func TestAnnotateLargeOrderValue(t *testing.T) {
	r := Row{
		ArtifactKind:            KindBlockTrade,
		LargestOrderNotionalARS: LargeOrderNotionalARSThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasLargeOrderValue {
		t.Fatal("> threshold must flag large-order")
	}
}

func TestParseOMS(t *testing.T) {
	body := []byte(`Order Blotter
oms_platform: Charles River
order_side: buy
order_type: limit
execution_venue: BYMA
sociedad_gerente_cuit: 30-71234567-8
sender_comp_id: ALYC123
target_comp_id: BYMA01
order_count: 4250
fill_count: 3980
broker_count: 12
restricted_ticker_count: 8
largest_order_notional_ars: 250000000
`)
	f := ParseOMS(body)
	if f.OMSPlatform != PlatformCharlesRiver {
		t.Fatalf("platform=%q", f.OMSPlatform)
	}
	if f.OrderSide != SideBuy {
		t.Fatalf("side=%q", f.OrderSide)
	}
	if f.OrderType != TypeLimit {
		t.Fatalf("type=%q", f.OrderType)
	}
	if f.ExecutionVenue != VenueBYMA {
		t.Fatalf("venue=%q", f.ExecutionVenue)
	}
	if f.SociedadGerenteCuitRaw == "" {
		t.Fatal("sociedad-gerente CUIT must extract")
	}
	if f.FIXSenderCompID != "ALYC123" {
		t.Fatalf("sender=%q", f.FIXSenderCompID)
	}
	if f.FIXTargetCompID != "BYMA01" {
		t.Fatalf("target=%q", f.FIXTargetCompID)
	}
	if f.OrderCount != 4250 {
		t.Fatalf("orders=%d", f.OrderCount)
	}
	if f.FillCount != 3980 {
		t.Fatalf("fills=%d", f.FillCount)
	}
	if f.BrokerCount != 12 {
		t.Fatalf("brokers=%d", f.BrokerCount)
	}
	if f.RestrictedTickerCount != 8 {
		t.Fatalf("restricted=%d", f.RestrictedTickerCount)
	}
	if f.LargestOrderNotionalARS != 250000000 {
		t.Fatalf("largest=%d", f.LargestOrderNotionalARS)
	}
}

func TestParseOMSFIXSessionConfig(t *testing.T) {
	body := []byte(`[SESSION]
BeginString=FIX.4.4
SenderCompID=ALYC987
TargetCompID=BYMA01
fix_password=hunter2
`)
	f := ParseOMS(body)
	if !f.HasPassword {
		t.Fatal("fix_password must extract")
	}
	if f.FIXSenderCompID != "ALYC987" {
		t.Fatalf("sender=%q", f.FIXSenderCompID)
	}
	if f.FIXTargetCompID != "BYMA01" {
		t.Fatalf("target=%q", f.FIXTargetCompID)
	}
}

func TestParseOMSJSONForm(t *testing.T) {
	body := []byte(`{
  "oms_platform": "Bloomberg AIM",
  "order_side": "sell",
  "order_type": "vwap",
  "execution_venue": "NYSE",
  "api_key": "secret_value_123"
}`)
	f := ParseOMS(body)
	if !f.HasPassword {
		t.Fatal("api_key must trigger password")
	}
	if f.OMSPlatform != PlatformBloombergAIM {
		t.Fatalf("platform=%q", f.OMSPlatform)
	}
	if f.OrderSide != SideSell {
		t.Fatalf("side=%q", f.OrderSide)
	}
	if f.OrderType != TypeVWAP {
		t.Fatalf("type=%q", f.OrderType)
	}
	if f.ExecutionVenue != VenueNYSE {
		t.Fatalf("venue=%q", f.ExecutionVenue)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	omsDir := filepath.Join(usersBase, "alice", "oms")
	must(t, os.MkdirAll(omsDir, 0o755))

	blotterPath := filepath.Join(omsDir, "order_blotter_20260624.csv")
	must(t, os.WriteFile(blotterPath, []byte(`OrderID,Ticker,Side,Qty,Px
ORD-1,GGAL,buy,10000,1500
order_count: 1
sociedad_gerente_cuit: 30-71234567-8
`), 0o644))

	restrictedPath := filepath.Join(omsDir, "restricted_list_202606.csv")
	must(t, os.WriteFile(restrictedPath, []byte(`Ticker,Reason
YPF,IPO_advisory
GGAL,MNPI_review
restricted_ticker_count: 25
`), 0o644))

	bestExPath := filepath.Join(omsDir, "best_ex_report_2026q2.pdf")
	must(t, os.WriteFile(bestExPath, []byte(`Best Execution Report Q2 2026
oms_platform: Fidessa
execution_venue: BYMA
`), 0o644))

	fixPath := filepath.Join(omsDir, "fix_session.cfg")
	must(t, os.WriteFile(fixPath, []byte(`[SESSION]
BeginString=FIX.4.4
SenderCompID=ALYC987
TargetCompID=BYMA01
fix_password=hunter2
`), 0o644))

	blockPath := filepath.Join(omsDir, "block_trade_20260624.csv")
	must(t, os.WriteFile(blockPath, []byte(`TradeID,Ticker,Notional
BT-1,YPF,500000000
largest_order_notional_ars: 500000000
`), 0o644))

	must(t, os.WriteFile(filepath.Join(omsDir, "random.txt"),
		[]byte(`nope`), 0o644))

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
	if len(got) != 5 {
		t.Fatalf("want 5 (blotter+restricted+best+fix+block), got %d: %+v", len(got), got)
	}

	var blot, rest, best, fix, blk Row
	for _, r := range got {
		switch r.FilePath {
		case blotterPath:
			blot = r
		case restrictedPath:
			rest = r
		case bestExPath:
			best = r
		case fixPath:
			fix = r
		case blockPath:
			blk = r
		}
	}

	if blot.ArtifactKind != KindOrderBlotter {
		t.Fatalf("blot kind=%q", blot.ArtifactKind)
	}
	if !blot.IsOrderAuditTrailLeak {
		t.Fatalf("blot must flag OAT leak: %+v", blot)
	}
	if !blot.HasSociedadGerenteCuit {
		t.Fatalf("blot must flag sociedad-gerente cuit: %+v", blot)
	}

	if rest.ArtifactKind != KindRestrictedList {
		t.Fatalf("rest kind=%q", rest.ArtifactKind)
	}
	if !rest.IsInsiderInformationRisk {
		t.Fatalf("rest must flag insider risk: %+v", rest)
	}
	if rest.RestrictedTickerCount != 25 {
		t.Fatalf("rest count=%d", rest.RestrictedTickerCount)
	}

	if best.ArtifactKind != KindBestExReport {
		t.Fatalf("best kind=%q", best.ArtifactKind)
	}
	if !best.IsBestExecutionDisclosureRisk {
		t.Fatalf("best must flag best-ex disclosure risk: %+v", best)
	}
	if best.OMSPlatform != PlatformFidessa {
		t.Fatalf("best platform=%q", best.OMSPlatform)
	}

	if fix.ArtifactKind != KindFIXSessionConfig {
		t.Fatalf("fix kind=%q", fix.ArtifactKind)
	}
	if !fix.HasPasswordInConfig {
		t.Fatalf("fix must flag password: %+v", fix)
	}
	if !fix.IsCredentialExposureRisk {
		t.Fatalf("fix must flag credential exposure: %+v", fix)
	}
	if fix.FIXSenderCompIDHash == "" {
		t.Fatalf("fix must hash sender comp id: %+v", fix)
	}

	if blk.ArtifactKind != KindBlockTrade {
		t.Fatalf("blk kind=%q", blk.ArtifactKind)
	}
	if !blk.HasLargeOrderValue {
		t.Fatalf("blk must flag large order value: %+v", blk)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-oms")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "oms_config.ini"),
		[]byte(`[OMS]
oms_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "OMS_DIR" {
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
		installRoots: []string{"/nope-oms"},
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
		{FilePath: "/b", ArtifactKind: KindOrderBlotter},
		{FilePath: "/a", ArtifactKind: KindFillReport},
		{FilePath: "/a", ArtifactKind: KindOrderBlotter},
	}
	SortRows(rs)
	// "oms-fill-report" < "oms-order-blotter" alphabetically.
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindFillReport {
		t.Fatalf("sort drift: %+v", rs)
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("ALYC123")
	b := HashSecret("alyc123")
	if a != b {
		t.Fatal("hash must be case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestCuitEntityOnlyFingerprint(t *testing.T) {
	prefix, suffix4 := CuitEntityOnlyFingerprint("sociedad_gerente_cuit: 30-71234567-8")
	if prefix != "30" {
		t.Fatalf("prefix=%q", prefix)
	}
	if suffix4 != "5678" {
		t.Fatalf("suffix4=%q", suffix4)
	}
	// Reject individual prefix (20).
	prefix, _ = CuitEntityOnlyFingerprint("20-12345678-9")
	if prefix != "" {
		t.Fatalf("individual prefix must be rejected: %q", prefix)
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if got := PeriodFromFilename("order_blotter_20260624.csv"); got != "202606" {
		t.Fatalf("got=%q", got)
	}
	if got := PeriodFromFilename("cnv_rg731_report_2026.xml"); got != "2026" {
		t.Fatalf("got=%q", got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
