package winargtesoro

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindAuctionBid), "tesoro-auction-bid"},
		{string(KindAllocation), "tesoro-allocation"},
		{string(KindPrimaryDealerRoster), "tesoro-primary-dealer-roster"},
		{string(KindDebtIssuancePlan), "tesoro-debt-issuance-plan"},
		{string(KindSyndicatedPlacement), "tesoro-syndicated-placement"},
		{string(KindDebtRestructuring), "tesoro-debt-restructuring"},
		{string(KindCNVMPSettlement), "tesoro-cnvmp-settlement"},
		{string(KindROFEXPrimary), "tesoro-rofex-primary"},
		{string(KindFinancingProgram), "tesoro-financing-program"},
		{string(KindBCRACoordination), "tesoro-bcra-coordination"},
		{string(KindMECONResolution), "tesoro-mecon-resolution"},
		{string(KindIMFEngagement), "tesoro-imf-engagement"},
		{string(InstLECAP), "lecap"},
		{string(InstAL30), "al30"},
		{string(InstGD30), "gd30"},
		{string(InstBOPREAL), "bopreal"},
		{string(InstTX26), "tx26"},
		{string(MethodCompetitiveAuction), "competitive-auction"},
		{string(MethodSyndicated), "syndicated"},
		{string(MethodSwap), "swap"},
		{string(RolePrimaryDealer), "primary-dealer"},
		{string(RoleIMFLiaison), "imf-liaison"},
		{string(RoleBCRACoordinator), "bcra-coordinator"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"auction_bid_LECAP_20260624.csv",
		"allocation_LECAP_20260624.csv",
		"primary_dealer_roster_202606.csv",
		"debt_issuance_plan_2026q2.pdf",
		"syndicated_placement_GD30.pdf",
		"debt_restructuring_2026.pdf",
		"cnvmp_settlement_20260624.csv",
		"rofex_primary_20260624.csv",
		"financing_program_2026.pdf",
		"bcra_coordination_202606.pdf",
		"mecon_resolution_56_2022.pdf",
		"imf_engagement_2026.pdf",
		"tesoro_config.ini",
		"lecap_S30J6.csv",
		"al30_holders.csv",
		"gd30_curve.csv",
		"bopreal_serie3.csv",
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
		"auction_bid_LECAP_20260624.csv":   KindAuctionBid,
		"oferta_licitacion_LECAP.csv":      KindAuctionBid,
		"allocation_LECAP_20260624.csv":    KindAllocation,
		"asignacion_LECAP.csv":             KindAllocation,
		"primary_dealer_roster_202606.csv": KindPrimaryDealerRoster,
		"creadores_mercado_202606.csv":     KindPrimaryDealerRoster,
		"debt_issuance_plan_2026q2.pdf":    KindDebtIssuancePlan,
		"emision_deuda_2026q2.pdf":         KindDebtIssuancePlan,
		"syndicated_placement_GD30.pdf":    KindSyndicatedPlacement,
		"colocacion_sindicada_GD30.pdf":    KindSyndicatedPlacement,
		"debt_restructuring_2026.pdf":      KindDebtRestructuring,
		"canje_deuda_2026.pdf":             KindDebtRestructuring,
		"cnvmp_settlement_20260624.csv":    KindCNVMPSettlement,
		"rofex_primary_20260624.csv":       KindROFEXPrimary,
		"financing_program_2026.pdf":       KindFinancingProgram,
		"programa_financiero_2026.pdf":     KindFinancingProgram,
		"bcra_coordination_202606.pdf":     KindBCRACoordination,
		"tesoro_bcra_202606.pdf":           KindBCRACoordination,
		"mecon_resolution_56_2022.pdf":     KindMECONResolution,
		"resolucion_mecon_56_2022.pdf":     KindMECONResolution,
		"imf_engagement_2026.pdf":          KindIMFEngagement,
		"fmi_acuerdo_2026.pdf":             KindIMFEngagement,
		"tesoro_config.ini":                KindConfig,
		"credentials.json":                 KindCredentials,
		"tesoro_installer_setup.msi":       KindInstaller,
		"":                                 KindUnknown,
		"random_unrelated.txt":             KindOther,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestInstrumentClassFromName(t *testing.T) {
	cases := map[string]InstrumentClass{
		"lecap_S30J6.csv":    InstLECAP,
		"lecer_X18M6.csv":    InstLECER,
		"lede_X30A6.csv":     InstLEDE,
		"bonte_2027.csv":     InstBONTE,
		"boncer_TX26.csv":    InstBONCER,
		"bonad_2026.csv":     InstBONAD,
		"al30_holders.csv":   InstAL30,
		"al35_holders.csv":   InstAL35,
		"al38_holders.csv":   InstAL38,
		"al41_holders.csv":   InstAL41,
		"gd29_curve.csv":     InstGD29,
		"gd30_curve.csv":     InstGD30,
		"gd35_curve.csv":     InstGD35,
		"gd38_curve.csv":     InstGD38,
		"gd41_curve.csv":     InstGD41,
		"gd46_curve.csv":     InstGD46,
		"parp_holders.csv":   InstPARP,
		"dica_holders.csv":   InstDICA,
		"dicy_holders.csv":   InstDICY,
		"tx26_curve.csv":     InstTX26,
		"tx28_curve.csv":     InstTX28,
		"ty27_curve.csv":     InstTY27,
		"bopreal_serie3.csv": InstBOPREAL,
		"random.txt":         InstUnknown,
	}
	for in, want := range cases {
		if got := InstrumentClassFromName(in); got != want {
			t.Fatalf("InstrumentClassFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectInstrument(t *testing.T) {
	cases := map[string]InstrumentClass{
		"lecap":   InstLECAP,
		"al30":    InstAL30,
		"gd30":    InstGD30,
		"bopreal": InstBOPREAL,
		"random":  InstUnknown,
	}
	for in, want := range cases {
		if got := detectInstrument(in); got != want {
			t.Fatalf("detectInstrument(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectPlacementMethod(t *testing.T) {
	cases := map[string]PlacementMethod{
		"competitive_auction": MethodCompetitiveAuction,
		"competitiva":         MethodCompetitiveAuction,
		"non_competitive":     MethodNonCompetitive,
		"no_competitiva":      MethodNonCompetitive,
		"syndicated":          MethodSyndicated,
		"sindicada":           MethodSyndicated,
		"private_placement":   MethodPrivatePlacement,
		"privada":             MethodPrivatePlacement,
		"swap":                MethodSwap,
		"canje":               MethodSwap,
		"buyback":             MethodBuyback,
		"recompra":            MethodBuyback,
		"random":              MethodUnknown,
	}
	for in, want := range cases {
		if got := detectPlacementMethod(in); got != want {
			t.Fatalf("detectPlacementMethod(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsPreAuctionKind(t *testing.T) {
	yes := []ArtifactKind{KindAuctionBid, KindDebtIssuancePlan, KindFinancingProgram}
	for _, k := range yes {
		if !IsPreAuctionKind(k) {
			t.Fatalf("expected pre-auction: %q", k)
		}
	}
	for _, k := range []ArtifactKind{
		KindAllocation, KindPrimaryDealerRoster,
		KindSyndicatedPlacement, KindDebtRestructuring,
		KindCNVMPSettlement, KindROFEXPrimary,
		KindBCRACoordination, KindMECONResolution,
		KindIMFEngagement,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown,
	} {
		if IsPreAuctionKind(k) {
			t.Fatalf("expected NOT pre-auction: %q", k)
		}
	}
}

func TestIsAllocationLeakKind(t *testing.T) {
	yes := []ArtifactKind{KindAllocation, KindSyndicatedPlacement, KindCNVMPSettlement}
	for _, k := range yes {
		if !IsAllocationLeakKind(k) {
			t.Fatalf("expected alloc leak: %q", k)
		}
	}
}

func TestIsSovereignStrategyKind(t *testing.T) {
	yes := []ArtifactKind{
		KindDebtRestructuring, KindIMFEngagement,
		KindBCRACoordination, KindMECONResolution,
	}
	for _, k := range yes {
		if !IsSovereignStrategyKind(k) {
			t.Fatalf("expected sovereign strategy: %q", k)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindAuctionBid, KindAllocation,
		KindPrimaryDealerRoster, KindDebtIssuancePlan,
		KindSyndicatedPlacement, KindDebtRestructuring,
		KindCNVMPSettlement, KindROFEXPrimary,
		KindFinancingProgram, KindBCRACoordination,
		KindMECONResolution, KindIMFEngagement,
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

func TestAnnotatePreAuctionDisclosure(t *testing.T) {
	r := Row{
		ArtifactKind: KindAuctionBid,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasAuctionBid {
		t.Fatal("auction bid kind must flag")
	}
	if !r.IsPreAuctionDisclosureRisk {
		t.Fatal("readable + auction bid = pre-auction disclosure risk")
	}
}

func TestAnnotateAllocationLeak(t *testing.T) {
	r := Row{
		ArtifactKind: KindAllocation,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasAllocation {
		t.Fatal("allocation kind must flag")
	}
	if !r.IsAllocationLeakRisk {
		t.Fatal("readable + allocation = allocation leak risk")
	}
}

func TestAnnotateSovereignStrategyLeak(t *testing.T) {
	r := Row{
		ArtifactKind: KindIMFEngagement,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasIMFEngagement {
		t.Fatal("IMF kind must flag")
	}
	if !r.IsSovereignDebtStrategyLeak {
		t.Fatal("readable + IMF = sovereign strategy leak")
	}
}

func TestAnnotateCredentialExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindConfig,
		FileMode:            0o644,
		HasPasswordInConfig: true,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + config + password = credential exposure")
	}
}

func TestAnnotateLargeBidValue(t *testing.T) {
	r := Row{
		ArtifactKind:          KindAuctionBid,
		LargestBidNotionalARS: LargeBidNotionalARSThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasLargeBidValue {
		t.Fatal("> 10B ARS must flag large-bid")
	}
}

func TestParseTesoro(t *testing.T) {
	body := []byte(`Auction Bid Book
instrument: LECAP
placement_method: competitive_auction
dealer_cuit: 30-71234567-8
auction_id: SUB-2026-0001
bid_count: 42
allocation_count: 38
dealer_count: 15
largest_bid_notional_ars: 25000000000
total_offered_ars: 800000000000
total_allocated_ars: 600000000000
`)
	f := ParseTesoro(body)
	if f.InstrumentClass != InstLECAP {
		t.Fatalf("inst=%q", f.InstrumentClass)
	}
	if f.PlacementMethod != MethodCompetitiveAuction {
		t.Fatalf("method=%q", f.PlacementMethod)
	}
	if f.DealerCuitRaw == "" {
		t.Fatal("dealer_cuit must extract")
	}
	if f.AuctionID != "SUB-2026-0001" {
		t.Fatalf("auction_id=%q", f.AuctionID)
	}
	if f.BidCount != 42 {
		t.Fatalf("bids=%d", f.BidCount)
	}
	if f.AllocationCount != 38 {
		t.Fatalf("alloc=%d", f.AllocationCount)
	}
	if f.DealerCount != 15 {
		t.Fatalf("dealers=%d", f.DealerCount)
	}
	if f.LargestBidNotionalARS != 25_000_000_000 {
		t.Fatalf("largest=%d", f.LargestBidNotionalARS)
	}
	if f.TotalOfferedARS != 800_000_000_000 {
		t.Fatalf("offered=%d", f.TotalOfferedARS)
	}
	if f.TotalAllocatedARS != 600_000_000_000 {
		t.Fatalf("allocated=%d", f.TotalAllocatedARS)
	}
}

func TestParseTesoroJSONForm(t *testing.T) {
	body := []byte(`{
  "instrument": "al30",
  "placement_method": "syndicated",
  "api_key": "secret"
}`)
	f := ParseTesoro(body)
	if !f.HasPassword {
		t.Fatal("api_key must trigger password")
	}
	if f.InstrumentClass != InstAL30 {
		t.Fatalf("inst=%q", f.InstrumentClass)
	}
	if f.PlacementMethod != MethodSyndicated {
		t.Fatalf("method=%q", f.PlacementMethod)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	tesoroDir := filepath.Join(usersBase, "alice", "tesoro")
	must(t, os.MkdirAll(tesoroDir, 0o755))

	bidPath := filepath.Join(tesoroDir, "auction_bid_LECAP_20260624.csv")
	must(t, os.WriteFile(bidPath, []byte(`bid_id,dealer,price,qty
1,ALYC,1.05,100000
instrument: LECAP
dealer_cuit: 30-71234567-8
largest_bid_notional_ars: 50000000000
`), 0o644))

	allocPath := filepath.Join(tesoroDir, "allocation_GD30_20260624.csv")
	must(t, os.WriteFile(allocPath, []byte(`alloc_id,dealer,qty
1,ALYC,100000
instrument: gd30
placement_method: competitive_auction
`), 0o644))

	imfPath := filepath.Join(tesoroDir, "imf_engagement_2026.pdf")
	must(t, os.WriteFile(imfPath, []byte(`IMF Engagement Letter
auction_id: IMF-2026-EFF
`), 0o644))

	planPath := filepath.Join(tesoroDir, "financing_program_2026.pdf")
	must(t, os.WriteFile(planPath, []byte(`Programa Financiero 2026
total_offered_ars: 5000000000000
`), 0o644))

	must(t, os.WriteFile(filepath.Join(tesoroDir, "random.txt"),
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
	if len(got) != 4 {
		t.Fatalf("want 4 (bid+alloc+imf+plan), got %d: %+v", len(got), got)
	}

	var bid, alloc, imf, plan Row
	for _, r := range got {
		switch r.FilePath {
		case bidPath:
			bid = r
		case allocPath:
			alloc = r
		case imfPath:
			imf = r
		case planPath:
			plan = r
		}
	}

	if bid.ArtifactKind != KindAuctionBid {
		t.Fatalf("bid kind=%q", bid.ArtifactKind)
	}
	if bid.InstrumentClass != InstLECAP {
		t.Fatalf("bid inst=%q", bid.InstrumentClass)
	}
	if !bid.IsPreAuctionDisclosureRisk {
		t.Fatalf("bid must flag pre-auction risk: %+v", bid)
	}
	if !bid.HasDealerCuit {
		t.Fatalf("bid must flag dealer cuit: %+v", bid)
	}
	if !bid.HasLargeBidValue {
		t.Fatalf("bid must flag large value: %+v", bid)
	}

	if alloc.ArtifactKind != KindAllocation {
		t.Fatalf("alloc kind=%q", alloc.ArtifactKind)
	}
	if alloc.InstrumentClass != InstGD30 {
		t.Fatalf("alloc inst=%q", alloc.InstrumentClass)
	}
	if !alloc.IsAllocationLeakRisk {
		t.Fatalf("alloc must flag alloc leak: %+v", alloc)
	}

	if imf.ArtifactKind != KindIMFEngagement {
		t.Fatalf("imf kind=%q", imf.ArtifactKind)
	}
	if !imf.IsSovereignDebtStrategyLeak {
		t.Fatalf("imf must flag sovereign strategy leak: %+v", imf)
	}

	if plan.ArtifactKind != KindFinancingProgram {
		t.Fatalf("plan kind=%q", plan.ArtifactKind)
	}
	if !plan.IsPreAuctionDisclosureRisk {
		t.Fatalf("plan must flag pre-auction risk: %+v", plan)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-tesoro")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "tesoro_config.ini"),
		[]byte(`[Tesoro]
tesoro_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "TESORO_DIR" {
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
		installRoots: []string{"/nope-tesoro"},
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
		{FilePath: "/b", ArtifactKind: KindAuctionBid},
		{FilePath: "/a", ArtifactKind: KindAllocation},
		{FilePath: "/a", ArtifactKind: KindAuctionBid},
	}
	SortRows(rs)
	// "tesoro-allocation" < "tesoro-auction-bid" alphabetically.
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindAllocation {
		t.Fatalf("sort drift: %+v", rs)
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("ALYC-DEALER")
	b := HashSecret("alyc-dealer")
	if a != b {
		t.Fatal("hash must be case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestCuitEntityOnlyFingerprint(t *testing.T) {
	prefix, suffix4 := CuitEntityOnlyFingerprint("dealer_cuit: 30-71234567-8")
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
	if got := PeriodFromFilename("auction_bid_LECAP_20260624.csv"); got != "202606" {
		t.Fatalf("got=%q", got)
	}
	if got := PeriodFromFilename("financing_program_2026.pdf"); got != "2026" {
		t.Fatalf("got=%q", got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
