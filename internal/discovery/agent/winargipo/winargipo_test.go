package winargipo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindRoadshow), "ipo-roadshow"},
		{string(KindBookbuilding), "ipo-bookbuilding"},
		{string(KindUnderwritingAgreement), "ipo-underwriting-agreement"},
		{string(KindProspectusDraft), "ipo-prospectus-draft"},
		{string(KindLockupCalendar), "ipo-lockup-calendar"},
		{string(KindGreenshoe), "ipo-greenshoe"},
		{string(KindStabilization), "ipo-stabilization"},
		{string(KindSyndicateFeeSplit), "ipo-syndicate-fee-split"},
		{string(KindInsiderRestriction), "ipo-insider-restriction"},
		{string(KindComfortLetter), "ipo-comfort-letter"},
		{string(KindLegalOpinion), "ipo-legal-opinion"},
		{string(KindCNVRG622Filing), "ipo-cnv-rg622-filing"},
		{string(KindPricingDecision), "ipo-pricing-decision"},
		{string(ALYCSantanderInvestment), "santander-investment"},
		{string(ALYCGaliciaInvestments), "galicia-investments"},
		{string(ALYCBTGPactualAR), "btg-pactual-ar"},
		{string(RoleLeadBookrunner), "lead-bookrunner"},
		{string(RoleStabilizingAgent), "stabilizing-agent"},
		{string(OfferingIPO), "ipo"},
		{string(OfferingSPACMerger), "spac-merger"},
		{string(OfferingADRIssuance), "adr-issuance"},
		{string(IPORoleEquityCapitalMarkets), "equity-capital-markets"},
		{string(IPORoleProspectusCounsel), "prospectus-counsel"},
		{string(VenueBYMA), "byma"},
		{string(VenueNYSE), "nyse"},
		{string(VenueB3), "b3"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"roadshow_LomaNegra_202606.csv",
		"bookbuilding_LomaNegra_20260624.csv",
		"book_building_LomaNegra.csv",
		"underwriting_agreement_LomaNegra.pdf",
		"ua_draft_LomaNegra.pdf",
		"prospectus_LomaNegra_v3.pdf",
		"lockup_calendar_LomaNegra.csv",
		"greenshoe_LomaNegra_20260624.csv",
		"over_allotment_LomaNegra.csv",
		"stabilization_LomaNegra_20260624.csv",
		"estabilizacion_LomaNegra.csv",
		"syndicate_fee_split_LomaNegra.csv",
		"insider_restriction_LomaNegra.csv",
		"lista_insider_LomaNegra.csv",
		"comfort_letter_LomaNegra_v2.pdf",
		"legal_opinion_LomaNegra_Marval.pdf",
		"opinion_legal_LomaNegra.pdf",
		"cnv_rg622_filing_LomaNegra_2026q2.xml",
		"pricing_decision_LomaNegra_20260624.pdf",
		"memo_pricing_LomaNegra.pdf",
		"ipo_config.ini",
		"santander_investment_data.csv",
		"galicia_investments_data.csv",
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
		"roadshow_LomaNegra_202606.csv":           KindRoadshow,
		"bookbuilding_LomaNegra_20260624.csv":     KindBookbuilding,
		"book_building_LomaNegra.csv":             KindBookbuilding,
		"underwriting_agreement_LomaNegra.pdf":    KindUnderwritingAgreement,
		"ua_draft_LomaNegra.pdf":                  KindUnderwritingAgreement,
		"prospectus_LomaNegra_v3.pdf":             KindProspectusDraft,
		"lockup_calendar_LomaNegra.csv":           KindLockupCalendar,
		"lock_up_calendar_LomaNegra.csv":          KindLockupCalendar,
		"greenshoe_LomaNegra_20260624.csv":        KindGreenshoe,
		"over_allotment_LomaNegra.csv":            KindGreenshoe,
		"stabilization_LomaNegra_20260624.csv":    KindStabilization,
		"estabilizacion_LomaNegra.csv":            KindStabilization,
		"syndicate_fee_split_LomaNegra.csv":       KindSyndicateFeeSplit,
		"insider_restriction_LomaNegra.csv":       KindInsiderRestriction,
		"lista_insider_LomaNegra.csv":             KindInsiderRestriction,
		"comfort_letter_LomaNegra_v2.pdf":         KindComfortLetter,
		"legal_opinion_LomaNegra_Marval.pdf":      KindLegalOpinion,
		"opinion_legal_LomaNegra.pdf":             KindLegalOpinion,
		"cnv_rg622_filing_LomaNegra_2026q2.xml":   KindCNVRG622Filing,
		"cnv_filing_ipo_LomaNegra.xml":            KindCNVRG622Filing,
		"pricing_decision_LomaNegra_20260624.pdf": KindPricingDecision,
		"memo_pricing_LomaNegra.pdf":              KindPricingDecision,
		"ipo_config.ini":                          KindConfig,
		"credentials.json":                        KindCredentials,
		"ipo_installer_setup.msi":                 KindInstaller,
		"":                                        KindUnknown,
		"random_unrelated.txt":                    KindOther,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBookrunnerALYCFromName(t *testing.T) {
	cases := map[string]BookrunnerALYC{
		"santander_investment_data.csv": ALYCSantanderInvestment,
		"galicia_investments_data.csv":  ALYCGaliciaInvestments,
		"bbva_ar_data.csv":              ALYCBBVAAR,
		"macro_securities_data.csv":     ALYCMacroSecurities,
		"btg_pactual_data.csv":          ALYCBTGPactualAR,
		"btg_pactual_ar_data.csv":       ALYCBTGPactualAR,
		"allaria_data.csv":              ALYCAllaria,
		"cohen_bursatil_data.csv":       ALYCCohenBursatil,
		"bacs_data.csv":                 ALYCBACS,
		"balanz_capital_data.csv":       ALYCBalanzCapital,
		"itau_ar_data.csv":              ALYCItauAR,
		"random.txt":                    ALYCUnknown,
	}
	for in, want := range cases {
		if got := BookrunnerALYCFromName(in); got != want {
			t.Fatalf("BookrunnerALYCFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectBookrunnerALYC(t *testing.T) {
	cases := map[string]BookrunnerALYC{
		"Santander Investment Securities": ALYCSantanderInvestment,
		"Galicia Investments":             ALYCGaliciaInvestments,
		"BBVA AR":                         ALYCBBVAAR,
		"Macro Securities":                ALYCMacroSecurities,
		"BTG Pactual AR":                  ALYCBTGPactualAR,
		"Allaria":                         ALYCAllaria,
		"Cohen Bursatil":                  ALYCCohenBursatil,
		"Balanz Capital":                  ALYCBalanzCapital,
		"random":                          ALYCUnknown,
	}
	for in, want := range cases {
		if got := detectBookrunnerALYC(in); got != want {
			t.Fatalf("detectBookrunnerALYC(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectBookrunnerRole(t *testing.T) {
	cases := map[string]BookrunnerRole{
		"lead_bookrunner":      RoleLeadBookrunner,
		"joint_bookrunner":     RoleJointBookrunner,
		"co_manager":           RoleCoManager,
		"senior_co_manager":    RoleSeniorCoManager,
		"selling_group_member": RoleSellingGroupMember,
		"stabilizing_agent":    RoleStabilizingAgent,
		"listing_agent":        RoleListingAgent,
		"random":               RoleUnknown,
	}
	for in, want := range cases {
		if got := detectBookrunnerRole(in); got != want {
			t.Fatalf("detectBookrunnerRole(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectOfferingType(t *testing.T) {
	cases := map[string]OfferingType{
		"ipo":                       OfferingIPO,
		"spo":                       OfferingSPO,
		"follow_on":                 OfferingFollowOn,
		"rights_issue":              OfferingRightsIssue,
		"block_trade":               OfferingBlockTrade,
		"private_placement_pre_ipo": OfferingPrivatePlacementPreIPO,
		"direct_listing":            OfferingDirectListing,
		"spac_merger":               OfferingSPACMerger,
		"adr_issuance":              OfferingADRIssuance,
		"random":                    OfferingUnknown,
	}
	for in, want := range cases {
		if got := detectOfferingType(in); got != want {
			t.Fatalf("detectOfferingType(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectListingVenue(t *testing.T) {
	cases := map[string]ListingVenue{
		"byma":   VenueBYMA,
		"bcba":   VenueBCBA,
		"mae":    VenueMAE,
		"nyse":   VenueNYSE,
		"nasdaq": VenueNASDAQ,
		"lse":    VenueLSE,
		"bme":    VenueBME,
		"ssx":    VenueSSX,
		"b3":     VenueB3,
		"random": VenueUnknown,
	}
	for in, want := range cases {
		if got := detectListingVenue(in); got != want {
			t.Fatalf("detectListingVenue(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindRoadshow, KindBookbuilding,
		KindUnderwritingAgreement, KindProspectusDraft,
		KindLockupCalendar, KindGreenshoe,
		KindStabilization, KindSyndicateFeeSplit,
		KindInsiderRestriction, KindComfortLetter,
		KindLegalOpinion, KindCNVRG622Filing,
		KindPricingDecision,
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

func TestIsPrePricingKind(t *testing.T) {
	yes := []ArtifactKind{KindBookbuilding, KindPricingDecision, KindRoadshow}
	for _, k := range yes {
		if !IsPrePricingKind(k) {
			t.Fatalf("expected pre-pricing: %q", k)
		}
	}
}

func TestIsAllocationLeakKind(t *testing.T) {
	yes := []ArtifactKind{KindBookbuilding, KindSyndicateFeeSplit}
	for _, k := range yes {
		if !IsAllocationLeakKind(k) {
			t.Fatalf("expected alloc leak: %q", k)
		}
	}
}

func TestIsLockupIntelligenceKind(t *testing.T) {
	yes := []ArtifactKind{KindLockupCalendar, KindInsiderRestriction, KindGreenshoe}
	for _, k := range yes {
		if !IsLockupIntelligenceKind(k) {
			t.Fatalf("expected lockup intel: %q", k)
		}
	}
}

func TestAnnotatePrePricingDisclosure(t *testing.T) {
	r := Row{
		ArtifactKind: KindBookbuilding,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasBookbuilding {
		t.Fatal("bookbuilding kind must flag")
	}
	if !r.IsPrePricingDisclosureRisk {
		t.Fatal("readable + bookbuilding = pre-pricing risk")
	}
}

func TestAnnotateAllocationLeak(t *testing.T) {
	r := Row{
		ArtifactKind: KindSyndicateFeeSplit,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasSyndicateFeeSplit {
		t.Fatal("fee split kind must flag")
	}
	if !r.IsAllocationLeakRisk {
		t.Fatal("readable + fee split = allocation leak")
	}
}

func TestAnnotateLockupIntelligenceLeak(t *testing.T) {
	r := Row{
		ArtifactKind: KindLockupCalendar,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasLockupCalendar {
		t.Fatal("lockup kind must flag")
	}
	if !r.IsLockupIntelligenceLeak {
		t.Fatal("readable + lockup = lockup intelligence leak")
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

func TestAnnotateLargeOfferingSize(t *testing.T) {
	r := Row{
		ArtifactKind:    KindPricingDecision,
		OfferingSizeARS: LargeOfferingSizeARSThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasLargeOfferingSize {
		t.Fatal("> 5B ARS must flag large offering")
	}
}

func TestParseIPO(t *testing.T) {
	body := []byte(`Bookbuilding Allocation
bookrunner_alyc: Santander Investment
bookrunner_role: lead_bookrunner
offering_type: ipo
listing_venue: byma
issuer_cuit: 30-50000446-7
bookrunner_cuit: 30-71112233-4
deal_codename: Project Pampa
investor_count: 85
allocation_count: 75
insider_count: 12
offering_size_ars: 8500000000
greenshoe_size_ars: 1275000000
bookrunner_fee_bps: 350
`)
	f := ParseIPO(body)
	if f.BookrunnerALYC != ALYCSantanderInvestment {
		t.Fatalf("alyc=%q", f.BookrunnerALYC)
	}
	if f.BookrunnerRole != RoleLeadBookrunner {
		t.Fatalf("role=%q", f.BookrunnerRole)
	}
	if f.OfferingType != OfferingIPO {
		t.Fatalf("offering=%q", f.OfferingType)
	}
	if f.ListingVenue != VenueBYMA {
		t.Fatalf("venue=%q", f.ListingVenue)
	}
	if f.IssuerCuitRaw == "" {
		t.Fatal("issuer_cuit must extract")
	}
	if f.BookrunnerCuitRaw == "" {
		t.Fatal("bookrunner_cuit must extract")
	}
	if f.DealCodename != "Project Pampa" {
		t.Fatalf("deal=%q", f.DealCodename)
	}
	if f.InvestorCount != 85 {
		t.Fatalf("inv=%d", f.InvestorCount)
	}
	if f.AllocationCount != 75 {
		t.Fatalf("alloc=%d", f.AllocationCount)
	}
	if f.InsiderCount != 12 {
		t.Fatalf("ins=%d", f.InsiderCount)
	}
	if f.OfferingSizeARS != 8_500_000_000 {
		t.Fatalf("size=%d", f.OfferingSizeARS)
	}
	if f.GreenshoeSizeARS != 1_275_000_000 {
		t.Fatalf("gs=%d", f.GreenshoeSizeARS)
	}
	if f.BookrunnerFeeBps != 350 {
		t.Fatalf("fee=%d", f.BookrunnerFeeBps)
	}
}

func TestParseIPOJSONForm(t *testing.T) {
	body := []byte(`{
  "bookrunner_alyc": "Galicia Investments",
  "offering_type": "adr_issuance",
  "listing_venue": "nyse",
  "api_key": "secret"
}`)
	f := ParseIPO(body)
	if !f.HasPassword {
		t.Fatal("api_key must trigger password")
	}
	if f.BookrunnerALYC != ALYCGaliciaInvestments {
		t.Fatalf("alyc=%q", f.BookrunnerALYC)
	}
	if f.OfferingType != OfferingADRIssuance {
		t.Fatalf("offering=%q", f.OfferingType)
	}
	if f.ListingVenue != VenueNYSE {
		t.Fatalf("venue=%q", f.ListingVenue)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	ipoDir := filepath.Join(usersBase, "alice", "ipo")
	must(t, os.MkdirAll(ipoDir, 0o755))

	bookPath := filepath.Join(ipoDir, "bookbuilding_LomaNegra_20260624.csv")
	must(t, os.WriteFile(bookPath, []byte(`investor,shares,price
ANSES,500000,1500
bookrunner_alyc: Santander Investment
issuer_cuit: 30-50000446-7
bookrunner_cuit: 30-71112233-4
offering_size_ars: 8500000000
investor_count: 85
allocation_count: 75
`), 0o644))

	lockupPath := filepath.Join(ipoDir, "lockup_calendar_LomaNegra.csv")
	must(t, os.WriteFile(lockupPath, []byte(`insider,lockup_expiry
DIR1,2026-09-24
insider_count: 12
`), 0o644))

	feePath := filepath.Join(ipoDir, "syndicate_fee_split_LomaNegra.csv")
	must(t, os.WriteFile(feePath, []byte(`bookrunner,fee_bps
Santander,200
Galicia,150
bookrunner_fee_bps: 350
`), 0o644))

	pricingPath := filepath.Join(ipoDir, "pricing_decision_LomaNegra_20260624.pdf")
	must(t, os.WriteFile(pricingPath, []byte(`Final Pricing Memo
offering_size_ars: 8500000000
`), 0o644))

	must(t, os.WriteFile(filepath.Join(ipoDir, "random.txt"),
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
		t.Fatalf("want 4 (book+lockup+fee+pricing), got %d: %+v", len(got), got)
	}

	var book, lock, fee, pr Row
	for _, r := range got {
		switch r.FilePath {
		case bookPath:
			book = r
		case lockupPath:
			lock = r
		case feePath:
			fee = r
		case pricingPath:
			pr = r
		}
	}

	if book.ArtifactKind != KindBookbuilding {
		t.Fatalf("book kind=%q", book.ArtifactKind)
	}
	if book.BookrunnerALYC != ALYCSantanderInvestment {
		t.Fatalf("book alyc=%q", book.BookrunnerALYC)
	}
	if !book.IsPrePricingDisclosureRisk {
		t.Fatalf("book must flag pre-pricing: %+v", book)
	}
	if !book.IsAllocationLeakRisk {
		t.Fatalf("book must flag alloc leak: %+v", book)
	}
	if !book.HasIssuerCuit || !book.HasBookrunnerCuit {
		t.Fatalf("book must flag issuer+bookrunner cuit: %+v", book)
	}
	if !book.HasLargeOfferingSize {
		t.Fatalf("book must flag large offering: %+v", book)
	}

	if lock.ArtifactKind != KindLockupCalendar {
		t.Fatalf("lock kind=%q", lock.ArtifactKind)
	}
	if !lock.IsLockupIntelligenceLeak {
		t.Fatalf("lock must flag lockup leak: %+v", lock)
	}

	if fee.ArtifactKind != KindSyndicateFeeSplit {
		t.Fatalf("fee kind=%q", fee.ArtifactKind)
	}
	if !fee.IsAllocationLeakRisk {
		t.Fatalf("fee must flag alloc leak: %+v", fee)
	}
	if fee.BookrunnerFeeBps != 350 {
		t.Fatalf("fee bps=%d", fee.BookrunnerFeeBps)
	}

	if pr.ArtifactKind != KindPricingDecision {
		t.Fatalf("pr kind=%q", pr.ArtifactKind)
	}
	if !pr.IsPrePricingDisclosureRisk {
		t.Fatalf("pr must flag pre-pricing: %+v", pr)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-ipo")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "ipo_config.ini"),
		[]byte(`[IPO]
ipo_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "IPO_DIR" {
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
		installRoots: []string{"/nope-ipo"},
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
		{FilePath: "/b", ArtifactKind: KindRoadshow},
		{FilePath: "/a", ArtifactKind: KindBookbuilding},
		{FilePath: "/a", ArtifactKind: KindRoadshow},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindBookbuilding {
		t.Fatalf("sort drift: %+v", rs)
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("PROJECT-PAMPA")
	b := HashSecret("project-pampa")
	if a != b {
		t.Fatal("hash must be case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestCuitEntityOnlyFingerprint(t *testing.T) {
	prefix, suffix4 := CuitEntityOnlyFingerprint("issuer_cuit: 30-50000446-7")
	if prefix != "30" {
		t.Fatalf("prefix=%q", prefix)
	}
	if suffix4 != "4467" {
		t.Fatalf("suffix4=%q", suffix4)
	}
	prefix, _ = CuitEntityOnlyFingerprint("20-12345678-9")
	if prefix != "" {
		t.Fatalf("individual prefix must be rejected: %q", prefix)
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if got := PeriodFromFilename("bookbuilding_LomaNegra_202606.csv"); got != "202606" {
		t.Fatalf("got=%q", got)
	}
	if got := PeriodFromFilename("prospectus_LomaNegra_v3_2026.pdf"); got != "2026" {
		t.Fatalf("got=%q", got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
