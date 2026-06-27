package winargvasp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindWalletRoster), "vasp-wallet-roster"},
		{string(KindHotColdSegregation), "vasp-hot-cold-segregation"},
		{string(KindTravelRule), "vasp-travel-rule"},
		{string(KindChainAnalytics), "vasp-chain-analytics"},
		{string(KindSanctionsScreening), "vasp-sanctions-screening"},
		{string(KindStablecoinRedemption), "vasp-stablecoin-redemption"},
		{string(KindDeFiInteraction), "vasp-defi-interaction"},
		{string(KindBridgeSwap), "vasp-bridge-swap"},
		{string(KindSmartContractAudit), "vasp-smart-contract-audit"},
		{string(KindKYCTierClassification), "vasp-kyc-tier-classification"},
		{string(KindAFIPRG5697Filing), "vasp-afip-rg5697-filing"},
		{string(KindUIFSTR), "vasp-uif-str"},
		{string(KindCNVRG1058Filing), "vasp-cnv-rg1058-filing"},
		{string(FirmLemonCash), "lemon-cash"},
		{string(FirmBitsoAR), "bitso-ar"},
		{string(FirmSatoshiTango), "satoshitango"},
		{string(FirmBudaAR), "buda-ar"},
		{string(ChainBitcoin), "bitcoin"},
		{string(ChainTron), "tron"},
		{string(ChainBitcoinCash), "bitcoin-cash"},
		{string(TokenERC20Stablecoin), "erc20-stablecoin"},
		{string(TokenTRC20Stablecoin), "trc20-stablecoin"},
		{string(TokenNFTERC721), "nft-erc721"},
		{string(TRCompliant), "compliant"},
		{string(TRSelfHosted), "self-hosted"},
		{string(RoleChainalyticsAnalyst), "chainalytics-analyst"},
		{string(RoleSecurityEngineer), "security-engineer"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"wallet_roster_ethereum_202606.csv",
		"hot_cold_segregation_202606.csv",
		"travel_rule_20260624.json",
		"ivms101_20260624.json",
		"chain_analytics_chainalysis_202606.csv",
		"sanctions_screening_20260624.csv",
		"ofac_screen_20260624.csv",
		"stablecoin_redemption_20260624.csv",
		"defi_interaction_aave_20260624.csv",
		"bridge_swap_20260624.csv",
		"smart_contract_audit_LemonLP.pdf",
		"kyc_tier_202606.csv",
		"afip_rg5697_2026q2.xml",
		"uif_str_20260624.pdf",
		"cnv_rg1058_2026q2.xml",
		"vasp_config.ini",
		"lemon_cash_export.csv",
		"bitso_export.csv",
		"ripio_export.csv",
		"satoshitango_export.csv",
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
		"wallet_roster_ethereum_202606.csv":      KindWalletRoster,
		"wallets_202606.csv":                     KindWalletRoster,
		"hot_cold_segregation_202606.csv":        KindHotColdSegregation,
		"treasury_map_202606.csv":                KindHotColdSegregation,
		"travel_rule_20260624.json":              KindTravelRule,
		"ivms101_20260624.json":                  KindTravelRule,
		"chain_analytics_chainalysis_202606.csv": KindChainAnalytics,
		"chainalysis_202606.csv":                 KindChainAnalytics,
		"trm_labs_202606.csv":                    KindChainAnalytics,
		"elliptic_202606.csv":                    KindChainAnalytics,
		"sanctions_screening_20260624.csv":       KindSanctionsScreening,
		"ofac_screen_20260624.csv":               KindSanctionsScreening,
		"stablecoin_redemption_20260624.csv":     KindStablecoinRedemption,
		"usdt_redeem_20260624.csv":               KindStablecoinRedemption,
		"defi_interaction_aave_20260624.csv":     KindDeFiInteraction,
		"aave_logs_20260624.csv":                 KindDeFiInteraction,
		"uniswap_logs_20260624.csv":              KindDeFiInteraction,
		"bridge_swap_20260624.csv":               KindBridgeSwap,
		"cross_chain_20260624.csv":               KindBridgeSwap,
		"smart_contract_audit_LemonLP.pdf":       KindSmartContractAudit,
		"sca_report_LemonLP.pdf":                 KindSmartContractAudit,
		"my_contract.sol":                        KindSmartContractAudit,
		"kyc_tier_202606.csv":                    KindKYCTierClassification,
		"afip_rg5697_2026q2.xml":                 KindAFIPRG5697Filing,
		"rg5697_2026q2.xml":                      KindAFIPRG5697Filing,
		"uif_str_20260624.pdf":                   KindUIFSTR,
		"str_uif_20260624.pdf":                   KindUIFSTR,
		"cnv_rg1058_2026q2.xml":                  KindCNVRG1058Filing,
		"vasp_config.ini":                        KindConfig,
		"credentials.json":                       KindCredentials,
		"vasp_installer_setup.msi":               KindInstaller,
		"":                                       KindUnknown,
		"lemon_cash_export.csv":                  KindOther,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestVASPFirmFromName(t *testing.T) {
	cases := map[string]VASPFirm{
		"lemon_cash_export.csv": FirmLemonCash,
		"lemon_export.csv":      FirmLemonCash,
		"belo_export.csv":       FirmBelo,
		"bitso_export.csv":      FirmBitsoAR,
		"ripio_export.csv":      FirmRipio,
		"buenbit_export.csv":    FirmBuenbit,
		"bitnovo_export.csv":    FirmBitnovoAR,
		"satoshitango_data.csv": FirmSatoshiTango,
		"decrypto_export.csv":   FirmDecrypto,
		"bitex_export.csv":      FirmBitex,
		"letsbit_export.csv":    FirmLetsbit,
		"buda_ar_export.csv":    FirmBudaAR,
		"random.txt":            FirmUnknown,
	}
	for in, want := range cases {
		if got := VASPFirmFromName(in); got != want {
			t.Fatalf("VASPFirmFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectVASPFirm(t *testing.T) {
	cases := map[string]VASPFirm{
		"Lemon Cash":   FirmLemonCash,
		"LEMONCASH":    FirmLemonCash,
		"Belo":         FirmBelo,
		"Bitso":        FirmBitsoAR,
		"Bitso AR":     FirmBitsoAR,
		"Ripio":        FirmRipio,
		"Buenbit":      FirmBuenbit,
		"SatoshiTango": FirmSatoshiTango,
		"Decrypto":     FirmDecrypto,
		"random":       FirmUnknown,
	}
	for in, want := range cases {
		if got := detectVASPFirm(in); got != want {
			t.Fatalf("detectVASPFirm(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectBlockchain(t *testing.T) {
	cases := map[string]Blockchain{
		"bitcoin":      ChainBitcoin,
		"btc":          ChainBitcoin,
		"ethereum":     ChainEthereum,
		"eth":          ChainEthereum,
		"tron":         ChainTron,
		"trx":          ChainTron,
		"solana":       ChainSolana,
		"sol":          ChainSolana,
		"polygon":      ChainPolygon,
		"matic":        ChainPolygon,
		"arbitrum":     ChainArbitrum,
		"arb":          ChainArbitrum,
		"optimism":     ChainOptimism,
		"op":           ChainOptimism,
		"base":         ChainBase,
		"bsc":          ChainBSC,
		"bnb":          ChainBSC,
		"avalanche":    ChainAvalanche,
		"avax":         ChainAvalanche,
		"bitcoin_cash": ChainBitcoinCash,
		"bch":          ChainBitcoinCash,
		"litecoin":     ChainLitecoin,
		"ltc":          ChainLitecoin,
		"ripple":       ChainRipple,
		"xrp":          ChainRipple,
		"random":       ChainUnknown,
	}
	for in, want := range cases {
		if got := detectBlockchain(in); got != want {
			t.Fatalf("detectBlockchain(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectTokenClass(t *testing.T) {
	cases := map[string]TokenClass{
		"btc-native":         TokenBTCNative,
		"erc20-stablecoin":   TokenERC20Stablecoin,
		"erc-20-stablecoin":  TokenERC20Stablecoin,
		"erc20-utility":      TokenERC20Utility,
		"trc20-stablecoin":   TokenTRC20Stablecoin,
		"sol-spl-stablecoin": TokenSOLSPLStablecoin,
		"nft-erc721":         TokenNFTERC721,
		"nft-erc1155":        TokenNFTERC1155,
		"native-coin":        TokenNativeCoin,
		"wrapped-coin":       TokenWrappedCoin,
		"random":             TokenUnknown,
	}
	for in, want := range cases {
		if got := detectTokenClass(in); got != want {
			t.Fatalf("detectTokenClass(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectTravelRuleStatus(t *testing.T) {
	cases := map[string]TravelRuleStatus{
		"compliant":       TRCompliant,
		"cumple":          TRCompliant,
		"pending":         TRPending,
		"pendiente":       TRPending,
		"non_compliant":   TRNonCompliant,
		"no_cumple":       TRNonCompliant,
		"self_hosted":     TRSelfHosted,
		"auto_custodia":   TRSelfHosted,
		"below_threshold": TRBelowThreshold,
		"debajo_umbral":   TRBelowThreshold,
		"random":          TRUnknown,
	}
	for in, want := range cases {
		if got := detectTravelRuleStatus(in); got != want {
			t.Fatalf("detectTravelRuleStatus(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindWalletRoster, KindHotColdSegregation,
		KindTravelRule, KindChainAnalytics,
		KindSanctionsScreening, KindStablecoinRedemption,
		KindDeFiInteraction, KindBridgeSwap,
		KindSmartContractAudit, KindKYCTierClassification,
		KindAFIPRG5697Filing, KindUIFSTR,
		KindCNVRG1058Filing,
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

func TestIsWalletAddrPIIKind(t *testing.T) {
	yes := []ArtifactKind{
		KindWalletRoster, KindTravelRule,
		KindStablecoinRedemption, KindKYCTierClassification,
	}
	for _, k := range yes {
		if !IsWalletAddrPIIKind(k) {
			t.Fatalf("expected wallet PII: %q", k)
		}
	}
}

func TestIsTreasuryDisclosureKind(t *testing.T) {
	yes := []ArtifactKind{KindHotColdSegregation, KindCNVRG1058Filing}
	for _, k := range yes {
		if !IsTreasuryDisclosureKind(k) {
			t.Fatalf("expected treasury: %q", k)
		}
	}
}

func TestIsAMLScreeningKind(t *testing.T) {
	yes := []ArtifactKind{
		KindSanctionsScreening, KindChainAnalytics,
		KindUIFSTR, KindAFIPRG5697Filing,
	}
	for _, k := range yes {
		if !IsAMLScreeningKind(k) {
			t.Fatalf("expected AML screening: %q", k)
		}
	}
}

func TestAnnotateWalletAddrPII(t *testing.T) {
	r := Row{
		ArtifactKind: KindWalletRoster,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasWalletRoster {
		t.Fatal("wallet roster kind must flag")
	}
	if !r.IsWalletAddrPIIRisk {
		t.Fatal("readable + wallet roster = wallet PII risk")
	}
}

func TestAnnotateTreasuryDisclosure(t *testing.T) {
	r := Row{
		ArtifactKind: KindHotColdSegregation,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHotColdSegregation {
		t.Fatal("hot/cold kind must flag")
	}
	if !r.IsTreasuryDisclosureRisk {
		t.Fatal("readable + hot/cold = treasury disclosure risk")
	}
}

func TestAnnotateAMLScreeningLeak(t *testing.T) {
	r := Row{
		ArtifactKind: KindUIFSTR,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasUIFSTR {
		t.Fatal("UIF STR kind must flag")
	}
	if !r.IsAMLScreeningLeak {
		t.Fatal("readable + UIF STR = AML screening leak")
	}
}

func TestAnnotateCredentialExposureViaSeed(t *testing.T) {
	r := Row{
		ArtifactKind:           KindWalletRoster,
		FileMode:               0o644,
		HasSeedPhraseIndicator: true,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + wallet + seed indicator = credential exposure")
	}
}

func TestAnnotateLargeRedemption(t *testing.T) {
	r := Row{
		ArtifactKind:        KindStablecoinRedemption,
		RedemptionAmountUSD: LargeRedemptionAmountUSDThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasLargeRedemption {
		t.Fatal("> 100K USD must flag large redemption")
	}
}

func TestAnnotateSanctionsHit(t *testing.T) {
	r := Row{
		ArtifactKind:      KindSanctionsScreening,
		SanctionsHitCount: 3,
	}
	AnnotateSecurity(&r)
	if !r.HasSanctionsHit {
		t.Fatal("≥ 1 hit must flag sanctions hit")
	}
}

func TestParseVASP(t *testing.T) {
	body := []byte(`Wallet Roster
vasp_firm: Lemon Cash
blockchain: ethereum
token_class: erc20-stablecoin
travel_rule_status: compliant
vasp_cuit: 30-71445566-7
wallet_address: 0xabcd1234ef567890abcd1234ef567890abcd1234
counterparty_vasp: BITSO-AR-VASP-001
wallet_count: 250000
customer_count: 180000
hot_wallet_balance_usd: 15000000
cold_wallet_balance_usd: 85000000
sanctions_hit_count: 5
redemption_amount_usd: 250000
`)
	f := ParseVASP(body)
	if f.VASPFirm != FirmLemonCash {
		t.Fatalf("firm=%q", f.VASPFirm)
	}
	if f.Blockchain != ChainEthereum {
		t.Fatalf("chain=%q", f.Blockchain)
	}
	if f.TokenClass != TokenERC20Stablecoin {
		t.Fatalf("token=%q", f.TokenClass)
	}
	if f.TravelRuleStatus != TRCompliant {
		t.Fatalf("tr=%q", f.TravelRuleStatus)
	}
	if f.VASPCuitRaw == "" {
		t.Fatal("cuit must extract")
	}
	if f.WalletAddressRaw != "0xabcd1234ef567890abcd1234ef567890abcd1234" {
		t.Fatalf("addr=%q", f.WalletAddressRaw)
	}
	if f.CounterpartyVASPRaw != "BITSO-AR-VASP-001" {
		t.Fatalf("cp=%q", f.CounterpartyVASPRaw)
	}
	if f.WalletCount != 250000 {
		t.Fatalf("wc=%d", f.WalletCount)
	}
	if f.CustomerCount != 180000 {
		t.Fatalf("cc=%d", f.CustomerCount)
	}
	if f.HotWalletBalanceUSD != 15_000_000 {
		t.Fatalf("hot=%d", f.HotWalletBalanceUSD)
	}
	if f.ColdWalletBalanceUSD != 85_000_000 {
		t.Fatalf("cold=%d", f.ColdWalletBalanceUSD)
	}
	if f.SanctionsHitCount != 5 {
		t.Fatalf("sanctions=%d", f.SanctionsHitCount)
	}
	if f.RedemptionAmountUSD != 250000 {
		t.Fatalf("red=%d", f.RedemptionAmountUSD)
	}
}

func TestParseVASPSeedPhrase(t *testing.T) {
	body := []byte(`Wallet Backup
seed_phrase: word1 word2 word3 word4 word5 word6
`)
	f := ParseVASP(body)
	if !f.HasSeedPhraseIndicator {
		t.Fatal("seed_phrase: marker must trigger indicator")
	}
}

func TestParseVASPJSONForm(t *testing.T) {
	body := []byte(`{
  "vasp_firm": "Bitso AR",
  "blockchain": "tron",
  "api_key": "secret"
}`)
	f := ParseVASP(body)
	if !f.HasPassword {
		t.Fatal("api_key must trigger password")
	}
	if f.VASPFirm != FirmBitsoAR {
		t.Fatalf("firm=%q", f.VASPFirm)
	}
	if f.Blockchain != ChainTron {
		t.Fatalf("chain=%q", f.Blockchain)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	vDir := filepath.Join(usersBase, "alice", "vasp")
	must(t, os.MkdirAll(vDir, 0o755))

	rosterPath := filepath.Join(vDir, "wallet_roster_ethereum_202606.csv")
	must(t, os.WriteFile(rosterPath, []byte(`customer_id,wallet,balance
C001,0xabcd1234ef567890abcd1234ef567890abcd1234,5000
vasp_firm: Lemon Cash
vasp_cuit: 30-71445566-7
blockchain: ethereum
wallet_address: 0xabcd1234ef567890abcd1234ef567890abcd1234
wallet_count: 250000
`), 0o644))

	treasuryPath := filepath.Join(vDir, "hot_cold_segregation_202606.csv")
	must(t, os.WriteFile(treasuryPath, []byte(`tier,balance_usd
hot,15000000
cold,85000000
hot_wallet_balance_usd: 15000000
cold_wallet_balance_usd: 85000000
`), 0o644))

	strPath := filepath.Join(vDir, "uif_str_20260624.pdf")
	must(t, os.WriteFile(strPath, []byte(`UIF STR
typology: structuring
customer_count: 5
`), 0o644))

	sanctionsPath := filepath.Join(vDir, "sanctions_screening_20260624.csv")
	must(t, os.WriteFile(sanctionsPath, []byte(`screen_id,result
S001,hit
sanctions_hit_count: 3
`), 0o644))

	walletBackup := filepath.Join(vDir, "wallets_backup_202606.csv")
	must(t, os.WriteFile(walletBackup, []byte(`# Wallet recovery info
seed_phrase: word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12
`), 0o644))

	must(t, os.WriteFile(filepath.Join(vDir, "random.txt"),
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
		t.Fatalf("want 5 (roster+treasury+str+sanc+backup), got %d: %+v", len(got), got)
	}

	var ros, treas, str, sanc, bk Row
	for _, r := range got {
		switch r.FilePath {
		case rosterPath:
			ros = r
		case treasuryPath:
			treas = r
		case strPath:
			str = r
		case sanctionsPath:
			sanc = r
		case walletBackup:
			bk = r
		}
	}

	if ros.ArtifactKind != KindWalletRoster {
		t.Fatalf("ros kind=%q", ros.ArtifactKind)
	}
	if ros.VASPFirm != FirmLemonCash {
		t.Fatalf("ros firm=%q", ros.VASPFirm)
	}
	if ros.Blockchain != ChainEthereum {
		t.Fatalf("ros chain=%q", ros.Blockchain)
	}
	if !ros.HasVASPCuit {
		t.Fatalf("ros must flag VASP cuit: %+v", ros)
	}
	if !ros.HasWalletAddress {
		t.Fatalf("ros must flag wallet address: %+v", ros)
	}
	if !ros.IsWalletAddrPIIRisk {
		t.Fatalf("ros must flag wallet PII: %+v", ros)
	}

	if treas.ArtifactKind != KindHotColdSegregation {
		t.Fatalf("treas kind=%q", treas.ArtifactKind)
	}
	if !treas.IsTreasuryDisclosureRisk {
		t.Fatalf("treas must flag treasury disclosure: %+v", treas)
	}
	if treas.HotWalletBalanceUSD != 15_000_000 {
		t.Fatalf("treas hot=%d", treas.HotWalletBalanceUSD)
	}

	if str.ArtifactKind != KindUIFSTR {
		t.Fatalf("str kind=%q", str.ArtifactKind)
	}
	if !str.IsAMLScreeningLeak {
		t.Fatalf("str must flag AML leak: %+v", str)
	}

	if sanc.ArtifactKind != KindSanctionsScreening {
		t.Fatalf("sanc kind=%q", sanc.ArtifactKind)
	}
	if !sanc.HasSanctionsHit {
		t.Fatalf("sanc must flag sanctions hit: %+v", sanc)
	}
	if !sanc.IsAMLScreeningLeak {
		t.Fatalf("sanc must flag AML leak: %+v", sanc)
	}

	if bk.ArtifactKind != KindWalletRoster {
		t.Fatalf("bk kind=%q want wallet roster (matches wallets_ prefix)", bk.ArtifactKind)
	}
	if !bk.HasSeedPhraseIndicator {
		t.Fatalf("bk must flag seed indicator: %+v", bk)
	}
	if !bk.IsCredentialExposureRisk {
		t.Fatalf("bk must flag cred exposure: %+v", bk)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-vasp")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "vasp_config.ini"),
		[]byte(`[VASP]
vasp_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "VASP_DIR" {
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
		installRoots: []string{"/nope-vasp"},
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
		{FilePath: "/b", ArtifactKind: KindWalletRoster},
		{FilePath: "/a", ArtifactKind: KindHotColdSegregation},
		{FilePath: "/a", ArtifactKind: KindWalletRoster},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindHotColdSegregation {
		t.Fatalf("sort drift: %+v", rs)
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("0xABCD1234EF567890ABCD1234EF567890ABCD1234")
	b := HashSecret("0xabcd1234ef567890abcd1234ef567890abcd1234")
	if a != b {
		t.Fatal("hash must be case-insensitive (EIP-55 checksum)")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestCuitEntityOnlyFingerprint(t *testing.T) {
	prefix, suffix4 := CuitEntityOnlyFingerprint("vasp_cuit: 30-71445566-7")
	if prefix != "30" {
		t.Fatalf("prefix=%q", prefix)
	}
	if suffix4 != "5667" {
		t.Fatalf("suffix4=%q", suffix4)
	}
	prefix, _ = CuitEntityOnlyFingerprint("20-12345678-9")
	if prefix != "" {
		t.Fatalf("individual prefix must be rejected: %q", prefix)
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if got := PeriodFromFilename("wallet_roster_ethereum_202606.csv"); got != "202606" {
		t.Fatalf("got=%q", got)
	}
	if got := PeriodFromFilename("cnv_rg1058_2026q2.xml"); got != "2026" {
		t.Fatalf("got=%q", got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
