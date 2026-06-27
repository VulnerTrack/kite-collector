// Package winargvasp audits AR Virtual-Asset-Service-Provider
// (VASP / PSAV = Proveedor de Servicios de Activos Virtuales)
// artifact files cached on compliance-officer, AML-officer,
// chainalytics-analyst, treasury-officer, and security-engineer
// workstations at Lemon Cash, Belo, Bitso AR, Ripio, Buenbit,
// Bitnovo AR, SatoshiTango, Decrypto, Bitex, Letsbit, BUDA AR.
//
// Regulated under Ley 27.739 (Oct 2024 FATF Rec 15+16 adoption) +
// Ley 27.260 (FATCA/CRS) + CNV RG 1058/2024 (PSAV registry) + RG
// 1023 (cyber) + BCRA Com. A 8155 (crypto exposure) + 7724 (MULC)
// + UIF Res. 49/2024 (PLA/FT PSAV) + 21/2018 + AFIP RG 5697 +
// Ley 25.246 + 25.326 + 27.401 + 26.831 art.117.
//
// Distinct from prior iters because the shape is **crypto-rail
// back-office** — wallet roster = de-anonymized customer-to-
// address map, hot/cold segregation = exchange treasury topology
// (attack target), Travel Rule (FATF Rec 16) IVMS101 = VASP-to-
// VASP customer transfer graph, chain analytics = scoring
// methodology (evasion intel), sanctions screening = OFAC hit
// list, stablecoin redemption = off-ramp timing, DeFi/bridge
// logs = protocol exposure, UIF STR = AML typology.
//
// Read-only by intent. (Project guideline 4.2.)
package winargvasp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	MaxRows        = 16384
	MaxFileBytes   = 16 << 20
	RecentlyWindow = 90 * 24 * time.Hour
)

// LargeRedemptionAmountUSDThreshold — > 100K USD single
// redemption triggers large-redemption rollup. 100K USD is the
// FATF de-minimis threshold for enhanced due diligence and
// aligns with FATF Rec 10/16 thresholds.
const LargeRedemptionAmountUSDThreshold = 100_000

// SanctionsHitRollupThreshold — ≥ 1 sanctions hit triggers
// has_sanctions_hit. Explicit policy constant.
const SanctionsHitRollupThreshold = 1

// ArtifactKind pinned to host_arg_vasp.artifact_kind.
type ArtifactKind string

const (
	KindWalletRoster          ArtifactKind = "vasp-wallet-roster"
	KindHotColdSegregation    ArtifactKind = "vasp-hot-cold-segregation"
	KindTravelRule            ArtifactKind = "vasp-travel-rule"
	KindChainAnalytics        ArtifactKind = "vasp-chain-analytics"
	KindSanctionsScreening    ArtifactKind = "vasp-sanctions-screening"
	KindStablecoinRedemption  ArtifactKind = "vasp-stablecoin-redemption"
	KindDeFiInteraction       ArtifactKind = "vasp-defi-interaction"
	KindBridgeSwap            ArtifactKind = "vasp-bridge-swap"
	KindSmartContractAudit    ArtifactKind = "vasp-smart-contract-audit"
	KindKYCTierClassification ArtifactKind = "vasp-kyc-tier-classification"
	KindAFIPRG5697Filing      ArtifactKind = "vasp-afip-rg5697-filing"
	KindUIFSTR                ArtifactKind = "vasp-uif-str"
	KindCNVRG1058Filing       ArtifactKind = "vasp-cnv-rg1058-filing"
	KindConfig                ArtifactKind = "vasp-config"
	KindCredentials           ArtifactKind = "vasp-credentials"
	KindInstaller             ArtifactKind = "vasp-installer"
	KindOther                 ArtifactKind = "other"
	KindUnknown               ArtifactKind = "unknown"
)

// VASPFirm pinned to host_arg_vasp.vasp_firm.
type VASPFirm string

const (
	FirmLemonCash    VASPFirm = "lemon-cash"
	FirmBelo         VASPFirm = "belo"
	FirmBitsoAR      VASPFirm = "bitso-ar"
	FirmRipio        VASPFirm = "ripio"
	FirmBuenbit      VASPFirm = "buenbit"
	FirmBitnovoAR    VASPFirm = "bitnovo-ar"
	FirmSatoshiTango VASPFirm = "satoshitango"
	FirmDecrypto     VASPFirm = "decrypto"
	FirmBitex        VASPFirm = "bitex"
	FirmLetsbit      VASPFirm = "letsbit"
	FirmBudaAR       VASPFirm = "buda-ar"
	FirmCustom       VASPFirm = "custom"
	FirmNone         VASPFirm = "none"
	FirmUnknown      VASPFirm = "unknown"
)

// Blockchain pinned to host_arg_vasp.blockchain.
type Blockchain string

const (
	ChainBitcoin     Blockchain = "bitcoin"
	ChainEthereum    Blockchain = "ethereum"
	ChainTron        Blockchain = "tron"
	ChainSolana      Blockchain = "solana"
	ChainPolygon     Blockchain = "polygon"
	ChainArbitrum    Blockchain = "arbitrum"
	ChainOptimism    Blockchain = "optimism"
	ChainBase        Blockchain = "base"
	ChainBSC         Blockchain = "bsc"
	ChainAvalanche   Blockchain = "avalanche"
	ChainBitcoinCash Blockchain = "bitcoin-cash"
	ChainLitecoin    Blockchain = "litecoin"
	ChainRipple      Blockchain = "ripple"
	ChainCustom      Blockchain = "custom"
	ChainNone        Blockchain = "none"
	ChainUnknown     Blockchain = "unknown"
)

// TokenClass pinned to host_arg_vasp.token_class.
type TokenClass string

const (
	TokenBTCNative        TokenClass = "btc-native"
	TokenERC20Stablecoin  TokenClass = "erc20-stablecoin"   //#nosec G101 -- TokenClass enum value naming the ERC-20 stablecoin asset class, not a token credential
	TokenERC20Utility     TokenClass = "erc20-utility"      //#nosec G101 -- TokenClass enum value naming the ERC-20 utility asset class, not a token credential
	TokenTRC20Stablecoin  TokenClass = "trc20-stablecoin"   //#nosec G101 -- TokenClass enum value naming the TRC-20 stablecoin asset class, not a token credential
	TokenSOLSPLStablecoin TokenClass = "sol-spl-stablecoin" //#nosec G101 -- TokenClass enum value naming the Solana SPL stablecoin asset class, not a token credential
	TokenNFTERC721        TokenClass = "nft-erc721"         //#nosec G101 -- TokenClass enum value naming the ERC-721 NFT asset class, not a token credential
	TokenNFTERC1155       TokenClass = "nft-erc1155"        //#nosec G101 -- TokenClass enum value naming the ERC-1155 NFT asset class, not a token credential
	TokenNativeCoin       TokenClass = "native-coin"
	TokenWrappedCoin      TokenClass = "wrapped-coin"
	TokenCustom           TokenClass = "custom"
	TokenNone             TokenClass = "none"
	TokenUnknown          TokenClass = "unknown"
)

// TravelRuleStatus pinned to host_arg_vasp.travel_rule_status.
type TravelRuleStatus string

const (
	TRCompliant      TravelRuleStatus = "compliant"
	TRPending        TravelRuleStatus = "pending"
	TRNonCompliant   TravelRuleStatus = "non-compliant"
	TRSelfHosted     TravelRuleStatus = "self-hosted"
	TRBelowThreshold TravelRuleStatus = "below-threshold"
	TRNone           TravelRuleStatus = "none"
	TRUnknown        TravelRuleStatus = "unknown"
)

// VASPRole pinned to host_arg_vasp.vasp_role.
type VASPRole string

const (
	RoleComplianceOfficer   VASPRole = "compliance-officer"
	RoleAMLOfficer          VASPRole = "aml-officer"
	RoleChainalyticsAnalyst VASPRole = "chainalytics-analyst"
	RoleTreasuryOfficer     VASPRole = "treasury-officer"
	RoleSecurityEngineer    VASPRole = "security-engineer"
	RoleBackOffice          VASPRole = "back-office"
	RoleMiddleOffice        VASPRole = "middle-office"
	RoleCCO                 VASPRole = "cco"
	RoleAPI                 VASPRole = "api"
	RoleOther               VASPRole = "other"
	RoleUnknown             VASPRole = "unknown"
)

// Row mirrors host_arg_vasp column shape.
type Row struct {
	FilePath                 string           `json:"file_path"`
	FileHash                 string           `json:"file_hash"`
	UserProfile              string           `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind     `json:"artifact_kind"`
	VASPFirm                 VASPFirm         `json:"vasp_firm"`
	Blockchain               Blockchain       `json:"blockchain,omitempty"`
	TokenClass               TokenClass       `json:"token_class,omitempty"`
	TravelRuleStatus         TravelRuleStatus `json:"travel_rule_status,omitempty"`
	VASPRole                 VASPRole         `json:"vasp_role"`
	ReportingPeriod          string           `json:"reporting_period,omitempty"`
	VASPCuitPrefix           string           `json:"vasp_cuit_prefix,omitempty"`
	VASPCuitSuffix4          string           `json:"vasp_cuit_suffix4,omitempty"`
	WalletAddressHash        string           `json:"wallet_address_hash,omitempty"`
	CounterpartyVASPHash     string           `json:"counterparty_vasp_hash,omitempty"`
	WalletCount              int64            `json:"wallet_count,omitempty"`
	CustomerCount            int64            `json:"customer_count,omitempty"`
	HotWalletBalanceUSD      int64            `json:"hot_wallet_balance_usd,omitempty"`
	ColdWalletBalanceUSD     int64            `json:"cold_wallet_balance_usd,omitempty"`
	SanctionsHitCount        int64            `json:"sanctions_hit_count,omitempty"`
	RedemptionAmountUSD      int64            `json:"redemption_amount_usd,omitempty"`
	FileOwnerUID             int              `json:"file_owner_uid,omitempty"`
	FileMode                 int              `json:"file_mode,omitempty"`
	FileSize                 int64            `json:"file_size,omitempty"`
	HasPasswordInConfig      bool             `json:"has_password_in_config"`
	HasWalletRoster          bool             `json:"has_wallet_roster"`
	HasHotColdSegregation    bool             `json:"has_hot_cold_segregation"`
	HasTravelRule            bool             `json:"has_travel_rule"`
	HasChainAnalytics        bool             `json:"has_chain_analytics"`
	HasSanctionsScreening    bool             `json:"has_sanctions_screening"`
	HasStablecoinRedemption  bool             `json:"has_stablecoin_redemption"`
	HasDeFiInteraction       bool             `json:"has_defi_interaction"`
	HasBridgeSwap            bool             `json:"has_bridge_swap"`
	HasSmartContractAudit    bool             `json:"has_smart_contract_audit"`
	HasKYCTierClassification bool             `json:"has_kyc_tier_classification"`
	HasAFIPRG5697            bool             `json:"has_afip_rg5697"`
	HasUIFSTR                bool             `json:"has_uif_str"`
	HasCNVRG1058             bool             `json:"has_cnv_rg1058"`
	HasVASPCuit              bool             `json:"has_vasp_cuit"`
	HasWalletAddress         bool             `json:"has_wallet_address"`
	HasSeedPhraseIndicator   bool             `json:"has_seed_phrase_indicator"`
	HasLargeRedemption       bool             `json:"has_large_redemption"`
	HasSanctionsHit          bool             `json:"has_sanctions_hit"`
	IsRecent                 bool             `json:"is_recent"`
	IsWorldReadable          bool             `json:"is_world_readable"`
	IsGroupReadable          bool             `json:"is_group_readable"`
	IsCredentialExposureRisk bool             `json:"is_credential_exposure_risk"`
	IsWalletAddrPIIRisk      bool             `json:"is_wallet_addr_pii_risk"`
	IsTreasuryDisclosureRisk bool             `json:"is_treasury_disclosure_risk"`
	IsAMLScreeningLeak       bool             `json:"is_aml_screening_leak"`
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// HashSecret returns the SHA-256 hex of a normalized secret.
// Wallet addresses are normalised with case-insensitive hash
// since EVM addresses are case-insensitive (EIP-55 mixed case
// is a checksum, not semantic).
func HashSecret(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated VASP install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\VASP`,
		`C:\Lemon`,
		`C:\Bitso`,
		`C:\Ripio`,
		`C:\Program Files\VASP`,
		"/opt/vasp",
		"/opt/crypto",
	}
}

// DefaultUsersBases is the curated per-OS user-profile bases.
func DefaultUsersBases() []string {
	return []string{
		`C:\Users`,
		"/home",
		"/Users",
	}
}

// UserVASPDirs is the curated per-user relative path set.
func UserVASPDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "VASP"},
		{"AppData", "Roaming", "Lemon"},
		{"AppData", "Roaming", "Bitso"},
		{"AppData", "Roaming", "Ripio"},
		{"AppData", "Local", "VASP"},
		{".config", "vasp"},
		{".vasp"},
		{".lemon"},
		{".bitso"},
		{"Documents", "VASP"},
		{"Documents", "Crypto"},
		{"Documents", "Wallets"},
		{"vasp"},
		{"crypto"},
		{"wallets"},
		{"chain"},
		{"travel-rule"},
		{"Library", "Application Support", "VASP"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a VASP
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json",
		".cfg", ".ini", ".conf",
		".csv", ".tsv", ".log", ".txt",
		".xlsx", ".xls", ".ods",
		".pdf", ".doc", ".docx",
		".md", ".markdown",
		".yaml", ".yml", ".toml",
		".dat", ".sol",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the VASP catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"wallet_roster", "wallet-roster", "wallets_",
		"hot_cold_segregation", "hot-cold-segregation", "treasury_map",
		"travel_rule", "travel-rule", "ivms101", "ivms_101",
		"chain_analytics", "chain-analytics", "chainalysis", "trm_labs", "elliptic_",
		"sanctions_screening", "sanctions-screening", "ofac_screen", "ofac-screen",
		"stablecoin_redemption", "stablecoin-redemption", "usdt_redeem", "usdc_redeem",
		"defi_interaction", "defi-interaction", "aave_", "uniswap_", "curve_", "dydx_",
		"bridge_swap", "bridge-swap", "cross_chain",
		"smart_contract_audit", "smart-contract-audit", "sca_report",
		"kyc_tier", "kyc-tier",
		"afip_rg5697", "afip-rg5697", "rg5697_",
		"uif_str", "uif-str", "str_uif",
		"cnv_rg1058", "cnv-rg1058", "rg_1058", "rg-1058", "psav_",
		"vasp_config", "vasp-config", "vasp_",
		"lemon_cash", "lemon-cash", "lemoncash",
		"belo_", "bitso_", "ripio_", "buenbit_",
		"bitnovo_", "satoshitango", "decrypto_",
		"bitex_", "letsbit_", "buda_ar", "buda-ar",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ArtifactKindFromName classifies a filename heuristically.
func ArtifactKindFromName(name string) ArtifactKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".msi", ".exe", ".pkg", ".dmg":
		if strings.Contains(n, "vasp") || strings.Contains(n, "lemon") ||
			strings.Contains(n, "bitso") || strings.Contains(n, "ripio") {
			return KindInstaller
		}
		return KindOther
	case ".sol":
		return KindSmartContractAudit
	}
	switch {
	case strings.Contains(n, "cnv_rg1058") ||
		strings.Contains(n, "cnv-rg1058") ||
		strings.Contains(n, "rg_1058") ||
		strings.Contains(n, "rg-1058"):
		return KindCNVRG1058Filing
	case strings.Contains(n, "uif_str") ||
		strings.Contains(n, "uif-str") ||
		strings.Contains(n, "str_uif"):
		return KindUIFSTR
	case strings.Contains(n, "afip_rg5697") ||
		strings.Contains(n, "afip-rg5697") ||
		strings.HasPrefix(n, "rg5697_"):
		return KindAFIPRG5697Filing
	case strings.Contains(n, "kyc_tier") ||
		strings.Contains(n, "kyc-tier"):
		return KindKYCTierClassification
	case strings.Contains(n, "smart_contract_audit") ||
		strings.Contains(n, "smart-contract-audit") ||
		strings.Contains(n, "sca_report"):
		return KindSmartContractAudit
	case strings.Contains(n, "bridge_swap") ||
		strings.Contains(n, "bridge-swap") ||
		strings.Contains(n, "cross_chain"):
		return KindBridgeSwap
	case strings.Contains(n, "defi_interaction") ||
		strings.Contains(n, "defi-interaction") ||
		strings.HasPrefix(n, "aave_") ||
		strings.HasPrefix(n, "uniswap_") ||
		strings.HasPrefix(n, "curve_") ||
		strings.HasPrefix(n, "dydx_"):
		return KindDeFiInteraction
	case strings.Contains(n, "stablecoin_redemption") ||
		strings.Contains(n, "stablecoin-redemption") ||
		strings.Contains(n, "usdt_redeem") ||
		strings.Contains(n, "usdc_redeem"):
		return KindStablecoinRedemption
	case strings.Contains(n, "sanctions_screening") ||
		strings.Contains(n, "sanctions-screening") ||
		strings.Contains(n, "ofac_screen") ||
		strings.Contains(n, "ofac-screen"):
		return KindSanctionsScreening
	case strings.Contains(n, "chain_analytics") ||
		strings.Contains(n, "chain-analytics") ||
		strings.Contains(n, "chainalysis") ||
		strings.Contains(n, "trm_labs") ||
		strings.Contains(n, "elliptic_"):
		return KindChainAnalytics
	case strings.Contains(n, "travel_rule") ||
		strings.Contains(n, "travel-rule") ||
		strings.Contains(n, "ivms101") ||
		strings.Contains(n, "ivms_101"):
		return KindTravelRule
	case strings.Contains(n, "hot_cold_segregation") ||
		strings.Contains(n, "hot-cold-segregation") ||
		strings.Contains(n, "treasury_map"):
		return KindHotColdSegregation
	case strings.Contains(n, "wallet_roster") ||
		strings.Contains(n, "wallet-roster") ||
		strings.HasPrefix(n, "wallets_"):
		return KindWalletRoster
	case n == "credentials.json" || n == "credentials.yaml" ||
		n == "credentials.yml" || strings.HasPrefix(n, "credentials"):
		return KindCredentials
	case strings.Contains(n, "vasp") && strings.Contains(n, "config"):
		return KindConfig
	}
	return KindOther
}

// VASPFirmFromName detects VASP firm from filename.
func VASPFirmFromName(name string) VASPFirm {
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "lemon_cash") ||
		strings.Contains(n, "lemon-cash") ||
		strings.Contains(n, "lemoncash") ||
		strings.HasPrefix(n, "lemon_"):
		return FirmLemonCash
	case strings.HasPrefix(n, "belo_") || strings.Contains(n, "_belo_"):
		return FirmBelo
	case strings.HasPrefix(n, "bitso_") || strings.Contains(n, "_bitso_"):
		return FirmBitsoAR
	case strings.HasPrefix(n, "ripio_") || strings.Contains(n, "_ripio_"):
		return FirmRipio
	case strings.HasPrefix(n, "buenbit_") || strings.Contains(n, "_buenbit_"):
		return FirmBuenbit
	case strings.HasPrefix(n, "bitnovo_") || strings.Contains(n, "_bitnovo_"):
		return FirmBitnovoAR
	case strings.Contains(n, "satoshitango"):
		return FirmSatoshiTango
	case strings.HasPrefix(n, "decrypto_") || strings.Contains(n, "_decrypto_"):
		return FirmDecrypto
	case strings.HasPrefix(n, "bitex_") || strings.Contains(n, "_bitex_"):
		return FirmBitex
	case strings.HasPrefix(n, "letsbit_") || strings.Contains(n, "_letsbit_"):
		return FirmLetsbit
	case strings.Contains(n, "buda_ar") || strings.Contains(n, "buda-ar"):
		return FirmBudaAR
	}
	return FirmUnknown
}

// CuitEntityOnlyPrefixes is the entity-only subset.
func CuitEntityOnlyPrefixes() []string {
	return []string{"30", "33", "34"}
}

// IsValidCuitEntityOnlyPrefix reports prefix membership.
func IsValidCuitEntityOnlyPrefix(p string) bool {
	for _, v := range CuitEntityOnlyPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches 11-digit CUIT bounded by non-digit / edges.
var cuitRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// CuitEntityOnlyFingerprint extracts VASP CUIT (entity prefix).
func CuitEntityOnlyFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuitEntityOnlyPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// PeriodFromFilename extracts YYYYMM or YYYY from a filename.
func PeriodFromFilename(name string) string {
	if m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name)); m != nil {
		return m[1] + m[2]
	}
	if m := regexp.MustCompile(`(20\d{2})`).
		FindStringSubmatch(filepath.Base(name)); m != nil {
		return m[1]
	}
	return ""
}

// IsCredentialKind reports whether the kind carries PII /
// credential material.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindWalletRoster, KindHotColdSegregation,
		KindTravelRule, KindChainAnalytics,
		KindSanctionsScreening, KindStablecoinRedemption,
		KindDeFiInteraction, KindBridgeSwap,
		KindSmartContractAudit, KindKYCTierClassification,
		KindAFIPRG5697Filing, KindUIFSTR,
		KindCNVRG1058Filing,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsWalletAddrPIIKind reports whether the kind carries
// customer-to-wallet-address mapping material.
func IsWalletAddrPIIKind(k ArtifactKind) bool {
	switch k {
	case KindWalletRoster, KindTravelRule,
		KindStablecoinRedemption, KindKYCTierClassification:
		return true
	case KindHotColdSegregation, KindChainAnalytics,
		KindSanctionsScreening, KindDeFiInteraction,
		KindBridgeSwap, KindSmartContractAudit,
		KindAFIPRG5697Filing, KindUIFSTR,
		KindCNVRG1058Filing,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsTreasuryDisclosureKind reports whether the kind reveals
// VASP treasury topology + solvency material.
func IsTreasuryDisclosureKind(k ArtifactKind) bool {
	switch k {
	case KindHotColdSegregation, KindCNVRG1058Filing:
		return true
	case KindWalletRoster, KindTravelRule, KindChainAnalytics,
		KindSanctionsScreening, KindStablecoinRedemption,
		KindDeFiInteraction, KindBridgeSwap,
		KindSmartContractAudit, KindKYCTierClassification,
		KindAFIPRG5697Filing, KindUIFSTR,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsAMLScreeningKind reports whether the kind carries
// sanctions / chain-analytics / STR / tax-filing material
// (AML methodology + targets).
func IsAMLScreeningKind(k ArtifactKind) bool {
	switch k {
	case KindSanctionsScreening, KindChainAnalytics,
		KindUIFSTR, KindAFIPRG5697Filing:
		return true
	case KindWalletRoster, KindHotColdSegregation,
		KindTravelRule, KindStablecoinRedemption,
		KindDeFiInteraction, KindBridgeSwap,
		KindSmartContractAudit, KindKYCTierClassification,
		KindCNVRG1058Filing,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets derived booleans.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.VASPCuitPrefix != "" {
		r.HasVASPCuit = true
	}
	if r.WalletAddressHash != "" {
		r.HasWalletAddress = true
	}
	switch r.ArtifactKind {
	case KindWalletRoster:
		r.HasWalletRoster = true
	case KindHotColdSegregation:
		r.HasHotColdSegregation = true
	case KindTravelRule:
		r.HasTravelRule = true
	case KindChainAnalytics:
		r.HasChainAnalytics = true
	case KindSanctionsScreening:
		r.HasSanctionsScreening = true
	case KindStablecoinRedemption:
		r.HasStablecoinRedemption = true
	case KindDeFiInteraction:
		r.HasDeFiInteraction = true
	case KindBridgeSwap:
		r.HasBridgeSwap = true
	case KindSmartContractAudit:
		r.HasSmartContractAudit = true
	case KindKYCTierClassification:
		r.HasKYCTierClassification = true
	case KindAFIPRG5697Filing:
		r.HasAFIPRG5697 = true
	case KindUIFSTR:
		r.HasUIFSTR = true
	case KindCNVRG1058Filing:
		r.HasCNVRG1058 = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag.
	}
	if r.RedemptionAmountUSD >= LargeRedemptionAmountUSDThreshold {
		r.HasLargeRedemption = true
	}
	if r.SanctionsHitCount >= SanctionsHitRollupThreshold {
		r.HasSanctionsHit = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasSeedPhraseIndicator
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && IsWalletAddrPIIKind(r.ArtifactKind) {
		r.IsWalletAddrPIIRisk = true
	}
	if readable && IsTreasuryDisclosureKind(r.ArtifactKind) {
		r.IsTreasuryDisclosureRisk = true
	}
	if readable && IsAMLScreeningKind(r.ArtifactKind) {
		r.IsAMLScreeningLeak = true
	}
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].ArtifactKind != rs[j].ArtifactKind {
			return rs[i].ArtifactKind < rs[j].ArtifactKind
		}
		return rs[i].ReportingPeriod < rs[j].ReportingPeriod
	})
}
