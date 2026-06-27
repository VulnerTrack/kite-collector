// Package winargtesoro audits AR Tesoro-Nacional primary-debt-
// issuance artifact files cached on creador-de-mercado (primary-
// dealer) ALYC desks, BCRA-coordination officers, MECON Secretaría
// de Finanzas debt managers, IMF-liaison and pricing-officer
// workstations — entities participating in or servicing the
// primary market for Tesoro debt (LECAP/LECER/LEDE Letras,
// BONTE/BONCER/AL30/GD30/PARP/TX26 Bonos, BOPREAL).
//
// Regulated under Ley 24.156 (LAF) + Ley 27.541/27.605/27.668
// (Solidaridad / Sostenibilidad / FMI), Decreto 1344/2007, MECON
// Res. 18/2017 + 56/2022 (Creadores de Mercado), BCRA Com. A
// 7724/7726 (Tesoro-LELIQ coordination), CNV RG 622 art.40 (ALYC
// primary), CNV RG 731 art.7 (best execution deuda pública), AFIP
// RG 4815, UIF Res. 21/2018.
//
// Distinct from prior iters because the shape is **primary-market
// debt-issuance back-office** — pre-auction bid book reveals
// dealer demand (front-run material), post-auction allocation
// reveals dealer inventory (MNPI for secondary supply), Programa
// Financiero reveals issuance calendar pre-publication, debt-
// restructuring (canje) reveals haircuts pre-announcement (Ley
// 26.831 art.117 insider).
//
// Read-only by intent. (Project guideline 4.2.)
package winargtesoro

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

// LargeBidNotionalARSThreshold — > 10B ARS bid in a single
// auction flags large-bid rollup. Tesoro single-dealer cap
// is typically 25 % of auction size; 10B ARS represents a
// large institutional bid.
const LargeBidNotionalARSThreshold = 10_000_000_000

// ArtifactKind pinned to host_arg_tesoro.artifact_kind.
type ArtifactKind string

const (
	KindAuctionBid          ArtifactKind = "tesoro-auction-bid"
	KindAllocation          ArtifactKind = "tesoro-allocation"
	KindPrimaryDealerRoster ArtifactKind = "tesoro-primary-dealer-roster"
	KindDebtIssuancePlan    ArtifactKind = "tesoro-debt-issuance-plan"
	KindSyndicatedPlacement ArtifactKind = "tesoro-syndicated-placement"
	KindDebtRestructuring   ArtifactKind = "tesoro-debt-restructuring"
	KindCNVMPSettlement     ArtifactKind = "tesoro-cnvmp-settlement"
	KindROFEXPrimary        ArtifactKind = "tesoro-rofex-primary"
	KindFinancingProgram    ArtifactKind = "tesoro-financing-program"
	KindBCRACoordination    ArtifactKind = "tesoro-bcra-coordination"
	KindMECONResolution     ArtifactKind = "tesoro-mecon-resolution"
	KindIMFEngagement       ArtifactKind = "tesoro-imf-engagement"
	KindConfig              ArtifactKind = "tesoro-config"
	KindCredentials         ArtifactKind = "tesoro-credentials"
	KindInstaller           ArtifactKind = "tesoro-installer"
	KindOther               ArtifactKind = "other"
	KindUnknown             ArtifactKind = "unknown"
)

// InstrumentClass pinned to host_arg_tesoro.instrument_class.
type InstrumentClass string

const (
	InstLECAP   InstrumentClass = "lecap"
	InstLECER   InstrumentClass = "lecer"
	InstLEDE    InstrumentClass = "lede"
	InstLEMIN   InstrumentClass = "lemin"
	InstBONTE   InstrumentClass = "bonte"
	InstBONCER  InstrumentClass = "boncer"
	InstBONAD   InstrumentClass = "bonad"
	InstAL30    InstrumentClass = "al30"
	InstAL35    InstrumentClass = "al35"
	InstAL38    InstrumentClass = "al38"
	InstAL41    InstrumentClass = "al41"
	InstGD29    InstrumentClass = "gd29"
	InstGD30    InstrumentClass = "gd30"
	InstGD35    InstrumentClass = "gd35"
	InstGD38    InstrumentClass = "gd38"
	InstGD41    InstrumentClass = "gd41"
	InstGD46    InstrumentClass = "gd46"
	InstPARP    InstrumentClass = "parp"
	InstDICA    InstrumentClass = "dica"
	InstDICY    InstrumentClass = "dicy"
	InstTX26    InstrumentClass = "tx26"
	InstTX28    InstrumentClass = "tx28"
	InstTY27    InstrumentClass = "ty27"
	InstBOPREAL InstrumentClass = "bopreal"
	InstCustom  InstrumentClass = "custom"
	InstNone    InstrumentClass = "none"
	InstUnknown InstrumentClass = "unknown"
)

// PlacementMethod pinned to host_arg_tesoro.placement_method.
type PlacementMethod string

const (
	MethodCompetitiveAuction PlacementMethod = "competitive-auction"
	MethodNonCompetitive     PlacementMethod = "non-competitive"
	MethodSyndicated         PlacementMethod = "syndicated"
	MethodPrivatePlacement   PlacementMethod = "private-placement"
	MethodSwap               PlacementMethod = "swap"
	MethodBuyback            PlacementMethod = "buyback"
	MethodCustom             PlacementMethod = "custom"
	MethodNone               PlacementMethod = "none"
	MethodUnknown            PlacementMethod = "unknown"
)

// TesoroRole pinned to host_arg_tesoro.tesoro_role.
type TesoroRole string

const (
	RolePrimaryDealer      TesoroRole = "primary-dealer"
	RoleFinanceSecretariat TesoroRole = "finance-secretariat"
	RoleTreasuryOfficer    TesoroRole = "treasury-officer"
	RoleDebtManager        TesoroRole = "debt-manager"
	RoleIMFLiaison         TesoroRole = "imf-liaison"
	RoleBCRACoordinator    TesoroRole = "bcra-coordinator"
	RolePricingOfficer     TesoroRole = "pricing-officer"
	RoleComplianceOfficer  TesoroRole = "compliance-officer"
	RoleCCO                TesoroRole = "cco"
	RoleAPI                TesoroRole = "api"
	RoleOther              TesoroRole = "other"
	RoleUnknown            TesoroRole = "unknown"
)

// Row mirrors host_arg_tesoro column shape.
type Row struct {
	FilePath                    string          `json:"file_path"`
	FileHash                    string          `json:"file_hash"`
	UserProfile                 string          `json:"user_profile,omitempty"`
	ArtifactKind                ArtifactKind    `json:"artifact_kind"`
	InstrumentClass             InstrumentClass `json:"instrument_class"`
	PlacementMethod             PlacementMethod `json:"placement_method,omitempty"`
	TesoroRole                  TesoroRole      `json:"tesoro_role"`
	ReportingPeriod             string          `json:"reporting_period,omitempty"`
	DealerCuitPrefix            string          `json:"dealer_cuit_prefix,omitempty"`
	DealerCuitSuffix4           string          `json:"dealer_cuit_suffix4,omitempty"`
	AuctionID                   string          `json:"auction_id,omitempty"`
	BidCount                    int64           `json:"bid_count,omitempty"`
	AllocationCount             int64           `json:"allocation_count,omitempty"`
	DealerCount                 int64           `json:"dealer_count,omitempty"`
	LargestBidNotionalARS       int64           `json:"largest_bid_notional_ars,omitempty"`
	TotalOfferedARS             int64           `json:"total_offered_ars,omitempty"`
	TotalAllocatedARS           int64           `json:"total_allocated_ars,omitempty"`
	FileOwnerUID                int             `json:"file_owner_uid,omitempty"`
	FileMode                    int             `json:"file_mode,omitempty"`
	FileSize                    int64           `json:"file_size,omitempty"`
	HasPasswordInConfig         bool            `json:"has_password_in_config"`
	HasAuctionBid               bool            `json:"has_auction_bid"`
	HasAllocation               bool            `json:"has_allocation"`
	HasPrimaryDealerRoster      bool            `json:"has_primary_dealer_roster"`
	HasDebtIssuancePlan         bool            `json:"has_debt_issuance_plan"`
	HasSyndicatedPlacement      bool            `json:"has_syndicated_placement"`
	HasDebtRestructuring        bool            `json:"has_debt_restructuring"`
	HasCNVMPSettlement          bool            `json:"has_cnvmp_settlement"`
	HasROFEXPrimary             bool            `json:"has_rofex_primary"`
	HasFinancingProgram         bool            `json:"has_financing_program"`
	HasBCRACoordination         bool            `json:"has_bcra_coordination"`
	HasMECONResolution          bool            `json:"has_mecon_resolution"`
	HasIMFEngagement            bool            `json:"has_imf_engagement"`
	HasDealerCuit               bool            `json:"has_dealer_cuit"`
	HasLargeBidValue            bool            `json:"has_large_bid_value"`
	IsRecent                    bool            `json:"is_recent"`
	IsWorldReadable             bool            `json:"is_world_readable"`
	IsGroupReadable             bool            `json:"is_group_readable"`
	IsCredentialExposureRisk    bool            `json:"is_credential_exposure_risk"`
	IsPreAuctionDisclosureRisk  bool            `json:"is_pre_auction_disclosure_risk"`
	IsAllocationLeakRisk        bool            `json:"is_allocation_leak_risk"`
	IsSovereignDebtStrategyLeak bool            `json:"is_sovereign_debt_strategy_leak"`
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
func HashSecret(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Tesoro`,
		`C:\MECON`,
		`C:\PrimaryDealer`,
		`C:\Program Files\Tesoro`,
		"/opt/tesoro",
		"/opt/mecon",
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

// UserTesoroDirs is the curated per-user relative path set.
func UserTesoroDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Tesoro"},
		{"AppData", "Roaming", "MECON"},
		{"AppData", "Roaming", "PrimaryDealer"},
		{"AppData", "Local", "Tesoro"},
		{".config", "tesoro"},
		{".tesoro"},
		{"Documents", "Tesoro"},
		{"Documents", "Licitaciones"},
		{"Documents", "DeudaPublica"},
		{"tesoro"},
		{"licitaciones"},
		{"creadores-mercado"},
		{"deuda-publica"},
		{"Library", "Application Support", "Tesoro"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a Tesoro
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
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Tesoro catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"auction_bid", "auction-bid", "oferta_licitacion", "oferta-licitacion",
		"allocation_", "allocation-", "asignacion_", "asignacion-",
		"primary_dealer", "primary-dealer", "creadores_mercado",
		"creadores-mercado", "creador_mercado",
		"debt_issuance", "debt-issuance", "emision_deuda",
		"syndicated_placement", "syndicated-placement", "colocacion_sindicada",
		"debt_restructuring", "debt-restructuring", "canje_deuda",
		"cnvmp_settlement", "cnvmp-settlement",
		"rofex_primary", "rofex-primary",
		"financing_program", "financing-program", "programa_financiero",
		"bcra_coordination", "bcra-coordination", "tesoro_bcra", "tesoro-bcra",
		"mecon_resolution", "mecon-resolution", "resolucion_mecon",
		"imf_engagement", "imf-engagement", "fmi_acuerdo", "fmi-acuerdo",
		"tesoro_config", "tesoro-config", "tesoro_",
		"lecap_", "lecer_", "lede_", "lemin_",
		"bonte_", "boncer_", "bonad_",
		"al30_", "al35_", "al38_", "al41_",
		"gd29_", "gd30_", "gd35_", "gd38_", "gd41_", "gd46_",
		"parp_", "dica_", "dicy_", "tx26_", "tx28_", "ty27_",
		"bopreal_",
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
		if strings.Contains(n, "tesoro") || strings.Contains(n, "mecon") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "imf_engagement") ||
		strings.Contains(n, "imf-engagement") ||
		strings.Contains(n, "fmi_acuerdo") ||
		strings.Contains(n, "fmi-acuerdo"):
		return KindIMFEngagement
	case strings.Contains(n, "mecon_resolution") ||
		strings.Contains(n, "mecon-resolution") ||
		strings.Contains(n, "resolucion_mecon"):
		return KindMECONResolution
	case strings.Contains(n, "bcra_coordination") ||
		strings.Contains(n, "bcra-coordination") ||
		strings.Contains(n, "tesoro_bcra") ||
		strings.Contains(n, "tesoro-bcra"):
		return KindBCRACoordination
	case strings.Contains(n, "financing_program") ||
		strings.Contains(n, "financing-program") ||
		strings.Contains(n, "programa_financiero"):
		return KindFinancingProgram
	case strings.Contains(n, "rofex_primary") ||
		strings.Contains(n, "rofex-primary"):
		return KindROFEXPrimary
	case strings.Contains(n, "cnvmp_settlement") ||
		strings.Contains(n, "cnvmp-settlement"):
		return KindCNVMPSettlement
	case strings.Contains(n, "debt_restructuring") ||
		strings.Contains(n, "debt-restructuring") ||
		strings.Contains(n, "canje_deuda"):
		return KindDebtRestructuring
	case strings.Contains(n, "syndicated_placement") ||
		strings.Contains(n, "syndicated-placement") ||
		strings.Contains(n, "colocacion_sindicada"):
		return KindSyndicatedPlacement
	case strings.Contains(n, "debt_issuance") ||
		strings.Contains(n, "debt-issuance") ||
		strings.Contains(n, "emision_deuda"):
		return KindDebtIssuancePlan
	case strings.Contains(n, "primary_dealer") ||
		strings.Contains(n, "primary-dealer") ||
		strings.Contains(n, "creadores_mercado") ||
		strings.Contains(n, "creadores-mercado") ||
		strings.Contains(n, "creador_mercado"):
		return KindPrimaryDealerRoster
	case strings.Contains(n, "allocation_") ||
		strings.Contains(n, "allocation-") ||
		strings.Contains(n, "asignacion_") ||
		strings.Contains(n, "asignacion-"):
		return KindAllocation
	case strings.Contains(n, "auction_bid") ||
		strings.Contains(n, "auction-bid") ||
		strings.Contains(n, "oferta_licitacion") ||
		strings.Contains(n, "oferta-licitacion"):
		return KindAuctionBid
	case n == "credentials.json" || n == "credentials.yaml" ||
		n == "credentials.yml" || strings.HasPrefix(n, "credentials"):
		return KindCredentials
	case strings.Contains(n, "tesoro") && strings.Contains(n, "config"):
		return KindConfig
	}
	return KindOther
}

// InstrumentClassFromName detects instrument class from filename.
func InstrumentClassFromName(name string) InstrumentClass {
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "lecap"):
		return InstLECAP
	case strings.Contains(n, "lecer"):
		return InstLECER
	case strings.Contains(n, "lede"):
		return InstLEDE
	case strings.Contains(n, "lemin"):
		return InstLEMIN
	case strings.Contains(n, "bonte"):
		return InstBONTE
	case strings.Contains(n, "boncer"):
		return InstBONCER
	case strings.Contains(n, "bonad"):
		return InstBONAD
	case strings.Contains(n, "al30"):
		return InstAL30
	case strings.Contains(n, "al35"):
		return InstAL35
	case strings.Contains(n, "al38"):
		return InstAL38
	case strings.Contains(n, "al41"):
		return InstAL41
	case strings.Contains(n, "gd29"):
		return InstGD29
	case strings.Contains(n, "gd30"):
		return InstGD30
	case strings.Contains(n, "gd35"):
		return InstGD35
	case strings.Contains(n, "gd38"):
		return InstGD38
	case strings.Contains(n, "gd41"):
		return InstGD41
	case strings.Contains(n, "gd46"):
		return InstGD46
	case strings.Contains(n, "parp"):
		return InstPARP
	case strings.Contains(n, "dica"):
		return InstDICA
	case strings.Contains(n, "dicy"):
		return InstDICY
	case strings.Contains(n, "tx26"):
		return InstTX26
	case strings.Contains(n, "tx28"):
		return InstTX28
	case strings.Contains(n, "ty27"):
		return InstTY27
	case strings.Contains(n, "bopreal"):
		return InstBOPREAL
	}
	return InstUnknown
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

// CuitEntityOnlyFingerprint extracts primary-dealer CUIT.
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

// IsPreAuctionKind reports whether the kind reveals
// pre-auction / pre-publication issuance info.
func IsPreAuctionKind(k ArtifactKind) bool {
	switch k {
	case KindAuctionBid, KindDebtIssuancePlan, KindFinancingProgram:
		return true
	case KindAllocation, KindPrimaryDealerRoster,
		KindSyndicatedPlacement, KindDebtRestructuring,
		KindCNVMPSettlement, KindROFEXPrimary,
		KindBCRACoordination, KindMECONResolution,
		KindIMFEngagement,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsAllocationLeakKind reports whether the kind reveals
// post-auction confidential allocation.
func IsAllocationLeakKind(k ArtifactKind) bool {
	switch k {
	case KindAllocation, KindSyndicatedPlacement, KindCNVMPSettlement:
		return true
	case KindAuctionBid, KindPrimaryDealerRoster,
		KindDebtIssuancePlan, KindDebtRestructuring,
		KindROFEXPrimary, KindFinancingProgram,
		KindBCRACoordination, KindMECONResolution,
		KindIMFEngagement,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsSovereignStrategyKind reports whether the kind reveals
// sovereign-debt-policy strategic material.
func IsSovereignStrategyKind(k ArtifactKind) bool {
	switch k {
	case KindDebtRestructuring, KindIMFEngagement,
		KindBCRACoordination, KindMECONResolution:
		return true
	case KindAuctionBid, KindAllocation,
		KindPrimaryDealerRoster, KindDebtIssuancePlan,
		KindSyndicatedPlacement, KindCNVMPSettlement,
		KindROFEXPrimary, KindFinancingProgram,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsCredentialKind reports whether the kind carries PII /
// credential material.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindAuctionBid, KindAllocation,
		KindPrimaryDealerRoster, KindDebtIssuancePlan,
		KindSyndicatedPlacement, KindDebtRestructuring,
		KindCNVMPSettlement, KindROFEXPrimary,
		KindFinancingProgram, KindBCRACoordination,
		KindMECONResolution, KindIMFEngagement,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
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
	if r.DealerCuitPrefix != "" {
		r.HasDealerCuit = true
	}
	switch r.ArtifactKind {
	case KindAuctionBid:
		r.HasAuctionBid = true
	case KindAllocation:
		r.HasAllocation = true
	case KindPrimaryDealerRoster:
		r.HasPrimaryDealerRoster = true
	case KindDebtIssuancePlan:
		r.HasDebtIssuancePlan = true
	case KindSyndicatedPlacement:
		r.HasSyndicatedPlacement = true
	case KindDebtRestructuring:
		r.HasDebtRestructuring = true
	case KindCNVMPSettlement:
		r.HasCNVMPSettlement = true
	case KindROFEXPrimary:
		r.HasROFEXPrimary = true
	case KindFinancingProgram:
		r.HasFinancingProgram = true
	case KindBCRACoordination:
		r.HasBCRACoordination = true
	case KindMECONResolution:
		r.HasMECONResolution = true
	case KindIMFEngagement:
		r.HasIMFEngagement = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag.
	}
	if r.LargestBidNotionalARS >= LargeBidNotionalARSThreshold {
		r.HasLargeBidValue = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	if readable && r.HasPasswordInConfig && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && IsPreAuctionKind(r.ArtifactKind) {
		r.IsPreAuctionDisclosureRisk = true
	}
	if readable && IsAllocationLeakKind(r.ArtifactKind) {
		r.IsAllocationLeakRisk = true
	}
	if readable && IsSovereignStrategyKind(r.ArtifactKind) {
		r.IsSovereignDebtStrategyLeak = true
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
