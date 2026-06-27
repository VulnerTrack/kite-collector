// Package winargipo audits AR IPO / Oferta-Pública-Primaria
// management artifact files cached on bookrunner-officer, ECM
// (Equity-Capital-Markets), syndicate-desk, prospectus-counsel,
// listing-agent, and roadshow-coordinator workstations at the
// bookrunner ALYCs leading AR equity issuances on BYMA + NYSE/
// NASDAQ cross-listings (Santander Investment Securities, Galicia
// Investments, BBVA AR, Macro Securities, BTG Pactual AR,
// Allaria, Cohen Bursátil, BACS, Balanz Capital).
//
// Regulated under Ley 26.831 + Ley 27.260 + CNV RG 622 art.13
// (prospecto) + art.18 (IPO requisitos) + art.30-bis (estabilización)
// + art.41 (block-trade) + CNV RG 731 art.6 (best ex colocación) +
// RG 1023 + BCRA Com. A 8005 + AFIP RG 4815 + UIF Res. 21/2018 +
// Ley 26.831 art.117 (insider) + Ley 27.401 + SEC Reg. S / Rule
// 144A / Reg. M (for cross-listed AR ADR Level 3 issuances).
//
// Distinct from prior iters because the shape is **equity-primary-
// issuance underwriting back-office** — bookbuilding allocation =
// pre-pricing investor demand (price-discovery MNPI), roadshow =
// FII courting signal (front-running), final-pricing memo = MNPI
// of discount-to-market, lockup calendar = post-IPO selling
// pressure timing, greenshoe = strong-vs-weak demand signal,
// stabilization = Reg M / RG 622 art.30-bis audit trail, syndicate
// fee split = bookrunner economics, comfort letter = subsequent-
// events MNPI.
//
// Read-only by intent. (Project guideline 4.2.)
package winargipo

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

// LargeOfferingSizeARSThreshold — > 5B ARS notional offering
// triggers large-offering rollup. 5B ARS ≈ 50M USD wholesale FX
// and represents a sizeable AR IPO (most AR IPOs since 2020
// have been smaller; YPF, Loma Negra, and Corp. América were
// > USD 100M, easily exceeding this threshold).
const LargeOfferingSizeARSThreshold = 5_000_000_000

// ArtifactKind pinned to host_arg_ipo.artifact_kind.
type ArtifactKind string

const (
	KindRoadshow              ArtifactKind = "ipo-roadshow"
	KindBookbuilding          ArtifactKind = "ipo-bookbuilding"
	KindUnderwritingAgreement ArtifactKind = "ipo-underwriting-agreement"
	KindProspectusDraft       ArtifactKind = "ipo-prospectus-draft"
	KindLockupCalendar        ArtifactKind = "ipo-lockup-calendar"
	KindGreenshoe             ArtifactKind = "ipo-greenshoe"
	KindStabilization         ArtifactKind = "ipo-stabilization"
	KindSyndicateFeeSplit     ArtifactKind = "ipo-syndicate-fee-split"
	KindInsiderRestriction    ArtifactKind = "ipo-insider-restriction"
	KindComfortLetter         ArtifactKind = "ipo-comfort-letter"
	KindLegalOpinion          ArtifactKind = "ipo-legal-opinion"
	KindCNVRG622Filing        ArtifactKind = "ipo-cnv-rg622-filing"
	KindPricingDecision       ArtifactKind = "ipo-pricing-decision"
	KindConfig                ArtifactKind = "ipo-config"
	KindCredentials           ArtifactKind = "ipo-credentials"
	KindInstaller             ArtifactKind = "ipo-installer"
	KindOther                 ArtifactKind = "other"
	KindUnknown               ArtifactKind = "unknown"
)

// BookrunnerALYC pinned to host_arg_ipo.bookrunner_alyc.
type BookrunnerALYC string

const (
	ALYCSantanderInvestment BookrunnerALYC = "santander-investment"
	ALYCGaliciaInvestments  BookrunnerALYC = "galicia-investments"
	ALYCBBVAAR              BookrunnerALYC = "bbva-ar"
	ALYCMacroSecurities     BookrunnerALYC = "macro-securities"
	ALYCBTGPactualAR        BookrunnerALYC = "btg-pactual-ar"
	ALYCAllaria             BookrunnerALYC = "allaria"
	ALYCCohenBursatil       BookrunnerALYC = "cohen-bursatil"
	ALYCBACS                BookrunnerALYC = "bacs"
	ALYCBalanzCapital       BookrunnerALYC = "balanz-capital"
	ALYCItauAR              BookrunnerALYC = "itau-ar"
	ALYCCustom              BookrunnerALYC = "custom"
	ALYCNone                BookrunnerALYC = "none"
	ALYCUnknown             BookrunnerALYC = "unknown"
)

// BookrunnerRole pinned to host_arg_ipo.bookrunner_role.
type BookrunnerRole string

const (
	RoleLeadBookrunner     BookrunnerRole = "lead-bookrunner"
	RoleJointBookrunner    BookrunnerRole = "joint-bookrunner"
	RoleCoManager          BookrunnerRole = "co-manager"
	RoleSeniorCoManager    BookrunnerRole = "senior-co-manager"
	RoleSellingGroupMember BookrunnerRole = "selling-group-member"
	RoleStabilizingAgent   BookrunnerRole = "stabilizing-agent"
	RoleListingAgent       BookrunnerRole = "listing-agent"
	RoleCustom             BookrunnerRole = "custom"
	RoleNone               BookrunnerRole = "none"
	RoleUnknown            BookrunnerRole = "unknown"
)

// OfferingType pinned to host_arg_ipo.offering_type.
type OfferingType string

const (
	OfferingIPO                    OfferingType = "ipo"
	OfferingSPO                    OfferingType = "spo"
	OfferingFollowOn               OfferingType = "follow-on"
	OfferingRightsIssue            OfferingType = "rights-issue"
	OfferingBlockTrade             OfferingType = "block-trade"
	OfferingPrivatePlacementPreIPO OfferingType = "private-placement-pre-ipo"
	OfferingDirectListing          OfferingType = "direct-listing"
	OfferingSPACMerger             OfferingType = "spac-merger"
	OfferingADRIssuance            OfferingType = "adr-issuance"
	OfferingCustom                 OfferingType = "custom"
	OfferingNone                   OfferingType = "none"
	OfferingUnknown                OfferingType = "unknown"
)

// IPORole pinned to host_arg_ipo.ipo_role.
type IPORole string

const (
	IPORoleBookrunnerOfficer    IPORole = "bookrunner-officer"
	IPORoleEquityCapitalMarkets IPORole = "equity-capital-markets"
	IPORoleSyndicateDesk        IPORole = "syndicate-desk"
	IPORoleComplianceOfficer    IPORole = "compliance-officer"
	IPORoleProspectusCounsel    IPORole = "prospectus-counsel"
	IPORoleListingAgent         IPORole = "listing-agent"
	IPORoleRoadshowCoordinator  IPORole = "roadshow-coordinator"
	IPORoleBackOffice           IPORole = "back-office"
	IPORoleMiddleOffice         IPORole = "middle-office"
	IPORoleCCO                  IPORole = "cco"
	IPORoleAPI                  IPORole = "api"
	IPORoleOther                IPORole = "other"
	IPORoleUnknown              IPORole = "unknown"
)

// ListingVenue pinned to host_arg_ipo.listing_venue.
type ListingVenue string

const (
	VenueBYMA    ListingVenue = "byma"
	VenueBCBA    ListingVenue = "bcba"
	VenueMAE     ListingVenue = "mae"
	VenueNYSE    ListingVenue = "nyse"
	VenueNASDAQ  ListingVenue = "nasdaq"
	VenueLSE     ListingVenue = "lse"
	VenueBME     ListingVenue = "bme"
	VenueSSX     ListingVenue = "ssx"
	VenueB3      ListingVenue = "b3"
	VenueCustom  ListingVenue = "custom"
	VenueNone    ListingVenue = "none"
	VenueUnknown ListingVenue = "unknown"
)

// Row mirrors host_arg_ipo column shape.
type Row struct {
	FilePath                   string         `json:"file_path"`
	FileHash                   string         `json:"file_hash"`
	UserProfile                string         `json:"user_profile,omitempty"`
	ArtifactKind               ArtifactKind   `json:"artifact_kind"`
	BookrunnerALYC             BookrunnerALYC `json:"bookrunner_alyc"`
	BookrunnerRole             BookrunnerRole `json:"bookrunner_role,omitempty"`
	OfferingType               OfferingType   `json:"offering_type,omitempty"`
	IPORole                    IPORole        `json:"ipo_role"`
	ListingVenue               ListingVenue   `json:"listing_venue,omitempty"`
	ReportingPeriod            string         `json:"reporting_period,omitempty"`
	IssuerCuitPrefix           string         `json:"issuer_cuit_prefix,omitempty"`
	IssuerCuitSuffix4          string         `json:"issuer_cuit_suffix4,omitempty"`
	BookrunnerCuitPrefix       string         `json:"bookrunner_cuit_prefix,omitempty"`
	BookrunnerCuitSuffix4      string         `json:"bookrunner_cuit_suffix4,omitempty"`
	DealCodename               string         `json:"deal_codename,omitempty"`
	InvestorCount              int64          `json:"investor_count,omitempty"`
	AllocationCount            int64          `json:"allocation_count,omitempty"`
	InsiderCount               int64          `json:"insider_count,omitempty"`
	OfferingSizeARS            int64          `json:"offering_size_ars,omitempty"`
	GreenshoeSizeARS           int64          `json:"greenshoe_size_ars,omitempty"`
	BookrunnerFeeBps           int64          `json:"bookrunner_fee_bps,omitempty"`
	FileOwnerUID               int            `json:"file_owner_uid,omitempty"`
	FileMode                   int            `json:"file_mode,omitempty"`
	FileSize                   int64          `json:"file_size,omitempty"`
	HasPasswordInConfig        bool           `json:"has_password_in_config"`
	HasRoadshow                bool           `json:"has_roadshow"`
	HasBookbuilding            bool           `json:"has_bookbuilding"`
	HasUnderwritingAgreement   bool           `json:"has_underwriting_agreement"`
	HasProspectusDraft         bool           `json:"has_prospectus_draft"`
	HasLockupCalendar          bool           `json:"has_lockup_calendar"`
	HasGreenshoe               bool           `json:"has_greenshoe"`
	HasStabilization           bool           `json:"has_stabilization"`
	HasSyndicateFeeSplit       bool           `json:"has_syndicate_fee_split"`
	HasInsiderRestriction      bool           `json:"has_insider_restriction"`
	HasComfortLetter           bool           `json:"has_comfort_letter"`
	HasLegalOpinion            bool           `json:"has_legal_opinion"`
	HasCNVRG622Filing          bool           `json:"has_cnv_rg622_filing"`
	HasPricingDecision         bool           `json:"has_pricing_decision"`
	HasIssuerCuit              bool           `json:"has_issuer_cuit"`
	HasBookrunnerCuit          bool           `json:"has_bookrunner_cuit"`
	HasLargeOfferingSize       bool           `json:"has_large_offering_size"`
	IsRecent                   bool           `json:"is_recent"`
	IsWorldReadable            bool           `json:"is_world_readable"`
	IsGroupReadable            bool           `json:"is_group_readable"`
	IsCredentialExposureRisk   bool           `json:"is_credential_exposure_risk"`
	IsPrePricingDisclosureRisk bool           `json:"is_pre_pricing_disclosure_risk"`
	IsAllocationLeakRisk       bool           `json:"is_allocation_leak_risk"`
	IsLockupIntelligenceLeak   bool           `json:"is_lockup_intelligence_leak"`
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

// DefaultInstallRoots is the curated IPO install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\IPO`,
		`C:\ECM`,
		`C:\Bookrunner`,
		`C:\Program Files\IPO`,
		"/opt/ipo",
		"/opt/ecm",
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

// UserIPODirs is the curated per-user relative path set.
func UserIPODirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "IPO"},
		{"AppData", "Roaming", "ECM"},
		{"AppData", "Roaming", "Bookrunner"},
		{"AppData", "Local", "IPO"},
		{".config", "ipo"},
		{".ipo"},
		{"Documents", "IPO"},
		{"Documents", "ECM"},
		{"Documents", "Deals"},
		{"Documents", "Prospectus"},
		{"ipo"},
		{"ecm"},
		{"deals"},
		{"prospectus"},
		{"roadshow"},
		{"bookbuilding"},
		{"Library", "Application Support", "IPO"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries an IPO
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
// to the IPO catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"roadshow_", "roadshow-",
		"bookbuilding_", "bookbuilding-", "book_building", "book-building",
		"underwriting_agreement", "underwriting-agreement", "ua_draft",
		"prospectus_", "prospectus-",
		"lockup_calendar", "lockup-calendar", "lock_up_calendar", "lock-up-calendar",
		"greenshoe_", "greenshoe-", "over_allotment", "over-allotment",
		"stabilization_", "stabilization-", "estabilizacion",
		"syndicate_fee_split", "syndicate-fee-split",
		"insider_restriction", "insider-restriction", "lista_insider",
		"comfort_letter", "comfort-letter",
		"legal_opinion", "legal-opinion", "opinion_legal",
		"cnv_rg622_filing", "cnv-rg622-filing", "cnv_filing_ipo",
		"pricing_decision", "pricing-decision", "memo_pricing",
		"ipo_config", "ipo-config", "ipo_",
		"santander_investment", "galicia_investments",
		"macro_securities", "btg_pactual", "btg-pactual",
		"allaria_", "cohen_bursatil", "cohen-bursatil",
		"bacs_", "balanz_capital", "balanz-capital",
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
		if strings.Contains(n, "ipo") || strings.Contains(n, "ecm") ||
			strings.Contains(n, "bookrunner") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "pricing_decision") ||
		strings.Contains(n, "pricing-decision") ||
		strings.Contains(n, "memo_pricing"):
		return KindPricingDecision
	case strings.Contains(n, "cnv_rg622_filing") ||
		strings.Contains(n, "cnv-rg622-filing") ||
		strings.Contains(n, "cnv_filing_ipo"):
		return KindCNVRG622Filing
	case strings.Contains(n, "legal_opinion") ||
		strings.Contains(n, "legal-opinion") ||
		strings.Contains(n, "opinion_legal"):
		return KindLegalOpinion
	case strings.Contains(n, "comfort_letter") ||
		strings.Contains(n, "comfort-letter"):
		return KindComfortLetter
	case strings.Contains(n, "insider_restriction") ||
		strings.Contains(n, "insider-restriction") ||
		strings.Contains(n, "lista_insider"):
		return KindInsiderRestriction
	case strings.Contains(n, "syndicate_fee_split") ||
		strings.Contains(n, "syndicate-fee-split"):
		return KindSyndicateFeeSplit
	case strings.Contains(n, "stabilization") ||
		strings.Contains(n, "estabilizacion"):
		return KindStabilization
	case strings.Contains(n, "greenshoe") ||
		strings.Contains(n, "over_allotment") ||
		strings.Contains(n, "over-allotment"):
		return KindGreenshoe
	case strings.Contains(n, "lockup_calendar") ||
		strings.Contains(n, "lockup-calendar") ||
		strings.Contains(n, "lock_up_calendar") ||
		strings.Contains(n, "lock-up-calendar"):
		return KindLockupCalendar
	case strings.Contains(n, "prospectus"):
		return KindProspectusDraft
	case strings.Contains(n, "underwriting_agreement") ||
		strings.Contains(n, "underwriting-agreement") ||
		strings.Contains(n, "ua_draft"):
		return KindUnderwritingAgreement
	case strings.Contains(n, "bookbuilding") ||
		strings.Contains(n, "book_building") ||
		strings.Contains(n, "book-building"):
		return KindBookbuilding
	case strings.HasPrefix(n, "roadshow_") ||
		strings.HasPrefix(n, "roadshow-"):
		return KindRoadshow
	case n == "credentials.json" || n == "credentials.yaml" ||
		n == "credentials.yml" || strings.HasPrefix(n, "credentials"):
		return KindCredentials
	case strings.Contains(n, "ipo") && strings.Contains(n, "config"):
		return KindConfig
	}
	return KindOther
}

// BookrunnerALYCFromName detects bookrunner ALYC from filename.
func BookrunnerALYCFromName(name string) BookrunnerALYC {
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "santander_investment") ||
		strings.Contains(n, "santander-investment"):
		return ALYCSantanderInvestment
	case strings.Contains(n, "galicia_investments") ||
		strings.Contains(n, "galicia-investments"):
		return ALYCGaliciaInvestments
	case strings.HasPrefix(n, "bbva_ar") ||
		strings.HasPrefix(n, "bbva-ar"):
		return ALYCBBVAAR
	case strings.Contains(n, "macro_securities") ||
		strings.Contains(n, "macro-securities"):
		return ALYCMacroSecurities
	case strings.Contains(n, "btg_pactual") ||
		strings.Contains(n, "btg-pactual"):
		return ALYCBTGPactualAR
	case strings.HasPrefix(n, "allaria_") ||
		strings.Contains(n, "_allaria_"):
		return ALYCAllaria
	case strings.Contains(n, "cohen_bursatil") ||
		strings.Contains(n, "cohen-bursatil"):
		return ALYCCohenBursatil
	case strings.HasPrefix(n, "bacs_") ||
		strings.Contains(n, "_bacs_"):
		return ALYCBACS
	case strings.Contains(n, "balanz_capital") ||
		strings.Contains(n, "balanz-capital"):
		return ALYCBalanzCapital
	case strings.HasPrefix(n, "itau_ar") ||
		strings.HasPrefix(n, "itau-ar"):
		return ALYCItauAR
	}
	return ALYCUnknown
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

// CuitEntityOnlyFingerprint extracts entity CUIT (issuer +
// bookrunner are always entities).
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
	case KindRoadshow, KindBookbuilding,
		KindUnderwritingAgreement, KindProspectusDraft,
		KindLockupCalendar, KindGreenshoe,
		KindStabilization, KindSyndicateFeeSplit,
		KindInsiderRestriction, KindComfortLetter,
		KindLegalOpinion, KindCNVRG622Filing,
		KindPricingDecision,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsPrePricingKind reports whether the kind reveals
// pre-pricing demand / final-price MNPI material.
func IsPrePricingKind(k ArtifactKind) bool {
	switch k {
	case KindBookbuilding, KindPricingDecision, KindRoadshow:
		return true
	case KindUnderwritingAgreement, KindProspectusDraft,
		KindLockupCalendar, KindGreenshoe,
		KindStabilization, KindSyndicateFeeSplit,
		KindInsiderRestriction, KindComfortLetter,
		KindLegalOpinion, KindCNVRG622Filing,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsAllocationLeakKind reports whether the kind reveals
// allocation + bookrunner-economics confidential material.
func IsAllocationLeakKind(k ArtifactKind) bool {
	switch k {
	case KindBookbuilding, KindSyndicateFeeSplit:
		return true
	case KindRoadshow, KindUnderwritingAgreement,
		KindProspectusDraft, KindLockupCalendar,
		KindGreenshoe, KindStabilization,
		KindInsiderRestriction, KindComfortLetter,
		KindLegalOpinion, KindCNVRG622Filing,
		KindPricingDecision,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsLockupIntelligenceKind reports whether the kind reveals
// post-IPO selling-pressure-timing material.
func IsLockupIntelligenceKind(k ArtifactKind) bool {
	switch k {
	case KindLockupCalendar, KindInsiderRestriction, KindGreenshoe:
		return true
	case KindRoadshow, KindBookbuilding,
		KindUnderwritingAgreement, KindProspectusDraft,
		KindStabilization, KindSyndicateFeeSplit,
		KindComfortLetter, KindLegalOpinion,
		KindCNVRG622Filing, KindPricingDecision,
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
	if r.IssuerCuitPrefix != "" {
		r.HasIssuerCuit = true
	}
	if r.BookrunnerCuitPrefix != "" {
		r.HasBookrunnerCuit = true
	}
	switch r.ArtifactKind {
	case KindRoadshow:
		r.HasRoadshow = true
	case KindBookbuilding:
		r.HasBookbuilding = true
	case KindUnderwritingAgreement:
		r.HasUnderwritingAgreement = true
	case KindProspectusDraft:
		r.HasProspectusDraft = true
	case KindLockupCalendar:
		r.HasLockupCalendar = true
	case KindGreenshoe:
		r.HasGreenshoe = true
	case KindStabilization:
		r.HasStabilization = true
	case KindSyndicateFeeSplit:
		r.HasSyndicateFeeSplit = true
	case KindInsiderRestriction:
		r.HasInsiderRestriction = true
	case KindComfortLetter:
		r.HasComfortLetter = true
	case KindLegalOpinion:
		r.HasLegalOpinion = true
	case KindCNVRG622Filing:
		r.HasCNVRG622Filing = true
	case KindPricingDecision:
		r.HasPricingDecision = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag.
	}
	if r.OfferingSizeARS >= LargeOfferingSizeARSThreshold {
		r.HasLargeOfferingSize = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	if readable && r.HasPasswordInConfig && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && IsPrePricingKind(r.ArtifactKind) {
		r.IsPrePricingDisclosureRisk = true
	}
	if readable && IsAllocationLeakKind(r.ArtifactKind) {
		r.IsAllocationLeakRisk = true
	}
	if readable && IsLockupIntelligenceKind(r.ArtifactKind) {
		r.IsLockupIntelligenceLeak = true
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
