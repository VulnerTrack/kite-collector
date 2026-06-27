// Package winargfgs audits ANSES FGS (Fondo de Garantía de
// Sustentabilidad, Ley 26.425) sovereign-wealth-fund artifact
// files cached on Argentine government, ANSES, and FGS executive
// workstations.
//
// FGS is the AR public pension sovereign wealth fund. Distinct
// from all prior iters because the shape is **state-owned
// sovereign-wealth-fund** under public-administration law (Ley
// 24.156), not CNV RG 731 (broker-dealer ALYC):
//
//   - vs iter 187 winargssn       — private insurance investor.
//   - vs iter 186 winargcrs       — cross-border CRS/FATCA tax.
//   - vs iter 185 winargcohen     — broker-dealer ALYC.
//   - vs iter 178 winargsintesis  — FCI back-office.
//
// FGS is the largest single institutional holder of AR equity
// (~10-15% of Merval panel líder market cap) plus the dominant
// holder of LICs (Letras Intransferibles — non-tradeable special
// government instruments unique to FGS).
//
// Headline finding shapes:
//
//   - `has_cartera_fgs=1` — FGS portfolio detail.
//   - `has_lic_record=1` — LIC subscription / holding.
//   - `has_directorio_acta=1` — board minutes (insider-info).
//   - `has_primary_auction_bid=1` — auction bid pre-result.
//   - `has_voting_record=1` — asamblea voting position.
//   - `has_sipa_pension_record=1` — SIPA pensioner roster.
//   - `has_byma_panel_lider_holding=1` — FGS >5% in panel líder.
//   - `is_market_moving_info_risk=1` — readable + (acta OR
//     auction bid OR voting record).
//
// Read-only by intent. (Project guideline 4.2.)
package winargfgs

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

// MaxRows bounds per-scan output.
const MaxRows = 16384

// MaxFileBytes bounds per-file read (16 MiB).
const MaxFileBytes = 16 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// InstitutionalPortfolioInstrumentsThreshold — > 100 distinct
// instruments flags a full sovereign-wealth-fund portfolio.
const InstitutionalPortfolioInstrumentsThreshold = 100

// PanelLiderHoldingThreshold — FGS holds > 5% in many panel
// líder names; > 3 distinct panel líder positions in one
// cartera = systemic-risk relevance.
const PanelLiderHoldingThreshold = 3

// ArtifactKind pinned to host_arg_fgs.artifact_kind.
type ArtifactKind string

const (
	KindCarteraFGS           ArtifactKind = "fgs-cartera"
	KindLICRecord            ArtifactKind = "fgs-lic-record"
	KindDirectorioActa       ArtifactKind = "fgs-directorio-acta"
	KindComiteActa           ArtifactKind = "fgs-comite-acta"
	KindLineamientosDoc      ArtifactKind = "fgs-lineamientos-doc"
	KindPrimaryAuctionBid    ArtifactKind = "fgs-primary-auction-bid"
	KindPrimaryAuctionResult ArtifactKind = "fgs-primary-auction-result"
	KindCustodiaRecord       ArtifactKind = "fgs-custodia-record"
	KindVotingRecord         ArtifactKind = "fgs-voting-record"
	KindSIPAPensionRecord    ArtifactKind = "fgs-sipa-pension-record"
	KindFilingReceipt        ArtifactKind = "fgs-filing-receipt"
	KindConfig               ArtifactKind = "fgs-config"
	KindCredentials          ArtifactKind = "fgs-credentials"
	KindInstaller            ArtifactKind = "fgs-installer"
	KindOther                ArtifactKind = "other"
	KindUnknown              ArtifactKind = "unknown"
)

// HolderRole pinned to host_arg_fgs.holder_role.
type HolderRole string

const (
	RoleDirector            HolderRole = "director"
	RoleComiteInversiones   HolderRole = "comite-inversiones"
	RoleTesoreria           HolderRole = "tesoreria"
	RoleCustodia            HolderRole = "custodia"
	RoleAuditoriaSIGEN      HolderRole = "auditoria-sigen"
	RoleRiesgo              HolderRole = "riesgo"
	RoleAnalistaEquity      HolderRole = "analista-equity"
	RoleAnalistaFixedIncome HolderRole = "analista-fixed-income"
	RoleComplianceOfficer   HolderRole = "compliance-officer"
	RoleAPI                 HolderRole = "api"
	RoleOther               HolderRole = "other"
	RoleUnknown             HolderRole = "unknown"
)

// PortfolioClass pinned to host_arg_fgs.portfolio_class.
type PortfolioClass string

const (
	PortfolioLIC            PortfolioClass = "lic"
	PortfolioARSovBond      PortfolioClass = "ar-sovereign-bond"
	PortfolioARCorporate    PortfolioClass = "ar-corporate-bond"
	PortfolioAREquity       PortfolioClass = "ar-equity"
	PortfolioARFCI          PortfolioClass = "ar-fci"
	PortfolioRealEstate     PortfolioClass = "real-estate-fund"
	PortfolioProjectFinance PortfolioClass = "project-finance"
	PortfolioTimeDeposit    PortfolioClass = "time-deposit"
	PortfolioCash           PortfolioClass = "cash"
	PortfolioMultiAsset     PortfolioClass = "multi-asset"
	PortfolioOther          PortfolioClass = "other"
	PortfolioUnknown        PortfolioClass = "unknown"
)

// AuctionWindow pinned to host_arg_fgs.auction_window.
type AuctionWindow string

const (
	WindowBCRAPrimary      AuctionWindow = "bcra-primary"
	WindowMineconPrimary   AuctionWindow = "minecon-primary"
	WindowANSESLIC         AuctionWindow = "anses-lic"
	WindowTesoroCortoPlazo AuctionWindow = "tesoro-corto-plazo"
	WindowTesoroLargoPlazo AuctionWindow = "tesoro-largo-plazo"
	WindowONCorporate      AuctionWindow = "on-corporate"
	WindowCustom           AuctionWindow = "custom"
	WindowNone             AuctionWindow = "none"
	WindowUnknown          AuctionWindow = "unknown"
)

// Row mirrors host_arg_fgs column shape.
type Row struct {
	FilePath                    string         `json:"file_path"`
	FileHash                    string         `json:"file_hash"`
	UserProfile                 string         `json:"user_profile,omitempty"`
	ArtifactKind                ArtifactKind   `json:"artifact_kind"`
	HolderRole                  HolderRole     `json:"holder_role"`
	PortfolioClass              PortfolioClass `json:"portfolio_class"`
	AuctionWindow               AuctionWindow  `json:"auction_window,omitempty"`
	ReportingPeriod             string         `json:"reporting_period,omitempty"`
	ClienteCuitPrefix           string         `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4          string         `json:"cliente_cuit_suffix4,omitempty"`
	TrabajadorCuilPrefix        string         `json:"trabajador_cuil_prefix,omitempty"`
	TrabajadorCuilSuffix4       string         `json:"trabajador_cuil_suffix4,omitempty"`
	FGSSeriesCode               string         `json:"fgs_series_code,omitempty"`
	AuctionID                   string         `json:"auction_id,omitempty"`
	ActaID                      string         `json:"acta_id,omitempty"`
	PortfolioInstrumentsCount   int64          `json:"portfolio_instruments_count,omitempty"`
	LICFaceValueARSMillions     int64          `json:"lic_face_value_ars_millions,omitempty"`
	EquityHoldingCount          int64          `json:"equity_holding_count,omitempty"`
	SovBondHoldingCount         int64          `json:"sov_bond_holding_count,omitempty"`
	PanelLiderHoldingCount      int64          `json:"panel_lider_holding_count,omitempty"`
	AuctionBidAmountARSMillions int64          `json:"auction_bid_amount_ars_millions,omitempty"`
	SIPAPensionerCount          int64          `json:"sipa_pensioner_count,omitempty"`
	FileOwnerUID                int            `json:"file_owner_uid,omitempty"`
	FileMode                    int            `json:"file_mode,omitempty"`
	FileSize                    int64          `json:"file_size,omitempty"`
	HasPasswordInConfig         bool           `json:"has_password_in_config"`
	HasCarteraFGS               bool           `json:"has_cartera_fgs"`
	HasLICRecord                bool           `json:"has_lic_record"`
	HasDirectorioActa           bool           `json:"has_directorio_acta"`
	HasComiteActa               bool           `json:"has_comite_acta"`
	HasLineamientosDoc          bool           `json:"has_lineamientos_doc"`
	HasPrimaryAuctionBid        bool           `json:"has_primary_auction_bid"`
	HasPrimaryAuctionResult     bool           `json:"has_primary_auction_result"`
	HasCustodiaRecord           bool           `json:"has_custodia_record"`
	HasVotingRecord             bool           `json:"has_voting_record"`
	HasSIPAPensionRecord        bool           `json:"has_sipa_pension_record"`
	HasFilingReceipt            bool           `json:"has_filing_receipt"`
	HasBYMAPanelLiderHolding    bool           `json:"has_byma_panel_lider_holding"`
	HasInstitutionalPortfolio   bool           `json:"has_institutional_portfolio"`
	HasPreDisclosureRisk        bool           `json:"has_pre_disclosure_risk"`
	HasClienteCuit              bool           `json:"has_cliente_cuit"`
	HasTrabajadorCuil           bool           `json:"has_trabajador_cuil"`
	IsRecent                    bool           `json:"is_recent"`
	IsWorldReadable             bool           `json:"is_world_readable"`
	IsGroupReadable             bool           `json:"is_group_readable"`
	IsCredentialExposureRisk    bool           `json:"is_credential_exposure_risk"`
	IsMarketMovingInfoRisk      bool           `json:"is_market_moving_info_risk"`
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

// DefaultInstallRoots is the curated FGS-tool install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\FGS`,
		`C:\ANSES FGS`,
		`C:\Program Files\FGS`,
		`C:\Program Files (x86)\FGS`,
		"/opt/fgs",
		"/opt/anses-fgs",
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

// UserFGSDirs is the curated per-user relative path set.
func UserFGSDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "FGS"},
		{"AppData", "Roaming", "ANSES FGS"},
		{"AppData", "Local", "FGS"},
		{"AppData", "Local", "ANSES FGS"},
		{".config", "fgs"},
		{".fgs"},
		{"Documents", "FGS"},
		{"Documents", "ANSES"},
		{"Documents", "Sustentabilidad"},
		{"Library", "Application Support", "FGS"},
		{"Descargas"},
		{"Downloads"},
	}
}

// PanelLiderStems is the curated BYMA "panel líder" ticker set
// — the top-tier AR equity index where FGS holds large stakes.
func PanelLiderStems() []string {
	return []string{
		"GGAL", "BMA", "BBAR", "SUPV", "VALO",
		"YPFD", "PAMP", "TGSU2", "TGNO4", "TRAN",
		"ALUA", "TXAR", "EDN", "CEPU", "CRES",
		"COME", "MIRG", "BYMA", "LOMA", "CVH",
	}
}

// IsPanelLiderStem reports membership.
func IsPanelLiderStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range PanelLiderStems() {
		if v == t {
			return true
		}
	}
	return false
}

// ARSovereignBondStems mirrors the SSN iter set.
func ARSovereignBondStems() []string {
	return []string{
		"AL29", "AL30", "AL35", "AL41", "AE38",
		"GD29", "GD30", "GD35", "GD38", "GD41", "GD46",
		"TX26", "TX28", "TX31",
		"PARP", "CUAP", "DICP",
		"TDF24", "TDA24",
	}
}

// IsARSovereignBondStem reports membership.
func IsARSovereignBondStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range ARSovereignBondStems() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries an FGS
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json",
		".cfg", ".ini",
		".csv", ".tsv", ".log", ".txt",
		".xlsx", ".xls", ".ods",
		".pdf",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the FGS catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"fgs", "anses",
		"cartera_fgs", "cartera-fgs",
		"lic_", "lic-", "letras_intransferibles",
		"directorio", "acta",
		"comite_inversiones", "comite-inversiones",
		"comité_inversiones",
		"lineamientos",
		"subasta", "auction", "licitacion", "licitación",
		"custodia",
		"voting", "votacion", "votación", "asamblea",
		"sipa", "pensioner", "pensionado",
		"sustentabilidad",
		"bcra_primary", "minecon_primary",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ArtifactKindFromName classifies a filename heuristically.
//
// Order matters: more-specific tokens precede generic ones.
func ArtifactKindFromName(name string) ArtifactKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".msi", ".exe", ".pkg", ".dmg":
		if strings.Contains(n, "fgs") || strings.Contains(n, "anses") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case (strings.Contains(n, "fgs") || strings.Contains(n, "anses")) &&
		strings.Contains(n, "config"):
		return KindConfig
	case strings.Contains(n, "lic_") ||
		strings.Contains(n, "lic-") ||
		strings.Contains(n, "letras_intransferibles") ||
		strings.Contains(n, "letras-intransferibles"):
		return KindLICRecord
	case strings.Contains(n, "cartera_fgs") ||
		strings.Contains(n, "cartera-fgs") ||
		(strings.Contains(n, "cartera") && strings.Contains(n, "fgs")):
		return KindCarteraFGS
	case strings.Contains(n, "directorio") ||
		(strings.Contains(n, "acta") && strings.Contains(n, "dir")):
		return KindDirectorioActa
	case strings.Contains(n, "comite_inversiones") ||
		strings.Contains(n, "comite-inversiones") ||
		strings.Contains(n, "comité_inversiones") ||
		strings.Contains(n, "comité-inversiones") ||
		(strings.Contains(n, "acta") && strings.Contains(n, "comite")):
		return KindComiteActa
	case strings.Contains(n, "lineamientos"):
		return KindLineamientosDoc
	case strings.Contains(n, "bid_") ||
		(strings.Contains(n, "subasta") && strings.Contains(n, "bid")) ||
		(strings.Contains(n, "auction") && strings.Contains(n, "bid")) ||
		(strings.Contains(n, "licitacion") && strings.Contains(n, "bid")):
		return KindPrimaryAuctionBid
	case strings.Contains(n, "result_") ||
		(strings.Contains(n, "subasta") && strings.Contains(n, "result")) ||
		(strings.Contains(n, "auction") && strings.Contains(n, "result")) ||
		(strings.Contains(n, "licitacion") && strings.Contains(n, "result")):
		return KindPrimaryAuctionResult
	case strings.Contains(n, "subasta") ||
		strings.Contains(n, "auction") ||
		strings.Contains(n, "licitacion") ||
		strings.Contains(n, "licitación"):
		return KindPrimaryAuctionBid
	case strings.Contains(n, "custodia"):
		return KindCustodiaRecord
	case strings.Contains(n, "voting") ||
		strings.Contains(n, "votacion") ||
		strings.Contains(n, "votación") ||
		strings.Contains(n, "asamblea"):
		return KindVotingRecord
	case strings.Contains(n, "sipa") ||
		strings.Contains(n, "pensioner") ||
		strings.Contains(n, "pensionado"):
		return KindSIPAPensionRecord
	case strings.Contains(n, "fgs_receipt") ||
		strings.Contains(n, "fgs-receipt") ||
		strings.Contains(n, "receipt_fgs") ||
		(strings.Contains(n, "sigen") && strings.Contains(n, "receipt")) ||
		(strings.Contains(n, "presentacion") && strings.Contains(n, "fgs")) ||
		strings.Contains(n, "filing_receipt"):
		return KindFilingReceipt
	}
	return KindOther
}

// CuitEntityPrefixes mirrors AFIP collector list.
func CuitEntityPrefixes() []string {
	return []string{"20", "23", "24", "27", "30", "33", "34"}
}

// IsValidCuitEntityPrefix reports prefix membership.
func IsValidCuitEntityPrefix(p string) bool {
	for _, v := range CuitEntityPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// CuilEntityPrefixes is the trabajador-CUIL valid prefix set.
func CuilEntityPrefixes() []string {
	return []string{"20", "23", "24", "27"}
}

// IsValidCuilEntityPrefix reports prefix membership.
func IsValidCuilEntityPrefix(p string) bool {
	for _, v := range CuilEntityPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches 11-digit CUIT bounded by non-digit / edges.
var cuitRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// CuitFingerprint extracts (prefix, suffix4) from text.
func CuitFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuitEntityPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// CuilFingerprint extracts (prefix, suffix4) from text where the
// prefix is restricted to individual prefixes.
func CuilFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuilEntityPrefix(prefix) {
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
// credential material subject to the exposure rollup.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindCarteraFGS, KindLICRecord,
		KindDirectorioActa, KindComiteActa,
		KindLineamientosDoc,
		KindPrimaryAuctionBid, KindPrimaryAuctionResult,
		KindCustodiaRecord, KindVotingRecord,
		KindSIPAPensionRecord, KindFilingReceipt,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsMarketMovingKind reports whether the kind carries pre-
// disclosure / insider-information material under CNV RG 622
// art.50.
func IsMarketMovingKind(k ArtifactKind) bool {
	switch k {
	case KindDirectorioActa, KindComiteActa,
		KindPrimaryAuctionBid, KindVotingRecord:
		return true
	case KindCarteraFGS, KindLICRecord,
		KindLineamientosDoc, KindPrimaryAuctionResult,
		KindCustodiaRecord, KindSIPAPensionRecord,
		KindFilingReceipt,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets derived booleans. Caller populates scalar
// fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.ClienteCuitPrefix != "" {
		r.HasClienteCuit = true
	}
	if r.TrabajadorCuilPrefix != "" {
		r.HasTrabajadorCuil = true
	}
	switch r.ArtifactKind {
	case KindCarteraFGS:
		r.HasCarteraFGS = true
	case KindLICRecord:
		r.HasLICRecord = true
	case KindDirectorioActa:
		r.HasDirectorioActa = true
	case KindComiteActa:
		r.HasComiteActa = true
	case KindLineamientosDoc:
		r.HasLineamientosDoc = true
	case KindPrimaryAuctionBid:
		r.HasPrimaryAuctionBid = true
	case KindPrimaryAuctionResult:
		r.HasPrimaryAuctionResult = true
	case KindCustodiaRecord:
		r.HasCustodiaRecord = true
	case KindVotingRecord:
		r.HasVotingRecord = true
	case KindSIPAPensionRecord:
		r.HasSIPAPensionRecord = true
	case KindFilingReceipt:
		r.HasFilingReceipt = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag for these kinds.
	}
	if r.PortfolioInstrumentsCount >= InstitutionalPortfolioInstrumentsThreshold {
		r.HasInstitutionalPortfolio = true
	}
	if r.PanelLiderHoldingCount >= PanelLiderHoldingThreshold {
		r.HasBYMAPanelLiderHolding = true
	}
	if (r.HasDirectorioActa || r.HasComiteActa ||
		r.HasPrimaryAuctionBid || r.HasVotingRecord) &&
		(r.HasBYMAPanelLiderHolding || r.HasCarteraFGS ||
			r.HasPrimaryAuctionBid) {
		r.HasPreDisclosureRisk = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasCarteraFGS ||
		r.HasLICRecord || r.HasDirectorioActa ||
		r.HasComiteActa || r.HasSIPAPensionRecord ||
		r.HasClienteCuit || r.HasTrabajadorCuil
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && IsMarketMovingKind(r.ArtifactKind) {
		r.IsMarketMovingInfoRisk = true
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
