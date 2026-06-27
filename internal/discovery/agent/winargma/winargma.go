// Package winargma audits AR M&A advisory / Investment Banking
// deal-pipeline artifact files cached on Argentine advisor
// analyst, associate, VP, MD, and operations workstations across
// Windows, Linux, and macOS.
//
// AR M&A advisors (Banco Galicia ECM, Cohen Investment Banking,
// BTG Pactual Argentina, Adcap Securities, Allaria Ledesma IB,
// plus AR desks of JPMorgan, Morgan Stanley, Citi, Itaú BBA)
// handle every AR sell-side / buy-side mandate. Regulated under
// CNV RG 622 art.50 + Ley 26.831 art.117.
//
// Distinct from prior iters because the shape is **deal-pipeline
// back-office** (advisor perspective):
//
//   - vs iter 191 winargperito       — audit-firm back-office.
//   - vs iter 190 winargcalificadora — rating agency.
//   - vs iter 189 winargfideicomiso  — issuer side (FF).
//   - vs iter 185 winargcohen        — broker-dealer ALYC.
//
// Headline finding shapes:
//
//   - `has_dataroom_manifest=1` — DR manifest with file list.
//   - `has_bidder_roster=1` — bidder roster with PII.
//   - `has_dcf_model=1` — valuation IP.
//   - `has_spa_draft=1` — pre-signing transaction terms.
//   - `has_hecho_relevante_draft=1` — pre-publication CNV.
//   - `has_pre_announcement_draft=1` — DRAFT marker.
//   - `has_public_target=1` — CNV-listed target.
//   - `is_insider_information_risk=1` — readable + (draft OR DR
//     OR SPA OR bid evaluation OR hecho relevante draft).
//   - `is_valuation_ip_risk=1` — readable + (DCF OR LBO OR
//     merger model OR synergy).
//
// Read-only by intent. (Project guideline 4.2.)
package winargma

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

// LargeBidderRosterThreshold — > 10 bidders in one roster = full
// auction process (CWE-200 across competitive landscape).
const LargeBidderRosterThreshold = 10

// LargeDataroomThreshold — > 100 files in DR manifest = full-
// scope due diligence package.
const LargeDataroomThreshold = 100

// ArtifactKind pinned to host_arg_ma.artifact_kind.
type ArtifactKind string

const (
	KindPitchDeck             ArtifactKind = "ma-pitch-deck"
	KindNDA                   ArtifactKind = "ma-nda"
	KindInformationMemorandum ArtifactKind = "ma-information-memorandum"
	KindDataroomManifest      ArtifactKind = "ma-dataroom-manifest"
	KindBidderRoster          ArtifactKind = "ma-bidder-roster"
	KindProcessLetter         ArtifactKind = "ma-process-letter"
	KindBidEvaluation         ArtifactKind = "ma-bid-evaluation"
	KindDCFModel              ArtifactKind = "ma-dcf-model"
	KindLBOModel              ArtifactKind = "ma-lbo-model"
	KindMergerModel           ArtifactKind = "ma-merger-model"
	KindQofEReport            ArtifactKind = "ma-qofe-report"
	KindSPADraft              ArtifactKind = "ma-spa-draft"
	KindDisclosureSchedules   ArtifactKind = "ma-disclosure-schedules"
	KindClosingMemo           ArtifactKind = "ma-closing-memo"
	KindFairnessOpinion       ArtifactKind = "ma-fairness-opinion"
	KindSynergyAnalysis       ArtifactKind = "ma-synergy-analysis"
	KindAntitrustMemo         ArtifactKind = "ma-antitrust-memo"
	KindHechoRelevanteDraft   ArtifactKind = "ma-hecho-relevante-draft"
	KindConfig                ArtifactKind = "ma-config"
	KindCredentials           ArtifactKind = "ma-credentials"
	KindInstaller             ArtifactKind = "ma-installer"
	KindOther                 ArtifactKind = "other"
	KindUnknown               ArtifactKind = "unknown"
)

// AdvisorFirm pinned to host_arg_ma.advisor_firm.
type AdvisorFirm string

const (
	FirmBancoGaliciaECM        AdvisorFirm = "banco-galicia-ecm"
	FirmCohenIB                AdvisorFirm = "cohen-ib"
	FirmBTGPactualArgentina    AdvisorFirm = "btg-pactual-argentina"
	FirmAdcapSecuritiesIB      AdvisorFirm = "adcap-securities-ib"
	FirmAllariaLedesmaIB       AdvisorFirm = "allaria-ledesma-ib"
	FirmBalanzIB               AdvisorFirm = "balanz-ib"
	FirmJPMorganArgentina      AdvisorFirm = "jpmorgan-argentina"
	FirmMorganStanleyArgentina AdvisorFirm = "morgan-stanley-argentina"
	FirmCitiArgentina          AdvisorFirm = "citi-argentina"
	FirmItauBBAArgentina       AdvisorFirm = "itau-bba-argentina"
	FirmBBVAArgentinaIB        AdvisorFirm = "bbva-argentina-ib"
	FirmSantanderRioIB         AdvisorFirm = "santander-rio-ib"
	FirmLocalBoutique          AdvisorFirm = "local-boutique"
	FirmCustom                 AdvisorFirm = "custom"
	FirmNone                   AdvisorFirm = "none"
	FirmUnknown                AdvisorFirm = "unknown"
)

// DealRole pinned to host_arg_ma.deal_role.
type DealRole string

const (
	RoleAnalyst              DealRole = "analyst"
	RoleAssociate            DealRole = "associate"
	RoleVP                   DealRole = "vp"
	RoleDirector             DealRole = "director"
	RoleManagingDirector     DealRole = "managing-director"
	RolePartner              DealRole = "partner"
	RoleOperations           DealRole = "operations"
	RoleComplianceOfficer    DealRole = "compliance-officer"
	RoleDataRoomAdmin        DealRole = "data-room-admin"
	RoleEngagementTeamLeader DealRole = "engagement-team-leader"
	RoleAntitrustCounsel     DealRole = "antitrust-counsel"
	RoleAPI                  DealRole = "api"
	RoleOther                DealRole = "other"
	RoleUnknown              DealRole = "unknown"
)

// MandateType pinned to host_arg_ma.mandate_type.
type MandateType string

const (
	MandateSellSide        MandateType = "sell-side"
	MandateBuySide         MandateType = "buy-side"
	MandateFairnessOpinion MandateType = "fairness-opinion"
	MandateDefense         MandateType = "defense"
	MandateDivestiture     MandateType = "divestiture"
	MandateSpinOff         MandateType = "spin-off"
	MandateCapitalRaise    MandateType = "capital-raise"
	MandateRestructuring   MandateType = "restructuring"
	MandateCustom          MandateType = "custom"
	MandateNone            MandateType = "none"
	MandateUnknown         MandateType = "unknown"
)

// DealStage pinned to host_arg_ma.deal_stage.
type DealStage string

const (
	StageOrigination DealStage = "origination"
	StagePitch       DealStage = "pitch"
	StageExclusivity DealStage = "exclusivity"
	StageExecution   DealStage = "execution"
	StageClosing     DealStage = "closing"
	StagePostClosing DealStage = "post-closing"
	StageCustom      DealStage = "custom"
	StageNone        DealStage = "none"
	StageUnknown     DealStage = "unknown"
)

// Row mirrors host_arg_ma column shape.
type Row struct {
	FilePath                   string       `json:"file_path"`
	FileHash                   string       `json:"file_hash"`
	UserProfile                string       `json:"user_profile,omitempty"`
	ArtifactKind               ArtifactKind `json:"artifact_kind"`
	AdvisorFirm                AdvisorFirm  `json:"advisor_firm"`
	DealRole                   DealRole     `json:"deal_role"`
	MandateType                MandateType  `json:"mandate_type,omitempty"`
	DealStage                  DealStage    `json:"deal_stage,omitempty"`
	ReportingPeriod            string       `json:"reporting_period,omitempty"`
	TargetCuitPrefix           string       `json:"target_cuit_prefix,omitempty"`
	TargetCuitSuffix4          string       `json:"target_cuit_suffix4,omitempty"`
	BidderCuitPrefix           string       `json:"bidder_cuit_prefix,omitempty"`
	BidderCuitSuffix4          string       `json:"bidder_cuit_suffix4,omitempty"`
	ProjectNameHash            string       `json:"project_name_hash,omitempty"`
	DealID                     string       `json:"deal_id,omitempty"`
	BidderCount                int64        `json:"bidder_count,omitempty"`
	DataroomFileCount          int64        `json:"dataroom_file_count,omitempty"`
	EnterpriseValueARSMillions int64        `json:"enterprise_value_ars_millions,omitempty"`
	AdvisoryFeeARSMillions     int64        `json:"advisory_fee_ars_millions,omitempty"`
	SuccessFeeBPS              int64        `json:"success_fee_bps,omitempty"`
	FileOwnerUID               int          `json:"file_owner_uid,omitempty"`
	FileMode                   int          `json:"file_mode,omitempty"`
	FileSize                   int64        `json:"file_size,omitempty"`
	HasPasswordInConfig        bool         `json:"has_password_in_config"`
	HasPitchDeck               bool         `json:"has_pitch_deck"`
	HasNDA                     bool         `json:"has_nda"`
	HasInformationMemorandum   bool         `json:"has_information_memorandum"`
	HasDataroomManifest        bool         `json:"has_dataroom_manifest"`
	HasBidderRoster            bool         `json:"has_bidder_roster"`
	HasProcessLetter           bool         `json:"has_process_letter"`
	HasBidEvaluation           bool         `json:"has_bid_evaluation"`
	HasDCFModel                bool         `json:"has_dcf_model"`
	HasLBOModel                bool         `json:"has_lbo_model"`
	HasMergerModel             bool         `json:"has_merger_model"`
	HasQofEReport              bool         `json:"has_qofe_report"`
	HasSPADraft                bool         `json:"has_spa_draft"`
	HasDisclosureSchedules     bool         `json:"has_disclosure_schedules"`
	HasClosingMemo             bool         `json:"has_closing_memo"`
	HasFairnessOpinion         bool         `json:"has_fairness_opinion"`
	HasSynergyAnalysis         bool         `json:"has_synergy_analysis"`
	HasAntitrustMemo           bool         `json:"has_antitrust_memo"`
	HasHechoRelevanteDraft     bool         `json:"has_hecho_relevante_draft"`
	HasPreAnnouncementDraft    bool         `json:"has_pre_announcement_draft"`
	HasCrossBorderTarget       bool         `json:"has_cross_border_target"`
	HasPublicTarget            bool         `json:"has_public_target"`
	HasTargetCuit              bool         `json:"has_target_cuit"`
	HasBidderCuit              bool         `json:"has_bidder_cuit"`
	IsRecent                   bool         `json:"is_recent"`
	IsWorldReadable            bool         `json:"is_world_readable"`
	IsGroupReadable            bool         `json:"is_group_readable"`
	IsCredentialExposureRisk   bool         `json:"is_credential_exposure_risk"`
	IsInsiderInformationRisk   bool         `json:"is_insider_information_risk"`
	IsValuationIPRisk          bool         `json:"is_valuation_ip_risk"`
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

// DefaultInstallRoots is the curated IB-tool install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\IB`,
		`C:\InvestmentBanking`,
		`C:\Program Files\IB`,
		`C:\Program Files (x86)\IB`,
		"/opt/ib",
		"/opt/investment-banking",
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

// UserMADirs is the curated per-user relative path set.
func UserMADirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "IB"},
		{"AppData", "Roaming", "InvestmentBanking"},
		{"AppData", "Local", "IB"},
		{".config", "ib"},
		{".ib"},
		{"Documents", "IB"},
		{"Documents", "Deals"},
		{"Documents", "Projects"},
		{"Documents", "M&A"},
		{"Documents", "Investment Banking"},
		{"Library", "Application Support", "IB"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries an M&A
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json",
		".cfg", ".ini",
		".csv", ".tsv", ".log", ".txt",
		".xlsx", ".xls", ".ods",
		".pdf", ".doc", ".docx",
		".pptx", ".ppt", ".odp",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the M&A catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"pitch_deck", "pitch-deck", "pitchdeck",
		"nda_", "nda-", "nda.",
		"information_memorandum", "information-memorandum",
		"info_memo", "info-memo",
		"dataroom", "data_room", "data-room",
		"bidder_roster", "bidder-roster", "bidderlist",
		"process_letter", "process-letter",
		"bid_evaluation", "bid-evaluation",
		"dcf_model", "dcf-model",
		"lbo_model", "lbo-model",
		"merger_model", "merger-model",
		"qofe", "quality_of_earnings", "quality-of-earnings",
		"spa_draft", "spa-draft", "sale_purchase",
		"disclosure_schedules", "disclosure-schedules",
		"closing_memo", "closing-memo",
		"fairness_opinion", "fairness-opinion",
		"synergy_analysis", "synergy-analysis",
		"antitrust_memo", "antitrust-memo", "antitrust_analysis",
		"hecho_relevante", "hecho-relevante",
		"comparable_companies", "comparable-companies",
		"precedent_transactions", "precedent-transactions",
		"investment_banking", "investment-banking",
		"ma_deal", "ma-deal", "m_and_a", "m-and-a",
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
		if strings.Contains(n, "ib_") || strings.Contains(n, "deal") ||
			strings.Contains(n, "investment_banking") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case (strings.Contains(n, "ib_") || strings.Contains(n, "ma_") ||
		strings.Contains(n, "deal")) &&
		strings.Contains(n, "config"):
		return KindConfig
	case strings.Contains(n, "hecho_relevante") ||
		strings.Contains(n, "hecho-relevante"):
		return KindHechoRelevanteDraft
	case strings.Contains(n, "pitch_deck") ||
		strings.Contains(n, "pitch-deck") ||
		strings.Contains(n, "pitchdeck"):
		return KindPitchDeck
	case strings.HasPrefix(n, "nda") ||
		strings.Contains(n, "_nda_") ||
		strings.Contains(n, "_nda.") ||
		strings.Contains(n, "-nda-") ||
		strings.Contains(n, "-nda."):
		return KindNDA
	case strings.Contains(n, "information_memorandum") ||
		strings.Contains(n, "information-memorandum") ||
		strings.Contains(n, "info_memo") ||
		strings.Contains(n, "info-memo") ||
		strings.HasPrefix(n, "im_") || strings.HasPrefix(n, "im-"):
		return KindInformationMemorandum
	case strings.Contains(n, "dataroom_manifest") ||
		strings.Contains(n, "dataroom-manifest") ||
		strings.Contains(n, "data_room_manifest") ||
		strings.Contains(n, "data-room-manifest") ||
		(strings.Contains(n, "dataroom") && strings.Contains(n, "manifest")):
		return KindDataroomManifest
	case strings.Contains(n, "bidder_roster") ||
		strings.Contains(n, "bidder-roster") ||
		strings.Contains(n, "bidderlist"):
		return KindBidderRoster
	case strings.Contains(n, "process_letter") ||
		strings.Contains(n, "process-letter"):
		return KindProcessLetter
	case strings.Contains(n, "bid_evaluation") ||
		strings.Contains(n, "bid-evaluation"):
		return KindBidEvaluation
	case strings.Contains(n, "dcf_model") ||
		strings.Contains(n, "dcf-model"):
		return KindDCFModel
	case strings.Contains(n, "lbo_model") ||
		strings.Contains(n, "lbo-model"):
		return KindLBOModel
	case strings.Contains(n, "merger_model") ||
		strings.Contains(n, "merger-model"):
		return KindMergerModel
	case strings.Contains(n, "qofe") ||
		strings.Contains(n, "quality_of_earnings") ||
		strings.Contains(n, "quality-of-earnings"):
		return KindQofEReport
	case strings.Contains(n, "spa_draft") ||
		strings.Contains(n, "spa-draft") ||
		strings.Contains(n, "sale_purchase"):
		return KindSPADraft
	case strings.Contains(n, "disclosure_schedules") ||
		strings.Contains(n, "disclosure-schedules"):
		return KindDisclosureSchedules
	case strings.Contains(n, "closing_memo") ||
		strings.Contains(n, "closing-memo"):
		return KindClosingMemo
	case strings.Contains(n, "fairness_opinion") ||
		strings.Contains(n, "fairness-opinion"):
		return KindFairnessOpinion
	case strings.Contains(n, "synergy_analysis") ||
		strings.Contains(n, "synergy-analysis"):
		return KindSynergyAnalysis
	case strings.Contains(n, "antitrust_memo") ||
		strings.Contains(n, "antitrust-memo") ||
		strings.Contains(n, "antitrust_analysis"):
		return KindAntitrustMemo
	}
	return KindOther
}

// CuitEntityOnlyPrefixes is the corporate-only subset for
// target / bidder entity CUIT.
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

// CuitEntityOnlyFingerprint extracts target/bidder CUIT.
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
// credential material subject to the exposure rollup.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindPitchDeck, KindNDA,
		KindInformationMemorandum, KindDataroomManifest,
		KindBidderRoster, KindProcessLetter,
		KindBidEvaluation, KindDCFModel,
		KindLBOModel, KindMergerModel,
		KindQofEReport, KindSPADraft,
		KindDisclosureSchedules, KindClosingMemo,
		KindFairnessOpinion, KindSynergyAnalysis,
		KindAntitrustMemo, KindHechoRelevanteDraft,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsInsiderInformationKind reports whether the kind carries
// pre-announcement information under CNV RG 622 art.50.
func IsInsiderInformationKind(k ArtifactKind) bool {
	switch k {
	case KindPitchDeck, KindInformationMemorandum,
		KindDataroomManifest, KindBidderRoster,
		KindBidEvaluation, KindSPADraft,
		KindDisclosureSchedules, KindClosingMemo,
		KindFairnessOpinion, KindHechoRelevanteDraft,
		KindAntitrustMemo:
		return true
	case KindNDA, KindProcessLetter,
		KindDCFModel, KindLBOModel, KindMergerModel,
		KindQofEReport, KindSynergyAnalysis,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsValuationIPKind reports whether the kind carries advisor
// valuation IP.
func IsValuationIPKind(k ArtifactKind) bool {
	switch k {
	case KindDCFModel, KindLBOModel,
		KindMergerModel, KindSynergyAnalysis:
		return true
	case KindPitchDeck, KindNDA,
		KindInformationMemorandum, KindDataroomManifest,
		KindBidderRoster, KindProcessLetter,
		KindBidEvaluation, KindQofEReport,
		KindSPADraft, KindDisclosureSchedules,
		KindClosingMemo, KindFairnessOpinion,
		KindAntitrustMemo, KindHechoRelevanteDraft,
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
	if r.TargetCuitPrefix != "" {
		r.HasTargetCuit = true
	}
	if r.BidderCuitPrefix != "" {
		r.HasBidderCuit = true
	}
	switch r.ArtifactKind {
	case KindPitchDeck:
		r.HasPitchDeck = true
	case KindNDA:
		r.HasNDA = true
	case KindInformationMemorandum:
		r.HasInformationMemorandum = true
	case KindDataroomManifest:
		r.HasDataroomManifest = true
	case KindBidderRoster:
		r.HasBidderRoster = true
	case KindProcessLetter:
		r.HasProcessLetter = true
	case KindBidEvaluation:
		r.HasBidEvaluation = true
	case KindDCFModel:
		r.HasDCFModel = true
	case KindLBOModel:
		r.HasLBOModel = true
	case KindMergerModel:
		r.HasMergerModel = true
	case KindQofEReport:
		r.HasQofEReport = true
	case KindSPADraft:
		r.HasSPADraft = true
	case KindDisclosureSchedules:
		r.HasDisclosureSchedules = true
	case KindClosingMemo:
		r.HasClosingMemo = true
	case KindFairnessOpinion:
		r.HasFairnessOpinion = true
	case KindSynergyAnalysis:
		r.HasSynergyAnalysis = true
	case KindAntitrustMemo:
		r.HasAntitrustMemo = true
	case KindHechoRelevanteDraft:
		r.HasHechoRelevanteDraft = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag for these kinds.
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasPitchDeck ||
		r.HasInformationMemorandum || r.HasDataroomManifest ||
		r.HasBidderRoster || r.HasTargetCuit ||
		r.HasBidderCuit
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && (r.HasPreAnnouncementDraft ||
		r.HasHechoRelevanteDraft ||
		IsInsiderInformationKind(r.ArtifactKind)) {
		r.IsInsiderInformationRisk = true
	}
	if readable && IsValuationIPKind(r.ArtifactKind) {
		r.IsValuationIPRisk = true
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
