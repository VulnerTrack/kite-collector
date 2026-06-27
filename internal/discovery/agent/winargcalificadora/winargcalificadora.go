// Package winargcalificadora audits AR Calificadoras de Riesgo
// (rating agency) back-office artifact files cached on Argentine
// analyst, rating-committee-member, and methodology-team
// workstations across Windows, Linux, and macOS.
//
// AR rating agencies (FIX SCR Argentina = Fitch local affiliate,
// Moody's Local Argentina, Evaluadora Latinoamericana, Untref,
// ACR — Argentine Credit Rating) issue ratings on FF trust certs,
// AR sovereign bonds, ON corporate bonds, ALYC-issued instruments,
// and SSN-regulated insurer paper. Regulated under CNV RG 622
// art.62 + Ley 26.831.
//
// Distinct from prior iters because the shape is **rating-
// agency back-office** (analyst perspective, NOT issuer):
//
//   - vs iter 189 winargfideicomiso — issuer side (FF).
//   - vs iter 188 winargfgs         — sovereign-wealth-fund.
//   - vs iter 187 winargssn         — private insurer investor.
//   - vs iter 185 winargcohen       — broker-dealer ALYC.
//
// Headline finding shapes:
//
//   - `has_rating_letter=1` — final rating action.
//   - `has_methodology_doc=1` — methodology IP.
//   - `has_committee_minutes=1` — rating committee minutes.
//   - `has_watchlist=1` — current watch list.
//   - `has_internal_credit_model=1` — PD/LGD/EAD model.
//   - `has_dissenting_opinion=1` — split-committee dissent.
//   - `has_pending_watch_action=1` — watch ≠ "stable".
//   - `is_market_moving_info_risk=1` — readable + (pending watch
//     OR committee split OR rating letter OR dissent).
//   - `is_intellectual_property_risk=1` — readable + (methodology
//     OR internal credit model).
//
// Read-only by intent. (Project guideline 4.2.)
package winargcalificadora

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

// LargeIssuerRosterThreshold — > 50 distinct issuers in one
// roster = full mid-tier calificadora client list.
const LargeIssuerRosterThreshold = 50

// LargeWatchlistThreshold — > 5 issuers on watch simultaneously
// = systemic stress signal (calificadoras usually keep watch
// lists short).
const LargeWatchlistThreshold = 5

// ArtifactKind pinned to host_arg_calificadora.artifact_kind.
type ArtifactKind string

const (
	KindRatingLetter          ArtifactKind = "cal-rating-letter"
	KindMethodologyDoc        ArtifactKind = "cal-methodology-doc"
	KindCommitteeMinutes      ArtifactKind = "cal-committee-minutes"
	KindMonitoringReport      ArtifactKind = "cal-monitoring-report"
	KindWatchlist             ArtifactKind = "cal-watchlist"
	KindConflictOfInterestDoc ArtifactKind = "cal-conflict-of-interest-doc"
	KindFeeSchedule           ArtifactKind = "cal-fee-schedule"
	KindInternalCreditModel   ArtifactKind = "cal-internal-credit-model" //#nosec G101 -- ArtifactKind enum naming the calificadora internal credit-model artifact category, not a credential
	KindDissentingOpinion     ArtifactKind = "cal-dissenting-opinion"
	KindIssuerRoster          ArtifactKind = "cal-issuer-roster"
	KindCNVFiling             ArtifactKind = "cal-cnv-filing"
	KindSOCReport             ArtifactKind = "cal-soc-report"
	KindConfig                ArtifactKind = "cal-config"
	KindCredentials           ArtifactKind = "cal-credentials"
	KindInstaller             ArtifactKind = "cal-installer"
	KindOther                 ArtifactKind = "other"
	KindUnknown               ArtifactKind = "unknown"
)

// CalificadoraID pinned to host_arg_calificadora.calificadora_id.
type CalificadoraID string

const (
	CalFIXSCRArgentina           CalificadoraID = "fix-scr-argentina"
	CalMoodysLocalArgentina      CalificadoraID = "moodys-local-argentina"
	CalEvaluadoraLatinoamericana CalificadoraID = "evaluadora-latinoamericana"
	CalUntref                    CalificadoraID = "untref"
	CalACR                       CalificadoraID = "acr"
	CalStandardAndPoorsArgentina CalificadoraID = "standard-and-poors-argentina"
	CalCustom                    CalificadoraID = "custom"
	CalNone                      CalificadoraID = "none"
	CalUnknown                   CalificadoraID = "unknown"
)

// AnalystRole pinned to host_arg_calificadora.analyst_role.
type AnalystRole string

const (
	RoleLeadAnalyst        AnalystRole = "lead-analyst"
	RoleBackupAnalyst      AnalystRole = "backup-analyst"
	RoleCommitteeChair     AnalystRole = "committee-chair"
	RoleCommitteeMember    AnalystRole = "committee-member"
	RoleMethodologyOfficer AnalystRole = "methodology-officer"
	RoleComplianceOfficer  AnalystRole = "compliance-officer"
	RoleQualityControl     AnalystRole = "quality-control"
	RoleCRM                AnalystRole = "crm"
	RoleAPI                AnalystRole = "api"
	RoleOther              AnalystRole = "other"
	RoleUnknown            AnalystRole = "unknown"
)

// RatingClass pinned to host_arg_calificadora.rating_class.
type RatingClass string

const (
	RatingAAA       RatingClass = "aaa"
	RatingAA        RatingClass = "aa"
	RatingA         RatingClass = "a"
	RatingBBB       RatingClass = "bbb"
	RatingBB        RatingClass = "bb"
	RatingB         RatingClass = "b"
	RatingCCC       RatingClass = "ccc"
	RatingCC        RatingClass = "cc"
	RatingC         RatingClass = "c"
	RatingD         RatingClass = "d"
	RatingNoRating  RatingClass = "no-rating"
	RatingWithdrawn RatingClass = "withdrawn"
	RatingCustom    RatingClass = "custom"
	RatingNone      RatingClass = "none"
	RatingUnknown   RatingClass = "unknown"
)

// WatchStatus pinned to host_arg_calificadora.watch_status.
type WatchStatus string

const (
	WatchPositive    WatchStatus = "positive"
	WatchNegative    WatchStatus = "negative"
	WatchDeveloping  WatchStatus = "developing"
	WatchStable      WatchStatus = "stable"
	WatchUnderReview WatchStatus = "under-review"
	WatchCustom      WatchStatus = "custom"
	WatchNone        WatchStatus = "none"
	WatchUnknown     WatchStatus = "unknown"
)

// IssuerClass pinned to host_arg_calificadora.issuer_class.
type IssuerClass string

const (
	IssuerSovereign             IssuerClass = "sovereign"
	IssuerSubSovereign          IssuerClass = "sub-sovereign"
	IssuerCorporateBond         IssuerClass = "corporate-bond"
	IssuerFideicomisoFinanciero IssuerClass = "fideicomiso-financiero"
	IssuerFinancialInstitution  IssuerClass = "financial-institution"
	IssuerInsurance             IssuerClass = "insurance"
	IssuerPYMEOn                IssuerClass = "pyme-on"
	IssuerStructuredFinance     IssuerClass = "structured-finance"
	IssuerCoveredBond           IssuerClass = "covered-bond"
	IssuerProjectFinance        IssuerClass = "project-finance"
	IssuerCustom                IssuerClass = "custom"
	IssuerNone                  IssuerClass = "none"
	IssuerUnknown               IssuerClass = "unknown"
)

// Row mirrors host_arg_calificadora column shape.
type Row struct {
	FilePath                   string         `json:"file_path"`
	FileHash                   string         `json:"file_hash"`
	UserProfile                string         `json:"user_profile,omitempty"`
	ArtifactKind               ArtifactKind   `json:"artifact_kind"`
	CalificadoraID             CalificadoraID `json:"calificadora_id"`
	AnalystRole                AnalystRole    `json:"analyst_role"`
	RatingClass                RatingClass    `json:"rating_class,omitempty"`
	WatchStatus                WatchStatus    `json:"watch_status,omitempty"`
	IssuerClass                IssuerClass    `json:"issuer_class,omitempty"`
	ReportingPeriod            string         `json:"reporting_period,omitempty"`
	ClienteEmisorCuitPrefix    string         `json:"cliente_emisor_cuit_prefix,omitempty"`
	ClienteEmisorCuitSuffix4   string         `json:"cliente_emisor_cuit_suffix4,omitempty"`
	ClienteAnalystCuilPrefix   string         `json:"cliente_analyst_cuil_prefix,omitempty"`
	ClienteAnalystCuilSuffix4  string         `json:"cliente_analyst_cuil_suffix4,omitempty"`
	RatingID                   string         `json:"rating_id,omitempty"`
	MethodologyVersion         string         `json:"methodology_version,omitempty"`
	SeriesID                   string         `json:"series_id,omitempty"`
	IssuerCount                int64          `json:"issuer_count,omitempty"`
	WatchIssuerCount           int64          `json:"watch_issuer_count,omitempty"`
	DissentingOpinionCount     int64          `json:"dissenting_opinion_count,omitempty"`
	ModelInputParamCount       int64          `json:"model_input_param_count,omitempty"`
	FeeTotalARSMillions        int64          `json:"fee_total_ars_millions,omitempty"`
	FileOwnerUID               int            `json:"file_owner_uid,omitempty"`
	FileMode                   int            `json:"file_mode,omitempty"`
	FileSize                   int64          `json:"file_size,omitempty"`
	HasPasswordInConfig        bool           `json:"has_password_in_config"`
	HasRatingLetter            bool           `json:"has_rating_letter"`
	HasMethodologyDoc          bool           `json:"has_methodology_doc"`
	HasCommitteeMinutes        bool           `json:"has_committee_minutes"`
	HasMonitoringReport        bool           `json:"has_monitoring_report"`
	HasWatchlist               bool           `json:"has_watchlist"`
	HasConflictOfInterestDoc   bool           `json:"has_conflict_of_interest_doc"`
	HasFeeSchedule             bool           `json:"has_fee_schedule"`
	HasInternalCreditModel     bool           `json:"has_internal_credit_model"`
	HasDissentingOpinion       bool           `json:"has_dissenting_opinion"`
	HasIssuerRoster            bool           `json:"has_issuer_roster"`
	HasCNVFiling               bool           `json:"has_cnv_filing"`
	HasSOCReport               bool           `json:"has_soc_report"`
	HasPendingWatchAction      bool           `json:"has_pending_watch_action"`
	HasMethodologyChange       bool           `json:"has_methodology_change"`
	HasCommitteeSplit          bool           `json:"has_committee_split"`
	HasCrossIssuerComparable   bool           `json:"has_cross_issuer_comparable"`
	HasClienteEmisorCuit       bool           `json:"has_cliente_emisor_cuit"`
	HasClienteAnalystCuil      bool           `json:"has_cliente_analyst_cuil"`
	IsRecent                   bool           `json:"is_recent"`
	IsWorldReadable            bool           `json:"is_world_readable"`
	IsGroupReadable            bool           `json:"is_group_readable"`
	IsCredentialExposureRisk   bool           `json:"is_credential_exposure_risk"`
	IsMarketMovingInfoRisk     bool           `json:"is_market_moving_info_risk"`
	IsIntellectualPropertyRisk bool           `json:"is_intellectual_property_risk"`
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

// DefaultInstallRoots is the curated calificadora-tool install-
// root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Calificadora`,
		`C:\FIX SCR`,
		`C:\Moodys Local`,
		`C:\Program Files\Calificadora`,
		`C:\Program Files (x86)\Calificadora`,
		"/opt/calificadora",
		"/opt/rating-agency",
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

// UserCalDirs is the curated per-user relative path set.
func UserCalDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Calificadora"},
		{"AppData", "Roaming", "FIX SCR"},
		{"AppData", "Roaming", "Moodys Local"},
		{"AppData", "Roaming", "Evaluadora"},
		{"AppData", "Local", "Calificadora"},
		{"AppData", "Local", "FIX SCR"},
		{".config", "calificadora"},
		{".calificadora"},
		{"Documents", "Calificadora"},
		{"Documents", "Rating"},
		{"Documents", "Calificaciones"},
		{"Library", "Application Support", "Calificadora"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// calificadora artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json",
		".cfg", ".ini",
		".csv", ".tsv", ".log", ".txt",
		".xlsx", ".xls", ".ods",
		".pdf", ".doc", ".docx",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the calificadora catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"calificadora", "calificacion", "calificación",
		"rating",
		"metodologia", "metodología", "methodology",
		"comite_calificacion", "comite-calificacion",
		"comité_calificacion", "rating_committee", "committee_minutes",
		"monitoreo", "monitoring",
		"watchlist", "watch_list", "watch-list",
		"conflicto_interes", "conflicto-interes", "coi",
		"honorarios", "fee_schedule", "fee-schedule",
		"modelo_pd", "modelo-pd", "modelo_lgd", "modelo-lgd",
		"modelo_ead", "modelo-ead", "pd_model", "lgd_model",
		"opinion_disidente", "opinión_disidente",
		"dissenting_opinion", "dissent",
		"cliente_emisor", "issuer_roster",
		"cnv_filing", "cnv-filing",
		"soc_report", "soc-report", "soc1", "soc2",
		"fix_scr", "fix-scr", "fixscr",
		"moodys_local", "moodys-local",
		"evaluadora", "untref", "acr",
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
		if strings.Contains(n, "calificadora") ||
			strings.Contains(n, "fix scr") ||
			strings.Contains(n, "moodys") ||
			strings.Contains(n, "rating") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "calificadora") &&
		strings.Contains(n, "config"):
		return KindConfig
	case strings.Contains(n, "metodologia") ||
		strings.Contains(n, "metodología") ||
		strings.Contains(n, "methodology"):
		return KindMethodologyDoc
	case strings.Contains(n, "comite_calificacion") ||
		strings.Contains(n, "comite-calificacion") ||
		strings.Contains(n, "comité_calificacion") ||
		strings.Contains(n, "rating_committee") ||
		strings.Contains(n, "committee_minutes"):
		return KindCommitteeMinutes
	case strings.Contains(n, "opinion_disidente") ||
		strings.Contains(n, "opinión_disidente") ||
		strings.Contains(n, "dissenting_opinion") ||
		strings.Contains(n, "dissent"):
		return KindDissentingOpinion
	case strings.Contains(n, "watchlist") ||
		strings.Contains(n, "watch_list") ||
		strings.Contains(n, "watch-list"):
		return KindWatchlist
	case strings.Contains(n, "monitoreo") ||
		strings.Contains(n, "monitoring"):
		return KindMonitoringReport
	case strings.Contains(n, "conflicto_interes") ||
		strings.Contains(n, "conflicto-interes") ||
		strings.Contains(n, "coi_") || strings.Contains(n, "coi-"):
		return KindConflictOfInterestDoc
	case strings.Contains(n, "honorarios") ||
		strings.Contains(n, "fee_schedule") ||
		strings.Contains(n, "fee-schedule"):
		return KindFeeSchedule
	case strings.Contains(n, "modelo_pd") ||
		strings.Contains(n, "modelo-pd") ||
		strings.Contains(n, "modelo_lgd") ||
		strings.Contains(n, "modelo-lgd") ||
		strings.Contains(n, "modelo_ead") ||
		strings.Contains(n, "modelo-ead") ||
		strings.Contains(n, "pd_model") ||
		strings.Contains(n, "lgd_model") ||
		strings.Contains(n, "credit_model"):
		return KindInternalCreditModel
	case strings.Contains(n, "cliente_emisor") ||
		strings.Contains(n, "issuer_roster"):
		return KindIssuerRoster
	case strings.Contains(n, "cnv_filing") ||
		strings.Contains(n, "cnv-filing") ||
		strings.Contains(n, "cnv_presentacion"):
		return KindCNVFiling
	case strings.Contains(n, "soc_report") ||
		strings.Contains(n, "soc-report") ||
		strings.Contains(n, "soc1") ||
		strings.Contains(n, "soc2"):
		return KindSOCReport
	case strings.Contains(n, "calificacion") ||
		strings.Contains(n, "calificación") ||
		strings.Contains(n, "rating"):
		return KindRatingLetter
	}
	return KindOther
}

// CuitEntityOnlyPrefixes is the issuer-corporate-only subset.
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

// CuilEntityPrefixes is the analyst-individual-only subset.
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

// CuitEntityOnlyFingerprint extracts issuer-CUIT (prefix, suffix4).
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

// CuilFingerprint extracts analyst-CUIL (prefix, suffix4).
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
	case KindRatingLetter, KindMethodologyDoc,
		KindCommitteeMinutes, KindMonitoringReport,
		KindWatchlist, KindConflictOfInterestDoc,
		KindFeeSchedule, KindInternalCreditModel,
		KindDissentingOpinion, KindIssuerRoster,
		KindCNVFiling, KindSOCReport,
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
	case KindRatingLetter, KindCommitteeMinutes,
		KindWatchlist, KindDissentingOpinion:
		return true
	case KindMethodologyDoc, KindMonitoringReport,
		KindConflictOfInterestDoc, KindFeeSchedule,
		KindInternalCreditModel, KindIssuerRoster,
		KindCNVFiling, KindSOCReport,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsIntellectualPropertyKind reports whether the kind carries
// calificadora IP (methodology + internal credit models).
func IsIntellectualPropertyKind(k ArtifactKind) bool {
	switch k {
	case KindMethodologyDoc, KindInternalCreditModel:
		return true
	case KindRatingLetter, KindCommitteeMinutes,
		KindMonitoringReport, KindWatchlist,
		KindConflictOfInterestDoc, KindFeeSchedule,
		KindDissentingOpinion, KindIssuerRoster,
		KindCNVFiling, KindSOCReport,
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
	if r.ClienteEmisorCuitPrefix != "" {
		r.HasClienteEmisorCuit = true
	}
	if r.ClienteAnalystCuilPrefix != "" {
		r.HasClienteAnalystCuil = true
	}
	switch r.ArtifactKind {
	case KindRatingLetter:
		r.HasRatingLetter = true
	case KindMethodologyDoc:
		r.HasMethodologyDoc = true
	case KindCommitteeMinutes:
		r.HasCommitteeMinutes = true
	case KindMonitoringReport:
		r.HasMonitoringReport = true
	case KindWatchlist:
		r.HasWatchlist = true
	case KindConflictOfInterestDoc:
		r.HasConflictOfInterestDoc = true
	case KindFeeSchedule:
		r.HasFeeSchedule = true
	case KindInternalCreditModel:
		r.HasInternalCreditModel = true
	case KindDissentingOpinion:
		r.HasDissentingOpinion = true
	case KindIssuerRoster:
		r.HasIssuerRoster = true
	case KindCNVFiling:
		r.HasCNVFiling = true
	case KindSOCReport:
		r.HasSOCReport = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag for these kinds.
	}
	if r.WatchStatus != "" && r.WatchStatus != WatchStable &&
		r.WatchStatus != WatchUnknown && r.WatchStatus != WatchNone {
		r.HasPendingWatchAction = true
	}
	if r.DissentingOpinionCount > 0 {
		r.HasCommitteeSplit = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasRatingLetter ||
		r.HasMethodologyDoc || r.HasCommitteeMinutes ||
		r.HasWatchlist || r.HasInternalCreditModel ||
		r.HasIssuerRoster || r.HasClienteEmisorCuit
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && (r.HasPendingWatchAction ||
		r.HasCommitteeSplit ||
		IsMarketMovingKind(r.ArtifactKind)) {
		r.IsMarketMovingInfoRisk = true
	}
	if readable && IsIntellectualPropertyKind(r.ArtifactKind) {
		r.IsIntellectualPropertyRisk = true
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
