// Package winargmaeclear audits MAEclear OTC clearing
// artifact files cached on Argentine bank, ALYC, and
// sociedad-gerente back-office workstations across Windows,
// Linux, and macOS.
//
// MAEclear is the central counterparty (CCP) + clearing
// system for OTC trades on the MAE (Mercado Abierto
// Electrónico) platform — the *clearing* leg of MAE (vs.
// SIOPEL the trading terminal).
//
// MAEclear settles:
//
//   - Sovereign + corporate bonds (AL30/GD30/AY24/etc.).
//   - REPO / caución bilateral OTC.
//   - BCRA-direct Leliq + Leliq-USD (BCRA-only counterparty).
//   - FX-forward bilateral confirms.
//   - Bilateral "afirmación" workflow (T+0 confirms).
//
// **The OTC clearing layer.** Distinct from:
//
//   - iter 136 winargsiopel     — SIOPEL trading terminal.
//   - iter 137 winargcvsa       — CVSA equity custody.
//   - iter 109 winargmatbarofex — MTR-Rofex futures CCP.
//   - iter 156 winargbymadata   — BYMA market-data feed.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — terminal cleartext.
//   - `has_fix_drop_copy=1` — FIX drop-copy session.
//   - `has_settlement_failure=1` — T+1 settle fail event
//     (CNV RG 622 art. 47 monitoring).
//   - `has_repo_activity=1` — REPO bilateral book.
//   - `has_long_tenor_repo=1` — REPO > 30-day tenor.
//   - `has_bcra_leliq_settlement=1` — BCRA-direct Leliq.
//   - `has_sovereign_otc_activity=1` — AL30/GD30 OTC.
//   - `has_cross_border_fx_forward=1` — USD/ARS FX-forward
//     (BCRA Com. A 7916 scrutiny).
//   - `has_high_settlement_volume=1` — > 1 G ARS / day.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargmaeclear

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

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 16 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// LongTenorRepoThresholdDays is the per-REPO tenor threshold
// above which the rollup flags long-tenor.
const LongTenorRepoThresholdDays = 30

// HighVolumeARSCents is the per-file settlement volume above
// which the rollup flags high volume (1 G ARS = 1e11 cents).
const HighVolumeARSCents = 100_000_000_000

// ArtifactKind pinned to host_arg_maeclear.artifact_kind.
type ArtifactKind string

const (
	KindConfig         ArtifactKind = "maeclear-config"
	KindCredentials    ArtifactKind = "maeclear-credentials" //#nosec G101 -- ArtifactKind enum naming the MAEClear credentials artifact category, not a credential value
	KindSettlementBook ArtifactKind = "maeclear-settlement-book"
	KindAffirmationLog ArtifactKind = "maeclear-affirmation-log"
	KindRepoBook       ArtifactKind = "maeclear-repo-book"
	KindLeliqLog       ArtifactKind = "maeclear-leliq-log"
	KindDropCopy       ArtifactKind = "maeclear-drop-copy"
	KindSessionLog     ArtifactKind = "maeclear-session-log"
	KindInstaller      ArtifactKind = "maeclear-installer"
	KindOther          ArtifactKind = "other"
	KindUnknown        ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_maeclear.account_class.
type AccountClass string

const (
	AccountBank            AccountClass = "bank"
	AccountALYC            AccountClass = "alyc"
	AccountSociedadGerente AccountClass = "sociedad-gerente"
	AccountBCRA            AccountClass = "bcra"
	AccountAuditor         AccountClass = "auditor"
	AccountDemo            AccountClass = "demo"
	AccountOther           AccountClass = "other"
	AccountUnknown         AccountClass = "unknown"
)

// Row mirrors host_arg_maeclear column shape.
type Row struct {
	FilePath                  string       `json:"file_path"`
	FileHash                  string       `json:"file_hash"`
	UserProfile               string       `json:"user_profile,omitempty"`
	ArtifactKind              ArtifactKind `json:"artifact_kind"`
	AccountClass              AccountClass `json:"account_class"`
	ParticipantID             string       `json:"participant_id,omitempty"`
	ClienteCuitPrefix         string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4        string       `json:"cliente_cuit_suffix4,omitempty"`
	FIXSessionSender          string       `json:"fix_session_sender,omitempty"`
	FIXSessionTarget          string       `json:"fix_session_target,omitempty"`
	SettlementFirstSeen       string       `json:"settlement_first_seen,omitempty"`
	SettlementLastSeen        string       `json:"settlement_last_seen,omitempty"`
	PeriodYYYYMM              string       `json:"period_yyyymm,omitempty"`
	SettlementCount           int64        `json:"settlement_count,omitempty"`
	SettlementFailCount       int64        `json:"settlement_fail_count,omitempty"`
	AffirmationCount          int64        `json:"affirmation_count,omitempty"`
	RepoCount                 int64        `json:"repo_count,omitempty"`
	RepoMaxTenorDays          int64        `json:"repo_max_tenor_days,omitempty"`
	LeliqSettlementCount      int64        `json:"leliq_settlement_count,omitempty"`
	SovereignOTCCount         int64        `json:"sovereign_otc_count,omitempty"`
	FXForwardCount            int64        `json:"fx_forward_count,omitempty"`
	TotalVolumeARSCents       int64        `json:"total_volume_ars_cents,omitempty"`
	DistinctCounterpartyCount int64        `json:"distinct_counterparty_count,omitempty"`
	FileOwnerUID              int          `json:"file_owner_uid,omitempty"`
	FileMode                  int          `json:"file_mode,omitempty"`
	FileSize                  int64        `json:"file_size,omitempty"`
	HasPasswordInConfig       bool         `json:"has_password_in_config"`
	HasFIXDropCopy            bool         `json:"has_fix_drop_copy"`
	HasSettlementFailure      bool         `json:"has_settlement_failure"`
	HasRepoActivity           bool         `json:"has_repo_activity"`
	HasLongTenorRepo          bool         `json:"has_long_tenor_repo"`
	HasBCRALeliqSettlement    bool         `json:"has_bcra_leliq_settlement"`
	HasSovereignOTCActivity   bool         `json:"has_sovereign_otc_activity"`
	HasCrossBorderFXForward   bool         `json:"has_cross_border_fx_forward"`
	HasHighSettlementVolume   bool         `json:"has_high_settlement_volume"`
	HasClienteCuit            bool         `json:"has_cliente_cuit"`
	IsRecent                  bool         `json:"is_recent"`
	IsWorldReadable           bool         `json:"is_world_readable"`
	IsGroupReadable           bool         `json:"is_group_readable"`
	IsCredentialExposureRisk  bool         `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated MAEclear install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\MAEclear`,
		`C:\MAE\MAEclear`,
		`C:\MAE_Clear`,
		`C:\Program Files\MAEclear`,
		`C:\Program Files\MAE\MAEclear`,
		`C:\Program Files (x86)\MAEclear`,
		`/opt/maeclear`,
		`/opt/mae-clear`,
		`/Applications/MAEclear.app`,
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

// UserMAEclearDirs is the curated per-user relative path set.
func UserMAEclearDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "MAEclear"},
		{"AppData", "Roaming", "MAE"},
		{"AppData", "Local", "MAEclear"},
		{"AppData", "Local", "MAE"},
		{"Documents", "MAEclear"},
		{"Documents", "MAE"},
		{".maeclear"},
		{"Library", "Application Support", "MAEclear"},
		{"Descargas"},
		{"Downloads"},
	}
}

// SovereignBondPrefixes returns the curated set of sovereign
// bond ticker stems that flag OTC market-maker activity.
func SovereignBondPrefixes() []string {
	return []string{
		"AL29", "AL30", "AL35", "AL38", "AL41",
		"AY24", "AE38", "AO20",
		"GD29", "GD30", "GD35", "GD38", "GD41", "GD46",
		"TX26", "TX28", "TX31",
		"TC25", "TC27",
		"T2X5", "T2X6",
		"PARP", "DICP",
		"BOPREAL", "BPY26", "BPA7", "BPB7",
	}
}

// IsSovereignBondTicker reports whether the ticker matches a
// curated sovereign-bond stem.
func IsSovereignBondTicker(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, p := range SovereignBondPrefixes() {
		if t == p || strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// LeliqTickerPrefixes returns the curated set of BCRA Leliq
// ticker stems.
func LeliqTickerPrefixes() []string {
	return []string{
		"LELIQ", "LEDIV", "LELIQ-USD", "LELIQUSD",
		"NOCOM", "NOCOM-USD",
	}
}

// IsLeliqTicker reports whether the ticker matches a curated
// BCRA Leliq stem.
func IsLeliqTicker(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, p := range LeliqTickerPrefixes() {
		if t == p || strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries a
// MAEclear artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json", ".ini", ".cfg", ".conf",
		".yaml", ".yml",
		".log", ".txt", ".fix",
		".csv", ".tsv",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the MAEclear catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if ext == ".fix" {
		return true
	}
	for _, tok := range []string{
		"maeclear", "mae_clear", "mae-clear",
		"settlement", "liquidacion", "liquidaci\u00f3n",
		"afirmacion", "afirmaci\u00f3n", "affirmation",
		"repo_book", "repo-book", "caucion_book", "leliq",
		"drop_copy", "drop-copy", "dropcopy",
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
		if strings.Contains(n, "maeclear") || strings.Contains(n, "mae_clear") ||
			strings.Contains(n, "mae-clear") {
			return KindInstaller
		}
		return KindOther
	case ".fix":
		return KindDropCopy
	}
	switch {
	case strings.Contains(n, "drop_copy") || strings.Contains(n, "drop-copy") ||
		strings.Contains(n, "dropcopy"):
		return KindDropCopy
	case strings.Contains(n, "leliq"):
		return KindLeliqLog
	case strings.Contains(n, "repo_book") || strings.Contains(n, "repo-book") ||
		strings.Contains(n, "caucion_book"):
		return KindRepoBook
	case strings.Contains(n, "afirmacion") || strings.Contains(n, "afirmaci\u00f3n") ||
		strings.Contains(n, "affirmation"):
		return KindAffirmationLog
	case strings.Contains(n, "settlement") || strings.Contains(n, "liquidacion"):
		return KindSettlementBook
	case strings.Contains(n, "session") &&
		(ext == ".log" || ext == ".txt"):
		return KindSessionLog
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_key") ||
		strings.Contains(n, "token"):
		return KindCredentials
	case (strings.Contains(n, "config") || strings.Contains(n, "settings") ||
		strings.Contains(n, "maeclear")) &&
		(ext == ".xml" || ext == ".json" || ext == ".ini" || ext == ".cfg" ||
			ext == ".conf" || ext == ".yaml" || ext == ".yml"):
		return KindConfig
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

// cuitScanRE uses word boundaries so adjacent CUITs separated
// only by `\n` still match (FindAll non-overlapping).
var cuitScanRE = regexp.MustCompile(`\b(\d{2})-?(\d{8})-?(\d)\b`)

// DistinctCounterpartiesInBody returns the count of distinct
// valid CUITs found in body (used for counterparty rollup).
func DistinctCounterpartiesInBody(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range cuitScanRE.FindAllSubmatch(body, -1) {
		prefix := string(m[1])
		if !IsValidCuitEntityPrefix(prefix) {
			continue
		}
		key := prefix + string(m[2]) + string(m[3])
		seen[key] = struct{}{}
	}
	return int64(len(seen))
}

// ParticipantIDFromText extracts a MAE participant code.
// Char class includes `>` so XML tag-form `<mae_id>987</...>`
// is matched alongside INI/JSON `participant_id: 987`.
var participantRE = regexp.MustCompile(
	`(?i)(?:participant[_\- ]?id|participante|mae[_\- ]?id|alyc[_\- ]?id|matr[íi]cula)["'>\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// ParticipantIDFromText extracts a participant ID.
func ParticipantIDFromText(text string) string {
	m := participantRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// PeriodFromFilename extracts YYYYMM from a filename.
func PeriodFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// IsCredentialKind reports whether the kind carries PII /
// credential material subject to the exposure rollup.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindConfig, KindCredentials, KindSettlementBook,
		KindAffirmationLog, KindRepoBook, KindLeliqLog,
		KindDropCopy, KindSessionLog:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets derived booleans. Caller populates
// scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.ClienteCuitPrefix != "" {
		r.HasClienteCuit = true
	}
	if r.SettlementFailCount > 0 {
		r.HasSettlementFailure = true
	}
	if r.RepoCount > 0 {
		r.HasRepoActivity = true
	}
	if r.RepoMaxTenorDays > LongTenorRepoThresholdDays {
		r.HasLongTenorRepo = true
	}
	if r.LeliqSettlementCount > 0 {
		r.HasBCRALeliqSettlement = true
	}
	if r.SovereignOTCCount > 0 {
		r.HasSovereignOTCActivity = true
	}
	if r.FXForwardCount > 0 {
		r.HasCrossBorderFXForward = true
	}
	if r.TotalVolumeARSCents >= HighVolumeARSCents {
		r.HasHighSettlementVolume = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasClienteCuit
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
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
		return rs[i].PeriodYYYYMM < rs[j].PeriodYYYYMM
	})
}
