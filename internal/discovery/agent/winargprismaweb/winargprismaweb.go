// Package winargprismaweb audits BYMA PrismaWeb clearing &
// settlement portal artifact files cached on Argentine ALYC
// clearing-member, FCI-manager, and bank back-office
// workstations across Windows, Linux, and macOS.
//
// PrismaWeb is BYMA's clearing & settlement portal — the
// equity / option / CEDEAR / FCI cash-flow post-trade layer.
// It is the equity-side complement to MAEclear (OTC bonds).
//
// PrismaWeb settles:
//
//   - Equity T+1 + T+2 (BYMA-listed shares).
//   - CEDEAR settlement (foreign-stock receipts).
//   - Argentine equity option exercise/assignment.
//   - FCI cash flow (suscripción/rescate primary).
//   - Margin calls (alycs vs. clearing house).
//   - Garantías (collateral postings).
//   - Member position reports.
//
// **The equity clearing layer.** Distinct from:
//
//   - iter 157 winargmaeclear   — MAE OTC bond clearing.
//   - iter 137 winargcvsa       — CVSA equity custody.
//   - iter 109 winargmatbarofex — MTR-Rofex futures CCP.
//   - iter 156 winargbymadata   — BYMA market-data feed.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — portal cleartext.
//   - `has_fix_drop_copy=1` — FIX drop-copy session.
//   - `has_margin_call_event=1` — member margin call event.
//   - `has_options_exercise=1` — equity options exercise.
//   - `has_t1_fail=1` — T+1 settle fail (CNV RG 622 art. 47).
//   - `has_high_collateral=1` — > 100 M ARS garantías.
//   - `has_cedear_settlement=1` — CEDEAR settle row.
//   - `has_fci_cashflow=1` — FCI primary cashflow.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargprismaweb

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

// HighCollateralARSCents is the per-file garantías threshold
// above which the rollup flags high collateral (100 M ARS =
// 1e10 cents).
const HighCollateralARSCents = 10_000_000_000

// ArtifactKind pinned to host_arg_prismaweb.artifact_kind.
type ArtifactKind string

const (
	KindConfig          ArtifactKind = "prismaweb-config"
	KindCredentials     ArtifactKind = "prismaweb-credentials"
	KindDailySettlement ArtifactKind = "prismaweb-daily-settlement"
	KindCollateral      ArtifactKind = "prismaweb-collateral"
	KindMarginCalls     ArtifactKind = "prismaweb-margin-calls"
	KindOptionsExercise ArtifactKind = "prismaweb-options-exercise"
	KindFCICashflow     ArtifactKind = "prismaweb-fci-cashflow"
	KindFIXDropCopy     ArtifactKind = "prismaweb-fix-drop-copy"
	KindMemberPosition  ArtifactKind = "prismaweb-member-position"
	KindInstaller       ArtifactKind = "prismaweb-installer"
	KindOther           ArtifactKind = "other"
	KindUnknown         ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_prismaweb.account_class.
type AccountClass string

const (
	AccountALYCClearing     AccountClass = "alyc-clearing"
	AccountALYCNonClearing  AccountClass = "alyc-non-clearing"
	AccountFCIManager       AccountClass = "fci-manager"
	AccountBankingCustodian AccountClass = "banking-custodian"
	AccountAuditor          AccountClass = "auditor"
	AccountDemo             AccountClass = "demo"
	AccountOther            AccountClass = "other"
	AccountUnknown          AccountClass = "unknown"
)

// Row mirrors host_arg_prismaweb column shape.
type Row struct {
	FilePath                  string       `json:"file_path"`
	FileHash                  string       `json:"file_hash"`
	UserProfile               string       `json:"user_profile,omitempty"`
	ArtifactKind              ArtifactKind `json:"artifact_kind"`
	AccountClass              AccountClass `json:"account_class"`
	MemberID                  string       `json:"member_id,omitempty"`
	ClienteCuitPrefix         string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4        string       `json:"cliente_cuit_suffix4,omitempty"`
	FIXSessionSender          string       `json:"fix_session_sender,omitempty"`
	FIXSessionTarget          string       `json:"fix_session_target,omitempty"`
	SessionFirstSeen          string       `json:"session_first_seen,omitempty"`
	SessionLastSeen           string       `json:"session_last_seen,omitempty"`
	PeriodYYYYMM              string       `json:"period_yyyymm,omitempty"`
	SettlementCount           int64        `json:"settlement_count,omitempty"`
	SettlementFailCount       int64        `json:"settlement_fail_count,omitempty"`
	MarginCallCount           int64        `json:"margin_call_count,omitempty"`
	OptionsExerciseCount      int64        `json:"options_exercise_count,omitempty"`
	CEDEARSettlementCount     int64        `json:"cedear_settlement_count,omitempty"`
	FCICashflowCount          int64        `json:"fci_cashflow_count,omitempty"`
	CollateralARSCents        int64        `json:"collateral_ars_cents,omitempty"`
	TotalVolumeARSCents       int64        `json:"total_volume_ars_cents,omitempty"`
	DistinctCounterpartyCount int64        `json:"distinct_counterparty_count,omitempty"`
	FileOwnerUID              int          `json:"file_owner_uid,omitempty"`
	FileMode                  int          `json:"file_mode,omitempty"`
	FileSize                  int64        `json:"file_size,omitempty"`
	HasPasswordInConfig       bool         `json:"has_password_in_config"`
	HasFIXDropCopy            bool         `json:"has_fix_drop_copy"`
	HasMarginCallEvent        bool         `json:"has_margin_call_event"`
	HasOptionsExercise        bool         `json:"has_options_exercise"`
	HasT1Fail                 bool         `json:"has_t1_fail"`
	HasHighCollateral         bool         `json:"has_high_collateral"`
	HasCEDEARSettlement       bool         `json:"has_cedear_settlement"`
	HasFCICashflow            bool         `json:"has_fci_cashflow"`
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

// DefaultInstallRoots is the curated PrismaWeb install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\PrismaWeb`,
		`C:\BYMA\PrismaWeb`,
		`C:\Prisma_Web`,
		`C:\Program Files\PrismaWeb`,
		`C:\Program Files\BYMA\PrismaWeb`,
		`C:\Program Files (x86)\PrismaWeb`,
		`/opt/prismaweb`,
		`/opt/byma-prismaweb`,
		`/Applications/PrismaWeb.app`,
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

// UserPrismaWebDirs is the curated per-user relative path set.
func UserPrismaWebDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "PrismaWeb"},
		{"AppData", "Roaming", "BYMA", "PrismaWeb"},
		{"AppData", "Local", "PrismaWeb"},
		{"AppData", "Local", "BYMA", "PrismaWeb"},
		{"Documents", "PrismaWeb"},
		{"Documents", "BYMA", "PrismaWeb"},
		{".prismaweb"},
		{"Library", "Application Support", "PrismaWeb"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// PrismaWeb artifact.
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
// to the PrismaWeb catalogue.
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
		"prismaweb", "prisma_web", "prisma-web",
		"liquidacion", "liquidaci\u00f3n",
		"daily_settle", "daily-settle",
		"garantias", "garant\u00edas", "collateral",
		"margin_call", "margin-call",
		"ejercicio_opciones", "options_exercise",
		"fci_cashflow", "fci-cashflow",
		"member_position", "member-position",
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
		if strings.Contains(n, "prismaweb") || strings.Contains(n, "prisma_web") ||
			strings.Contains(n, "prisma-web") {
			return KindInstaller
		}
		return KindOther
	case ".fix":
		return KindFIXDropCopy
	}
	switch {
	case strings.Contains(n, "drop_copy") || strings.Contains(n, "drop-copy") ||
		strings.Contains(n, "dropcopy"):
		return KindFIXDropCopy
	case strings.Contains(n, "margin_call") || strings.Contains(n, "margin-call") ||
		strings.Contains(n, "llamada_margen"):
		return KindMarginCalls
	case strings.Contains(n, "ejercicio_opciones") ||
		strings.Contains(n, "ejercicio-opciones") ||
		strings.Contains(n, "options_exercise") ||
		strings.Contains(n, "options-exercise"):
		return KindOptionsExercise
	case strings.Contains(n, "fci_cashflow") || strings.Contains(n, "fci-cashflow") ||
		strings.Contains(n, "fci_flujo"):
		return KindFCICashflow
	case strings.Contains(n, "garantias") || strings.Contains(n, "garant\u00edas") ||
		strings.Contains(n, "collateral"):
		return KindCollateral
	case strings.Contains(n, "member_position") || strings.Contains(n, "member-position") ||
		strings.Contains(n, "miembro_posicion"):
		return KindMemberPosition
	case strings.Contains(n, "daily_settle") || strings.Contains(n, "daily-settle") ||
		strings.Contains(n, "liquidacion") || strings.Contains(n, "liquidaci\u00f3n"):
		return KindDailySettlement
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_key") ||
		strings.Contains(n, "token"):
		return KindCredentials
	case (strings.Contains(n, "config") || strings.Contains(n, "settings") ||
		strings.Contains(n, "prismaweb")) &&
		(ext == ".xml" || ext == ".json" || ext == ".ini" || ext == ".cfg" ||
			ext == ".conf" || ext == ".yaml" || ext == ".yml"):
		return KindConfig
	}
	return KindOther
}

// CEDEARTickerPrefixes returns a curated set of common CEDEAR
// ticker stems for detection. CEDEARs use the underlying-USD
// ticker (AAPL/MSFT/etc) on BYMA.
func CEDEARTickerPrefixes() []string {
	return []string{
		"AAPL", "MSFT", "GOOG", "GOOGL", "AMZN",
		"META", "TSLA", "NVDA", "NFLX", "DIS",
		"KO", "PEP", "JPM", "BAC", "WMT",
		"VALE", "PBR", "ITUB", "BBD",
		"BABA", "JD", "BIDU",
	}
}

// IsCEDEARTicker reports whether the symbol matches a curated
// CEDEAR underlying.
func IsCEDEARTicker(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, p := range CEDEARTickerPrefixes() {
		if t == p || strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
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

// memberIDRE matches a BYMA / PrismaWeb member ID. Char class
// includes `>` so XML tag-form `<member_id>987</member_id>` is
// matched alongside INI/JSON `member_id: 987`.
var memberIDRE = regexp.MustCompile(
	`(?i)(?:member[_\- ]?id|miembro[_\- ]?id|matr[íi]cula|byma[_\- ]?member|clearing[_\- ]?member|alyc[_\- ]?id)["'>\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// MemberIDFromText extracts a member ID.
func MemberIDFromText(text string) string {
	m := memberIDRE.FindStringSubmatch(text)
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
	case KindConfig, KindCredentials, KindDailySettlement,
		KindCollateral, KindMarginCalls, KindOptionsExercise,
		KindFCICashflow, KindFIXDropCopy, KindMemberPosition:
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
		r.HasT1Fail = true
	}
	if r.MarginCallCount > 0 {
		r.HasMarginCallEvent = true
	}
	if r.OptionsExerciseCount > 0 {
		r.HasOptionsExercise = true
	}
	if r.CEDEARSettlementCount > 0 {
		r.HasCEDEARSettlement = true
	}
	if r.FCICashflowCount > 0 {
		r.HasFCICashflow = true
	}
	if r.CollateralARSCents >= HighCollateralARSCents {
		r.HasHighCollateral = true
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
