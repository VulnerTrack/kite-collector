// Package winargecotrader audits Eco Trader / ROFEX Trader
// Pro desktop-terminal artifact files cached on Argentine
// prop-desk, quant, and broker workstations across Windows,
// Linux, and macOS.
//
// ROFEX Trader Pro (also branded "Eco Trader") is the
// commercial Windows desktop terminal for ROFEX (MATba-Rofex)
// futures + options trading. It is the GUI alternative to
// the Primary REST/WS API (used by quants) and SIOPEL
// (used for MAE OTC).
//
// **The ROFEX-desktop-GUI layer.** Distinct from:
//
//   - iter 109 winargmatbarofex  — MATba-Rofex positions
//   - iter 139 winargprimary     — Primary REST/WS (pyRofex)
//   - iter 143 winargmt          — MetaTrader 4/5
//   - iter 148 winargninjatrader — NinjaTrader 8 futures
//   - iter 136 winargsiopel      — SIOPEL/MAE OTC terminal
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — settings.xml cleartext.
//   - `has_dollar_futures_dlr=1` — DLR / DOM in watchlist
//     (BCRA Com. A 7916 scrutiny).
//   - `has_agro_futures=1` — SOJ / MAI / TRI / GIR / SOR.
//   - `has_inflation_futures=1` — CER / UVA futures.
//   - `has_mtr_usd_bridge=1` — MTR-USD micro-future.
//   - `has_after_hours_session=1` — outside 09:00-16:00 ART.
//   - `is_credential_exposure_risk=1` — readable file +
//     (password OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargecotrader

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

// VenueOpenHourART — MATba-Rofex futures venue opens at 09:00
// ART (UTC-3) under the standard operatoria.
const VenueOpenHourART = 9

// VenueCloseHourART — MATba-Rofex futures venue closes 16:00
// ART under the standard operatoria.
const VenueCloseHourART = 16

// ArtifactKind pinned to host_arg_ecotrader.artifact_kind.
type ArtifactKind string

const (
	KindConfig         ArtifactKind = "ecotrader-config"
	KindSessionLog     ArtifactKind = "ecotrader-session-log"
	KindPositionsCache ArtifactKind = "ecotrader-positions-cache"
	KindWatchlist      ArtifactKind = "ecotrader-watchlist"
	KindChartTemplate  ArtifactKind = "ecotrader-chart-template"
	KindQuotesCache    ArtifactKind = "ecotrader-quotes-cache"
	KindInstaller      ArtifactKind = "ecotrader-installer"
	KindOther          ArtifactKind = "other"
	KindUnknown        ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_ecotrader.account_class.
type AccountClass string

const (
	AccountPrimaryAPI AccountClass = "primary-api"
	AccountDirectFIX  AccountClass = "direct-fix"
	AccountDemo       AccountClass = "demo"
	AccountOther      AccountClass = "other"
	AccountUnknown    AccountClass = "unknown"
)

// Row mirrors host_arg_ecotrader column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AccountClass             AccountClass `json:"account_class"`
	BrokerMatricula          string       `json:"broker_matricula,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	AccountLoginSuffix4      string       `json:"account_login_suffix4,omitempty"`
	SessionFirstSeen         string       `json:"session_first_seen,omitempty"`
	SessionLastSeen          string       `json:"session_last_seen,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	DistinctFuturesCount     int64        `json:"distinct_futures_count,omitempty"`
	MaxPositionLots          int64        `json:"max_position_lots,omitempty"`
	DollarFuturesLots        int64        `json:"dollar_futures_lots,omitempty"`
	AgroFuturesLots          int64        `json:"agro_futures_lots,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasDollarFuturesDLR      bool         `json:"has_dollar_futures_dlr"`
	HasAgroFutures           bool         `json:"has_agro_futures"`
	HasInflationFutures      bool         `json:"has_inflation_futures"`
	HasMTRUSDBridge          bool         `json:"has_mtr_usd_bridge"`
	HasAfterHoursSession     bool         `json:"has_after_hours_session"`
	HasClienteCuit           bool         `json:"has_cliente_cuit"`
	IsRecent                 bool         `json:"is_recent"`
	IsWorldReadable          bool         `json:"is_world_readable"`
	IsGroupReadable          bool         `json:"is_group_readable"`
	IsCredentialExposureRisk bool         `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated Eco Trader install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\ROFEX\TraderPro`,
		`C:\ROFEX\Trader Pro`,
		`C:\ROFEX Trader Pro`,
		`C:\Eco Trader`,
		`C:\EcoTrader`,
		`C:\Program Files\ROFEX TraderPro`,
		`C:\Program Files (x86)\ROFEX TraderPro`,
		`C:\Program Files\Eco Trader`,
		`/opt/ecotrader`,
		`/opt/rofex-traderpro`,
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

// UserEcoTraderDirs is the curated per-user relative path set.
func UserEcoTraderDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "ROFEX TraderPro"},
		{"AppData", "Roaming", "Eco Trader"},
		{"AppData", "Local", "ROFEX TraderPro"},
		{"AppData", "Local", "Eco Trader"},
		{"Documents", "ROFEX TraderPro"},
		{"Documents", "Eco Trader"},
		{"Documents", "Trading", "ROFEX"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries an
// Eco Trader artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json", ".csv", ".tsv",
		".ini", ".cfg", ".conf",
		".log", ".txt",
		".cht", ".qte",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Eco Trader catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	// `.cht` / `.qte` are Eco-specific extensions.
	if ext == ".cht" || ext == ".qte" {
		return true
	}
	for _, tok := range []string{
		"rofex", "ecotrader", "eco_trader", "eco-trader",
		"traderpro", "trader_pro", "trader-pro",
		"watchlist", "positions_cache", "positions-cache",
		"session_", "quotes_", "settings",
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
	case ".msi", ".exe":
		if strings.Contains(n, "rofex") || strings.Contains(n, "ecotrader") ||
			strings.Contains(n, "trader") {
			return KindInstaller
		}
		return KindOther
	case ".cht":
		return KindChartTemplate
	case ".qte":
		return KindQuotesCache
	}
	switch {
	case (strings.Contains(n, "settings") ||
		strings.Contains(n, "rofex") ||
		strings.Contains(n, "ecotrader") ||
		strings.Contains(n, "eco_trader")) &&
		(ext == ".ini" || ext == ".cfg" || ext == ".conf" ||
			ext == ".xml"):
		return KindConfig
	case strings.Contains(n, "session") &&
		(ext == ".log" || ext == ".txt"):
		return KindSessionLog
	case strings.Contains(n, "positions_cache") ||
		strings.Contains(n, "positions-cache") ||
		strings.Contains(n, "positions"):
		return KindPositionsCache
	case strings.Contains(n, "watchlist"):
		return KindWatchlist
	case strings.Contains(n, "quotes"):
		return KindQuotesCache
	}
	return KindOther
}

// DollarFuturesSymbols returns the curated set of dollar-
// futures symbols (BCRA Com. A 7916 scrutiny).
func DollarFuturesSymbols() []string {
	return []string{
		"DLR", "DOM", "ROS-DLR", "MTR-USD",
	}
}

// AgroFuturesSymbols returns the curated set of agro-futures
// symbols.
func AgroFuturesSymbols() []string {
	return []string{
		"SOJ", "MAI", "TRI", "GIR", "SOR",
		"ROS20", "ROS-SOJ", "ROS-MAI", "ROS-TRI",
	}
}

// InflationFuturesSymbols returns the curated set of CER /
// UVA inflation-linked futures.
func InflationFuturesSymbols() []string {
	return []string{
		"CER", "UVA", "CER-FUT", "UVA-FUT",
	}
}

// IsDollarFutures reports whether the symbol matches the
// curated dollar-futures set.
func IsDollarFutures(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range DollarFuturesSymbols() {
		if v == t || strings.HasPrefix(t, v) {
			return true
		}
	}
	return false
}

// IsAgroFutures reports whether the symbol matches an agro-
// futures set.
func IsAgroFutures(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range AgroFuturesSymbols() {
		if v == t || strings.HasPrefix(t, v) {
			return true
		}
	}
	return false
}

// IsInflationFutures reports CER / UVA membership.
func IsInflationFutures(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range InflationFuturesSymbols() {
		if v == t || strings.HasPrefix(t, v) {
			return true
		}
	}
	return false
}

// IsMTRUSDBridge reports whether the symbol is the MERVAL-USD
// micro-future bridge.
func IsMTRUSDBridge(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	return strings.HasPrefix(t, "MTR-USD") || strings.HasPrefix(t, "MTRUSD")
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

// matriculaRE matches MATba-Rofex broker matrícula in text.
var matriculaRE = regexp.MustCompile(`(?i)(?:matr[íi]cula|broker[_\- ]?matricula|rofex[_\- ]?matricula)[\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// MatriculaFromText extracts the matrícula.
func MatriculaFromText(text string) string {
	m := matriculaRE.FindStringSubmatch(text)
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

// IsAfterHoursStamp parses a "HH:MM" / "HH:MM:SS" / `YYYY-MM-DD
// HH:MM` token in ART (UTC-3) and reports whether it falls
// outside the venue window.
func IsAfterHoursStamp(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	re := regexp.MustCompile(`(\d{1,2}):\d{2}`)
	m := re.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	h := 0
	for _, c := range m[1] {
		h = h*10 + int(c-'0')
	}
	if h < 0 || h > 23 {
		return false
	}
	return h < VenueOpenHourART || h >= VenueCloseHourART
}

// IsSensitiveKind reports whether the kind carries PII /
// credential material subject to the exposure rollup.
func IsSensitiveKind(k ArtifactKind) bool {
	switch k {
	case KindConfig, KindSessionLog, KindPositionsCache:
		return true
	case KindWatchlist, KindChartTemplate, KindQuotesCache,
		KindInstaller, KindOther, KindUnknown:
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
	if r.DollarFuturesLots > 0 {
		r.HasDollarFuturesDLR = true
	}
	if r.AgroFuturesLots > 0 {
		r.HasAgroFutures = true
	}
	if r.SessionFirstSeen != "" && IsAfterHoursStamp(r.SessionFirstSeen) {
		r.HasAfterHoursSession = true
	}
	if !r.HasAfterHoursSession && r.SessionLastSeen != "" &&
		IsAfterHoursStamp(r.SessionLastSeen) {
		r.HasAfterHoursSession = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasClienteCuit
	if readable && credSignal && IsSensitiveKind(r.ArtifactKind) {
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
