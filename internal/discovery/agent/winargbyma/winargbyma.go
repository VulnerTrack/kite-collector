// Package winargbyma audits BYMA equity-terminal files
// cached on Argentine bank, broker, prop-desk, and back-
// office workstations across Windows, Linux, and macOS.
//
// BYMA (Bolsas y Mercados Argentinos) is the Argentine
// stock exchange. Workstations cache Edge / Aries / SX
// terminal configs, BYMA Connect API credentials, RV
// (Renta Variable) trade blotters, CEDEAR positions, T+2
// liquidación records, and caución bursátil RV-side
// records.
//
// **The equity-terminal layer.** Distinct from:
//
//   - iter 113 winargfix        — FIX wire-protocol session
//   - iter 117 winargcvsa       — CVSA central custody
//   - iter 136 winargsiopel     — SIOPEL/MAE OTC terminal
//   - iter 109 winargmatbarofex — derivatives (futures)
//
// Headline finding shapes:
//
//   - `has_api_key_in_config=1` — Connect.api.json carries
//     api_key/bearer/secret in cleartext.
//   - `has_cedear_position=1` — file references CEDEAR
//     tickers (offshore-equity exposure).
//   - `has_mep_ccl_arbitrage=1` — paired AL30/AL30D or
//     GD30/GD30D in the same body.
//   - `has_caucion_long_tenor=1` — caución RV > 60 days.
//   - `is_credential_exposure_risk=1` — readable file +
//     cliente CUIT + (api-key OR trade body).
//
// Read-only by intent. (Project guideline 4.2.)
package winargbyma

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

// MaxFileBytes bounds per-file read. BYMA blotter XML files
// rarely exceed 4 MiB; CEDEAR position dumps can be larger.
const MaxFileBytes = 16 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// CaucionMaxTenorDaysCap — BYMA Reglamento Operativo limit
// for caución bursátil RV-side in days. Entries above flag.
const CaucionMaxTenorDaysCap = 60

// HighConcentrationPct — single-ticker concentration in % of
// total blotter notional. Above flags has_high_concentration.
const HighConcentrationPct = 50

// VenueOpenHourART — BYMA RV concertación window opens
// 11:00 ART (UTC-3). Anything before flags after-hours.
const VenueOpenHourART = 11

// VenueCloseHourART — BYMA RV window closes 17:00 ART.
const VenueCloseHourART = 17

// ArtifactKind pinned to host_arg_byma.artifact_kind.
type ArtifactKind string

const (
	KindEdgeConfig      ArtifactKind = "byma-edge-config"
	KindAriesConfig     ArtifactKind = "byma-aries-config"
	KindSXConfig        ArtifactKind = "byma-sx-config"
	KindConnectAPI      ArtifactKind = "byma-connect-api"
	KindRVBlotter       ArtifactKind = "byma-rv-blotter"
	KindCEDEARPos       ArtifactKind = "byma-cedear-pos"
	KindBCV             ArtifactKind = "byma-bcv"
	KindLiquidacionT2   ArtifactKind = "byma-liquidacion-t2"
	KindCaucionRV       ArtifactKind = "byma-caucion-rv"
	KindMarketDataCache ArtifactKind = "byma-market-data-cache"
	KindInstaller       ArtifactKind = "byma-installer"
	KindOther           ArtifactKind = "other"
	KindUnknown         ArtifactKind = "unknown"
)

// Terminal pinned to host_arg_byma.terminal.
type Terminal string

const (
	TerminalEdge       Terminal = "edge"
	TerminalAries      Terminal = "aries"
	TerminalSXBursatil Terminal = "sx-bursatil"
	TerminalConnectAPI Terminal = "connect-api"
	TerminalBackOffice Terminal = "back-office"
	TerminalOther      Terminal = "other"
	TerminalUnknown    Terminal = "unknown"
)

// Row mirrors host_arg_byma column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	Terminal                 Terminal     `json:"terminal"`
	BrokerMatricula          string       `json:"broker_matricula,omitempty"`
	OperatorCuitPrefix       string       `json:"operator_cuit_prefix,omitempty"`
	OperatorCuitSuffix4      string       `json:"operator_cuit_suffix4,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	APIKeyHash               string       `json:"api_key_hash,omitempty"`
	SessionFirstSeen         string       `json:"session_first_seen,omitempty"`
	SessionLastSeen          string       `json:"session_last_seen,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	TradeCount               int64        `json:"trade_count,omitempty"`
	CEDEARTickerCount        int64        `json:"cedear_ticker_count,omitempty"`
	SovereignTickerCount     int64        `json:"sovereign_ticker_count,omitempty"`
	DistinctTickerCount      int64        `json:"distinct_ticker_count,omitempty"`
	MaxPositionARSCents      int64        `json:"max_position_ars_cents,omitempty"`
	TotalPositionARSCents    int64        `json:"total_position_ars_cents,omitempty"`
	MaxPositionPct           int          `json:"max_position_pct,omitempty"`
	CaucionMaxTenorDays      int          `json:"caucion_max_tenor_days,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasAPIKeyInConfig        bool         `json:"has_api_key_in_config"`
	HasCEDEARPosition        bool         `json:"has_cedear_position"`
	HasMEPCCLArbitrage       bool         `json:"has_mep_ccl_arbitrage"`
	HasCaucionLongTenor      bool         `json:"has_caucion_long_tenor"`
	HasHighConcentration     bool         `json:"has_high_concentration"`
	HasConcertacion          bool         `json:"has_concertacion"`
	IsAfterHours             bool         `json:"is_after_hours"`
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

// HashSecret returns the SHA-256 hex of a credential fragment.
// Used to retain a detection signal without persisting the
// raw key.
func HashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated BYMA install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\BYMA`,
		`C:\BYMA\Edge`,
		`C:\BYMA\Aries`,
		`C:\BYMA\SX`,
		`C:\BYMA\Connect`,
		`C:\BYMA\BackOffice`,
		`C:\Program Files\BYMA`,
		`C:\Program Files (x86)\BYMA`,
		`/opt/byma`,
		`/opt/byma-edge`,
		`/opt/byma-connect`,
		`/srv/byma`,
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

// UserBYMADirs is the curated per-user relative path set.
func UserBYMADirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "BYMA"},
		{"AppData", "Roaming", "BYMA", "Edge"},
		{"AppData", "Roaming", "BYMA", "Aries"},
		{"AppData", "Roaming", "BYMA", "SX"},
		{"AppData", "Roaming", "BYMA", "Connect"},
		{"AppData", "Local", "BYMA"},
		{"Documents", "BYMA"},
		{"Documents", "Trading", "BYMA"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// BYMA artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".ini", ".cfg", ".conf",
		".json", ".yaml", ".yml",
		".xml", ".csv", ".tsv",
		".dat", ".log",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the BYMA catalogue (after passing extension gate).
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"byma", "edge", "aries", "sx_bursatil", "sx-bursatil",
		"sxbursatil", "connect",
		"rv_blotter", "rv-blotter", "blotter_rv",
		"cedear", "cedears",
		"bcv_", "bcv-", "boleto_compra", "boleto-compra",
		"liquidacion_t2", "liquidacion-t2", "t2_liquidacion",
		"caucion_rv", "caucion-rv", "rv_caucion",
		"_byma.", "-byma.",
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
		if strings.Contains(n, "byma") || strings.Contains(n, "edge") ||
			strings.Contains(n, "aries") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "connect") &&
		(ext == ".json" || ext == ".yaml" || ext == ".yml" ||
			strings.Contains(n, "api")):
		return KindConnectAPI
	case strings.Contains(n, "edge") &&
		(ext == ".ini" || ext == ".cfg" || ext == ".conf" ||
			ext == ".json"):
		return KindEdgeConfig
	case strings.Contains(n, "aries") &&
		(ext == ".ini" || ext == ".cfg" || ext == ".conf" ||
			ext == ".json"):
		return KindAriesConfig
	case (strings.Contains(n, "sx_bursatil") ||
		strings.Contains(n, "sx-bursatil") ||
		strings.Contains(n, "sxbursatil")) &&
		(ext == ".ini" || ext == ".cfg" || ext == ".conf" ||
			ext == ".json"):
		return KindSXConfig
	case strings.Contains(n, "rv_blotter") ||
		strings.Contains(n, "rv-blotter") ||
		strings.Contains(n, "blotter_rv") ||
		strings.Contains(n, "blotter-rv") ||
		(strings.Contains(n, "blotter") &&
			strings.Contains(n, "byma")):
		return KindRVBlotter
	case strings.Contains(n, "cedear") || strings.Contains(n, "cedears"):
		return KindCEDEARPos
	case strings.Contains(n, "bcv_") ||
		strings.Contains(n, "bcv-") ||
		strings.Contains(n, "boleto_compra") ||
		strings.Contains(n, "boleto-compra"):
		return KindBCV
	case strings.Contains(n, "liquidacion_t2") ||
		strings.Contains(n, "liquidacion-t2") ||
		strings.Contains(n, "t2_liquidacion") ||
		strings.Contains(n, "_t2_") ||
		strings.HasPrefix(n, "t2_"):
		return KindLiquidacionT2
	case strings.Contains(n, "caucion_rv") ||
		strings.Contains(n, "caucion-rv") ||
		strings.Contains(n, "rv_caucion") ||
		strings.Contains(n, "rv-caucion") ||
		strings.Contains(n, "caucion"):
		return KindCaucionRV
	case ext == ".dat" && strings.Contains(n, "byma"):
		return KindMarketDataCache
	}
	return KindOther
}

// TerminalFromPath classifies the terminal from path tokens.
//
// On Linux CI, Windows-style paths still need to classify
// correctly, so we normalize backslashes to forward-slashes
// before token matching.
func TerminalFromPath(path string) Terminal {
	if path == "" {
		return TerminalUnknown
	}
	lower := strings.ToLower(
		strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	switch {
	case strings.Contains(lower, "/edge/") ||
		strings.Contains(lower, "byma_edge") ||
		strings.Contains(lower, "byma-edge"):
		return TerminalEdge
	case strings.Contains(lower, "/aries/") ||
		strings.Contains(lower, "byma_aries") ||
		strings.Contains(lower, "byma-aries"):
		return TerminalAries
	case strings.Contains(lower, "/sx/") ||
		strings.Contains(lower, "sx_bursatil") ||
		strings.Contains(lower, "sx-bursatil") ||
		strings.Contains(lower, "sxbursatil"):
		return TerminalSXBursatil
	case strings.Contains(lower, "/connect/") ||
		strings.Contains(lower, "byma_connect") ||
		strings.Contains(lower, "byma-connect") ||
		strings.Contains(lower, "connect_api") ||
		strings.Contains(lower, "connect-api"):
		return TerminalConnectAPI
	case strings.Contains(lower, "/backoffice/") ||
		strings.Contains(lower, "back-office") ||
		strings.Contains(lower, "back_office") ||
		strings.Contains(lower, "/liquidacion/"):
		return TerminalBackOffice
	case strings.Contains(lower, "/byma/") ||
		strings.Contains(lower, "byma_") ||
		strings.Contains(lower, "_byma"):
		return TerminalOther
	}
	return TerminalUnknown
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

// IsOperatorCuitPrefix reports whether the prefix is a human-
// operator class (20/23/24/27).
func IsOperatorCuitPrefix(p string) bool {
	switch p {
	case "20", "23", "24", "27":
		return true
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

// matriculaRE matches BYMA broker matrícula in text.
var matriculaRE = regexp.MustCompile(`(?i)(?:matr[íi]cula|alyc[_-]matricula|broker[_-]matricula|matricula_byma)[\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// MatriculaFromText extracts BYMA broker matrícula.
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

// CEDEARTickers returns the curated set of CEDEAR tickers
// traded on BYMA (foreign-equity receipts in ARS). Used to
// distinguish CEDEAR positions from local-equity positions.
func CEDEARTickers() []string {
	return []string{
		"AAPL", "MSFT", "GOOGL", "GOOG", "AMZN", "META",
		"NVDA", "TSLA", "NFLX", "BABA", "JPM", "BAC",
		"WMT", "DIS", "KO", "PEP", "JNJ", "PG",
		"V", "MA", "INTC", "AMD", "ORCL", "CRM",
		"XOM", "CVX", "BA", "GE", "MELI", "GLOB",
	}
}

// LocalEquityTickers returns Argentine listed equities.
func LocalEquityTickers() []string {
	return []string{
		"GGAL", "YPFD", "PAMP", "ALUA", "COME",
		"TXAR", "TGSU2", "TGNO4", "EDN", "TS",
		"CRES", "CEPU", "MIRG", "TRAN", "BMA",
		"BBAR", "SUPV", "VALO", "BHIP",
	}
}

// SovereignTickers returns AR sovereign-bond tickers.
// AL30/AL35/GD30/GD35 are MEP/CCL-eligible (paired with
// their D/C suffixed counterparts).
func SovereignTickers() []string {
	return []string{
		"AL30", "AL30D", "AL30C",
		"AL35", "AL35D", "AL35C",
		"AL41", "AL41D", "AL41C",
		"GD30", "GD30D", "GD30C",
		"GD35", "GD35D", "GD35C",
		"GD38", "GD38D", "GD38C",
		"GD41", "GD41D", "GD41C",
		"GD46", "GD46D", "GD46C",
	}
}

// IsCEDEARTicker reports membership.
func IsCEDEARTicker(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	for _, v := range CEDEARTickers() {
		if v == t {
			return true
		}
	}
	return false
}

// IsSovereignTicker reports membership.
func IsSovereignTicker(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	for _, v := range SovereignTickers() {
		if v == t {
			return true
		}
	}
	return false
}

// IsMEPCCLPair reports whether the (a, b) tickers are an
// MEP/CCL arbitrage pair (e.g. AL30 + AL30D / GD30 + GD30C).
//
// MEP = bond bought in ARS, sold in USD-MEP (D suffix).
// CCL = bond bought in ARS, sold in USD-CCL (C suffix).
// The arbitrage pattern is buying the ARS-denominated ticker
// and selling its D or C counterpart in the same session.
func IsMEPCCLPair(a, b string) bool {
	a = strings.ToUpper(strings.TrimSpace(a))
	b = strings.ToUpper(strings.TrimSpace(b))
	if a == "" || b == "" || a == b {
		return false
	}
	stem := func(t string) string {
		switch {
		case strings.HasSuffix(t, "D") && len(t) > 1:
			return t[:len(t)-1]
		case strings.HasSuffix(t, "C") && len(t) > 1:
			return t[:len(t)-1]
		}
		return t
	}
	suffix := func(t string) byte {
		if t == "" {
			return 0
		}
		last := t[len(t)-1]
		if last == 'D' || last == 'C' {
			return last
		}
		return 0
	}
	if !IsSovereignTicker(a) || !IsSovereignTicker(b) {
		return false
	}
	stemA, stemB := stem(a), stem(b)
	if stemA != stemB {
		return false
	}
	sufA, sufB := suffix(a), suffix(b)
	// One must carry no suffix (ARS-denominated) AND the other
	// must carry D or C (USD-denominated).
	return (sufA == 0 && (sufB == 'D' || sufB == 'C')) ||
		(sufB == 0 && (sufA == 'D' || sufA == 'C'))
}

// IsAfterHoursStamp parses a "HH:MM" or "HH:MM:SS" token
// and reports whether it falls outside the BYMA-RV venue
// window [VenueOpenHourART, VenueCloseHourART).
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

// IsBlotterArtifactKind reports whether the kind carries
// trade-blotter / position data.
func IsBlotterArtifactKind(k ArtifactKind) bool {
	switch k {
	case KindRVBlotter, KindCEDEARPos, KindBCV,
		KindLiquidacionT2, KindCaucionRV:
		return true
	case KindEdgeConfig, KindAriesConfig, KindSXConfig,
		KindConnectAPI, KindMarketDataCache, KindInstaller,
		KindOther, KindUnknown:
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
	if r.CEDEARTickerCount > 0 {
		r.HasCEDEARPosition = true
	}
	if r.CaucionMaxTenorDays > CaucionMaxTenorDaysCap {
		r.HasCaucionLongTenor = true
	}
	if r.MaxPositionPct >= HighConcentrationPct {
		r.HasHighConcentration = true
	}
	if r.TradeCount > 0 {
		r.HasConcertacion = true
	}
	if r.SessionFirstSeen != "" && IsAfterHoursStamp(r.SessionFirstSeen) {
		r.IsAfterHours = true
	}
	if !r.IsAfterHours && r.SessionLastSeen != "" &&
		IsAfterHoursStamp(r.SessionLastSeen) {
		r.IsAfterHours = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	bodySignal := r.HasAPIKeyInConfig || r.TradeCount > 0 ||
		r.MaxPositionARSCents > 0
	if readable && r.HasClienteCuit && bodySignal {
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
