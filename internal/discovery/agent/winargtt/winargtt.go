// Package winargtt audits Trading Technologies (TT) Desktop /
// FIX-adapter / ADL / Algo SE / Aurora / Score / TTAS artifact
// files cached on Argentine pro futures, prop-desk, HFT, and
// institutional-quant workstations across Windows, Linux, and
// macOS.
//
// Trading Technologies (TT) is the direct competitor to CQG
// (iter 167). Argentine pro futures traders use either CQG or
// TT depending on broker preference. Both connect to CME group
// + MATba-Rofex (via TTAS — TT Access Service).
//
// TT distinctive surfaces:
//
//   - TT Desktop / Web      HTML5 terminal.
//   - TT Mobile             mobile execution.
//   - TT FIX adapter        FIX 4.4 institutional gateway.
//   - TT ADL                Algo Development Language (visual).
//   - TT Algo SE            Strategy Engine (server-side).
//   - TT Aurora             HFT-grade execution.
//   - TT Score              algo monitoring + audit.
//   - TTAS                  TT Access Service (broker connect).
//   - TT REST API           Python / Java SDK.
//
// **The TT pro futures platform layer.** Distinct from:
//
//   - iter 167 winargcqg          — CQG (competitor, same tier).
//   - iter 109 winargmatbarofex   — MATba-Rofex positions.
//   - iter 139 winargprimary      — Primary REST/WS API.
//   - iter 143 winargmt           — MetaTrader (FX retail).
//   - iter 148 winargninjatrader  — NinjaTrader (futures retail).
//   - iter 160 winarglean         — LEAN (backtest framework).
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — config cleartext.
//   - `has_api_credentials=1` — TT API key leak.
//   - `has_tt_fix_session=1` — FIX 4.4 institutional.
//   - `has_matba_rofex_routing=1` — TTAS AR routing.
//   - `has_cme_futures=1` — CME group products.
//   - `has_adl_visual_algo=1` — TT ADL visual strategy.
//   - `has_algo_se_strategy=1` — TT Algo SE script.
//   - `has_aurora_hft=1` — TT Aurora HFT execution.
//   - `has_score_audit=1` — TT Score algo monitoring.
//   - `has_cross_venue_arb=1` — MATba-Rofex AND CME both.
//   - `has_high_message_rate=1` — > 1000 msg/s HFT pattern.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR api OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargtt

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

// HighMessageRateThreshold is the per-second msg threshold for
// HFT-pattern flag.
const HighMessageRateThreshold = 1000

// ArtifactKind pinned to host_arg_tt.artifact_kind.
type ArtifactKind string

const (
	KindConfig           ArtifactKind = "tt-config"
	KindCredentials      ArtifactKind = "tt-credentials"
	KindDesktopConfig    ArtifactKind = "tt-desktop-config"
	KindFIXAdapterConfig ArtifactKind = "tt-fix-adapter-config"
	KindADLStrategy      ArtifactKind = "tt-adl-strategy"
	KindAlgoSEStrategy   ArtifactKind = "tt-algo-se-strategy"
	KindAuroraConfig     ArtifactKind = "tt-aurora-config"
	KindScoreReport      ArtifactKind = "tt-score-report"
	KindAPIScript        ArtifactKind = "tt-api-script"
	KindSessionLog       ArtifactKind = "tt-session-log"
	KindInstaller        ArtifactKind = "tt-installer"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_tt.account_class.
type AccountClass string

const (
	AccountProFutures    AccountClass = "pro-futures"
	AccountPropTrader    AccountClass = "prop-trader"
	AccountArbitrageur   AccountClass = "arbitrageur"
	AccountInstitutional AccountClass = "institutional"
	AccountAPI           AccountClass = "api"
	AccountHFT           AccountClass = "hft"
	AccountDemo          AccountClass = "demo"
	AccountOther         AccountClass = "other"
	AccountUnknown       AccountClass = "unknown"
)

// ProductClass pinned to host_arg_tt.product_class.
type ProductClass string

const (
	ProductCMEFutures    ProductClass = "cme-futures"
	ProductMATbaRofex    ProductClass = "matba-rofex"
	ProductGlobalFutures ProductClass = "global-futures"
	ProductMultiVenue    ProductClass = "multi-venue"
	ProductOptions       ProductClass = "options"
	ProductHFTExecution  ProductClass = "hft-execution"
	ProductOther         ProductClass = "other"
	ProductUnknown       ProductClass = "unknown"
)

// Row mirrors host_arg_tt column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AccountClass             AccountClass `json:"account_class"`
	ProductClass             ProductClass `json:"product_class"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	TTAccountID              string       `json:"tt_account_id,omitempty"`
	FIXSenderCompID          string       `json:"fix_sender_compid,omitempty"`
	FIXTargetCompID          string       `json:"fix_target_compid,omitempty"`
	APIKeyHash               string       `json:"api_key_hash,omitempty"`
	UsernameHash             string       `json:"username_hash,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount     int64        `json:"distinct_symbols_count,omitempty"`
	MATbaSymbolsCount        int64        `json:"matba_symbols_count,omitempty"`
	CMESymbolsCount          int64        `json:"cme_symbols_count,omitempty"`
	PeakMsgPerSec            int64        `json:"peak_msg_per_sec,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasAPICredentials        bool         `json:"has_api_credentials"`
	HasTTFIXSession          bool         `json:"has_tt_fix_session"`
	HasMATbaRofexRouting     bool         `json:"has_matba_rofex_routing"`
	HasCMEFutures            bool         `json:"has_cme_futures"`
	HasADLVisualAlgo         bool         `json:"has_adl_visual_algo"`
	HasAlgoSEStrategy        bool         `json:"has_algo_se_strategy"`
	HasAuroraHFT             bool         `json:"has_aurora_hft"`
	HasScoreAudit            bool         `json:"has_score_audit"`
	HasCrossVenueArb         bool         `json:"has_cross_venue_arb"`
	HasHighMessageRate       bool         `json:"has_high_message_rate"`
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

// HashSecret returns the SHA-256 hex of a normalized secret.
func HashSecret(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated TT install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\TradingTechnologies`,
		`C:\TT`,
		`C:\TT\Desktop`,
		`C:\TT\Aurora`,
		`C:\TT\ADL`,
		`C:\TT\AlgoSE`,
		`C:\TT\Score`,
		`C:\TT\FIX`,
		`C:\Program Files\TradingTechnologies`,
		`C:\Program Files (x86)\TradingTechnologies`,
		`/opt/tt`,
		`/opt/tradingtechnologies`,
		`/Applications/TT Desktop.app`,
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

// UserTTDirs is the curated per-user relative path set.
func UserTTDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "TT"},
		{"AppData", "Local", "TT"},
		{"AppData", "Roaming", "TradingTechnologies"},
		{"AppData", "Local", "TradingTechnologies"},
		{"Documents", "TT"},
		{".tt"},
		{".tt-api"},
		{"projects", "tt"},
		{"projects", "futures"},
		{"Library", "Application Support", "TT"},
		{"Descargas"},
		{"Downloads"},
	}
}

// MATbaRofexSymbols mirrors CQG (iter 167) classifier — same
// MATba-Rofex stems are accessible via TTAS.
func MATbaRofexSymbols() []string {
	return []string{
		"DLR", "DOM", "ROS-DLR", "MTR-USD", "MTRUSD",
		"SOJ", "MAI", "TRI", "GIR", "SOR",
		"ROS20", "ROS-SOJ", "ROS-MAI", "ROS-TRI",
		"CER", "UVA", "CER-FUT", "UVA-FUT",
		"MERV", "MERVAL",
	}
}

// CMEFuturesSymbols mirrors CQG classifier.
func CMEFuturesSymbols() []string {
	return []string{
		"ES", "NQ", "YM", "RTY", "EMD",
		"6E", "6B", "6J", "6A", "6C", "6S", "6N", "6M",
		"DXY", "EUR/USD", "GBP/USD", "USD/JPY",
		"CL", "NG", "HO", "RB", "BZ",
		"GC", "SI", "HG", "PL", "PA",
		"ZC", "ZS", "ZW", "ZL", "ZM", "ZR",
		"ZN", "ZB", "ZF", "ZT", "UB",
		"BTC", "MBT", "ETH", "MET",
	}
}

// IsMATbaRofexSymbol reports membership.
func IsMATbaRofexSymbol(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range MATbaRofexSymbols() {
		if v == t || strings.HasPrefix(t, v) {
			return true
		}
	}
	return false
}

// IsCMEFuturesSymbol reports membership.
func IsCMEFuturesSymbol(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range CMEFuturesSymbols() {
		if v == t || strings.HasPrefix(t, v) {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries a
// TT artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json", ".ini", ".cfg", ".conf",
		".yaml", ".yml",
		".csv", ".tsv", ".log", ".txt",
		".fix", ".adl", ".tt", ".score",
		".py", ".ipynb",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the TT catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if ext == ".adl" || ext == ".tt" || ext == ".score" {
		return true
	}
	for _, tok := range []string{
		"tradingtechnologies", "trading_technologies",
		"trading-technologies",
		"tt_", "tt-", "tt.",
		"ttas",
		"aurora", "algose", "algo_se", "algo-se",
		"fix_adapter", "fix-adapter",
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
		if strings.Contains(n, "tradingtechnologies") ||
			strings.Contains(n, "trading_technologies") ||
			strings.Contains(n, "trading-technologies") ||
			strings.Contains(n, "tt_desktop") ||
			strings.Contains(n, "tt-desktop") {
			return KindInstaller
		}
		return KindOther
	case ".adl":
		return KindADLStrategy
	case ".tt":
		return KindAlgoSEStrategy
	case ".score":
		return KindScoreReport
	case ".py", ".ipynb":
		if strings.Contains(n, "tt_api") || strings.Contains(n, "tt-api") ||
			strings.Contains(n, "tt_rest") || strings.Contains(n, "tt-rest") {
			return KindAPIScript
		}
		return KindOther
	case ".log", ".txt":
		if strings.Contains(n, "tt") || strings.Contains(n, "ttas") {
			return KindSessionLog
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "tt_score") || strings.Contains(n, "tt-score") ||
		strings.Contains(n, "score_report"):
		return KindScoreReport
	case strings.Contains(n, "tt_aurora") || strings.Contains(n, "tt-aurora") ||
		strings.Contains(n, "aurora"):
		return KindAuroraConfig
	case strings.Contains(n, "tt_algose") || strings.Contains(n, "tt-algose") ||
		strings.Contains(n, "tt_algo_se") || strings.Contains(n, "tt-algo-se") ||
		strings.Contains(n, "algose"):
		return KindAlgoSEStrategy
	case strings.Contains(n, "tt_adl") || strings.Contains(n, "tt-adl") ||
		strings.Contains(n, "adl_strategy"):
		return KindADLStrategy
	case strings.Contains(n, "tt_fix") || strings.Contains(n, "tt-fix") ||
		strings.Contains(n, "fix_adapter") || strings.Contains(n, "fix-adapter"):
		return KindFIXAdapterConfig
	case strings.Contains(n, "tt_desktop") || strings.Contains(n, "tt-desktop") ||
		strings.Contains(n, "tt_workspace"):
		return KindDesktopConfig
	case strings.Contains(n, "tt_api") || strings.Contains(n, "tt-api") ||
		strings.Contains(n, "tt_rest"):
		return KindAPIScript
	case strings.Contains(n, "tt") &&
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
	case KindConfig, KindCredentials, KindDesktopConfig,
		KindFIXAdapterConfig, KindADLStrategy, KindAlgoSEStrategy,
		KindAuroraConfig, KindScoreReport, KindAPIScript,
		KindSessionLog:
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
	if r.MATbaSymbolsCount > 0 {
		r.HasMATbaRofexRouting = true
	}
	if r.CMESymbolsCount > 0 {
		r.HasCMEFutures = true
	}
	if r.MATbaSymbolsCount > 0 && r.CMESymbolsCount > 0 {
		r.HasCrossVenueArb = true
	}
	if r.ArtifactKind == KindADLStrategy {
		r.HasADLVisualAlgo = true
	}
	if r.ArtifactKind == KindAlgoSEStrategy {
		r.HasAlgoSEStrategy = true
	}
	if r.ArtifactKind == KindAuroraConfig {
		r.HasAuroraHFT = true
	}
	if r.ArtifactKind == KindScoreReport {
		r.HasScoreAudit = true
	}
	if r.PeakMsgPerSec >= HighMessageRateThreshold {
		r.HasHighMessageRate = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasAPICredentials || r.HasClienteCuit
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
