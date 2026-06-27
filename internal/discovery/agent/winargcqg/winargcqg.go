// Package winargcqg audits CQG (Continuum / IC / QTrader /
// API / FIX-adapter) artifact files cached on Argentine pro
// futures, prop-desk, arbitrageur, and institutional-quant
// workstations across Windows, Linux, and macOS.
//
// CQG is the dominant US-based futures-trading platform with
// direct connectivity to CME group (CME / CBOT / NYMEX /
// COMEX) and many non-US futures venues including MATba-Rofex
// via FIX. Argentine pro futures traders use CQG for direct
// MATba-Rofex execution, CME group access, cross-venue
// arbitrage (MTR-USD ↔ CME DXY), block trades (QTrader), and
// algorithmic execution (Algo SE).
//
// **The pro futures platform layer.** Distinct from:
//
//   - iter 109 winargmatbarofex   — MATba-Rofex positions.
//   - iter 139 winargprimary      — Primary REST/WS API.
//   - iter 143 winargmt           — MetaTrader (FX retail).
//   - iter 148 winargninjatrader  — NinjaTrader (futures retail).
//   - iter 160 winarglean         — LEAN (backtest framework).
//   - iter 165 winargib           — IB (general brokerage).
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — config cleartext.
//   - `has_api_credentials=1` — CQG API key leak.
//   - `has_continuum_fix_session=1` — FIX 4.4 institutional.
//   - `has_matba_rofex_routing=1` — AR futures routing.
//   - `has_cme_futures=1` — CME group products.
//   - `has_block_qtrader=1` — QTrader pre-arranged block.
//   - `has_algo_se_strategy=1` — CQG Algo SE script.
//   - `has_fix_drop_copy=1` — FIX drop-copy session.
//   - `has_cross_venue_arb=1` — MATba-Rofex AND CME both
//     (dual-jurisdiction reporting AFIP RG 5193 + IRS 1042).
//   - `has_high_message_rate=1` — > 1000 msg/s HFT pattern.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR api OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargcqg

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

// ArtifactKind pinned to host_arg_cqg.artifact_kind.
type ArtifactKind string

const (
	KindConfig          ArtifactKind = "cqg-config"
	KindCredentials     ArtifactKind = "cqg-credentials"
	KindICConfig        ArtifactKind = "cqg-ic-config"
	KindQTraderConfig   ArtifactKind = "cqg-qtrader-config"
	KindContinuumConfig ArtifactKind = "cqg-continuum-config"
	KindAlgoSEStrategy  ArtifactKind = "cqg-algo-se-strategy"
	KindAPIScript       ArtifactKind = "cqg-api-script"
	KindSessionLog      ArtifactKind = "cqg-session-log"
	KindPositions       ArtifactKind = "cqg-positions"
	KindOrders          ArtifactKind = "cqg-orders"
	KindFIXLog          ArtifactKind = "cqg-fix-log"
	KindInstaller       ArtifactKind = "cqg-installer"
	KindOther           ArtifactKind = "other"
	KindUnknown         ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_cqg.account_class.
type AccountClass string

const (
	AccountProFutures    AccountClass = "pro-futures"
	AccountPropTrader    AccountClass = "prop-trader"
	AccountArbitrageur   AccountClass = "arbitrageur"
	AccountInstitutional AccountClass = "institutional"
	AccountAPI           AccountClass = "api"
	AccountDemo          AccountClass = "demo"
	AccountOther         AccountClass = "other"
	AccountUnknown       AccountClass = "unknown"
)

// ProductClass pinned to host_arg_cqg.product_class.
type ProductClass string

const (
	ProductCMEFutures    ProductClass = "cme-futures"
	ProductMATbaRofex    ProductClass = "matba-rofex"
	ProductGlobalFutures ProductClass = "global-futures"
	ProductMultiVenue    ProductClass = "multi-venue"
	ProductOptions       ProductClass = "options"
	ProductOther         ProductClass = "other"
	ProductUnknown       ProductClass = "unknown"
)

// Row mirrors host_arg_cqg column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AccountClass             AccountClass `json:"account_class"`
	ProductClass             ProductClass `json:"product_class"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	CQGAccountID             string       `json:"cqg_account_id,omitempty"`
	FIXSenderCompID          string       `json:"fix_sender_compid,omitempty"`
	FIXTargetCompID          string       `json:"fix_target_compid,omitempty"`
	APIKeyHash               string       `json:"api_key_hash,omitempty"`
	UsernameHash             string       `json:"username_hash,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount     int64        `json:"distinct_symbols_count,omitempty"`
	MATbaSymbolsCount        int64        `json:"matba_symbols_count,omitempty"`
	CMESymbolsCount          int64        `json:"cme_symbols_count,omitempty"`
	BlockTradeCount          int64        `json:"block_trade_count,omitempty"`
	PeakMsgPerSec            int64        `json:"peak_msg_per_sec,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasAPICredentials        bool         `json:"has_api_credentials"`
	HasContinuumFIXSession   bool         `json:"has_continuum_fix_session"`
	HasMATbaRofexRouting     bool         `json:"has_matba_rofex_routing"`
	HasCMEFutures            bool         `json:"has_cme_futures"`
	HasBlockQTrader          bool         `json:"has_block_qtrader"`
	HasAlgoSEStrategy        bool         `json:"has_algo_se_strategy"`
	HasFIXDropCopy           bool         `json:"has_fix_drop_copy"`
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

// DefaultInstallRoots is the curated CQG install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\CQG`,
		`C:\CQG\IC`,
		`C:\CQG\QTrader`,
		`C:\CQG\Continuum`,
		`C:\CQG\AlgoSE`,
		`C:\Program Files\CQG`,
		`C:\Program Files (x86)\CQG`,
		`/opt/cqg`,
		`/opt/cqg-api`,
		`/Applications/CQG IC.app`,
		`/Applications/CQG QTrader.app`,
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

// UserCQGDirs is the curated per-user relative path set.
func UserCQGDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "CQG"},
		{"AppData", "Local", "CQG"},
		{"Documents", "CQG"},
		{".cqg"},
		{".cqg-api"},
		{"projects", "cqg"},
		{"projects", "futures"},
		{"Library", "Application Support", "CQG"},
		{"Descargas"},
		{"Downloads"},
	}
}

// MATbaRofexSymbols returns curated MATba-Rofex futures stems.
func MATbaRofexSymbols() []string {
	return []string{
		// Dollar futures
		"DLR", "DOM", "ROS-DLR", "MTR-USD", "MTRUSD",
		// Agro futures
		"SOJ", "MAI", "TRI", "GIR", "SOR",
		"ROS20", "ROS-SOJ", "ROS-MAI", "ROS-TRI",
		// Inflation-linked
		"CER", "UVA", "CER-FUT", "UVA-FUT",
		// MERVAL futures
		"MERV", "MERVAL",
	}
}

// CMEFuturesSymbols returns curated CME group product stems.
func CMEFuturesSymbols() []string {
	return []string{
		// CME equity index
		"ES", "NQ", "YM", "RTY", "EMD",
		// CME FX
		"6E", "6B", "6J", "6A", "6C", "6S", "6N", "6M",
		"DXY", "EUR/USD", "GBP/USD", "USD/JPY",
		// NYMEX energy
		"CL", "NG", "HO", "RB", "BZ",
		// COMEX metals
		"GC", "SI", "HG", "PL", "PA",
		// CBOT grains
		"ZC", "ZS", "ZW", "ZL", "ZM", "ZR",
		// CBOT rates
		"ZN", "ZB", "ZF", "ZT", "UB",
		// Crypto futures (BTC/ETH micro)
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
// CQG artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json", ".ini", ".cfg", ".conf",
		".yaml", ".yml",
		".csv", ".tsv", ".log", ".txt",
		".fix", ".cqg",
		".py", ".ipynb",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the CQG catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if ext == ".cqg" || ext == ".fix" {
		return true
	}
	for _, tok := range []string{
		"cqg", "qtrader", "q_trader", "q-trader",
		"continuum", "algo_se", "algose", "algo-se",
		"cqg_api", "cqg-api",
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
		if strings.Contains(n, "cqg") || strings.Contains(n, "qtrader") {
			return KindInstaller
		}
		return KindOther
	case ".cqg":
		return KindAlgoSEStrategy
	case ".fix":
		return KindFIXLog
	case ".py", ".ipynb":
		if strings.Contains(n, "cqg") {
			return KindAPIScript
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "algo_se") || strings.Contains(n, "algose") ||
		strings.Contains(n, "algo-se"):
		return KindAlgoSEStrategy
	case strings.Contains(n, "qtrader") || strings.Contains(n, "q_trader") ||
		strings.Contains(n, "q-trader"):
		return KindQTraderConfig
	case strings.Contains(n, "continuum"):
		return KindContinuumConfig
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "cqg_api") || strings.Contains(n, "cqg-api"):
		return KindAPIScript
	case strings.Contains(n, "cqg_ic") || strings.Contains(n, "cqg-ic") ||
		(strings.Contains(n, "cqg") && strings.Contains(n, "ic")):
		return KindICConfig
	case strings.Contains(n, "session") &&
		(ext == ".log" || ext == ".txt"):
		return KindSessionLog
	case strings.Contains(n, "fix") &&
		(ext == ".log" || ext == ".txt"):
		return KindFIXLog
	case strings.Contains(n, "positions"):
		return KindPositions
	case strings.Contains(n, "orders") || strings.Contains(n, "ordenes"):
		return KindOrders
	case strings.Contains(n, "cqg") &&
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
	case KindConfig, KindCredentials, KindICConfig,
		KindQTraderConfig, KindContinuumConfig,
		KindAlgoSEStrategy, KindAPIScript,
		KindSessionLog, KindPositions, KindOrders, KindFIXLog:
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
	if r.BlockTradeCount > 0 || r.ArtifactKind == KindQTraderConfig {
		r.HasBlockQTrader = true
	}
	if r.ArtifactKind == KindAlgoSEStrategy {
		r.HasAlgoSEStrategy = true
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
