// Package winargcrypto audits Argentine crypto-PSAV
// (Proveedor de Servicios de Activos Virtuales) exchange
// files cached on retail trader, prop-desk, and OTC-broker
// workstations across Windows, Linux, and macOS.
//
// The CNV created the PSAV registry under Resol. 994/2024;
// UIF Resol. 49/2024 mandates KYC + ROS for virtual-asset
// operations. AFIP RG 5527/2024 obliges PSAVs to report
// operator-level activity. Argentine-registered PSAVs:
//
//	Bitso, Lemon, Belo, Ripio, Buenbit, Decrypto,
//	Satoshitango, Fiwind, Cryptomarket, Vibrant, Letsbit
//
// Plus offshore exchanges Argentine traders use (subject to
// AFIP Bienes Personales self-report): Binance, Kraken, OKX,
// Bybit, Coinbase, KuCoin.
//
// **The crypto-PSAV layer.** Distinct from:
//
//   - iter 108 winalgotrading   — generic algotrading
//   - iter 109 winargmatbarofex — futures positions
//   - iter 138 winarguifros     — UIF/AML compliance
//   - iter 139 winargprimary    — Primary REST/WS API
//
// Headline finding shapes:
//
//   - `has_api_key=1` — api_key/api_secret in cleartext.
//   - `has_wallet_seed_marker=1` — BIP39 / mnemonic marker
//     detected (presence-only — never extract).
//   - `has_otc_p2p_activity=1` — OTC P2P trade log.
//   - `has_high_volume_stablecoin=1` — USDT/USDC pair vol
//     > 10 M ARS (Com. A 7916 + AFIP RG 5193 scrutiny).
//   - `has_afip_unreported=1` — large vol without AFIP
//     marker in workstation cache.
//   - `is_credential_exposure_risk=1` — readable file +
//     (api-key OR seed OR P2P body).
//
// Wallet seeds detected via BIP39 wordlist density check
// only — the raw phrase is NEVER captured. Read-only by
// intent. (Project guideline 4.2.)
package winargcrypto

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

// MaxFileBytes bounds per-file read. Account exports can be
// large; cap at 32 MiB.
const MaxFileBytes = 32 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// HighVolumeStablecoinARSCents — 10 M ARS = 1 G cents.
// Above this stablecoin volume, the file warrants Com. A
// 7916 + AFIP RG 5193 scrutiny.
const HighVolumeStablecoinARSCents int64 = 1_000_000_000

// AfipUnreportedThresholdCents — 5 M ARS = 500 M cents.
// Above this volume without an AFIP-marker in the cache,
// the trader is likely under-reporting.
const AfipUnreportedThresholdCents int64 = 500_000_000

// ArtifactKind pinned to host_arg_crypto_psav.artifact_kind.
type ArtifactKind string

const (
	KindAPIKey         ArtifactKind = "crypto-api-key"
	KindAccountExport  ArtifactKind = "crypto-account-export"
	KindOTCP2PLog      ArtifactKind = "crypto-otc-p2p-log"
	KindWalletSeed     ArtifactKind = "crypto-wallet-seed"
	KindTaxReport      ArtifactKind = "crypto-tax-report"
	KindStablecoinLog  ArtifactKind = "crypto-stablecoin-trade-log"
	KindStrategyScript ArtifactKind = "crypto-strategy-script"
	KindCCXTCache      ArtifactKind = "crypto-ccxt-cache"
	KindInstaller      ArtifactKind = "crypto-installer"
	KindOther          ArtifactKind = "other"
	KindUnknown        ArtifactKind = "unknown"
)

// Exchange pinned to host_arg_crypto_psav.exchange.
type Exchange string

const (
	ExchangeBitso        Exchange = "bitso"
	ExchangeLemon        Exchange = "lemon"
	ExchangeBelo         Exchange = "belo"
	ExchangeRipio        Exchange = "ripio"
	ExchangeBuenbit      Exchange = "buenbit"
	ExchangeDecrypto     Exchange = "decrypto"
	ExchangeSatoshitango Exchange = "satoshitango"
	ExchangeFiwind       Exchange = "fiwind"
	ExchangeCryptomarket Exchange = "cryptomarket"
	ExchangeVibrant      Exchange = "vibrant"
	ExchangeLetsbit      Exchange = "letsbit"
	ExchangeBinance      Exchange = "binance"
	ExchangeKraken       Exchange = "kraken"
	ExchangeOKX          Exchange = "okx"
	ExchangeBybit        Exchange = "bybit"
	ExchangeCoinbase     Exchange = "coinbase"
	ExchangeKuCoin       Exchange = "kucoin"
	ExchangeOther        Exchange = "other"
	ExchangeUnknown      Exchange = "unknown"
)

// PSAVClass pinned to host_arg_crypto_psav.psav_class.
type PSAVClass string

const (
	PSAVArgRegistered      PSAVClass = "arg-registered-psav"
	PSAVOffshoreSelfReport PSAVClass = "offshore-self-report"
	PSAVWalletNonCustodial PSAVClass = "wallet-non-custodial"
	PSAVOther              PSAVClass = "other"
	PSAVUnknown            PSAVClass = "unknown"
)

// Row mirrors host_arg_crypto_psav column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	Exchange                 Exchange     `json:"exchange"`
	PSAVClass                PSAVClass    `json:"psav_class"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	APIKeyHash               string       `json:"api_key_hash,omitempty"`
	SessionFirstSeen         string       `json:"session_first_seen,omitempty"`
	SessionLastSeen          string       `json:"session_last_seen,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	TradeCount               int64        `json:"trade_count,omitempty"`
	OTCP2PCount              int64        `json:"otc_p2p_count,omitempty"`
	StablecoinVolumeARSCents int64        `json:"stablecoin_volume_ars_cents,omitempty"`
	MaxTradeARSCents         int64        `json:"max_trade_ars_cents,omitempty"`
	DistinctPairCount        int64        `json:"distinct_pair_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasAPIKey                bool         `json:"has_api_key"`
	HasAPISecret             bool         `json:"has_api_secret"`
	HasWalletSeedMarker      bool         `json:"has_wallet_seed_marker"`
	HasOTCP2PActivity        bool         `json:"has_otc_p2p_activity"`
	HasStablecoinVolume      bool         `json:"has_stablecoin_volume"`
	HasHighVolumeStablecoin  bool         `json:"has_high_volume_stablecoin"`
	HasStrategyScript        bool         `json:"has_strategy_script"`
	HasAfipUnreported        bool         `json:"has_afip_unreported"`
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
func HashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated crypto install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Crypto`,
		`C:\Bitso`,
		`C:\Lemon`,
		`C:\Ripio`,
		`C:\Binance`,
		`C:\Program Files\Crypto`,
		`/opt/crypto`,
		`/opt/ccxt`,
		`/srv/crypto`,
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

// UserCryptoDirs is the curated per-user relative path set.
func UserCryptoDirs() [][]string {
	return [][]string{
		{".bitso"},
		{".lemon"},
		{".belo"},
		{".ripio"},
		{".buenbit"},
		{".binance"},
		{".kraken"},
		{".config", "bitso"},
		{".config", "lemon"},
		{".config", "binance"},
		{".config", "ccxt"},
		{".ccxt"},
		{"AppData", "Roaming", "Crypto"},
		{"AppData", "Roaming", "Bitso"},
		{"AppData", "Roaming", "Lemon"},
		{"AppData", "Roaming", "Ripio"},
		{"AppData", "Roaming", "Binance"},
		{"Documents", "Crypto"},
		{"Documents", "Bitso"},
		{"Documents", "Trading", "Crypto"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// crypto-PSAV artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json", ".toml", ".ini", ".cfg", ".conf",
		".yaml", ".yml",
		".csv", ".tsv", ".xlsx",
		".log", ".txt",
		".py", ".ipynb",
		".msi", ".exe":
		return true
	}
	if ext == "" {
		base := strings.ToLower(filepath.Base(name))
		switch base {
		case "credentials", "api_key", "api_secret",
			"wallet_seed", "mnemonic", "seed_phrase":
			return true
		}
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the crypto-PSAV catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch n {
	case "credentials", "api_key", "api_secret",
		"wallet_seed", "mnemonic", "seed_phrase":
		return true
	}
	if ext == ".py" || ext == ".ipynb" {
		return strings.Contains(n, "ccxt") ||
			strings.Contains(n, "binance") ||
			strings.Contains(n, "bitso") ||
			strings.Contains(n, "crypto") ||
			strings.Contains(n, "exchange")
	}
	for _, tok := range []string{
		"bitso", "lemon", "belo", "ripio", "buenbit", "decrypto",
		"satoshitango", "fiwind", "cryptomarket", "vibrant",
		"letsbit", "binance", "kraken", "okx", "bybit",
		"coinbase", "kucoin",
		"ccxt", "crypto",
		"otc_p2p", "otc-p2p", "p2p_trade",
		"usdt_pair", "usdc_pair", "stablecoin",
		"bienes_personales", "bienes-personales",
		"wallet", "seed", "mnemonic",
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
	switch n {
	case "wallet_seed", "mnemonic", "seed_phrase":
		return KindWalletSeed
	case "credentials", "api_key", "api_secret":
		return KindAPIKey
	}
	switch ext {
	case ".msi", ".exe":
		if strings.Contains(n, "bitso") || strings.Contains(n, "lemon") ||
			strings.Contains(n, "binance") || strings.Contains(n, "crypto") {
			return KindInstaller
		}
		return KindOther
	case ".py", ".ipynb":
		return KindStrategyScript
	}
	switch {
	case strings.Contains(n, "wallet") &&
		(strings.Contains(n, "seed") || strings.Contains(n, "mnemonic") ||
			strings.Contains(n, "phrase")):
		return KindWalletSeed
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_key") || strings.Contains(n, "api-key"):
		return KindAPIKey
	case strings.Contains(n, "otc_p2p") || strings.Contains(n, "otc-p2p") ||
		strings.Contains(n, "p2p_trade") || strings.Contains(n, "p2p-trade"):
		return KindOTCP2PLog
	case strings.Contains(n, "usdt_pair") || strings.Contains(n, "usdt-pair") ||
		strings.Contains(n, "usdc_pair") || strings.Contains(n, "usdc-pair") ||
		strings.Contains(n, "stablecoin"):
		return KindStablecoinLog
	case strings.Contains(n, "bienes_personales") ||
		strings.Contains(n, "bienes-personales") ||
		strings.Contains(n, "afip_cripto"):
		return KindTaxReport
	case strings.Contains(n, "ccxt") &&
		(ext == ".json" || ext == ".yaml" || ext == ".yml"):
		return KindCCXTCache
	case strings.Contains(n, "export") &&
		(ext == ".csv" || ext == ".tsv" || ext == ".xlsx"):
		return KindAccountExport
	case ext == ".csv" || ext == ".tsv" || ext == ".xlsx":
		return KindAccountExport
	}
	return KindOther
}

// ExchangeFromPath classifies the exchange from path tokens.
//
// On Linux CI, Windows-style paths still need to classify
// correctly, so we normalize backslashes to forward-slashes
// before token matching.
func ExchangeFromPath(path string) Exchange {
	if path == "" {
		return ExchangeUnknown
	}
	lower := strings.ToLower(
		strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	// Order matters — more-specific names first to avoid false
	// substring matches.
	type entry struct {
		token  string
		result Exchange
	}
	for _, e := range []entry{
		{"satoshitango", ExchangeSatoshitango},
		{"cryptomarket", ExchangeCryptomarket},
		{"buenbit", ExchangeBuenbit},
		{"decrypto", ExchangeDecrypto},
		{"coinbase", ExchangeCoinbase},
		{"binance", ExchangeBinance},
		{"vibrant", ExchangeVibrant},
		{"letsbit", ExchangeLetsbit},
		{"fiwind", ExchangeFiwind},
		{"kraken", ExchangeKraken},
		{"kucoin", ExchangeKuCoin},
		{"bitso", ExchangeBitso},
		{"lemon", ExchangeLemon},
		{"ripio", ExchangeRipio},
		{"bybit", ExchangeBybit},
		{"belo", ExchangeBelo},
		{"okx", ExchangeOKX},
	} {
		if strings.Contains(lower, e.token) {
			return e.result
		}
	}
	return ExchangeUnknown
}

// PSAVClassFromExchange maps an exchange to its registration
// class.
func PSAVClassFromExchange(e Exchange) PSAVClass {
	switch e {
	case ExchangeBitso, ExchangeLemon, ExchangeBelo,
		ExchangeRipio, ExchangeBuenbit, ExchangeDecrypto,
		ExchangeSatoshitango, ExchangeFiwind, ExchangeCryptomarket,
		ExchangeVibrant, ExchangeLetsbit:
		return PSAVArgRegistered
	case ExchangeBinance, ExchangeKraken, ExchangeOKX,
		ExchangeBybit, ExchangeCoinbase, ExchangeKuCoin:
		return PSAVOffshoreSelfReport
	case ExchangeOther, ExchangeUnknown:
		return PSAVUnknown
	}
	return PSAVUnknown
}

// IsArgRegisteredPSAV reports CNV-PSAV-registry membership.
func IsArgRegisteredPSAV(e Exchange) bool {
	return PSAVClassFromExchange(e) == PSAVArgRegistered
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

// IsStablecoinPair reports whether a ticker token is a
// USDT/USDC/DAI/BUSD stablecoin pair (anchor for dollar
// arbitrage detection).
func IsStablecoinPair(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	for _, stable := range []string{"USDT", "USDC", "DAI", "BUSD"} {
		if strings.Contains(t, stable) {
			return true
		}
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
	if r.StablecoinVolumeARSCents > 0 {
		r.HasStablecoinVolume = true
	}
	if r.StablecoinVolumeARSCents >= HighVolumeStablecoinARSCents {
		r.HasHighVolumeStablecoin = true
	}
	if r.OTCP2PCount > 0 {
		r.HasOTCP2PActivity = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasAPIKey || r.HasAPISecret ||
		r.HasWalletSeedMarker || r.HasOTCP2PActivity
	if readable && credSignal {
		// Crypto credentials are always exposure — no
		// "production-only" gate (the keys ARE the funds).
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
