// Package winarglemoncash audits Lemon Cash artifact files
// cached on Argentine consumer, merchant, developer (SDK
// integrator), and compliance-officer workstations across
// Windows, Linux, and macOS.
//
// Lemon Cash (formerly Lemon) is an AR-headquartered crypto
// wallet + payment app **regulated as a Proveedor de Servicios
// de Pago (PSP)** under BCRA Comunicación "A" 7724. It is a
// key AR retail crypto rail with three distinguishing
// surfaces:
//
//  1. Crypto wallet — BTC, ETH, USDT, USDC, native tokens.
//  2. Lemon Card — Visa crypto-debit card (BCRA Com. A 7916
//     cross-border USD outflow concern + AFIP RG 5527).
//  3. Lemon Earn — yield product (stablecoin yield,
//     regulatorily ambiguous under CNV oversight).
//
// **The AR crypto-wallet PSP layer.** Distinct from:
//
//   - iter 162 winargccxt         — CCXT library (cross-
//     exchange Python SDK).
//   - iter 175 winargmercadopago  — MELI fintech (no crypto).
//   - iter 163 winargppi          — PPI broker (no crypto).
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — .env / cfg cleartext.
//   - `has_oauth_access_token=1` — Lemon OAuth bearer.
//   - `has_oauth_refresh_token=1` — refresh token.
//   - `has_sdk_credentials=1` — Python/JS SDK creds.
//   - `has_kyc_dump=1` — cliente KYC PII.
//   - `has_trade_log=1` — wallet trade log.
//   - `has_earn_positions=1` — Lemon Earn yield dump.
//   - `has_card_transactions=1` — crypto-card spend log.
//   - `has_usdt_ars_arbitrage=1` — brecha arbitrage logic.
//   - `has_high_balance=1` — > USD 10 K crypto.
//   - `has_marketplace_webhook=1` — merchant webhook cfg.
//   - `has_pii_bundle=1` — ≥2 of (DNI, CUIT, name).
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR OAuth token OR KYC dump OR card txns OR USDT/ARS
//     arb OR cliente PII).
//
// Read-only by intent. (Project guideline 4.2.)
package winarglemoncash

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

// HighBalanceUSDCents — USD 10 000 expressed in cents (AFIP RG
// 5527 crypto-reporting trigger).
const HighBalanceUSDCents int64 = 1_000_000

// ArtifactKind pinned to host_arg_lemoncash.artifact_kind.
type ArtifactKind string

const (
	KindConfig            ArtifactKind = "lemon-config"
	KindCredentials       ArtifactKind = "lemon-credentials" //#nosec G101 -- ArtifactKind enum naming the Lemon Cash credentials artifact category, not a credential value
	KindSDKScript         ArtifactKind = "lemon-sdk-script"
	KindTradeLog          ArtifactKind = "lemon-trade-log"
	KindEarnPositions     ArtifactKind = "lemon-earn-positions"
	KindKYCDump           ArtifactKind = "lemon-kyc-dump"
	KindCardTransactions  ArtifactKind = "lemon-card-transactions"
	KindArbitrageScript   ArtifactKind = "lemon-arbitrage-script"
	KindMarketplaceConfig ArtifactKind = "lemon-marketplace-config"
	KindWebhookConfig     ArtifactKind = "lemon-webhook-config"
	KindInstaller         ArtifactKind = "lemon-installer"
	KindOther             ArtifactKind = "other"
	KindUnknown           ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_lemoncash.account_class.
type AccountClass string

const (
	AccountConsumer          AccountClass = "consumer"
	AccountMerchant          AccountClass = "merchant"
	AccountDeveloper         AccountClass = "developer"
	AccountComplianceOfficer AccountClass = "compliance-officer"
	AccountAPI               AccountClass = "api"
	AccountDemo              AccountClass = "demo"
	AccountOther             AccountClass = "other"
	AccountUnknown           AccountClass = "unknown"
)

// ProductClass pinned to host_arg_lemoncash.product_class.
type ProductClass string

const (
	ProductCryptoWallet    ProductClass = "crypto-wallet"
	ProductCryptoCard      ProductClass = "crypto-card"
	ProductStablecoinRails ProductClass = "stablecoin-rails"
	ProductYieldEarn       ProductClass = "yield-earn"
	ProductMarketplace     ProductClass = "marketplace"
	ProductMultiProduct    ProductClass = "multi-product"
	ProductOther           ProductClass = "other"
	ProductUnknown         ProductClass = "unknown"
)

// Row mirrors host_arg_lemoncash column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AccountClass             AccountClass `json:"account_class"`
	ProductClass             ProductClass `json:"product_class"`
	LemonUserID              string       `json:"lemon_user_id,omitempty"`
	LemonAppID               string       `json:"lemon_app_id,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	ClienteDNIHash           string       `json:"cliente_dni_hash,omitempty"`
	AccessTokenHash          string       `json:"access_token_hash,omitempty"`
	RefreshTokenHash         string       `json:"refresh_token_hash,omitempty"`
	WebhookSecretHash        string       `json:"webhook_secret_hash,omitempty"`
	UsernameHash             string       `json:"username_hash,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	DistinctAssetsCount      int64        `json:"distinct_assets_count,omitempty"`
	TradeRecordCount         int64        `json:"trade_record_count,omitempty"`
	CardTxCount              int64        `json:"card_tx_count,omitempty"`
	EarnPositionCount        int64        `json:"earn_position_count,omitempty"`
	CryptoBalanceUSDCents    int64        `json:"crypto_balance_usd_cents,omitempty"`
	PIISignalCount           int64        `json:"pii_signal_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasOAuthAccessToken      bool         `json:"has_oauth_access_token"`
	HasOAuthRefreshToken     bool         `json:"has_oauth_refresh_token"`
	HasSDKCredentials        bool         `json:"has_sdk_credentials"`
	HasKYCDump               bool         `json:"has_kyc_dump"`
	HasTradeLog              bool         `json:"has_trade_log"`
	HasEarnPositions         bool         `json:"has_earn_positions"`
	HasCardTransactions      bool         `json:"has_card_transactions"`
	HasUSDTARSArbitrage      bool         `json:"has_usdt_ars_arbitrage"`
	HasHighBalance           bool         `json:"has_high_balance"`
	HasMarketplaceWebhook    bool         `json:"has_marketplace_webhook"`
	HasClienteDNI            bool         `json:"has_cliente_dni"`
	HasClienteCuit           bool         `json:"has_cliente_cuit"`
	HasPIIBundle             bool         `json:"has_pii_bundle"`
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

// DefaultInstallRoots is the curated Lemon install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Lemon`,
		`C:\LemonCash`,
		`C:\Program Files\Lemon`,
		`C:\Program Files (x86)\Lemon`,
		"/opt/lemon",
		"/opt/lemoncash",
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

// UserLemonDirs is the curated per-user relative path set.
func UserLemonDirs() [][]string {
	return [][]string{
		{".lemon"},
		{".lemoncash"},
		{".config", "lemon"},
		{".config", "lemoncash"},
		{"AppData", "Roaming", "Lemon"},
		{"AppData", "Local", "Lemon"},
		{"Documents", "Lemon"},
		{"Documents", "LemonCash"},
		{"projects", "lemon"},
		{"projects", "lemoncash"},
		{"Library", "Application Support", "Lemon"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// Lemon artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".env", ".json", ".ini", ".cfg", ".conf",
		".yaml", ".yml",
		".csv", ".tsv", ".log", ".txt",
		".py", ".ipynb", ".js", ".ts",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return strings.ToLower(filepath.Base(name)) == ".env"
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Lemon catalogue. As with MercadoPago (iter 175) we
// accept `.env` files anywhere because the walker is already
// scoped to per-user `.lemon/` directories.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if n == ".env" || ext == ".env" {
		return true
	}
	for _, tok := range []string{
		"lemon", "lemoncash", "lemon_cash", "lemon-cash",
		"earn", "kyc",
		"crypto_card", "crypto-card", "lemon_card", "lemon-card",
		"arbitrage", "stablecoin",
		"usdt_ars", "usdt-ars", "usdtars",
		"credentials",
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
		if strings.Contains(n, "lemon") {
			return KindInstaller
		}
		return KindOther
	}
	if n == ".env" ||
		strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "auth_token") ||
		strings.Contains(n, "session_token") ||
		strings.Contains(n, "token.json") ||
		strings.Contains(n, "tokens.json") {
		return KindCredentials
	}
	switch {
	case strings.Contains(n, "kyc"):
		return KindKYCDump
	case strings.Contains(n, "crypto_card") ||
		strings.Contains(n, "crypto-card") ||
		strings.Contains(n, "lemon_card") ||
		strings.Contains(n, "lemon-card") ||
		strings.Contains(n, "card_transactions") ||
		strings.Contains(n, "card-transactions"):
		return KindCardTransactions
	case strings.Contains(n, "earn") ||
		strings.Contains(n, "yield_positions") ||
		strings.Contains(n, "yield-positions"):
		return KindEarnPositions
	case strings.Contains(n, "arbitrage") ||
		strings.Contains(n, "usdt_ars") ||
		strings.Contains(n, "usdt-ars") ||
		strings.Contains(n, "usdtars"):
		if ext == ".py" || ext == ".ipynb" || ext == ".js" || ext == ".ts" {
			return KindArbitrageScript
		}
	case strings.Contains(n, "trade_log") || strings.Contains(n, "trade-log") ||
		strings.Contains(n, "wallet_log") || strings.Contains(n, "wallet-log"):
		return KindTradeLog
	case strings.Contains(n, "marketplace") ||
		strings.Contains(n, "marketplace_config") ||
		strings.Contains(n, "marketplace-config"):
		return KindMarketplaceConfig
	case strings.Contains(n, "webhook") ||
		strings.Contains(n, "webhook_handler") ||
		strings.Contains(n, "webhook-handler") ||
		strings.Contains(n, "webhook_config") ||
		strings.Contains(n, "webhook-config"):
		return KindWebhookConfig
	case (strings.Contains(n, "lemon") || strings.Contains(n, "lemon_sdk") ||
		strings.Contains(n, "lemon-sdk")) &&
		(ext == ".py" || ext == ".ipynb" || ext == ".js" || ext == ".ts"):
		return KindSDKScript
	case strings.Contains(n, "lemon"):
		if ext == ".json" || ext == ".ini" || ext == ".cfg" ||
			ext == ".conf" || ext == ".yaml" || ext == ".yml" {
			return KindConfig
		}
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
	case KindConfig, KindCredentials, KindSDKScript,
		KindTradeLog, KindEarnPositions, KindKYCDump,
		KindCardTransactions, KindArbitrageScript,
		KindMarketplaceConfig, KindWebhookConfig:
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
	if r.ClienteDNIHash != "" {
		r.HasClienteDNI = true
	}
	if r.ArtifactKind == KindKYCDump {
		r.HasKYCDump = true
	}
	if r.ArtifactKind == KindTradeLog || r.TradeRecordCount > 0 {
		r.HasTradeLog = true
	}
	if r.ArtifactKind == KindEarnPositions || r.EarnPositionCount > 0 {
		r.HasEarnPositions = true
	}
	if r.ArtifactKind == KindCardTransactions || r.CardTxCount > 0 {
		r.HasCardTransactions = true
	}
	if r.ArtifactKind == KindArbitrageScript {
		r.HasUSDTARSArbitrage = true
	}
	if r.ArtifactKind == KindWebhookConfig ||
		r.ArtifactKind == KindMarketplaceConfig {
		r.HasMarketplaceWebhook = true
	}
	if r.CryptoBalanceUSDCents >= HighBalanceUSDCents {
		r.HasHighBalance = true
	}
	if r.PIISignalCount >= 2 {
		r.HasPIIBundle = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig ||
		r.HasOAuthAccessToken || r.HasOAuthRefreshToken ||
		r.HasKYCDump || r.HasCardTransactions ||
		r.HasUSDTARSArbitrage || r.HasClienteCuit ||
		r.HasClienteDNI || r.HasSDKCredentials
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
