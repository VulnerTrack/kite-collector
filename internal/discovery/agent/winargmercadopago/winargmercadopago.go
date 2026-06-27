// Package winargmercadopago audits MercadoPago Inversiones
// artifact files cached on Argentine consumer, merchant,
// developer (Python / JS SDK integrator), and ALYC compliance-
// officer workstations across Windows, Linux, and macOS.
//
// MercadoPago Inversiones is the MercadoLibre (MELI) regulated
// subsidiary operating as an **ALYC bajo CNV RG 731**
// (Agente de Liquidación y Compensación Integral). It is the
// largest AR retail broker by user count (>40 M MercadoPago
// account holders, of which a large fraction has Inversiones
// enabled).
//
// MercadoPago Inversiones distinctive surfaces:
//
//   - Rendimientos             FCI money-market.
//   - Inversiones              BYMA equity + AR bonds.
//   - CEDEARs                  foreign equity via local listing.
//   - Marketplace auto-invest  merchant Rendimientos auto-fund.
//   - MercadoPago Python SDK   `mercadopago` PyPI package.
//   - REST API + OAuth2        access / refresh tokens.
//   - Webhooks                 payment / order events.
//   - DEBIN / Echeq            ARS rail.
//
// **The MELI ALYC fintech layer.** Distinct from:
//
//   - iter 154 winargbalanz       — Balanz Capital ALYC.
//   - iter 163 winargppi          — PPI (Banco Galicia) ALYC.
//   - iter 152 winargcocoscapital — Cocos Capital ALYC.
//   - iter 151 winargiolinvertironline — IOL ALYC.
//   - iter 164 winargallaria      — Allaria Ledesma ALYC.
//   - iter 155 winarghomebroker   — Decsis HomeBroker white-label.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — cfg cleartext.
//   - `has_oauth_access_token=1` — MP OAuth bearer leak.
//   - `has_oauth_refresh_token=1` — refresh token leak.
//   - `has_sdk_credentials=1` — Python/JS SDK creds.
//   - `has_rendimientos_export=1` — FCI positions export.
//   - `has_inversiones_export=1` — BYMA equity export.
//   - `has_high_balance=1` — > USD 50 K position.
//   - `has_marketplace_autoinvest=1` — auto-invest enabled.
//   - `has_webhook_secret=1` — webhook signing key.
//   - `has_audit_log=1` — audit operations log.
//   - `has_pii_bundle=1` — ≥2 of (DNI, CUIT, name).
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR OAuth token OR webhook secret OR rendimientos
//     export OR inversiones export OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargmercadopago

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

// HighBalanceUSDCents — USD 50 000 expressed in cents.
const HighBalanceUSDCents int64 = 5_000_000

// LongLivedTokenTTLDays — OAuth access-token TTL > 1 year is
// considered elevated-persistence (T1098).
const LongLivedTokenTTLDays = 365

// ArtifactKind pinned to host_arg_mercadopago.artifact_kind.
type ArtifactKind string

const (
	KindConfig             ArtifactKind = "mp-config"
	KindCredentials        ArtifactKind = "mp-credentials"
	KindSDKScript          ArtifactKind = "mp-sdk-script"
	KindWebhookConfig      ArtifactKind = "mp-webhook-config"
	KindRendimientosExport ArtifactKind = "mp-rendimientos-export"
	KindInversionesExport  ArtifactKind = "mp-inversiones-export"
	KindTradeLog           ArtifactKind = "mp-trade-log"
	KindMarketplaceConfig  ArtifactKind = "mp-marketplace-config"
	KindAuditLog           ArtifactKind = "mp-audit-log"
	KindInstaller          ArtifactKind = "mp-installer"
	KindOther              ArtifactKind = "other"
	KindUnknown            ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_mercadopago.account_class.
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

// ProductClass pinned to host_arg_mercadopago.product_class.
type ProductClass string

const (
	ProductRendimientosFCI   ProductClass = "rendimientos-fci"
	ProductInversionesEquity ProductClass = "inversiones-equity"
	ProductInversionesBonds  ProductClass = "inversiones-bonds"
	ProductInversionesCEDEAR ProductClass = "inversiones-cedears"
	ProductMultiProduct      ProductClass = "multi-product"
	ProductOther             ProductClass = "other"
	ProductUnknown           ProductClass = "unknown"
)

// Row mirrors host_arg_mercadopago column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AccountClass             AccountClass `json:"account_class"`
	ProductClass             ProductClass `json:"product_class"`
	MPUserID                 string       `json:"mp_user_id,omitempty"`
	MPAppID                  string       `json:"mp_app_id,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	ClienteDNIHash           string       `json:"cliente_dni_hash,omitempty"`
	AccessTokenHash          string       `json:"access_token_hash,omitempty"`
	RefreshTokenHash         string       `json:"refresh_token_hash,omitempty"`
	WebhookSecretHash        string       `json:"webhook_secret_hash,omitempty"`
	UsernameHash             string       `json:"username_hash,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	DistinctTickersCount     int64        `json:"distinct_tickers_count,omitempty"`
	CuentaCount              int64        `json:"cuenta_count,omitempty"`
	BalanceUSDCents          int64        `json:"balance_usd_cents,omitempty"`
	PIISignalCount           int64        `json:"pii_signal_count,omitempty"`
	RendimientosRecordCount  int64        `json:"rendimientos_record_count,omitempty"`
	InversionesRecordCount   int64        `json:"inversiones_record_count,omitempty"`
	AuditEventCount          int64        `json:"audit_event_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasOAuthAccessToken      bool         `json:"has_oauth_access_token"`
	HasOAuthRefreshToken     bool         `json:"has_oauth_refresh_token"`
	HasSDKCredentials        bool         `json:"has_sdk_credentials"`
	HasRendimientosExport    bool         `json:"has_rendimientos_export"`
	HasInversionesExport     bool         `json:"has_inversiones_export"`
	HasHighBalance           bool         `json:"has_high_balance"`
	HasMarketplaceAutoinvest bool         `json:"has_marketplace_autoinvest"`
	HasWebhookSecret         bool         `json:"has_webhook_secret"`
	HasAuditLog              bool         `json:"has_audit_log"`
	HasClienteCuit           bool         `json:"has_cliente_cuit"`
	HasClienteDNI            bool         `json:"has_cliente_dni"`
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

// DefaultInstallRoots is the curated MP install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\MercadoPago`,
		`C:\Mercado Pago`,
		`C:\Program Files\MercadoPago`,
		`C:\Program Files (x86)\MercadoPago`,
		`/opt/mercadopago`,
		`/opt/mp-sdk`,
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

// UserMPDirs is the curated per-user relative path set.
func UserMPDirs() [][]string {
	return [][]string{
		{".mercadopago"},
		{".mp"},
		{".mp-sdk"},
		{".config", "mercadopago"},
		{".config", "mp"},
		{"AppData", "Roaming", "MercadoPago"},
		{"AppData", "Local", "MercadoPago"},
		{"Documents", "MercadoPago"},
		{"Documents", "MP"},
		{"projects", "mercadopago"},
		{"projects", "mp"},
		{"Library", "Application Support", "MercadoPago"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// MercadoPago artifact.
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
	// .env files often have no extension at all (just `.env`).
	if strings.ToLower(filepath.Base(name)) == ".env" {
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the MercadoPago catalogue. Anything with a `.env`
// extension under our scoped per-user dirs counts as a
// candidate because the walk-tree already constrains us to
// `~/.mercadopago/`-style directories.
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
		"mercadopago", "mercado_pago", "mercado-pago",
		"mercadolibre", "mercado_libre",
		"mp_", "mp-", "mp.",
		"rendimientos", "rendimiento",
		"inversiones", "inversion",
		"mp_sdk", "mp-sdk",
		"mp_webhook", "mp-webhook",
		"mp_audit", "mp-audit",
		"mp_trade", "mp-trade",
		"marketplace_autoinvest", "marketplace-autoinvest",
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
		if strings.Contains(n, "mercadopago") || strings.Contains(n, "mp_") {
			return KindInstaller
		}
		return KindOther
	}
	if n == ".env" ||
		strings.Contains(n, "credentials") ||
		strings.Contains(n, "_credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "auth_token") ||
		strings.Contains(n, "session_token") ||
		strings.Contains(n, "token.json") ||
		strings.Contains(n, "tokens.json") {
		return KindCredentials
	}
	switch {
	case strings.Contains(n, "rendimientos") ||
		strings.Contains(n, "rendimiento") ||
		strings.Contains(n, "fci_positions") ||
		strings.Contains(n, "money_market"):
		return KindRendimientosExport
	case strings.Contains(n, "inversiones") ||
		strings.Contains(n, "inversion") ||
		strings.Contains(n, "equity_positions") ||
		strings.Contains(n, "stock_positions"):
		return KindInversionesExport
	case strings.Contains(n, "marketplace_autoinvest") ||
		strings.Contains(n, "marketplace-autoinvest") ||
		strings.Contains(n, "auto_invest") ||
		strings.Contains(n, "auto-invest"):
		return KindMarketplaceConfig
	case strings.Contains(n, "mp_webhook") || strings.Contains(n, "mp-webhook") ||
		strings.Contains(n, "webhook_handler") ||
		strings.Contains(n, "webhook-handler") ||
		strings.Contains(n, "webhook_config") ||
		strings.Contains(n, "webhook-config"):
		return KindWebhookConfig
	case strings.Contains(n, "mp_audit") || strings.Contains(n, "mp-audit") ||
		strings.Contains(n, "audit_log") || strings.Contains(n, "audit-log"):
		return KindAuditLog
	case strings.Contains(n, "mp_trade") || strings.Contains(n, "mp-trade") ||
		strings.Contains(n, "trade_log") || strings.Contains(n, "trade-log"):
		return KindTradeLog
	case strings.Contains(n, "mp_sdk") || strings.Contains(n, "mp-sdk"):
		if ext == ".py" || ext == ".ipynb" || ext == ".js" || ext == ".ts" {
			return KindSDKScript
		}
		return KindConfig
	case (strings.Contains(n, "mercadopago") || strings.Contains(n, "mp_") ||
		strings.Contains(n, "mp-") || strings.Contains(n, "mp.")) &&
		(ext == ".py" || ext == ".ipynb" || ext == ".js" || ext == ".ts"):
		return KindSDKScript
	case strings.Contains(n, "mercadopago") || strings.Contains(n, "mp_") ||
		strings.Contains(n, "mp-") || strings.Contains(n, "mp."):
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
	case KindConfig, KindCredentials,
		KindSDKScript, KindWebhookConfig,
		KindRendimientosExport, KindInversionesExport,
		KindTradeLog, KindMarketplaceConfig, KindAuditLog:
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
	if r.ArtifactKind == KindRendimientosExport || r.RendimientosRecordCount > 0 {
		r.HasRendimientosExport = true
	}
	if r.ArtifactKind == KindInversionesExport || r.InversionesRecordCount > 0 {
		r.HasInversionesExport = true
	}
	if r.ArtifactKind == KindAuditLog || r.AuditEventCount > 0 {
		r.HasAuditLog = true
	}
	if r.ArtifactKind == KindMarketplaceConfig {
		r.HasMarketplaceAutoinvest = true
	}
	if r.BalanceUSDCents >= HighBalanceUSDCents {
		r.HasHighBalance = true
	}
	if r.PIISignalCount >= 2 {
		r.HasPIIBundle = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig ||
		r.HasOAuthAccessToken || r.HasOAuthRefreshToken ||
		r.HasWebhookSecret || r.HasRendimientosExport ||
		r.HasInversionesExport || r.HasClienteCuit ||
		r.HasSDKCredentials
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
