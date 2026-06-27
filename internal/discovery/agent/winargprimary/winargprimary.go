// Package winargprimary audits Primary REST/WebSocket API
// client + pyRofex Python library files cached on Argentine
// prop-desk, retail-broker (Cocos / IOL / Balanz / PPI), and
// quant workstations across Windows, Linux, and macOS.
//
// Primary is the REST + WebSocket gateway operated by MATba-
// Rofex (api.primary.com.ar) that lets Python / JavaScript
// algo traders bridge to Argentine futures + equity markets
// without speaking raw FIX. The Python client library is
// `pyRofex` (pip install pyRofex).
//
// **The Primary REST/WS gateway layer.** Distinct from:
//
//   - iter 109 winargmatbarofex — MATba-Rofex positions files
//   - iter 113 winargfix        — raw FIX session logs
//   - iter 108 winalgotrading   — generic EA/Jupyter cover
//   - iter 136 winargsiopel     — SIOPEL/MAE OTC terminal
//   - iter 137 winargbyma       — BYMA equity terminal
//
// Headline finding shapes:
//
//   - `has_bearer_token=1` — credentials.json carries an
//     access_token / Bearer value in cleartext.
//   - `has_refresh_token=1` — long-lived refresh token on disk.
//   - `has_production_endpoint=1` — config points to
//     api.primary.com.ar (vs api.remarkets.primary.com.ar).
//   - `is_high_frequency=1` — order log shows > 100 orders/min.
//   - `has_strategy_script=1` — .py imports pyRofex.
//   - `is_credential_exposure_risk=1` — readable file +
//     (bearer OR password) + production endpoint.
//
// Read-only by intent. (Project guideline 4.2.)
package winargprimary

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

// MaxFileBytes bounds per-file read. Backtest histories can
// be > 100 MB; we cap at 32 MiB.
const MaxFileBytes = 32 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// HighFrequencyOrdersPerMinute — CNV RG 731 monitoring
// threshold for HFT activity classification.
const HighFrequencyOrdersPerMinute = 100

// ArtifactKind pinned to host_arg_primary_api.artifact_kind.
type ArtifactKind string

const (
	KindCredentialsJSON ArtifactKind = "primary-credentials-json"
	KindPyRofexConfig   ArtifactKind = "primary-pyrofex-config"
	KindWSSubscriptions ArtifactKind = "primary-ws-subscriptions"
	KindOrderAudit      ArtifactKind = "primary-order-audit"
	KindInstrumentCache ArtifactKind = "primary-instrument-cache"
	KindStrategyScript  ArtifactKind = "primary-strategy-script"
	KindBacktestHistory ArtifactKind = "primary-backtest-history"
	KindTokenCache      ArtifactKind = "primary-token-cache"
	KindInstaller       ArtifactKind = "primary-installer"
	KindOther           ArtifactKind = "other"
	KindUnknown         ArtifactKind = "unknown"
)

// Environment pinned to host_arg_primary_api.environment.
type Environment string

const (
	EnvRemarkets  Environment = "remarkets"
	EnvProduction Environment = "production"
	EnvDemo       Environment = "demo"
	EnvOther      Environment = "other"
	EnvUnknown    Environment = "unknown"
)

// BrokerRoute pinned to host_arg_primary_api.broker_route.
type BrokerRoute string

const (
	BrokerCocos      BrokerRoute = "cocos"
	BrokerIOL        BrokerRoute = "iol"
	BrokerBalanz     BrokerRoute = "balanz"
	BrokerPPI        BrokerRoute = "ppi"
	BrokerBullMarket BrokerRoute = "bullmarket"
	BrokerAllaria    BrokerRoute = "allaria"
	BrokerComafi     BrokerRoute = "comafi"
	BrokerDirect     BrokerRoute = "direct"
	BrokerOther      BrokerRoute = "other"
	BrokerUnknown    BrokerRoute = "unknown"
)

// Row mirrors host_arg_primary_api column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	Environment              Environment  `json:"environment"`
	BrokerRoute              BrokerRoute  `json:"broker_route"`
	AccountCuentaSuffix4     string       `json:"account_cuenta_suffix4,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	BearerTokenHash          string       `json:"bearer_token_hash,omitempty"`
	RefreshTokenHash         string       `json:"refresh_token_hash,omitempty"`
	SessionFirstSeen         string       `json:"session_first_seen,omitempty"`
	SessionLastSeen          string       `json:"session_last_seen,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	OrderCount               int64        `json:"order_count,omitempty"`
	OrderPerMinuteMax        int64        `json:"order_per_minute_max,omitempty"`
	InstrumentCount          int64        `json:"instrument_count,omitempty"`
	WSSubscriptionCount      int64        `json:"ws_subscription_count,omitempty"`
	MaxOrderNotionalARSCents int64        `json:"max_order_notional_ars_cents,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasBearerToken           bool         `json:"has_bearer_token"`
	HasRefreshToken          bool         `json:"has_refresh_token"`
	HasAccountPassword       bool         `json:"has_account_password"`
	HasProductionEndpoint    bool         `json:"has_production_endpoint"`
	HasStrategyScript        bool         `json:"has_strategy_script"`
	IsHighFrequency          bool         `json:"is_high_frequency"`
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

// DefaultInstallRoots is the curated Primary install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Primary`,
		`C:\pyRofex`,
		`C:\Program Files\Primary`,
		`/opt/primary`,
		`/opt/pyrofex`,
		`/srv/primary`,
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

// UserPrimaryDirs is the curated per-user relative path set.
//
// Note: dot-prefixed dirs (.primary, .pyrofex) are explicitly
// listed despite the collector's general skip-of-dot-user-
// profile rule — those skips apply to TOP-LEVEL home dirs
// (.git, .DS_Store), not nested per-app caches.
func UserPrimaryDirs() [][]string {
	return [][]string{
		{".primary"},
		{".pyrofex"},
		{".config", "primary"},
		{".config", "pyrofex"},
		{"AppData", "Roaming", "Primary"},
		{"AppData", "Roaming", "pyRofex"},
		{"AppData", "Local", "Primary"},
		{"Library", "Application Support", "Primary"},
		{"Documents", "Primary"},
		{"Documents", "Trading", "Primary"},
		{"Documents", "Trading", "pyRofex"},
		{"Documents", "Algo", "pyRofex"},
	}
}

// IsCandidateExt reports whether the extension carries a
// Primary / pyRofex artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json", ".ini", ".cfg", ".conf",
		".yaml", ".yml", ".toml",
		".py", ".ipynb",
		".log", ".txt",
		".csv", ".tsv", ".parquet",
		".msi", ".exe":
		return true
	}
	// Files without extension (e.g. `refresh_token`) — accept
	// only when the name is exactly one of the canonical
	// token-cache filenames.
	if ext == "" {
		base := strings.ToLower(filepath.Base(name))
		switch base {
		case "refresh_token", "access_token", "primary_token":
			return true
		}
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Primary / pyRofex catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	// Canonical token filenames (no extension).
	switch n {
	case "refresh_token", "access_token", "primary_token":
		return true
	}
	// .py / .ipynb are accepted only when the name carries a
	// pyRofex / primary token.
	if ext == ".py" || ext == ".ipynb" {
		return strings.Contains(n, "pyrofex") ||
			strings.Contains(n, "primary") ||
			strings.Contains(n, "rofex_") ||
			strings.Contains(n, "rofex-")
	}
	for _, tok := range []string{
		"primary", "pyrofex",
		"credentials", "instruments",
		"ws_state", "ws-state",
		"orders_", "orders-",
		"backtest_history", "backtest-history",
		"rofex_", "rofex-",
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
	case "refresh_token", "access_token", "primary_token":
		return KindTokenCache
	}
	switch ext {
	case ".msi", ".exe":
		if strings.Contains(n, "primary") || strings.Contains(n, "pyrofex") {
			return KindInstaller
		}
		return KindOther
	case ".py", ".ipynb":
		return KindStrategyScript
	case ".parquet":
		if strings.Contains(n, "backtest") || strings.Contains(n, "history") {
			return KindBacktestHistory
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") && ext == ".json":
		return KindCredentialsJSON
	case strings.Contains(n, "pyrofex") &&
		(ext == ".ini" || ext == ".cfg" || ext == ".conf" ||
			ext == ".yaml" || ext == ".yml" || ext == ".toml" ||
			ext == ".json"):
		return KindPyRofexConfig
	case (ext == ".ini" || ext == ".cfg" || ext == ".conf" ||
		ext == ".yaml" || ext == ".yml" || ext == ".toml") &&
		strings.Contains(n, "primary"):
		return KindPyRofexConfig
	case strings.Contains(n, "ws_state") || strings.Contains(n, "ws-state"):
		return KindWSSubscriptions
	case strings.Contains(n, "orders") && ext == ".log":
		return KindOrderAudit
	case strings.Contains(n, "orders") &&
		(ext == ".csv" || ext == ".tsv" || ext == ".json"):
		return KindOrderAudit
	case strings.Contains(n, "instruments") &&
		(ext == ".json" || ext == ".csv"):
		return KindInstrumentCache
	case strings.Contains(n, "backtest") || strings.Contains(n, "history"):
		return KindBacktestHistory
	}
	return KindOther
}

// EnvironmentFromPath / EnvironmentFromBody picks remarkets
// (sandbox) vs production based on canonical hostnames.
func EnvironmentFromBody(body []byte) Environment {
	if len(body) == 0 {
		return EnvUnknown
	}
	lower := strings.ToLower(string(body))
	switch {
	case strings.Contains(lower, "api.remarkets.primary.com.ar"):
		return EnvRemarkets
	case strings.Contains(lower, "demo.primary.com.ar"):
		return EnvDemo
	case strings.Contains(lower, "api.primary.com.ar"):
		return EnvProduction
	}
	return EnvUnknown
}

// BrokerRouteFromBody scans for known retail-broker host
// suffixes used in pyRofex configs (broker-specific Primary
// sub-routes).
func BrokerRouteFromBody(body []byte) BrokerRoute {
	if len(body) == 0 {
		return BrokerUnknown
	}
	lower := strings.ToLower(string(body))
	switch {
	case strings.Contains(lower, "cocos.capital") ||
		strings.Contains(lower, "cocos_capital") ||
		strings.Contains(lower, "/cocos/"):
		return BrokerCocos
	case strings.Contains(lower, "invertironline") ||
		strings.Contains(lower, "iol.com.ar") ||
		strings.Contains(lower, "/iol/"):
		return BrokerIOL
	case strings.Contains(lower, "balanz.com") ||
		strings.Contains(lower, "/balanz/"):
		return BrokerBalanz
	case strings.Contains(lower, "portfoliopersonal") ||
		strings.Contains(lower, "ppi.com.ar") ||
		strings.Contains(lower, "/ppi/"):
		return BrokerPPI
	case strings.Contains(lower, "bullmarket") ||
		strings.Contains(lower, "/bullmarket/"):
		return BrokerBullMarket
	case strings.Contains(lower, "allaria") ||
		strings.Contains(lower, "/allaria/"):
		return BrokerAllaria
	case strings.Contains(lower, "comafi.com.ar") ||
		strings.Contains(lower, "/comafi/"):
		return BrokerComafi
	case strings.Contains(lower, "api.primary.com.ar") ||
		strings.Contains(lower, "api.remarkets.primary"):
		return BrokerDirect
	}
	return BrokerUnknown
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

// AccountRE matches a `cuenta=NNNNNN` / `account=NNNNNN` /
// `comitente=NNNN` row.
var accountRE = regexp.MustCompile(
	`(?i)(?:cuenta|account|comitente|account_id|cuenta_comitente)\s*[:=]\s*"?(\d{4,12})"?`)

// AccountSuffix4 extracts the last 4 digits of a cuenta
// comitente number.
func AccountSuffix4(text string) string {
	m := accountRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	n := m[1]
	if len(n) <= 4 {
		return n
	}
	return n[len(n)-4:]
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

// IsCredentialKind reports whether the kind carries credential
// material (token / password). Used in the exposure roll-up.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindCredentialsJSON, KindPyRofexConfig, KindTokenCache:
		return true
	case KindWSSubscriptions, KindOrderAudit, KindInstrumentCache,
		KindStrategyScript, KindBacktestHistory, KindInstaller,
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
	if r.OrderPerMinuteMax >= HighFrequencyOrdersPerMinute {
		r.IsHighFrequency = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	hasCreds := r.HasBearerToken || r.HasRefreshToken ||
		r.HasAccountPassword
	if readable && hasCreds && r.HasProductionEndpoint {
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
