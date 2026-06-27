// Package winargtradingview audits TradingView Desktop +
// Pine Script algotrading files cached on Argentine retail-
// trader and prop-desk workstations across Windows, Linux,
// and macOS.
//
// TradingView (tradingview.com) is the dominant web-based
// charting + algotrading platform. The Desktop app (Electron)
// + the saved-locally Pine Script files form the audit
// surface.
//
// Pine Script v6 (2024) added full algotrading via webhook
// integrations. Argentine retail algotraders rely on:
//
//	Pine `strategy()` functions — backtesting engine
//	Pine alerts with webhook JSON — live signal dispatch
//	Linked broker accounts — trade execution
//
// **The TradingView desktop + Pine layer.** Distinct from:
//
//   - iter 108 winalgotrading    — generic EA cover
//   - iter 143 winargmt          — MetaTrader 4/5
//   - iter 148 winargninjatrader — NinjaTrader 8 futures
//   - iter 139 winargprimary     — Primary REST/WS
//
// Headline finding shapes:
//
//   - `has_pine_strategy=1` — `strategy(...)` in .pine.
//   - `has_webhook_with_secret=1` — webhook config has
//     bearer / api_key / secret.
//   - `has_broker_linked_live=1` — linked broker is live.
//   - `has_alert_with_pii=1` — alert payload carries
//     cliente CUIT.
//   - `has_argentine_pine_strategy=1` — Argentine ticker
//     in .pine (broker-dealer / prop-desk affiliation).
//   - `has_api_key_in_pine=1` — API key in .pine source.
//   - `is_credential_exposure_risk=1` — readable file +
//     (webhook secret OR pine api-key OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargtradingview

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

// ArtifactKind pinned to host_arg_tradingview.artifact_kind.
type ArtifactKind string

const (
	KindPineScript    ArtifactKind = "tv-pine-script"
	KindStrategyAlert ArtifactKind = "tv-strategy-alert"
	KindWebhookConfig ArtifactKind = "tv-webhook-config"
	KindWatchlist     ArtifactKind = "tv-watchlist"
	KindChartLayout   ArtifactKind = "tv-chart-layout"
	KindIndicator     ArtifactKind = "tv-indicator"
	KindBrokerLink    ArtifactKind = "tv-broker-link"
	KindConfig        ArtifactKind = "tv-config"
	KindCache         ArtifactKind = "tv-cache"
	KindInstaller     ArtifactKind = "tv-installer"
	KindOther         ArtifactKind = "other"
	KindUnknown       ArtifactKind = "unknown"
)

// LinkedBroker pinned to host_arg_tradingview.linked_broker.
type LinkedBroker string

const (
	BrokerOANDA        LinkedBroker = "oanda"
	BrokerFXCM         LinkedBroker = "fxcm"
	BrokerCapitalCom   LinkedBroker = "capitalcom"
	BrokerEasyMarkets  LinkedBroker = "easymarkets"
	BrokerAlpaca       LinkedBroker = "alpaca"
	BrokerForexCom     LinkedBroker = "forexcom"
	BrokerSaxo         LinkedBroker = "saxo"
	BrokerTradier      LinkedBroker = "tradier"
	BrokerGemini       LinkedBroker = "gemini"
	BrokerBitstamp     LinkedBroker = "bitstamp"
	BrokerTradovate    LinkedBroker = "tradovate"
	BrokerPaperOnly    LinkedBroker = "paperonly"
	BrokerWebhookOther LinkedBroker = "webhook-other"
	BrokerOther        LinkedBroker = "other"
	BrokerUnknown      LinkedBroker = "unknown"
)

// PineVersion pinned to host_arg_tradingview.pine_version.
type PineVersion string

const (
	PineNone  PineVersion = ""
	PineV3    PineVersion = "v3"
	PineV4    PineVersion = "v4"
	PineV5    PineVersion = "v5"
	PineV6    PineVersion = "v6"
	PineOther PineVersion = "other"
)

// Row mirrors host_arg_tradingview column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	LinkedBroker             LinkedBroker `json:"linked_broker"`
	PineVersion              PineVersion  `json:"pine_version,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	APIKeyHash               string       `json:"api_key_hash,omitempty"`
	WebhookURLHash           string       `json:"webhook_url_hash,omitempty"`
	StrategyName             string       `json:"strategy_name,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	ArgentineTickerCount     int64        `json:"argentine_ticker_count,omitempty"`
	AlertCount               int64        `json:"alert_count,omitempty"`
	WatchlistTickerCount     int64        `json:"watchlist_ticker_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPineStrategy          bool         `json:"has_pine_strategy"`
	HasWebhookWithSecret     bool         `json:"has_webhook_with_secret"`
	HasBrokerLinkedLive      bool         `json:"has_broker_linked_live"`
	HasAlertWithPII          bool         `json:"has_alert_with_pii"`
	HasArgentinePineStrategy bool         `json:"has_argentine_pine_strategy"`
	HasAPIKeyInPine          bool         `json:"has_api_key_in_pine"`
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

// DefaultInstallRoots is the curated TradingView install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Program Files\TradingView Desktop`,
		`C:\Program Files (x86)\TradingView Desktop`,
		`/opt/tradingview`,
		`/Applications/TradingView.app/Contents`,
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

// UserTVDirs is the curated per-user relative path set.
func UserTVDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "TradingView Desktop"},
		{"AppData", "Local", "TradingView Desktop"},
		{".config", "tradingview"},
		{".tradingview-desktop"},
		{"Library", "Application Support", "TradingView"},
		{"Documents", "TradingView"},
		{"Documents", "Pine"},
		{"Documents", "Trading", "Pine"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// TradingView artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pine", ".pinescript",
		".json", ".yaml", ".yml",
		".csv", ".tsv",
		".html", ".htm",
		".ini", ".cfg", ".conf",
		".log", ".txt",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the TradingView catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".pine", ".pinescript":
		return true
	}
	for _, tok := range []string{
		"tradingview", "tv_", "tv-",
		"pine_", "pine-",
		"strategy_alert", "strategy-alert",
		"webhook", "watchlist",
		"chart_layout", "chart-layout",
		"indicator_",
		"broker_link", "broker-link",
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
		if strings.Contains(n, "tradingview") {
			return KindInstaller
		}
		return KindOther
	case ".pine", ".pinescript":
		if strings.Contains(n, "indicator") {
			return KindIndicator
		}
		return KindPineScript
	}
	switch {
	case strings.Contains(n, "webhook") &&
		(ext == ".json" || ext == ".yaml" || ext == ".yml"):
		return KindWebhookConfig
	case (strings.Contains(n, "strategy_alert") ||
		strings.Contains(n, "strategy-alert") ||
		strings.Contains(n, "alert_")) &&
		(ext == ".json" || ext == ".yaml" || ext == ".yml"):
		return KindStrategyAlert
	case strings.Contains(n, "watchlist") &&
		(ext == ".csv" || ext == ".json" || ext == ".tsv"):
		return KindWatchlist
	case strings.Contains(n, "chart_layout") ||
		strings.Contains(n, "chart-layout") ||
		strings.Contains(n, "layout_"):
		return KindChartLayout
	case strings.Contains(n, "broker_link") ||
		strings.Contains(n, "broker-link"):
		return KindBrokerLink
	case strings.Contains(n, "tradingview") &&
		(ext == ".ini" || ext == ".cfg" || ext == ".conf"):
		return KindConfig
	case strings.Contains(n, "cache") || strings.Contains(n, "indexeddb"):
		return KindCache
	}
	return KindOther
}

// LinkedBrokerFromBody scans for known broker hostnames in
// webhook config / broker-link bodies.
func LinkedBrokerFromBody(body []byte) LinkedBroker {
	if len(body) == 0 {
		return BrokerUnknown
	}
	lower := strings.ToLower(string(body))
	type entry struct {
		token string
		route LinkedBroker
	}
	for _, e := range []entry{
		{"capital.com", BrokerCapitalCom},
		{"easymarkets.com", BrokerEasyMarkets},
		{"forex.com", BrokerForexCom},
		{"oanda.com", BrokerOANDA},
		{"alpaca.markets", BrokerAlpaca},
		{"saxobank.com", BrokerSaxo},
		{"tradier.com", BrokerTradier},
		{"gemini.com", BrokerGemini},
		{"bitstamp.net", BrokerBitstamp},
		{"tradovate.com", BrokerTradovate},
		{"fxcm.com", BrokerFXCM},
		{"\"paper\"", BrokerPaperOnly},
		{"paper trading", BrokerPaperOnly},
	} {
		if strings.Contains(lower, e.token) {
			return e.route
		}
	}
	// Webhook URL without a known broker host = generic.
	if strings.Contains(lower, "webhook") ||
		strings.Contains(lower, "discord.com/api/webhooks") ||
		strings.Contains(lower, "hooks.slack.com") {
		return BrokerWebhookOther
	}
	return BrokerUnknown
}

// IsLiveBroker reports whether the broker is live (non-paper).
func IsLiveBroker(b LinkedBroker) bool {
	switch b {
	case BrokerOANDA, BrokerFXCM, BrokerCapitalCom,
		BrokerEasyMarkets, BrokerAlpaca, BrokerForexCom,
		BrokerSaxo, BrokerTradier, BrokerGemini,
		BrokerBitstamp, BrokerTradovate:
		return true
	case BrokerPaperOnly, BrokerWebhookOther, BrokerOther, BrokerUnknown:
		return false
	}
	return false
}

// ArgentineTickers returns the curated set used to flag
// Argentine-market focus in Pine scripts.
func ArgentineTickers() []string {
	return []string{
		// Equities (BYMA)
		"GGAL", "YPFD", "PAMP", "ALUA", "COME",
		"TXAR", "TGSU2", "TGNO4", "EDN", "TS",
		"CRES", "CEPU", "MIRG", "TRAN", "BMA",
		"BBAR", "SUPV", "VALO", "BHIP",
		// Sovereign bonds
		"AL30", "AL30D", "AL30C",
		"AL35", "AL35D", "AL35C",
		"GD30", "GD30D", "GD30C",
		"GD35", "GD35D", "GD35C",
		"GD38", "GD41", "GD46",
		// BCRA
		"LELIQ", "LECAP",
	}
}

// IsArgentineTicker reports membership.
func IsArgentineTicker(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	for _, v := range ArgentineTickers() {
		if v == t {
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

// PeriodFromFilename extracts YYYYMM from a filename.
func PeriodFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + m[2]
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
	if r.ArgentineTickerCount > 0 &&
		(r.ArtifactKind == KindPineScript ||
			r.ArtifactKind == KindIndicator) {
		r.HasArgentinePineStrategy = true
	}
	if IsLiveBroker(r.LinkedBroker) {
		r.HasBrokerLinkedLive = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasWebhookWithSecret || r.HasAPIKeyInPine ||
		r.HasAlertWithPII || r.HasClienteCuit
	if readable && credSignal {
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
