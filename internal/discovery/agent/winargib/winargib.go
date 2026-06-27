// Package winargib audits Interactive Brokers TWS / IB
// Gateway / ibapi-SDK artifact files cached on Argentine
// retail-quant, prop-desk, and institutional-quant
// workstations across Windows, Linux, and macOS.
//
// IB is the dominant US-based brokerage that Argentine
// residents use to access global markets (NYSE, NASDAQ,
// LSE, HKEX, TSE), CME / CBOT / NYMEX futures, CBOE
// options, FX, fixed income, and (since 2021) crypto.
//
// IB is **offshore** from a CNV perspective — Argentine
// residents who trade via IB do so directly with IBKR LLC
// (US) or IBKR UK Ltd., subject to AFIP RG 5193 + RG 5527
// + F.8125 + BCRA Com. A 7916.
//
// **The offshore-broker layer.** Distinct from:
//
//   - iter 151 winargiolinvertironline — IOL local retail.
//   - iter 154 winargbalanz            — Balanz local.
//   - iter 162 winargccxt              — crypto multi-exchange.
//   - iter 160 winarglean              — LEAN framework.
//
// IB connection surfaces:
//
//   - TWS Desktop   — Java app, port 7496 (live) / 7497 (paper).
//   - IB Gateway    — headless, port 4001 (live) / 4002 (paper).
//   - ibapi / ib_insync Python SDK.
//   - Mobile / Client Portal.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — jts.ini cleartext.
//   - `has_api_socket_exposed=1` — TWS API bound 0.0.0.0.
//   - `has_live_account=1` — live-mode (vs paper).
//   - `has_us_equity_positions=1` — US equity (AFIP RG 5193).
//   - `has_global_equity_positions=1` — LSE/HKEX/TSE/etc.
//   - `has_futures_cme=1` — CME / CBOT / NYMEX futures.
//   - `has_forex_trading=1` — FX cash/forward.
//   - `has_crypto_positions=1` — IB crypto (AFIP RG 5527).
//   - `has_flex_query_export=1` — XML/CSV tax export.
//   - `has_high_aum=1` — > USD 100 K.
//   - `has_bcra_above_cap=1` — > USD 200 K cross-border.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR API token OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargib

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

// HighAUMUSDCents is the AFIP RG 5193 + Bienes Personales
// trigger threshold (USD 100 K = 10 M cents).
const HighAUMUSDCents = 10_000_000

// BCRAIndividualCapUSDCents is the BCRA Com. A 7916
// natural-person monthly cap (USD 200 K = 20 M cents).
const BCRAIndividualCapUSDCents = 20_000_000

// IB-canonical socket ports.
const (
	PortTWSLive      = 7496
	PortTWSPaper     = 7497
	PortGatewayLive  = 4001
	PortGatewayPaper = 4002
)

// ArtifactKind pinned to host_arg_ib.artifact_kind.
type ArtifactKind string

const (
	KindConfig        ArtifactKind = "ib-config"
	KindGatewayConfig ArtifactKind = "ib-gateway-config"
	KindCredentials   ArtifactKind = "ib-credentials"
	KindTWSSettings   ArtifactKind = "ib-tws-settings"
	KindPositions     ArtifactKind = "ib-positions"
	KindOrders        ArtifactKind = "ib-orders"
	KindStrategyPy    ArtifactKind = "ib-strategy-py"
	KindTradeLog      ArtifactKind = "ib-trade-log"
	KindFlexQuery     ArtifactKind = "ib-flex-query"
	KindTaxStatement  ArtifactKind = "ib-tax-statement"
	KindInstaller     ArtifactKind = "ib-installer"
	KindOther         ArtifactKind = "other"
	KindUnknown       ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_ib.account_class.
type AccountClass string

const (
	AccountRetail        AccountClass = "retail"
	AccountPro           AccountClass = "pro"
	AccountInstitutional AccountClass = "institutional"
	AccountAPI           AccountClass = "api"
	AccountPaper         AccountClass = "paper"
	AccountDemo          AccountClass = "demo"
	AccountOther         AccountClass = "other"
	AccountUnknown       AccountClass = "unknown"
)

// ProductClass pinned to host_arg_ib.product_class.
type ProductClass string

const (
	ProductUSEquity     ProductClass = "us-equity"
	ProductGlobalEquity ProductClass = "global-equity"
	ProductFuturesCME   ProductClass = "futures-cme"
	ProductOptionsCBOE  ProductClass = "options-cboe"
	ProductForex        ProductClass = "forex"
	ProductBonds        ProductClass = "bonds"
	ProductCrypto       ProductClass = "crypto"
	ProductMultiAsset   ProductClass = "multi-asset"
	ProductOther        ProductClass = "other"
	ProductUnknown      ProductClass = "unknown"
)

// Row mirrors host_arg_ib column shape.
type Row struct {
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AccountClass             AccountClass `json:"account_class"`
	ProductClass             ProductClass `json:"product_class"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	IBAccountSuffix4         string       `json:"ib_account_suffix4,omitempty"`
	APISocketAddress         string       `json:"api_socket_address,omitempty"`
	FilePath                 string       `json:"file_path"`
	UsernameHash             string       `json:"username_hash,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	DistinctSymbolsCount     int64        `json:"distinct_symbols_count,omitempty"`
	PortfolioAUMUSDCents     int64        `json:"portfolio_aum_usd_cents,omitempty"`
	AboveCapCount            int64        `json:"above_cap_count,omitempty"`
	APISocketPort            int          `json:"api_socket_port,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasGlobalEquityPositions bool         `json:"has_global_equity_positions"`
	HasCryptoPositions       bool         `json:"has_crypto_positions"`
	HasLiveAccount           bool         `json:"has_live_account"`
	HasUSEquityPositions     bool         `json:"has_us_equity_positions"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasFuturesCME            bool         `json:"has_futures_cme"`
	HasForexTrading          bool         `json:"has_forex_trading"`
	HasAPISocketExposed      bool         `json:"has_api_socket_exposed"`
	HasFlexQueryExport       bool         `json:"has_flex_query_export"`
	HasHighAUM               bool         `json:"has_high_aum"`
	HasBCRAAboveCap          bool         `json:"has_bcra_above_cap"`
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

// DefaultInstallRoots is the curated IB install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Jts`,
		`C:\IBKR`,
		`C:\IBKR\Gateway`,
		`C:\Program Files\Interactive Brokers`,
		`C:\Program Files\IBKR`,
		`C:\Program Files\IB Gateway`,
		`C:\Program Files (x86)\Interactive Brokers`,
		`/opt/ibkr`,
		`/opt/ibgateway`,
		`/opt/jts`,
		`/Applications/Trader Workstation.app`,
		`/Applications/IB Gateway.app`,
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

// UserIBDirs is the curated per-user relative path set.
func UserIBDirs() [][]string {
	return [][]string{
		{"Jts"},
		{"Documents", "IB"},
		{"Documents", "IBKR"},
		{"Documents", "Interactive Brokers"},
		{".ib"},
		{".ib-insync"},
		{".ibkr"},
		{"projects", "ibapi"},
		{"projects", "quant"},
		{"AppData", "Roaming", "IBKR"},
		{"AppData", "Local", "IBKR"},
		{"Library", "Application Support", "IBKR"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries an
// IB artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".ini", ".cfg", ".conf",
		".json", ".yaml", ".yml",
		".xml", ".csv", ".tsv",
		".py", ".ipynb",
		".log", ".txt",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the IB catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"jts", "ibgateway", "ib_gateway", "ib-gateway",
		"ibkr", "interactivebrokers", "interactive_brokers",
		"ibapi", "ib_insync", "ib-insync",
		"twsstart", "tws_start", "tws-start",
		"flex_query", "flex-query", "flexquery",
		"tws_settings", "tws-settings",
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
		if strings.Contains(n, "ibkr") || strings.Contains(n, "tws") ||
			strings.Contains(n, "ibgateway") || strings.Contains(n, "ib_gateway") ||
			strings.Contains(n, "interactivebrokers") {
			return KindInstaller
		}
		return KindOther
	case ".py", ".ipynb":
		if strings.Contains(n, "ibapi") || strings.Contains(n, "ib_insync") ||
			strings.Contains(n, "ib-insync") || strings.Contains(n, "ibkr") {
			return KindStrategyPy
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "flex_query") || strings.Contains(n, "flex-query") ||
		strings.Contains(n, "flexquery") || strings.Contains(n, "flex_statement"):
		return KindFlexQuery
	case strings.Contains(n, "tax_statement") || strings.Contains(n, "tax-statement") ||
		strings.Contains(n, "1099") || strings.Contains(n, "ganancias"):
		return KindTaxStatement
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "tws_settings") || strings.Contains(n, "tws-settings"):
		return KindTWSSettings
	case strings.Contains(n, "ibgateway") || strings.Contains(n, "ib_gateway") ||
		strings.Contains(n, "ib-gateway"):
		return KindGatewayConfig
	case strings.Contains(n, "positions"):
		return KindPositions
	case strings.Contains(n, "orders") || strings.Contains(n, "ordenes"):
		return KindOrders
	case strings.Contains(n, "trade_log") || strings.Contains(n, "trade-log") ||
		strings.Contains(n, "execution") || strings.Contains(n, "fills"):
		return KindTradeLog
	case strings.Contains(n, "jts") && (ext == ".ini" || ext == ".cfg" ||
		ext == ".conf"):
		return KindConfig
	case (strings.Contains(n, "config") || strings.Contains(n, "settings")) &&
		(ext == ".ini" || ext == ".cfg" || ext == ".conf" ||
			ext == ".xml" || ext == ".json" || ext == ".yaml" || ext == ".yml"):
		return KindConfig
	}
	return KindOther
}

// GlobalEquityExchanges returns curated non-US equity exchange
// markers.
func GlobalEquityExchanges() []string {
	return []string{
		"LSE", "LSEETF", "AEB", "EBS", "FWB", "IBIS",
		"TSE", "TSEJ", "HKEX", "SEHK", "SGX", "ASX",
		"BMV", "BVL", "BOVESPA", "B3", "BME",
		"MEXI", "MILANO", "SBF", "EURONEXT",
	}
}

// USEquityExchanges returns curated US equity exchange markers.
func USEquityExchanges() []string {
	return []string{
		"NYSE", "NASDAQ", "AMEX", "ARCA", "BATS",
		"ISLAND", "ISE", "EDGEA", "EDGEX",
	}
}

// CMEFuturesExchanges returns CME group + related US futures
// exchange markers.
func CMEFuturesExchanges() []string {
	return []string{
		"CME", "CBOT", "NYMEX", "COMEX", "GLOBEX",
		"CFE", "ICE", "ICEUS", "ICEEU",
	}
}

// CryptoSymbols returns curated IB crypto product markers.
func CryptoSymbols() []string {
	return []string{
		"BTC", "ETH", "BCH", "LTC", "PAXOS", "PAYPAL",
		"BTC.USD", "ETH.USD",
	}
}

// ForexCurrencies returns curated FX cash markers.
func ForexCurrencies() []string {
	return []string{
		"EUR.USD", "GBP.USD", "USD.JPY", "USD.CHF",
		"AUD.USD", "USD.CAD", "EUR.GBP", "EUR.JPY",
		"NZD.USD", "USD.MXN", "USD.ARS", "USD.BRL",
		"USD.CNH", "USD.HKD",
	}
}

// hasAnyMarker reports whether body contains any of the
// curated markers (case-insensitive).
func hasAnyMarker(body []byte, markers []string) bool {
	low := strings.ToLower(string(body))
	for _, m := range markers {
		if strings.Contains(low, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// HasUSEquityMarker / HasGlobalEquityMarker / etc. convenience.
func HasUSEquityMarker(body []byte) bool {
	return hasAnyMarker(body, USEquityExchanges())
}

// HasGlobalEquityMarker reports non-US equity exchange presence.
func HasGlobalEquityMarker(body []byte) bool {
	return hasAnyMarker(body, GlobalEquityExchanges())
}

// HasCMEFuturesMarker reports CME group futures presence.
func HasCMEFuturesMarker(body []byte) bool {
	return hasAnyMarker(body, CMEFuturesExchanges())
}

// HasForexMarker reports FX presence.
func HasForexMarker(body []byte) bool {
	return hasAnyMarker(body, ForexCurrencies())
}

// HasCryptoMarker reports IB crypto presence.
func HasCryptoMarker(body []byte) bool {
	return hasAnyMarker(body, CryptoSymbols())
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

// ibAccountRE matches a `U1234567` IB account number (the
// canonical "U-prefix + 7 digits" form).
var ibAccountRE = regexp.MustCompile(`\b(U\d{7})\b`)

// IBAccountSuffix4 extracts the last 4 digits of an IB account.
func IBAccountSuffix4(text string) string {
	m := ibAccountRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	acc := m[1]
	if len(acc) < 4 {
		return ""
	}
	return acc[len(acc)-4:]
}

// PortToAccountClass maps IB canonical ports to mode.
func PortToAccountClass(port int) AccountClass {
	switch port {
	case PortTWSPaper, PortGatewayPaper:
		return AccountPaper
	case PortTWSLive, PortGatewayLive:
		return AccountRetail
	}
	return AccountUnknown
}

// IsLivePort reports whether the port is a live-trading port.
func IsLivePort(port int) bool {
	return port == PortTWSLive || port == PortGatewayLive
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
	case KindConfig, KindGatewayConfig, KindCredentials,
		KindTWSSettings, KindPositions, KindOrders,
		KindStrategyPy, KindTradeLog, KindFlexQuery,
		KindTaxStatement:
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
	if r.PortfolioAUMUSDCents >= HighAUMUSDCents {
		r.HasHighAUM = true
	}
	if r.AboveCapCount > 0 {
		r.HasBCRAAboveCap = true
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
