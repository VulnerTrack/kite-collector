// Package winargkdb audits KX Systems KDB+/Q artifact files
// cached on Argentine HFT prop-trader, quant-research, and
// institutional algo-execution workstations across Windows,
// Linux, and macOS.
//
// KDB+ is the **gold-standard HFT time-series database** sold
// by KX Systems. Its Q functional programming language is used
// by top-tier AR prop shops for tick-by-tick market-data
// storage, real-time order-book reconstruction (RDB tier),
// historical-data analysis (HDB tier), and co-located algo
// execution (sub-millisecond latency).
//
// KX commercial licenses cost > USD 100 K annually so KDB+
// adoption flags an **institutional / HFT-tier deployment**.
//
// KDB+/Q distinctive surfaces:
//
//   - .q                 Q programming-language script.
//   - .k                 K-language script (Q's predecessor).
//   - q.k                core Q library file.
//   - k4.lic / kc.lic    KX commercial license file.
//   - <table>/<date>/<col>.dat   HDB column-store partition.
//   - <table>/.d         column-name index.
//   - sym                global symbol table (HDB).
//   - tplog_<date>.log   real-time tick log.
//   - .qrc / q.q         user-startup config.
//   - hdb_root/par.txt   HDB partition map.
//
// **The KDB+/Q HFT tick-database layer.** Distinct from:
//
//   - iter 167 winargcqg          — CQG vendor terminal.
//   - iter 169 winargtt           — TT vendor terminal.
//   - iter 170 winargsierra       — Sierra Chart (DTC + ACSIL).
//   - iter 172 winargmulticharts  — MultiCharts PowerLanguage.
//   - iter 160 winarglean         — LEAN Python.
//   - iter 144 winargpybacktest   — Python backtest libraries.
//   - iter 113 winargfix          — FIX-protocol wire logs.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — script / .qrc cleartext.
//   - `has_kx_license=1` — KX commercial license file.
//   - `has_q_script=1` — .q strategy / data script.
//   - `has_k_script=1` — .k script.
//   - `has_tick_db=1` — tplog or HDB present.
//   - `has_large_hdb=1` — HDB column > 10 GB.
//   - `has_subscriber_config=1` — feed-handler / RPC surface.
//   - `has_matba_rofex_table=1` — MATba symbol table.
//   - `has_cme_futures_table=1` — CME futures table.
//   - `has_us_equity_table=1` — US equity table.
//   - `has_crypto_data=1` — crypto / USDT-ARS table.
//   - `has_cross_venue_arb=1` — multi-venue tables.
//   - `has_hft_pattern=1` — KDB+ implies HFT (auto-flag).
//   - `has_qrc_autoload=1` — .qrc with `\l <script>` chain.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR KX license OR subscriber cfg OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargkdb

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

// LargeHDBBytes — 10 GiB — single column-file size triggering
// large-HDB flag.
const LargeHDBBytes int64 = 10 << 30

// ArtifactKind pinned to host_arg_kdb.artifact_kind.
type ArtifactKind string

const (
	KindConfig           ArtifactKind = "kdb-config"
	KindCredentials      ArtifactKind = "kdb-credentials"
	KindQScript          ArtifactKind = "kdb-q-script"
	KindKScript          ArtifactKind = "kdb-k-script"
	KindLicense          ArtifactKind = "kdb-license"
	KindHDBColumn        ArtifactKind = "kdb-hdb-column"
	KindHDBMeta          ArtifactKind = "kdb-hdb-meta"
	KindTplog            ArtifactKind = "kdb-tplog"
	KindQRCStartup       ArtifactKind = "kdb-qrc-startup"
	KindSubscriberConfig ArtifactKind = "kdb-subscriber-config"
	KindInstaller        ArtifactKind = "kdb-installer"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_kdb.account_class.
type AccountClass string

const (
	AccountHFT           AccountClass = "hft"
	AccountPropTrader    AccountClass = "prop-trader"
	AccountQuantResearch AccountClass = "quant-research"
	AccountInstitutional AccountClass = "institutional"
	AccountMarketMaker   AccountClass = "market-maker"
	AccountAPI           AccountClass = "api"
	AccountDemo          AccountClass = "demo"
	AccountOther         AccountClass = "other"
	AccountUnknown       AccountClass = "unknown"
)

// ProductClass pinned to host_arg_kdb.product_class.
type ProductClass string

const (
	ProductMATbaRofex   ProductClass = "matba-rofex"
	ProductCMEFutures   ProductClass = "cme-futures"
	ProductUSEquity     ProductClass = "us-equity"
	ProductCrypto       ProductClass = "crypto"
	ProductMultiVenue   ProductClass = "multi-venue"
	ProductOptions      ProductClass = "options"
	ProductHFTExecution ProductClass = "hft-execution"
	ProductOther        ProductClass = "other"
	ProductUnknown      ProductClass = "unknown"
)

// LicenseClass pinned to host_arg_kdb.license_class.
type LicenseClass string

const (
	LicenseCommercial      LicenseClass = "commercial"
	LicensePersonalEdition LicenseClass = "personal-edition"
	LicenseEvaluation      LicenseClass = "evaluation"
	LicenseNone            LicenseClass = "none"
	LicenseUnknown         LicenseClass = "unknown"
)

// KDBNodeRole pinned to host_arg_kdb.kdb_node_role.
type KDBNodeRole string

const (
	RoleFeedHandler KDBNodeRole = "feed-handler"
	RoleTickerplant KDBNodeRole = "tickerplant"
	RoleRDB         KDBNodeRole = "rdb"
	RoleHDB         KDBNodeRole = "hdb"
	RoleGateway     KDBNodeRole = "gateway"
	RoleClient      KDBNodeRole = "client"
	RoleMultiRole   KDBNodeRole = "multi-role"
	RoleUnknown     KDBNodeRole = "unknown"
)

// Row mirrors host_arg_kdb column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	AccountClass             AccountClass `json:"account_class"`
	ProductClass             ProductClass `json:"product_class"`
	LicenseClass             LicenseClass `json:"license_class,omitempty"`
	KDBNodeRole              KDBNodeRole  `json:"kdb_node_role,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	APIKeyHash               string       `json:"api_key_hash,omitempty"`
	UsernameHash             string       `json:"username_hash,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	DistinctTablesCount      int64        `json:"distinct_tables_count,omitempty"`
	HDBPartitionCount        int64        `json:"hdb_partition_count,omitempty"`
	HDBTotalBytes            int64        `json:"hdb_total_bytes,omitempty"`
	TplogRecordCount         int64        `json:"tplog_record_count,omitempty"`
	RPCHandlerCount          int64        `json:"rpc_handler_count,omitempty"`
	AutoloadChainDepth       int64        `json:"autoload_chain_depth,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasKXLicense             bool         `json:"has_kx_license"`
	HasQScript               bool         `json:"has_q_script"`
	HasKScript               bool         `json:"has_k_script"`
	HasTickDB                bool         `json:"has_tick_db"`
	HasLargeHDB              bool         `json:"has_large_hdb"`
	HasSubscriberConfig      bool         `json:"has_subscriber_config"`
	HasMATbaRofexTable       bool         `json:"has_matba_rofex_table"`
	HasCMEFuturesTable       bool         `json:"has_cme_futures_table"`
	HasUSEquityTable         bool         `json:"has_us_equity_table"`
	HasCryptoData            bool         `json:"has_crypto_data"`
	HasCrossVenueArb         bool         `json:"has_cross_venue_arb"`
	HasHFTPattern            bool         `json:"has_hft_pattern"`
	HasQRCAutoload           bool         `json:"has_qrc_autoload"`
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

// DefaultInstallRoots is the curated KDB+ install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\q`,
		`C:\kx`,
		`C:\Program Files\KX`,
		`C:\Program Files (x86)\KX`,
		"/opt/kx",
		"/opt/kdb",
		"/opt/q",
		"/data/hdb",
		"/data/rdb",
		"/data/kdb",
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

// UserKDBDirs is the curated per-user relative path set.
func UserKDBDirs() [][]string {
	return [][]string{
		{"q"},
		{"kdb"},
		{".kx"},
		{".q"},
		{"projects", "kdb"},
		{"projects", "q"},
		{"Documents", "KDB"},
		{"Documents", "q"},
		{"AppData", "Roaming", "KX"},
		{"AppData", "Local", "KX"},
		{"Library", "Application Support", "KX"},
		{"Descargas"},
		{"Downloads"},
	}
}

// MATbaRofexSymbols mirrors prior algotrading classifiers.
func MATbaRofexSymbols() []string {
	return []string{
		"DLR", "DOM", "ROS-DLR", "MTR-USD", "MTRUSD",
		"SOJ", "MAI", "TRI", "GIR", "SOR",
		"ROS20", "ROS-SOJ", "ROS-MAI", "ROS-TRI",
		"CER", "UVA", "CER-FUT", "UVA-FUT",
		"MERV", "MERVAL",
	}
}

// CMEFuturesSymbols mirrors prior algotrading classifiers.
func CMEFuturesSymbols() []string {
	return []string{
		"ES", "NQ", "YM", "RTY", "EMD",
		"6E", "6B", "6J", "6A", "6C", "6S", "6N", "6M",
		"DXY", "CL", "NG", "HO", "RB", "BZ",
		"GC", "SI", "HG", "PL", "PA",
		"ZC", "ZS", "ZW", "ZL", "ZM", "ZR",
		"ZN", "ZB", "ZF", "ZT", "UB",
		"BTC", "MBT", "ETH", "MET",
	}
}

// USEquityCommonStems mirrors prior US-equity classifiers.
func USEquityCommonStems() []string {
	return []string{
		"AAPL", "MSFT", "AMZN", "GOOGL", "GOOG", "META",
		"TSLA", "NVDA", "AMD", "INTC", "QCOM",
		"NFLX", "DIS", "BA", "JPM", "BAC", "WFC", "GS", "MS",
		"SPY", "QQQ", "IWM", "DIA", "VTI", "VOO", "ARKK",
		"MELI",
	}
}

// CryptoSymbols — common crypto stems and AR-specific pairs.
func CryptoSymbols() []string {
	return []string{
		"BTC", "ETH", "USDT", "USDC", "BNB", "SOL",
		"ADA", "XRP", "DOT", "AVAX", "MATIC",
		"USDT/ARS", "USDC/ARS", "BTC/ARS", "ETH/ARS",
		"USDT-ARS", "USDC-ARS", "BTC-ARS", "ETH-ARS",
		"USDTARS", "USDCARS", "BTCARS", "ETHARS",
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

// IsUSEquityStem reports membership.
func IsUSEquityStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range USEquityCommonStems() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCryptoSymbol reports membership.
func IsCryptoSymbol(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range CryptoSymbols() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries a
// KDB+/Q artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".q", ".k",
		".dat", ".par", ".idx", ".sym",
		".lic",
		".log", ".txt",
		".qrc",
		".cfg", ".ini", ".json", ".xml",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	// Special-case bare filenames with no extension that KDB+
	// uses: `sym`, `q.k`, `q.exe`, etc.
	switch strings.ToLower(filepath.Base(name)) {
	case "sym", ".d", "par.txt", "q.k", "qkdb", "qrc":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the KDB+/Q catalogue. The `.dat` extension is included
// because HDB column files have arbitrary basenames; the
// walker only descends curated KDB roots (~/q, /opt/kx,
// /data/hdb, etc.) so the false-positive blast radius is
// bounded.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".q", ".k", ".qrc", ".lic", ".dat":
		return true
	}
	switch n {
	case "sym", ".d", "par.txt", "q.k", ".qrc":
		return true
	}
	for _, tok := range []string{
		"kdb", "kx", "tplog", "tickerplant",
		"feed_handler", "feed-handler",
		"hdb", "rdb",
		"q.k", "qrc",
		"k4.lic", "kc.lic",
		"par.txt",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ArtifactKindFromName classifies a filename heuristically.
//
// Order matters: bare-filename HDB-meta files (`q.k`, `sym`,
// `par.txt`) win over the generic `.k` / `.q` extension
// switches because `q.k` is the canonical Q core library
// rather than a user K script.
func ArtifactKindFromName(name string) ArtifactKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch n {
	case "sym", "par.txt", "q.k", ".d":
		return KindHDBMeta
	}
	switch ext {
	case ".msi", ".exe", ".pkg", ".dmg":
		if strings.Contains(n, "kdb") || strings.Contains(n, "kx") ||
			n == "q.exe" {
			return KindInstaller
		}
		return KindOther
	case ".lic":
		if strings.Contains(n, "k4") || strings.Contains(n, "kc") ||
			strings.Contains(n, "kx") || strings.Contains(n, "kdb") {
			return KindLicense
		}
		return KindOther
	case ".q":
		return KindQScript
	case ".k":
		return KindKScript
	case ".qrc":
		return KindQRCStartup
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "tplog") || strings.Contains(n, "tp_log"):
		return KindTplog
	case strings.Contains(n, "feed_handler") ||
		strings.Contains(n, "feed-handler") ||
		strings.Contains(n, "subscriber") ||
		strings.Contains(n, "tickerplant"):
		return KindSubscriberConfig
	case strings.HasSuffix(n, ".dat"):
		return KindHDBColumn
	case strings.Contains(n, "kdb") || strings.Contains(n, "kx"):
		if ext == ".cfg" || ext == ".ini" || ext == ".json" ||
			ext == ".xml" {
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
		KindQScript, KindKScript,
		KindLicense, KindHDBMeta, KindTplog,
		KindQRCStartup, KindSubscriberConfig:
		return true
	case KindHDBColumn, KindInstaller, KindOther, KindUnknown:
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
	if r.ArtifactKind == KindQScript {
		r.HasQScript = true
	}
	if r.ArtifactKind == KindKScript {
		r.HasKScript = true
	}
	if r.ArtifactKind == KindLicense {
		r.HasKXLicense = true
	}
	if r.ArtifactKind == KindTplog {
		r.HasTickDB = true
	}
	if r.ArtifactKind == KindHDBColumn {
		r.HasTickDB = true
		if r.FileSize >= LargeHDBBytes {
			r.HasLargeHDB = true
		}
		if r.HDBTotalBytes == 0 {
			r.HDBTotalBytes = r.FileSize
		}
	}
	if r.ArtifactKind == KindSubscriberConfig {
		r.HasSubscriberConfig = true
	}
	if r.AutoloadChainDepth > 0 {
		r.HasQRCAutoload = true
	}
	// KDB+ presence (any script, license, tick DB, subscriber)
	// flags HFT pattern by default.
	if r.HasQScript || r.HasKScript || r.HasKXLicense ||
		r.HasTickDB || r.HasSubscriberConfig {
		r.HasHFTPattern = true
	}
	venueCount := 0
	for _, b := range []bool{
		r.HasMATbaRofexTable, r.HasCMEFuturesTable,
		r.HasUSEquityTable, r.HasCryptoData,
	} {
		if b {
			venueCount++
		}
	}
	if venueCount >= 2 {
		r.HasCrossVenueArb = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasKXLicense ||
		r.HasSubscriberConfig || r.HasClienteCuit
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
