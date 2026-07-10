// Package winargbymadata audits Bymadata market-data feed
// artifact files cached on Argentine quant, prop-desk, ALYC,
// and FCI-manager workstations across Windows, Linux, and
// macOS.
//
// Bymadata is BYMA's official paid market-data product —
// the canonical real-time + historical feed for ARS-listed
// equity, options, fixed-income, and indices. It is the
// upstream data vendor that every broker/quant collector
// depends on.
//
// Distribution surfaces:
//
//   - FIX-FAST 5.0   institutional / vendor tier
//   - WebSocket      real-time streaming for retail/quant
//   - REST snapshot  daily/period batch
//   - Decsis-built Bloomberg-like terminal GUI
//   - Bymadata Vendor SDK (Python/Java/C#)
//
// **The market-data-vendor layer.** Distinct from:
//
//   - iter 109 winargmatbarofex   — futures positions/orders
//   - iter 139 winargprimary      — Primary REST/WS routing
//   - iter 150 winargpyhomebroker — portal scrape lib
//   - iter 155 winarghomebroker   — Decsis HB terminal
//   - iter 151/152/154 retail brokers
//
// Subscription tiers (CNV RG 731 art. 50 licensing):
//
//   - basic           top-of-book ARS equity only
//   - profesional     full depth-of-book + options
//   - internacional   ARS + LATAM mirror feeds
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — config cleartext.
//   - `has_api_key=1` — bymadata API key leak.
//   - `has_fix_fast_session=1` — institutional FIX-FAST.
//   - `has_websocket_session=1` — WS streaming session.
//   - `has_depth_of_book=1` — Level-2 (premium tier).
//   - `has_international_tier=1` — internacional sub.
//   - `has_historical_download=1` — bulk historical CSV.
//   - `has_high_message_rate=1` — > 1000 msg/s HFT pattern.
//   - `has_license_sharing_risk=1` — > 1 distinct CUIT in
//     same cache (CNV RG 731 art. 50 violation concern).
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR api key OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargbymadata

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

// HighMessageRateThreshold defines the msg/s threshold above
// which a WS / FIX-FAST log is flagged as HFT-pattern.
const HighMessageRateThreshold = 1000

// HistoricalRowsThreshold defines the per-file row count
// above which a CSV is flagged as a bulk historical download.
const HistoricalRowsThreshold = 1000

// LicenseSharingThreshold defines the # of distinct CUITs in
// the same cache above which the rollup flags license-share.
const LicenseSharingThreshold = 2

// ArtifactKind pinned to host_arg_bymadata.artifact_kind.
type ArtifactKind string

const (
	KindConfig         ArtifactKind = "bymadata-config"
	KindCredentials    ArtifactKind = "bymadata-credentials" //#nosec G101 -- ArtifactKind enum naming the BYMAdata credentials artifact category, not a credential value
	KindFIXFASTLog     ArtifactKind = "bymadata-fix-fast-log"
	KindWSLog          ArtifactKind = "bymadata-ws-log"
	KindRESTCache      ArtifactKind = "bymadata-rest-cache"
	KindHistoricalCSV  ArtifactKind = "bymadata-historical-csv"
	KindSDKScript      ArtifactKind = "bymadata-sdk-script"
	KindTerminalConfig ArtifactKind = "bymadata-terminal-config"
	KindInstaller      ArtifactKind = "bymadata-installer"
	KindOther          ArtifactKind = "other"
	KindUnknown        ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_bymadata.account_class.
type AccountClass string

const (
	AccountVendor           AccountClass = "vendor"
	AccountMarketMaker      AccountClass = "market-maker"
	AccountFCIManager       AccountClass = "fci-manager"
	AccountQuant            AccountClass = "quant"
	AccountRetailAggregator AccountClass = "retail-aggregator"
	AccountDemo             AccountClass = "demo"
	AccountOther            AccountClass = "other"
	AccountUnknown          AccountClass = "unknown"
)

// SubscriptionTier pinned to host_arg_bymadata.subscription_tier.
type SubscriptionTier string

const (
	TierBasic         SubscriptionTier = "basic"
	TierProfesional   SubscriptionTier = "profesional"
	TierInternacional SubscriptionTier = "internacional"
	TierOther         SubscriptionTier = "other"
	TierUnknown       SubscriptionTier = "unknown"
)

// Row mirrors host_arg_bymadata column shape.
type Row struct {
	FilePath                 string           `json:"file_path"`
	FileHash                 string           `json:"file_hash"`
	UserProfile              string           `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind     `json:"artifact_kind"`
	AccountClass             AccountClass     `json:"account_class"`
	SubscriptionTier         SubscriptionTier `json:"subscription_tier"`
	LicenseeCuitPrefix       string           `json:"licensee_cuit_prefix,omitempty"`
	LicenseeCuitSuffix4      string           `json:"licensee_cuit_suffix4,omitempty"`
	APIKeyHash               string           `json:"api_key_hash,omitempty"`
	UsernameHash             string           `json:"username_hash,omitempty"`
	FIXSessionSender         string           `json:"fix_session_sender,omitempty"`
	FIXSessionTarget         string           `json:"fix_session_target,omitempty"`
	SessionFirstSeen         string           `json:"session_first_seen,omitempty"`
	SessionLastSeen          string           `json:"session_last_seen,omitempty"`
	PeriodYYYYMM             string           `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount     int64            `json:"distinct_symbols_count,omitempty"`
	DistinctCuitCount        int64            `json:"distinct_cuit_count,omitempty"`
	MessageCount             int64            `json:"message_count,omitempty"`
	PeakMsgPerSec            int64            `json:"peak_msg_per_sec,omitempty"`
	HistoricalRowsCount      int64            `json:"historical_rows_count,omitempty"`
	FileOwnerUID             int              `json:"file_owner_uid,omitempty"`
	FileMode                 int              `json:"file_mode,omitempty"`
	FileSize                 int64            `json:"file_size,omitempty"`
	HasPasswordInConfig      bool             `json:"has_password_in_config"`
	HasAPIKey                bool             `json:"has_api_key"`
	HasFIXFASTSession        bool             `json:"has_fix_fast_session"`
	HasWebsocketSession      bool             `json:"has_websocket_session"`
	HasDepthOfBook           bool             `json:"has_depth_of_book"`
	HasInternationalTier     bool             `json:"has_international_tier"`
	HasHistoricalDownload    bool             `json:"has_historical_download"`
	HasHighMessageRate       bool             `json:"has_high_message_rate"`
	HasLicenseSharingRisk    bool             `json:"has_license_sharing_risk"`
	HasClienteCuit           bool             `json:"has_cliente_cuit"`
	IsRecent                 bool             `json:"is_recent"`
	IsWorldReadable          bool             `json:"is_world_readable"`
	IsGroupReadable          bool             `json:"is_group_readable"`
	IsCredentialExposureRisk bool             `json:"is_credential_exposure_risk"`
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

// HashSecret returns the SHA-256 hex of a normalized secret
// (lowercase, trimmed). Use for token / username persistence.
func HashSecret(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated Bymadata install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Bymadata`,
		`C:\Bymadata\Terminal`,
		`C:\BYMA\Bymadata`,
		`C:\Program Files\Bymadata`,
		`C:\Program Files\BYMA\Bymadata`,
		`C:\Program Files (x86)\Bymadata`,
		`/opt/bymadata`,
		`/opt/byma-bymadata`,
		`/Applications/Bymadata.app`,
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

// UserBymadataDirs is the curated per-user relative path set.
func UserBymadataDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Bymadata"},
		{"AppData", "Local", "Bymadata"},
		{"Documents", "Bymadata"},
		{"Documents", "bymadata-sdk"},
		{".bymadata"},
		{"bymadata-sdk"},
		{"Library", "Application Support", "Bymadata"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// Bymadata artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json", ".xml", ".ini", ".cfg", ".conf",
		".yaml", ".yml",
		".log", ".txt", ".fix",
		".csv", ".tsv", ".parquet",
		".py", ".ipynb", ".jar",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Bymadata catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"bymadata", "byma_data", "byma-data",
		"fix_fast", "fix-fast", "fixfast",
		"bymadata_sdk", "bymadata-sdk",
		"bymadata_ws", "bymadata-ws",
		"bymadata_rest", "bymadata-rest",
		"bymadata_historical", "bymadata-historical",
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
		if strings.Contains(n, "bymadata") || strings.Contains(n, "byma") {
			return KindInstaller
		}
		return KindOther
	case ".py", ".ipynb", ".jar":
		return KindSDKScript
	case ".csv", ".tsv", ".parquet":
		if strings.Contains(n, "historical") || strings.Contains(n, "histor") ||
			strings.Contains(n, "eod") || strings.Contains(n, "diario") {
			return KindHistoricalCSV
		}
		return KindOther
	}
	switch {
	case (strings.Contains(n, "fix") && strings.Contains(n, "fast")) ||
		strings.Contains(n, "fixfast"):
		return KindFIXFASTLog
	case strings.Contains(n, "ws") &&
		(ext == ".log" || ext == ".txt"):
		return KindWSLog
	case strings.Contains(n, "websocket"):
		return KindWSLog
	case strings.Contains(n, "rest") &&
		(ext == ".json" || ext == ".log"):
		return KindRESTCache
	case strings.Contains(n, "snapshot") ||
		strings.Contains(n, "snap_"):
		return KindRESTCache
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_key") ||
		strings.Contains(n, "apikey") ||
		strings.Contains(n, "vendor_key"):
		return KindCredentials
	case strings.Contains(n, "terminal") &&
		(ext == ".xml" || ext == ".json" || ext == ".ini"):
		return KindTerminalConfig
	case (strings.Contains(n, "config") || strings.Contains(n, "settings")) &&
		(ext == ".json" || ext == ".xml" || ext == ".ini" || ext == ".cfg" ||
			ext == ".conf" || ext == ".yaml" || ext == ".yml"):
		return KindConfig
	}
	return KindOther
}

// basicTierRE matches a basic-tier marker.
var basicTierRE = regexp.MustCompile(
	`(?i)"tier"\s*:\s*"basic"|\btier\s*=\s*basic\b|top_of_book|\blevel[_]?1\b`,
)

// SubscriptionTierFromBody classifies a body's subscription
// tier from per-feed markers.
func SubscriptionTierFromBody(body []byte) SubscriptionTier {
	low := strings.ToLower(string(body))
	switch {
	case strings.Contains(low, "internacional") ||
		strings.Contains(low, "international") ||
		strings.Contains(low, "latam_mirror"):
		return TierInternacional
	case strings.Contains(low, "profesional") ||
		strings.Contains(low, "professional") ||
		strings.Contains(low, "depth_of_book") ||
		strings.Contains(low, "level2") ||
		strings.Contains(low, "level_2") ||
		strings.Contains(low, "full_book"):
		return TierProfesional
	case basicTierRE.Match(body):
		return TierBasic
	}
	return TierUnknown
}

// HasDepthOfBookMarker reports whether body shows depth-of-
// book / Level-2 markers (premium tier).
func HasDepthOfBookMarker(body []byte) bool {
	low := strings.ToLower(string(body))
	for _, m := range []string{
		"depth_of_book", "depthofbook",
		"level2", "level_2", "level-2",
		"full_book", "marketdepth", "market_depth",
	} {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// HasInternationalMarker reports whether body shows the
// internacional-tier feed marker.
func HasInternationalMarker(body []byte) bool {
	low := strings.ToLower(string(body))
	for _, m := range []string{
		"internacional", "international",
		"latam_mirror", "latam-mirror",
		"b3_mirror", "b3-mirror", "bovespa_mirror",
	} {
		if strings.Contains(low, m) {
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

// cuitScanRE uses word-boundaries so adjacent CUITs separated
// only by `\n` still match (FindAll non-overlapping).
var cuitScanRE = regexp.MustCompile(`\b(\d{2})-?(\d{8})-?(\d)\b`)

// DistinctCuitsInBody returns the count of distinct valid
// CUITs found in body (used for license-sharing rollup).
func DistinctCuitsInBody(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range cuitScanRE.FindAllSubmatch(body, -1) {
		prefix := string(m[1])
		if !IsValidCuitEntityPrefix(prefix) {
			continue
		}
		key := prefix + string(m[2]) + string(m[3])
		seen[key] = struct{}{}
	}
	return int64(len(seen))
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
	case KindConfig, KindCredentials, KindTerminalConfig,
		KindFIXFASTLog, KindWSLog, KindRESTCache:
		return true
	case KindHistoricalCSV, KindSDKScript, KindInstaller,
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
	if r.LicenseeCuitPrefix != "" {
		r.HasClienteCuit = true
	}
	if r.PeakMsgPerSec >= HighMessageRateThreshold {
		r.HasHighMessageRate = true
	}
	if r.HistoricalRowsCount >= HistoricalRowsThreshold {
		r.HasHistoricalDownload = true
	}
	if r.DistinctCuitCount >= LicenseSharingThreshold {
		r.HasLicenseSharingRisk = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasAPIKey || r.HasClienteCuit
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
