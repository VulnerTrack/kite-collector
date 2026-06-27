// Package winargmaeonlinefx audits MAE OnlineFX OTC FX-trading
// artifact files cached on Argentine bank, ALYC, fintech,
// crypto-exchange, importer-exporter, and BCRA workstations
// across Windows, Linux, and macOS.
//
// MAE OnlineFX is the OTC FX trading platform on the MAE
// (Mercado Abierto Electrónico) — the *FX trading* leg of
// MAE, distinct from MAEclear (bond clearing) and SIOPEL
// (bond trading terminal).
//
// MAE OnlineFX product surface:
//
//   - USD/ARS Spot   — dolar mayorista (interbank).
//   - USD/ARS Forward — bilateral fwd contracts.
//   - USD/ARS NDF    — non-deliverable forwards.
//   - EUR/ARS Spot   — euro mayorista.
//   - BRL/ARS Spot   — cross-border with Brazil.
//   - USDT/ARS       — regulated crypto-FX (BCRA-PSAV).
//
// **The OTC FX trading layer.** Distinct from:
//
//   - iter 157 winargmaeclear     — MAE OTC bond clearing.
//   - iter 136 winargsiopel       — SIOPEL OTC bond terminal.
//   - iter 139 winargprimary      — Primary REST/WS futures.
//   - iter 100 winargbcraforex    — BCRA forex regulator side.
//   - iter 158 winargprismaweb    — BYMA equity clearing.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — terminal cleartext.
//   - `has_fix_drop_copy=1` — FIX drop-copy session.
//   - `has_usd_ars_spot=1` — dolar mayorista trades.
//   - `has_usd_ars_forward=1` — fwd contracts (BCRA scrutiny).
//   - `has_usd_ars_ndf=1` — NDF (capital flight signal).
//   - `has_usdt_ars_trading=1` — USDT/ARS (AFIP RG 5527 tap).
//   - `has_brl_ars_trading=1` — Brazil cross-border.
//   - `has_eur_ars_trading=1` — Euro mayorista.
//   - `has_high_volume_fx=1` — > USD 1 M daily volume.
//   - `has_bcra_above_cap=1` — > USD 200 K individual cap
//     (BCRA Com. A 7916 natural-person monthly).
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargmaeonlinefx

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

// BCRAIndividualCapUSDCents is the BCRA Com. A 7916
// natural-person monthly cap (USD 200 K = 20_000_000 cents).
const BCRAIndividualCapUSDCents = 20_000_000

// HighVolumeUSDCents is the per-file volume threshold above
// which the rollup flags high-volume FX (USD 1 M = 100 M cents).
const HighVolumeUSDCents = 100_000_000

// ArtifactKind pinned to host_arg_maeonlinefx.artifact_kind.
type ArtifactKind string

const (
	KindConfig       ArtifactKind = "mae-onlinefx-config"
	KindCredentials  ArtifactKind = "mae-onlinefx-credentials" //#nosec G101 -- ArtifactKind enum naming the MAE OnlineFX credentials artifact category, not a credential value
	KindQuotesCache  ArtifactKind = "mae-onlinefx-quotes-cache"
	KindTradeBlotter ArtifactKind = "mae-onlinefx-trade-blotter"
	KindForwardBook  ArtifactKind = "mae-onlinefx-forward-book"
	KindNDFBook      ArtifactKind = "mae-onlinefx-ndf-book"
	KindUSDTBook     ArtifactKind = "mae-onlinefx-usdt-book"
	KindSessionLog   ArtifactKind = "mae-onlinefx-session-log"
	KindFIXDropCopy  ArtifactKind = "mae-onlinefx-fix-drop-copy"
	KindInstaller    ArtifactKind = "mae-onlinefx-installer"
	KindOther        ArtifactKind = "other"
	KindUnknown      ArtifactKind = "unknown"
)

// ParticipantClass pinned to host_arg_maeonlinefx.participant_class.
type ParticipantClass string

const (
	ParticipantBank             ParticipantClass = "bank"
	ParticipantALYC             ParticipantClass = "alyc"
	ParticipantCriptoExchange   ParticipantClass = "cripto-exchange"
	ParticipantImporterExporter ParticipantClass = "importer-exporter"
	ParticipantFCIManager       ParticipantClass = "fci-manager"
	ParticipantBCRA             ParticipantClass = "bcra"
	ParticipantAuditor          ParticipantClass = "auditor"
	ParticipantDemo             ParticipantClass = "demo"
	ParticipantOther            ParticipantClass = "other"
	ParticipantUnknown          ParticipantClass = "unknown"
)

// Row mirrors host_arg_maeonlinefx column shape.
type Row struct {
	FilePath                  string           `json:"file_path"`
	FileHash                  string           `json:"file_hash"`
	UserProfile               string           `json:"user_profile,omitempty"`
	ArtifactKind              ArtifactKind     `json:"artifact_kind"`
	ParticipantClass          ParticipantClass `json:"participant_class"`
	ParticipantID             string           `json:"participant_id,omitempty"`
	ClienteCuitPrefix         string           `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4        string           `json:"cliente_cuit_suffix4,omitempty"`
	FIXSessionSender          string           `json:"fix_session_sender,omitempty"`
	FIXSessionTarget          string           `json:"fix_session_target,omitempty"`
	SessionFirstSeen          string           `json:"session_first_seen,omitempty"`
	SessionLastSeen           string           `json:"session_last_seen,omitempty"`
	PeriodYYYYMM              string           `json:"period_yyyymm,omitempty"`
	TradeCount                int64            `json:"trade_count,omitempty"`
	SpotTradeCount            int64            `json:"spot_trade_count,omitempty"`
	ForwardTradeCount         int64            `json:"forward_trade_count,omitempty"`
	NDFTradeCount             int64            `json:"ndf_trade_count,omitempty"`
	USDTTradeCount            int64            `json:"usdt_trade_count,omitempty"`
	BRLTradeCount             int64            `json:"brl_trade_count,omitempty"`
	EURTradeCount             int64            `json:"eur_trade_count,omitempty"`
	TotalVolumeUSDCents       int64            `json:"total_volume_usd_cents,omitempty"`
	AboveCapCount             int64            `json:"above_cap_count,omitempty"`
	DistinctCounterpartyCount int64            `json:"distinct_counterparty_count,omitempty"`
	FileOwnerUID              int              `json:"file_owner_uid,omitempty"`
	FileMode                  int              `json:"file_mode,omitempty"`
	FileSize                  int64            `json:"file_size,omitempty"`
	HasPasswordInConfig       bool             `json:"has_password_in_config"`
	HasFIXDropCopy            bool             `json:"has_fix_drop_copy"`
	HasUSDARSSpot             bool             `json:"has_usd_ars_spot"`
	HasUSDARSForward          bool             `json:"has_usd_ars_forward"`
	HasUSDARSNDF              bool             `json:"has_usd_ars_ndf"`
	HasUSDTARSTrading         bool             `json:"has_usdt_ars_trading"`
	HasBRLARSTrading          bool             `json:"has_brl_ars_trading"`
	HasEURARSTrading          bool             `json:"has_eur_ars_trading"`
	HasHighVolumeFX           bool             `json:"has_high_volume_fx"`
	HasBCRAAboveCap           bool             `json:"has_bcra_above_cap"`
	HasClienteCuit            bool             `json:"has_cliente_cuit"`
	IsRecent                  bool             `json:"is_recent"`
	IsWorldReadable           bool             `json:"is_world_readable"`
	IsGroupReadable           bool             `json:"is_group_readable"`
	IsCredentialExposureRisk  bool             `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated MAE OnlineFX install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\MAE\OnlineFX`,
		`C:\MAE_OnlineFX`,
		`C:\MAEOnlineFX`,
		`C:\Program Files\MAE\OnlineFX`,
		`C:\Program Files\MAE OnlineFX`,
		`C:\Program Files (x86)\MAE\OnlineFX`,
		`/opt/mae-onlinefx`,
		`/opt/mae/onlinefx`,
		`/Applications/MAE OnlineFX.app`,
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

// UserMAEOnlineFXDirs is the curated per-user relative path set.
func UserMAEOnlineFXDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "MAE", "OnlineFX"},
		{"AppData", "Roaming", "MAE OnlineFX"},
		{"AppData", "Local", "MAE", "OnlineFX"},
		{"AppData", "Local", "MAE OnlineFX"},
		{"Documents", "MAE", "OnlineFX"},
		{"Documents", "MAE OnlineFX"},
		{".mae-onlinefx"},
		{"Library", "Application Support", "MAE OnlineFX"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// MAE OnlineFX artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json", ".ini", ".cfg", ".conf",
		".yaml", ".yml",
		".log", ".txt", ".fix",
		".csv", ".tsv",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the MAE OnlineFX catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if ext == ".fix" {
		return true
	}
	for _, tok := range []string{
		"mae_onlinefx", "mae-onlinefx", "maeonlinefx", "onlinefx",
		"quotes_fx", "fx_quotes", "fx_blotter", "trade_blotter",
		"fwd_book", "forward_book", "ndf_book", "usdt_book",
		"drop_copy", "drop-copy", "dropcopy",
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
		if strings.Contains(n, "mae") || strings.Contains(n, "onlinefx") {
			return KindInstaller
		}
		return KindOther
	case ".fix":
		return KindFIXDropCopy
	}
	switch {
	case strings.Contains(n, "drop_copy") || strings.Contains(n, "drop-copy") ||
		strings.Contains(n, "dropcopy"):
		return KindFIXDropCopy
	case strings.Contains(n, "ndf_book") || strings.Contains(n, "ndf-book"):
		return KindNDFBook
	case strings.Contains(n, "usdt_book") || strings.Contains(n, "usdt-book"):
		return KindUSDTBook
	case strings.Contains(n, "fwd_book") || strings.Contains(n, "forward_book") ||
		strings.Contains(n, "forward-book"):
		return KindForwardBook
	case strings.Contains(n, "trade_blotter") || strings.Contains(n, "trade-blotter") ||
		strings.Contains(n, "fx_blotter") || strings.Contains(n, "blotter"):
		return KindTradeBlotter
	case strings.Contains(n, "quotes_fx") || strings.Contains(n, "fx_quotes") ||
		strings.Contains(n, "quotes"):
		return KindQuotesCache
	case strings.Contains(n, "session") &&
		(ext == ".log" || ext == ".txt"):
		return KindSessionLog
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_key") ||
		strings.Contains(n, "token"):
		return KindCredentials
	case (strings.Contains(n, "config") || strings.Contains(n, "settings") ||
		strings.Contains(n, "onlinefx")) &&
		(ext == ".xml" || ext == ".json" || ext == ".ini" || ext == ".cfg" ||
			ext == ".conf" || ext == ".yaml" || ext == ".yml"):
		return KindConfig
	}
	return KindOther
}

// FXProductPairs returns canonical MAE OnlineFX currency-pair
// stems. Matching is case-insensitive.
type FXProduct string

const (
	ProductUSDARSSpot    FXProduct = "USD/ARS-SPOT"
	ProductUSDARSForward FXProduct = "USD/ARS-FWD"
	ProductUSDARSNDF     FXProduct = "USD/ARS-NDF"
	ProductUSDTARSSpot   FXProduct = "USDT/ARS"
	ProductBRLARSSpot    FXProduct = "BRL/ARS"
	ProductEURARSSpot    FXProduct = "EUR/ARS"
	ProductOther         FXProduct = "other"
)

// USDARSSpotMarkers returns curated symbol markers.
func USDARSSpotMarkers() []string {
	return []string{
		"USD/ARS-SPOT", "USDARS-SPOT", "USD-ARS-SPOT",
		"USD/ARS", "USDARS",
		"DLR-SPOT", "DOLAR-MAYORISTA", "DLAR-MAYORISTA",
	}
}

// USDARSForwardMarkers returns curated forward markers.
func USDARSForwardMarkers() []string {
	return []string{
		"USD/ARS-FWD", "USDARS-FWD", "USD-ARS-FORWARD",
		"USD/ARS-FORWARD",
		"DLR-FWD", "DOLAR-FORWARD",
		"FWD-USD-ARS", "FWD-USDARS",
	}
}

// USDARSNDFMarkers returns curated NDF markers.
func USDARSNDFMarkers() []string {
	return []string{
		"USD/ARS-NDF", "USDARS-NDF", "USD-ARS-NDF",
		"NDF-USD-ARS", "NDF-USDARS",
		"DLR-NDF", "DOLAR-NDF",
	}
}

// USDTARSMarkers returns curated USDT/ARS markers.
func USDTARSMarkers() []string {
	return []string{
		"USDT/ARS", "USDTARS", "USDT-ARS",
		"TETHER/ARS", "STABLE-ARS",
	}
}

// BRLARSMarkers returns curated BRL/ARS markers.
func BRLARSMarkers() []string {
	return []string{
		"BRL/ARS", "BRLARS", "BRL-ARS",
		"REAL-ARS", "BRL-FX",
	}
}

// EURARSMarkers returns curated EUR/ARS markers.
func EURARSMarkers() []string {
	return []string{
		"EUR/ARS", "EURARS", "EUR-ARS",
		"EURO-ARS", "EUR-FX",
	}
}

// hasAnyMarker reports whether body contains any of the
// curated markers (case-insensitive substring).
func hasAnyMarker(body []byte, markers []string) bool {
	low := strings.ToLower(string(body))
	for _, m := range markers {
		if strings.Contains(low, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// HasUSDARSSpotMarker / etc. are convenience checks.
func HasUSDARSSpotMarker(body []byte) bool {
	return hasAnyMarker(body, USDARSSpotMarkers())
}

// HasUSDARSForwardMarker reports forward markers.
func HasUSDARSForwardMarker(body []byte) bool {
	return hasAnyMarker(body, USDARSForwardMarkers())
}

// HasUSDARSNDFMarker reports NDF markers.
func HasUSDARSNDFMarker(body []byte) bool {
	return hasAnyMarker(body, USDARSNDFMarkers())
}

// HasUSDTARSMarker reports USDT markers.
func HasUSDTARSMarker(body []byte) bool {
	return hasAnyMarker(body, USDTARSMarkers())
}

// HasBRLARSMarker reports BRL markers.
func HasBRLARSMarker(body []byte) bool {
	return hasAnyMarker(body, BRLARSMarkers())
}

// HasEURARSMarker reports EUR markers.
func HasEURARSMarker(body []byte) bool {
	return hasAnyMarker(body, EURARSMarkers())
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

// cuitScanRE uses word boundaries so adjacent CUITs separated
// only by `\n` still match (FindAll non-overlapping).
var cuitScanRE = regexp.MustCompile(`\b(\d{2})-?(\d{8})-?(\d)\b`)

// DistinctCounterpartiesInBody returns the count of distinct
// valid CUITs.
func DistinctCounterpartiesInBody(body []byte) int64 {
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

// participantRE matches a MAE participant ID. Char class
// includes `>` so XML tag-form is matched alongside INI/JSON.
var participantRE = regexp.MustCompile(
	`(?i)(?:participant[_\- ]?id|participante|mae[_\- ]?id|bank[_\- ]?id|alyc[_\- ]?id|matr[íi]cula)["'>\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// ParticipantIDFromText extracts a participant ID.
func ParticipantIDFromText(text string) string {
	m := participantRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
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
	case KindConfig, KindCredentials, KindTradeBlotter,
		KindForwardBook, KindNDFBook, KindUSDTBook,
		KindFIXDropCopy, KindSessionLog:
		return true
	case KindQuotesCache, KindInstaller, KindOther, KindUnknown:
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
	if r.SpotTradeCount > 0 {
		r.HasUSDARSSpot = true
	}
	if r.ForwardTradeCount > 0 {
		r.HasUSDARSForward = true
	}
	if r.NDFTradeCount > 0 {
		r.HasUSDARSNDF = true
	}
	if r.USDTTradeCount > 0 {
		r.HasUSDTARSTrading = true
	}
	if r.BRLTradeCount > 0 {
		r.HasBRLARSTrading = true
	}
	if r.EURTradeCount > 0 {
		r.HasEURARSTrading = true
	}
	if r.TotalVolumeUSDCents >= HighVolumeUSDCents {
		r.HasHighVolumeFX = true
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
