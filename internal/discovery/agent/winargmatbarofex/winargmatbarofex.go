// Package winargmatbarofex audits Argentine MATba-Rofex
// (Mercado a Término de Buenos Aires - Rosario Futures
// Exchange) commodity + financial-futures files cached on
// broker, commodity-trader, and proprietary-desk workstations
// across Windows, Linux, and macOS.
//
// MATba-Rofex handles agropecuarios (Trigo / Soja / Maíz /
// Girasol / Sorgo / Cebada) + financieros (DLR / DOM / ROS20
// / Oro). Specie codes follow `<COMMODITY><MONTH><YEAR>`
// pattern: WK24=Trigo julio 24, SJN24=Soja noviembre 24,
// MZA24=Maíz abril 24.
//
// **The agropecuarios + financial-derivatives layer.** Pairs
// with iter 107 winargcnvalyc (ALYC regulatory layer) +
// iter 108 winalgotrading (FIX/EA technical layer) for the
// complete broker-desk capital-market asset picture.
//
// Headline finding shapes:
//
//   - `is_speculative_size=1` — position contracts above the
//     curated hedge-typical threshold per commodity.
//   - `has_margin_call=1` — file contains margin-call /
//     llamada-de-margen markers.
//   - `has_concentration=1` — single contract month
//     concentrates the position.
//   - `has_foreign_currency_notional=1` — DLR / DOM futures
//     or USD-denominated underlying.
//   - `is_credential_exposure_risk=1` — readable file +
//     cliente cuenta CUIT present.
//
// All CUITs reduced to entity-type prefix + last 4 digits.
//
// Read-only by intent. (Project guideline 4.2.)
package winargmatbarofex

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
const MaxFileBytes = 8 << 20 // 8 MiB

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// ArtifactKind pinned to host_matba_rofex_derivatives.artifact_kind.
type ArtifactKind string

const (
	KindSettlementDaily   ArtifactKind = "settlement-daily"
	KindPositionReport    ArtifactKind = "position-report"
	KindContractSpec      ArtifactKind = "contract-spec"
	KindMarginRequirement ArtifactKind = "margin-requirement"
	KindTradeConfirmation ArtifactKind = "trade-confirmation"
	KindOptionsGreeks     ArtifactKind = "options-greeks"
	KindOther             ArtifactKind = "other"
	KindUnknown           ArtifactKind = "unknown"
)

// Commodity pinned to host_matba_rofex_derivatives.commodity.
type Commodity string

const (
	CommTrigo   Commodity = "trigo"
	CommSoja    Commodity = "soja"
	CommMaiz    Commodity = "maiz"
	CommGirasol Commodity = "girasol"
	CommSorgo   Commodity = "sorgo"
	CommCebada  Commodity = "cebada"
	CommDLR     Commodity = "dlr"
	CommDOM     Commodity = "dom"
	CommROS20   Commodity = "ros20"
	CommOro     Commodity = "oro"
	CommOther   Commodity = "other"
	CommUnknown Commodity = "unknown"
)

// HedgeThresholdContracts is the curated heuristic threshold
// per commodity above which a position is considered
// speculative (not a normal hedge).
func HedgeThresholdContracts() map[Commodity]int {
	return map[Commodity]int{
		CommTrigo:   50,
		CommSoja:    40,
		CommMaiz:    50,
		CommGirasol: 30,
		CommSorgo:   30,
		CommCebada:  30,
		// Financial futures — much higher threshold since
		// these are commonly used for FX hedging by corporates.
		CommDLR:   500,
		CommDOM:   500,
		CommROS20: 200,
		CommOro:   100,
	}
}

// Row mirrors host_matba_rofex_derivatives' column shape.
type Row struct {
	AccountCuitPrefix          string       `json:"account_cuit_prefix,omitempty"`
	BrokerMatricula            string       `json:"broker_matricula,omitempty"`
	PeriodYYYYMM               string       `json:"period_yyyymm,omitempty"`
	FilePath                   string       `json:"file_path"`
	FileHash                   string       `json:"file_hash"`
	UserProfile                string       `json:"user_profile,omitempty"`
	ArtifactKind               ArtifactKind `json:"artifact_kind"`
	Commodity                  Commodity    `json:"commodity"`
	ContractMonth              string       `json:"contract_month,omitempty"`
	AccountCuitSuffix4         string       `json:"account_cuit_suffix4,omitempty"`
	BrokerCuitPrefix           string       `json:"broker_cuit_prefix,omitempty"`
	BrokerCuitSuffix4          string       `json:"broker_cuit_suffix4,omitempty"`
	FileOwnerUID               int          `json:"file_owner_uid,omitempty"`
	OpenPositionContracts      int          `json:"open_position_contracts,omitempty"`
	FileMode                   int          `json:"file_mode,omitempty"`
	NotionalUSDCents           int64        `json:"notional_usd_cents,omitempty"`
	FileSize                   int64        `json:"file_size,omitempty"`
	IsRecent                   bool         `json:"is_recent"`
	HasMarginCall              bool         `json:"has_margin_call"`
	HasConcentration           bool         `json:"has_concentration"`
	HasForeignCurrencyNotional bool         `json:"has_foreign_currency_notional"`
	IsSpeculativeSize          bool         `json:"is_speculative_size"`
	IsWorldReadable            bool         `json:"is_world_readable"`
	IsGroupReadable            bool         `json:"is_group_readable"`
	IsCredentialExposureRisk   bool         `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated MATba-Rofex install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\MATBA-Rofex`,
		`C:\MATBA`,
		`C:\Rofex`,
		`C:\ROFEX`,
		`C:\Program Files\Rofex`,
		`/opt/matba-rofex`,
		`/opt/rofex`,
		`/srv/matba-rofex`,
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

// UserMatbaDirs is the curated per-user relative path set.
func UserMatbaDirs() [][]string {
	return [][]string{
		{"Documents", "MATBA-Rofex"},
		{"Documents", "Rofex"},
		{"Documents", "ROFEX"},
		{"Documents", "Derivados"},
		{"Documents", "Futuros"},
		{"Documents", "Trading", "MATBA"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateExt reports whether the extension carries a
// MATba-Rofex artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".csv", ".xml", ".json", ".txt", ".con":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the MATba-Rofex catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"matba", "rofex", "matbarofex", "matba-rofex",
		"settlement", "posiciones_", "posiciones-",
		"contratos_", "contratos-", "garantia_",
		"derivados", "futuros_", "futuros-",
		"trigo_", "soja_", "maiz_", "girasol_",
		"dlr_", "dom_", "ros20",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	if ext := strings.ToLower(filepath.Ext(n)); ext == ".con" {
		return true
	}
	return false
}

// ArtifactKindFromName classifies a filename heuristically.
func ArtifactKindFromName(name string) ArtifactKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "settlement"):
		return KindSettlementDaily
	case strings.Contains(n, "posiciones"):
		return KindPositionReport
	case strings.Contains(n, "contratos") ||
		strings.HasSuffix(n, ".con"):
		return KindContractSpec
	case strings.Contains(n, "garantia") || strings.Contains(n, "margen"):
		return KindMarginRequirement
	case strings.Contains(n, "trade_confirm") || strings.Contains(n, "confirmacion_trade"):
		return KindTradeConfirmation
	case strings.Contains(n, "greeks") || strings.Contains(n, "opciones_"):
		return KindOptionsGreeks
	case strings.Contains(n, "matba") || strings.Contains(n, "rofex") ||
		strings.Contains(n, "derivados") || strings.Contains(n, "futuros"):
		return KindOther
	}
	return KindUnknown
}

// CommodityFromText classifies a commodity from filename or
// specie code (WK/SJN/MZA/GIR/SOR/CEB/DLR/DOM/ROS20/ORO).
func CommodityFromText(text string) Commodity {
	t := strings.ToLower(text)
	switch {
	case t == "":
		return CommUnknown
	case strings.Contains(t, "trigo") || hasSpeciePrefix(t, "wk"):
		return CommTrigo
	case strings.Contains(t, "soja") || hasSpeciePrefix(t, "sjn") ||
		hasSpeciePrefix(t, "sj"):
		return CommSoja
	case strings.Contains(t, "maiz") || strings.Contains(t, "maíz") ||
		hasSpeciePrefix(t, "mza") || hasSpeciePrefix(t, "mz"):
		return CommMaiz
	case strings.Contains(t, "girasol") || hasSpeciePrefix(t, "gir"):
		return CommGirasol
	case strings.Contains(t, "sorgo") || hasSpeciePrefix(t, "sor"):
		return CommSorgo
	case strings.Contains(t, "cebada") || hasSpeciePrefix(t, "ceb"):
		return CommCebada
	case strings.Contains(t, "ros20"):
		return CommROS20
	case strings.Contains(t, "dlr_") || strings.Contains(t, "dlr-") ||
		strings.HasPrefix(t, "dlr") || strings.Contains(t, "_dlr") ||
		strings.Contains(t, "dolar_futuro") || strings.Contains(t, "dolar-futuro"):
		return CommDLR
	case strings.Contains(t, "_dom") || strings.Contains(t, "dom_") ||
		strings.HasPrefix(t, "dom") || strings.Contains(t, "dolar-mayorista"):
		return CommDOM
	case strings.Contains(t, "oro") || hasSpeciePrefix(t, "oro"):
		return CommOro
	}
	return CommOther
}

// hasSpeciePrefix reports whether `t` contains a token that
// starts with `prefix` followed by 2-4 digits (year+month).
func hasSpeciePrefix(t, prefix string) bool {
	idx := 0
	for idx < len(t) {
		pos := strings.Index(t[idx:], prefix)
		if pos < 0 {
			return false
		}
		end := idx + pos + len(prefix)
		if end < len(t) {
			c := t[end]
			if c >= '0' && c <= '9' {
				return true
			}
		}
		idx = idx + pos + len(prefix)
	}
	return false
}

// IsForeignCurrencyCommodity reports whether the commodity has
// foreign-currency notional.
func IsForeignCurrencyCommodity(c Commodity) bool {
	switch c {
	case CommDLR, CommDOM:
		return true
	case CommTrigo, CommSoja, CommMaiz, CommGirasol,
		CommSorgo, CommCebada, CommROS20, CommOro,
		CommOther, CommUnknown:
		return false
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

// cuitRE matches 11-digit CUIT (hyphen-optional) bounded by
// non-digit / edges.
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

// matriculaRE matches CNV broker matrícula in text.
var matriculaRE = regexp.MustCompile(`(?i)(?:matr[íi]cula|mat[\.\-]?cnv|broker[_-]matricula)[\s:#=\w\.\-]{0,30}?(\d{2,5})`)

// MatriculaFromText extracts the CNV broker matrícula.
func MatriculaFromText(text string) string {
	m := matriculaRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// contractMonthRE matches `MM-YYYY` or `MM/YYYY` or `YYYY-MM`.
var contractMonthRE = regexp.MustCompile(`(\d{2})[/-](20\d{2})|(20\d{2})[/-](\d{2})`)

// ContractMonthFromText extracts contract month from text.
func ContractMonthFromText(text string) string {
	m := contractMonthRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	if m[1] != "" {
		return m[1] + "-" + m[2]
	}
	return m[4] + "-" + m[3]
}

// periodRE matches YYYYMM in filename.
var periodRE = regexp.MustCompile(`(20\d{2})[-_]?(0[1-9]|1[0-2])`)

// PeriodFromName extracts YYYYMM from filename.
func PeriodFromName(name string) string {
	m := periodRE.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// IsSpeculativePosition reports whether `contracts` exceeds
// the hedge-typical threshold for the commodity.
func IsSpeculativePosition(commodity Commodity, contracts int) bool {
	threshold, ok := HedgeThresholdContracts()[commodity]
	if !ok {
		return false
	}
	return contracts > threshold
}

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if IsSpeculativePosition(r.Commodity, r.OpenPositionContracts) {
		r.IsSpeculativeSize = true
	}
	r.HasForeignCurrencyNotional = IsForeignCurrencyCommodity(r.Commodity)
	// PII exposure: cliente cuenta CUIT present + readable.
	if r.AccountCuitPrefix != "" && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].Commodity != rs[j].Commodity {
			return rs[i].Commodity < rs[j].Commodity
		}
		return rs[i].ContractMonth < rs[j].ContractMonth
	})
}
