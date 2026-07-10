// Package winargccp audits Argentine CCP (Central Counter-
// party / Cámara Compensadora) margin + settlement files
// cached on clearing-member, ALYC broker, prop-desk, and
// back-office workstations across Windows, Linux, and macOS.
//
// Argentine clearing houses:
//
//	Argentina Clearing y Compensación (ACyC)   ROFEX CCP
//	BYMA CCA (Cámara Compensadora de Activos)  equity + bonds
//	CVSA Garantías                             collateral mgmt
//	MAEClear                                   MAE post-trade
//
// **The CCP / clearing-house layer.** Distinct from:
//
//   - iter 109 winargmatbarofex — MATba-Rofex positions
//   - iter 113 winargfix        — raw FIX session logs
//   - iter 117 winargcvsa       — CVSA cash custody
//   - iter 137 winargbyma       — BYMA equity terminal
//   - iter 139 winargprimary    — Primary REST/WS order entry
//
// Headline finding shapes:
//
//   - `has_margin_call_active=1` — file has active margin
//     call (clearing member must post collateral).
//   - `has_collateral_shortfall=1` — initial margin posted
//     < required margin.
//   - `has_high_haircut=1` — single-asset haircut > 50 %.
//   - `has_negative_balance=1` — compensador balance < 0.
//   - `has_stress_test_breach=1` — stress test failed.
//   - `is_credential_exposure_risk=1` — readable file +
//     cliente CUIT + (margin OR settlement body).
//
// Read-only by intent. (Project guideline 4.2.)
package winargccp

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

// MaxFileBytes bounds per-file read. CCP settlement files
// rarely exceed 8 MiB.
const MaxFileBytes = 16 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// HighHaircutPct — CNV Reglamento Operativo Art. 47 default-
// risk-tightening threshold for single-asset collateral.
const HighHaircutPct = 50

// ArtifactKind pinned to host_arg_ccp.artifact_kind.
type ArtifactKind string

const (
	KindMarginCollateral      ArtifactKind = "ccp-margin-collateral"
	KindMarginCall            ArtifactKind = "ccp-margin-call"
	KindDailySettlement       ArtifactKind = "ccp-daily-settlement"
	KindHaircutTable          ArtifactKind = "ccp-haircut-table"
	KindClearingMemberBalance ArtifactKind = "ccp-clearing-member-balance"
	KindDefaultFund           ArtifactKind = "ccp-default-fund"
	KindHaircutFactor         ArtifactKind = "ccp-haircut-factor"
	KindStressTest            ArtifactKind = "ccp-stress-test"
	KindInstaller             ArtifactKind = "ccp-installer"
	KindOther                 ArtifactKind = "other"
	KindUnknown               ArtifactKind = "unknown"
)

// CCPEntity pinned to host_arg_ccp.ccp_entity.
type CCPEntity string

const (
	CCPArgentinaClearing    CCPEntity = "argentina-clearing"
	CCPBYMACCA              CCPEntity = "byma-cca"
	CCPCajaValoresGarantias CCPEntity = "caja-valores-garantias"
	CCPMAEClear             CCPEntity = "maeclear"
	CCPOther                CCPEntity = "other"
	CCPUnknown              CCPEntity = "unknown"
)

// AssetClass pinned to host_arg_ccp.asset_class.
type AssetClass string

const (
	AssetFuturesFinancial AssetClass = "futures-financial"
	AssetFuturesAgro      AssetClass = "futures-agro"
	AssetEquityRV         AssetClass = "equity-rv"
	AssetBondsRF          AssetClass = "bonds-rf"
	AssetCaucionRepo      AssetClass = "caucion-repo"
	AssetOptions          AssetClass = "options"
	AssetOther            AssetClass = "other"
	AssetUnknown          AssetClass = "unknown"
)

// Row mirrors host_arg_ccp column shape.
type Row struct {
	FilePath                     string       `json:"file_path"`
	FileHash                     string       `json:"file_hash"`
	UserProfile                  string       `json:"user_profile,omitempty"`
	ArtifactKind                 ArtifactKind `json:"artifact_kind"`
	CCPEntity                    CCPEntity    `json:"ccp_entity"`
	AssetClass                   AssetClass   `json:"asset_class"`
	ClearingMemberMatricula      string       `json:"clearing_member_matricula,omitempty"`
	ClienteCuitPrefix            string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4           string       `json:"cliente_cuit_suffix4,omitempty"`
	SettlementDate               string       `json:"settlement_date,omitempty"`
	PeriodYYYYMM                 string       `json:"period_yyyymm,omitempty"`
	MarginRequiredARSCents       int64        `json:"margin_required_ars_cents,omitempty"`
	MarginPostedARSCents         int64        `json:"margin_posted_ars_cents,omitempty"`
	MarginCallARSCents           int64        `json:"margin_call_ars_cents,omitempty"`
	MaxHaircutPct                int          `json:"max_haircut_pct,omitempty"`
	CompensadorBalanceCents      int64        `json:"compensador_balance_cents,omitempty"`
	DefaultFundContributionCents int64        `json:"default_fund_contribution_cents,omitempty"`
	StressTestVarCents           int64        `json:"stress_test_var_cents,omitempty"`
	FileOwnerUID                 int          `json:"file_owner_uid,omitempty"`
	FileMode                     int          `json:"file_mode,omitempty"`
	FileSize                     int64        `json:"file_size,omitempty"`
	HasMarginCallActive          bool         `json:"has_margin_call_active"`
	HasCollateralShortfall       bool         `json:"has_collateral_shortfall"`
	HasHighHaircut               bool         `json:"has_high_haircut"`
	HasNegativeBalance           bool         `json:"has_negative_balance"`
	HasStressTestBreach          bool         `json:"has_stress_test_breach"`
	HasDefaultFundCall           bool         `json:"has_default_fund_call"`
	HasClienteCuit               bool         `json:"has_cliente_cuit"`
	IsRecent                     bool         `json:"is_recent"`
	IsWorldReadable              bool         `json:"is_world_readable"`
	IsGroupReadable              bool         `json:"is_group_readable"`
	IsCredentialExposureRisk     bool         `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated CCP install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\ArgentinaClearing`,
		`C:\ACyC`,
		`C:\BYMA\CCA`,
		`C:\CVSA\Garantias`,
		`C:\MAEClear`,
		`C:\Clearing`,
		`C:\Compensacion`,
		`/opt/argentinaclearing`,
		`/opt/clearing`,
		`/srv/clearing`,
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

// UserCCPDirs is the curated per-user relative path set.
func UserCCPDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "ArgentinaClearing"},
		{"AppData", "Roaming", "ACyC"},
		{"AppData", "Roaming", "BYMA", "CCA"},
		{"AppData", "Roaming", "CVSA", "Garantias"},
		{"AppData", "Roaming", "MAEClear"},
		{"AppData", "Local", "Clearing"},
		{"Documents", "ArgentinaClearing"},
		{"Documents", "Clearing"},
		{"Documents", "Compensacion"},
		{"Documents", "BackOffice", "CCP"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a CCP
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".csv", ".tsv", ".json",
		".txt", ".log",
		".xlsx", ".xls",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the CCP catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"garantias_iniciales", "garantias-iniciales",
		"garantia_inicial", "garantia-inicial",
		"llamada_margen", "llamada-margen",
		"margin_call", "margin-call",
		"liquidacion_diaria", "liquidacion-diaria",
		"daily_settlement", "daily-settlement",
		"aforos_", "aforos-", "_aforos.", "-aforos.",
		"haircut_", "haircut-",
		"saldo_compensador", "saldo-compensador",
		"compensador_balance",
		"fondo_garantia", "fondo-garantia",
		"default_fund", "default-fund",
		"factor_riesgo", "factor-riesgo",
		"risk_factor",
		"stress_test", "stress-test",
		"acyc_", "acyc-",
		"argentinaclearing", "byma_cca", "byma-cca",
		"maeclear_settlement",
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
		if strings.Contains(n, "acyc") ||
			strings.Contains(n, "argentinaclearing") ||
			strings.Contains(n, "clearing") ||
			strings.Contains(n, "maeclear") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "garantias_iniciales") ||
		strings.Contains(n, "garantias-iniciales") ||
		strings.Contains(n, "garantia_inicial") ||
		strings.Contains(n, "garantia-inicial"):
		return KindMarginCollateral
	case strings.Contains(n, "llamada_margen") ||
		strings.Contains(n, "llamada-margen") ||
		strings.Contains(n, "margin_call") ||
		strings.Contains(n, "margin-call"):
		return KindMarginCall
	case strings.Contains(n, "liquidacion_diaria") ||
		strings.Contains(n, "liquidacion-diaria") ||
		strings.Contains(n, "daily_settlement") ||
		strings.Contains(n, "daily-settlement") ||
		strings.Contains(n, "maeclear_settlement"):
		return KindDailySettlement
	case strings.Contains(n, "aforos") ||
		strings.Contains(n, "haircut_") ||
		strings.Contains(n, "haircut-"):
		// Discriminate per-asset risk-factor (single asset)
		// from collateral haircut-table (full table).
		if strings.Contains(n, "factor") || strings.Contains(n, "risk") {
			return KindHaircutFactor
		}
		return KindHaircutTable
	case strings.Contains(n, "factor_riesgo") ||
		strings.Contains(n, "factor-riesgo") ||
		strings.Contains(n, "risk_factor"):
		return KindHaircutFactor
	case strings.Contains(n, "saldo_compensador") ||
		strings.Contains(n, "saldo-compensador") ||
		strings.Contains(n, "compensador_balance"):
		return KindClearingMemberBalance
	case strings.Contains(n, "fondo_garantia") ||
		strings.Contains(n, "fondo-garantia") ||
		strings.Contains(n, "default_fund") ||
		strings.Contains(n, "default-fund"):
		return KindDefaultFund
	case strings.Contains(n, "stress_test") ||
		strings.Contains(n, "stress-test"):
		return KindStressTest
	}
	return KindOther
}

// CCPEntityFromPath classifies the CCP from path tokens.
//
// On Linux CI, Windows-style paths still need to classify
// correctly, so we normalize backslashes to forward-slashes
// before token matching.
func CCPEntityFromPath(path string) CCPEntity {
	if path == "" {
		return CCPUnknown
	}
	lower := strings.ToLower(
		strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"),
	)
	switch {
	case strings.Contains(lower, "argentinaclearing") ||
		strings.Contains(lower, "argentina-clearing") ||
		strings.Contains(lower, "argentina_clearing") ||
		strings.Contains(lower, "/acyc/") ||
		strings.Contains(lower, "acyc_") ||
		strings.Contains(lower, "/rofex/"):
		return CCPArgentinaClearing
	case strings.Contains(lower, "byma_cca") ||
		strings.Contains(lower, "byma-cca") ||
		strings.Contains(lower, "/byma/cca/") ||
		strings.Contains(lower, "/byma/clearing/"):
		return CCPBYMACCA
	case strings.Contains(lower, "cvsa/garantias") ||
		strings.Contains(lower, "cvsa-garantias") ||
		strings.Contains(lower, "/caja_valores/garantias/") ||
		strings.Contains(lower, "/cajavalores/garantias/"):
		return CCPCajaValoresGarantias
	case strings.Contains(lower, "maeclear") ||
		strings.Contains(lower, "mae_clear") ||
		strings.Contains(lower, "mae-clear"):
		return CCPMAEClear
	case strings.Contains(lower, "/clearing/") ||
		strings.Contains(lower, "/compensacion/"):
		return CCPOther
	}
	return CCPUnknown
}

// AssetClassFromBody scans for asset-class markers.
func AssetClassFromBody(body []byte) AssetClass {
	if len(body) == 0 {
		return AssetUnknown
	}
	lower := strings.ToLower(string(body))
	switch {
	case strings.Contains(lower, "dolar futuro") ||
		strings.Contains(lower, "dlr") ||
		strings.Contains(lower, "dom_futuro") ||
		strings.Contains(lower, "futures_financial"):
		return AssetFuturesFinancial
	case strings.Contains(lower, "soja") ||
		strings.Contains(lower, "trigo") ||
		strings.Contains(lower, "maiz") ||
		strings.Contains(lower, "girasol") ||
		strings.Contains(lower, "sorgo") ||
		strings.Contains(lower, "futures_agro"):
		return AssetFuturesAgro
	case strings.Contains(lower, "ggal") ||
		strings.Contains(lower, "ypfd") ||
		strings.Contains(lower, "equity") ||
		strings.Contains(lower, "renta_variable"):
		return AssetEquityRV
	case strings.Contains(lower, "al30") ||
		strings.Contains(lower, "gd30") ||
		strings.Contains(lower, "soberano") ||
		strings.Contains(lower, "renta_fija") ||
		strings.Contains(lower, "bonos"):
		return AssetBondsRF
	case strings.Contains(lower, "caucion") ||
		strings.Contains(lower, "repo"):
		return AssetCaucionRepo
	case strings.Contains(lower, "options") ||
		strings.Contains(lower, "opciones"):
		return AssetOptions
	}
	return AssetUnknown
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

// MatriculaRE matches clearing-member matrícula.
var matriculaRE = regexp.MustCompile(
	`(?i)(?:matr[íi]cula|clearing[_\- ]?member|compensador)[\s:#=\w\.\-]{0,30}?(\d{1,5})`,
)

// MatriculaFromText extracts clearing-member matrícula.
func MatriculaFromText(text string) string {
	m := matriculaRE.FindStringSubmatch(text)
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

// SettlementDateFromFilename extracts YYYY-MM-DD from filename.
func SettlementDateFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})[\-_]?(0[1-9]|1[0-2])[\-_]?(0[1-9]|[12]\d|3[01])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + "-" + m[2] + "-" + m[3]
}

// IsSettlementKind reports whether the kind carries margin /
// settlement / balance data subject to credential-exposure
// rollup.
func IsSettlementKind(k ArtifactKind) bool {
	switch k {
	case KindMarginCollateral, KindMarginCall,
		KindDailySettlement, KindClearingMemberBalance,
		KindDefaultFund:
		return true
	case KindHaircutTable, KindHaircutFactor, KindStressTest,
		KindInstaller, KindOther, KindUnknown:
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
	if r.MarginCallARSCents > 0 {
		r.HasMarginCallActive = true
	}
	if r.MarginRequiredARSCents > 0 &&
		r.MarginPostedARSCents > 0 &&
		r.MarginPostedARSCents < r.MarginRequiredARSCents {
		r.HasCollateralShortfall = true
	}
	if r.MaxHaircutPct >= HighHaircutPct {
		r.HasHighHaircut = true
	}
	if r.CompensadorBalanceCents < 0 {
		r.HasNegativeBalance = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	bodySignal := IsSettlementKind(r.ArtifactKind) ||
		r.HasMarginCallActive
	if readable && r.HasClienteCuit && bodySignal {
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
