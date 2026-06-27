// Package winargafiprg5193 audits AFIP RG 5193 (securities)
// + RG 5527 (crypto) broker-side tax-reporting artifact files
// cached on Argentine ALYC, fintech, FCI-manager, and bank
// compliance workstations across Windows, Linux, and macOS.
//
// AFIP (now ARCA — Agencia de Recaudación y Control Aduanero
// as of 2024) regulates broker tax reporting via:
//
//   - RG 5193 (2022) — Securities daily transaction reports.
//   - RG 5527 (2024) — Crypto-asset exchange (PSAV) reports.
//   - RG 3293 (2012) — COTI for high-value investments.
//   - F.572 / F.8125 — Internal + foreign-asset transfers.
//
// **The tax-reporting layer.** Distinct from:
//
//   - iter 107 winargcnvalyc    — CNV ALYC broker side.
//   - iter 144 winargcnvrg1023  — CNV cyber resilience.
//   - iter 122 winarguifros     — UIF ROS / SAR reports.
//   - iter 157 winargmaeclear   — MAE clearing.
//   - iter 158 winargprismaweb  — BYMA clearing.
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — config cleartext.
//   - `has_afip_session_token=1` — AFIP Clave Fiscal token
//     (sovereign-grade impersonation risk).
//   - `has_crypto_reporting=1` — RG 5527 crypto present.
//   - `has_ganancias_withholding=1` — income tax retention.
//   - `has_bienes_personales=1` — wealth tax declaration.
//   - `has_high_value_threshold=1` — txn > $200 K USD
//     (F.8125 mandatory reporting trigger).
//   - `has_cross_border_transfer=1` — foreign transfer
//     (RG 3293 + BCRA Com. A 7916 tap).
//   - `has_pii_natural_person=1` — DNI+CUIT+name bundle
//     (direct Ley 25.326 breach surface).
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR AFIP token OR cliente CUIT OR PII bundle).
//
// Read-only by intent. (Project guideline 4.2.)
package winargafiprg5193

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

// HighValueUSDCents is the per-transaction threshold above
// which F.8125 mandatory reporting triggers (200 K USD =
// 20_000_000 cents).
const HighValueUSDCents = 20_000_000

// HighValueARSCents is the equivalent ARS threshold (~200 M
// ARS at ~1000 ARS/USD official rate as of 2025).
const HighValueARSCents = 20_000_000_000_000

// ArtifactKind pinned to host_arg_afiprg5193.artifact_kind.
type ArtifactKind string

const (
	KindRG5193Daily          ArtifactKind = "afip-rg5193-daily"
	KindRG5527Crypto         ArtifactKind = "afip-rg5527-crypto"
	KindCOTIInversiones      ArtifactKind = "afip-coti-inversiones"
	KindGananciasRetenciones ArtifactKind = "afip-ganancias-retenciones"
	KindBienesPersonales     ArtifactKind = "afip-bienes-personales"
	KindF8125Transfer        ArtifactKind = "afip-f8125-transfer"
	KindExteriorizacion      ArtifactKind = "afip-exteriorizacion"
	KindSessionToken         ArtifactKind = "afip-session-token"
	KindConfig               ArtifactKind = "afip-config"
	KindInstaller            ArtifactKind = "afip-installer"
	KindOther                ArtifactKind = "other"
	KindUnknown              ArtifactKind = "unknown"
)

// ReporterClass pinned to host_arg_afiprg5193.reporter_class.
type ReporterClass string

const (
	ReporterALYC             ReporterClass = "alyc"
	ReporterAsegurador       ReporterClass = "asegurador"
	ReporterSociedadBolsa    ReporterClass = "sociedad-bolsa"
	ReporterBankingCustodian ReporterClass = "banking-custodian"
	ReporterFCIManager       ReporterClass = "fci-manager"
	ReporterFintech          ReporterClass = "fintech"
	ReporterCriptoExchange   ReporterClass = "cripto-exchange"
	ReporterOther            ReporterClass = "other"
	ReporterUnknown          ReporterClass = "unknown"
)

// Row mirrors host_arg_afiprg5193 column shape.
type Row struct {
	FilePath                 string        `json:"file_path"`
	FileHash                 string        `json:"file_hash"`
	UserProfile              string        `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind  `json:"artifact_kind"`
	ReporterClass            ReporterClass `json:"reporter_class"`
	ReporterCuitPrefix       string        `json:"reporter_cuit_prefix,omitempty"`
	ReporterCuitSuffix4      string        `json:"reporter_cuit_suffix4,omitempty"`
	ClienteCuitPrefix        string        `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string        `json:"cliente_cuit_suffix4,omitempty"`
	AFIPTokenHash            string        `json:"afip_token_hash,omitempty"`
	PeriodYYYYMM             string        `json:"period_yyyymm,omitempty"`
	TransactionCount         int64         `json:"transaction_count,omitempty"`
	CryptoTransactionCount   int64         `json:"crypto_transaction_count,omitempty"`
	TotalVolumeARSCents      int64         `json:"total_volume_ars_cents,omitempty"`
	TotalVolumeUSDCents      int64         `json:"total_volume_usd_cents,omitempty"`
	DistinctClienteCount     int64         `json:"distinct_cliente_count,omitempty"`
	HighValueCount           int64         `json:"high_value_count,omitempty"`
	CrossBorderCount         int64         `json:"cross_border_count,omitempty"`
	FileOwnerUID             int           `json:"file_owner_uid,omitempty"`
	FileMode                 int           `json:"file_mode,omitempty"`
	FileSize                 int64         `json:"file_size,omitempty"`
	HasPasswordInConfig      bool          `json:"has_password_in_config"`
	HasAFIPSessionToken      bool          `json:"has_afip_session_token"`
	HasCryptoReporting       bool          `json:"has_crypto_reporting"`
	HasGananciasWithholding  bool          `json:"has_ganancias_withholding"`
	HasBienesPersonales      bool          `json:"has_bienes_personales"`
	HasHighValueThreshold    bool          `json:"has_high_value_threshold"`
	HasCrossBorderTransfer   bool          `json:"has_cross_border_transfer"`
	HasPIINaturalPerson      bool          `json:"has_pii_natural_person"`
	HasClienteCuit           bool          `json:"has_cliente_cuit"`
	IsRecent                 bool          `json:"is_recent"`
	IsWorldReadable          bool          `json:"is_world_readable"`
	IsGroupReadable          bool          `json:"is_group_readable"`
	IsCredentialExposureRisk bool          `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated AFIP install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\AFIP`,
		`C:\ARCA`,
		`C:\AFIP\RG5193`,
		`C:\AFIP\RG5527`,
		`C:\AFIP\COTI`,
		`C:\AFIP\Aplicativos`,
		`C:\Program Files\AFIP`,
		`C:\Program Files (x86)\AFIP`,
		`/opt/afip`,
		`/opt/arca`,
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

// UserAFIPDirs is the curated per-user relative path set.
func UserAFIPDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "AFIP"},
		{"AppData", "Roaming", "ARCA"},
		{"AppData", "Local", "AFIP"},
		{"AppData", "Local", "ARCA"},
		{"Documents", "AFIP"},
		{"Documents", "ARCA"},
		{"Documents", "Impuestos", "AFIP"},
		{".afip"},
		{".arca"},
		{"Library", "Application Support", "AFIP"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries an
// AFIP artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json", ".ini", ".cfg", ".conf",
		".txt", ".csv", ".tsv", ".xlsx", ".xls",
		".log", ".tok",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the AFIP catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if ext == ".tok" {
		return true
	}
	for _, tok := range []string{
		"afip", "arca",
		"rg5193", "rg_5193", "rg-5193",
		"rg5527", "rg_5527", "rg-5527",
		"rg4838", "rg_4838",
		"rg3293", "rg_3293",
		"coti_inversiones", "coti-inversiones",
		"ganancias_retenciones", "ganancias-retenciones",
		"bienes_personales", "bienes-personales",
		"f8125", "f_8125", "f-8125",
		"exteriorizacion", "exteriorizaci\u00f3n",
		"clave_fiscal", "clave-fiscal",
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
		if strings.Contains(n, "afip") || strings.Contains(n, "arca") {
			return KindInstaller
		}
		return KindOther
	case ".tok":
		return KindSessionToken
	}
	switch {
	case strings.Contains(n, "rg5527") || strings.Contains(n, "rg_5527") ||
		strings.Contains(n, "rg-5527") || strings.Contains(n, "crypto"):
		return KindRG5527Crypto
	case strings.Contains(n, "rg5193") || strings.Contains(n, "rg_5193") ||
		strings.Contains(n, "rg-5193") || strings.Contains(n, "rg4838") ||
		strings.Contains(n, "rg_4838"):
		return KindRG5193Daily
	case strings.Contains(n, "coti"):
		return KindCOTIInversiones
	case strings.Contains(n, "ganancias_retenciones") ||
		strings.Contains(n, "ganancias-retenciones") ||
		strings.Contains(n, "retenciones_ganancias") ||
		strings.Contains(n, "rg830"):
		return KindGananciasRetenciones
	case strings.Contains(n, "bienes_personales") ||
		strings.Contains(n, "bienes-personales") ||
		strings.Contains(n, "bienespers"):
		return KindBienesPersonales
	case strings.Contains(n, "f8125") || strings.Contains(n, "f_8125") ||
		strings.Contains(n, "f-8125") || strings.Contains(n, "transfer"):
		return KindF8125Transfer
	case strings.Contains(n, "exteriorizacion") ||
		strings.Contains(n, "exteriorizaci\u00f3n") ||
		strings.Contains(n, "foreign_asset"):
		return KindExteriorizacion
	case strings.Contains(n, "clave_fiscal") ||
		strings.Contains(n, "clave-fiscal") ||
		strings.Contains(n, "session_token") ||
		strings.Contains(n, "session-token"):
		return KindSessionToken
	case (strings.Contains(n, "config") || strings.Contains(n, "settings") ||
		strings.Contains(n, "afip") || strings.Contains(n, "arca")) &&
		(ext == ".xml" || ext == ".ini" || ext == ".cfg" || ext == ".conf" ||
			ext == ".json"):
		return KindConfig
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

// IsJuridicalCuitPrefix reports prefix as legal-entity (vs.
// natural-person).
func IsJuridicalCuitPrefix(p string) bool {
	return p == "30" || p == "33" || p == "34"
}

// IsNaturalCuitPrefix reports prefix as natural-person.
func IsNaturalCuitPrefix(p string) bool {
	return p == "20" || p == "23" || p == "24" || p == "27"
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

// DistinctClientesInBody returns the count of distinct valid
// natural-person CUITs found in body (cliente count rollup).
func DistinctClientesInBody(body []byte) int64 {
	seen := map[string]struct{}{}
	for _, m := range cuitScanRE.FindAllSubmatch(body, -1) {
		prefix := string(m[1])
		if !IsNaturalCuitPrefix(prefix) {
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
	case KindConfig, KindSessionToken,
		KindRG5193Daily, KindRG5527Crypto,
		KindCOTIInversiones, KindGananciasRetenciones,
		KindBienesPersonales, KindF8125Transfer,
		KindExteriorizacion:
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
	if r.CryptoTransactionCount > 0 || r.ArtifactKind == KindRG5527Crypto {
		r.HasCryptoReporting = true
	}
	if r.HighValueCount > 0 {
		r.HasHighValueThreshold = true
	}
	if r.CrossBorderCount > 0 {
		r.HasCrossBorderTransfer = true
	}
	if r.ArtifactKind == KindBienesPersonales {
		r.HasBienesPersonales = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasAFIPSessionToken ||
		r.HasClienteCuit || r.HasPIINaturalPerson
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
