// Package winargfci audits Argentine FCI (Fondos Comunes de
// Inversión) mutual-fund files cached on Sociedad Gerente /
// Sociedad Depositaria / asset-manager workstations across
// Windows, Linux, and macOS.
//
// CNV (Ley 24.083 + RG 622) regulates FCIs. Each fund's daily
// lifecycle generates NAV calculations, portfolio composition,
// investor (cuotapartista) lists, prospectuses, CNV
// regulatory disclosures, and Caja de Valores account files
// (`.cda`).
//
// **The mutual-fund regulatory layer.** Complements:
//   - iter 90 winargxbrl       — issuer XBRL position
//   - iter 107 winargcnvalyc   — ALYC broker-dealer disclosures
//   - iter 108 winalgotrading  — algotrading capability
//   - iter 109 winargmatbarofex — derivatives positions
//
// Headline finding shapes:
//
//   - `has_high_concentration=1` — single cuotapartista >
//     10 % AUM. KYC/AML concern.
//   - `has_foreign_dominated_portfolio=1` — > 50 % portfolio
//     in USD / EUR. Capital-flight signal.
//   - `has_cuotapartistas_list=1` — investor list present.
//     Raises blast radius if readable.
//   - `is_credential_exposure_risk=1` — readable file +
//     cuotapartistas list = direct natural-person investor
//     breach (Ley 25.326).
//
// CUITs (sociedad gerente + depositaria + cuotapartistas)
// reduced to entity-type prefix + last 4 digits. Sociedad
// gerente / depositaria restricted to juridical prefixes
// 30/33/34.
//
// Read-only by intent. (Project guideline 4.2.)
package winargfci

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

// HighConcentrationPct flips has_high_concentration when a
// single cuotapartista holds more than this %.
const HighConcentrationPct = 10

// ForeignDominatedPct flips has_foreign_dominated_portfolio
// when foreign-currency weight exceeds this %.
const ForeignDominatedPct = 50

// MaxDenominacionChars bounds persisted denominación length.
const MaxDenominacionChars = 128

// ArtifactKind pinned to host_arg_fci.artifact_kind enum.
type ArtifactKind string

const (
	KindNAVDiario          ArtifactKind = "nav-diario"
	KindComposicionCart    ArtifactKind = "composicion-cartera"
	KindCuotapartistas     ArtifactKind = "cuotapartistas"
	KindProspecto          ArtifactKind = "prospecto"
	KindRegimenInformativo ArtifactKind = "regimen-informativo"
	KindCDAAccount         ArtifactKind = "cda-account"
	KindOther              ArtifactKind = "other"
	KindUnknown            ArtifactKind = "unknown"
)

// Row mirrors host_arg_fci' column shape.
type Row struct {
	SociedadDepositariaCuitSuffix4 string       `json:"sociedad_depositaria_cuit_suffix4,omitempty"`
	FechaNAV                       string       `json:"fecha_nav,omitempty"`
	FilePath                       string       `json:"file_path"`
	PeriodYYYYMM                   string       `json:"period_yyyymm,omitempty"`
	SociedadDepositariaCuitPrefix  string       `json:"sociedad_depositaria_cuit_prefix,omitempty"`
	UserProfile                    string       `json:"user_profile,omitempty"`
	ArtifactKind                   ArtifactKind `json:"artifact_kind"`
	FciMatricula                   string       `json:"fci_matricula,omitempty"`
	FciDenominacion                string       `json:"fci_denominacion,omitempty"`
	SociedadGerenteCuitPrefix      string       `json:"sociedad_gerente_cuit_prefix,omitempty"`
	SociedadGerenteCuitSuffix4     string       `json:"sociedad_gerente_cuit_suffix4,omitempty"`
	FileHash                       string       `json:"file_hash"`
	FileMode                       int          `json:"file_mode,omitempty"`
	NavARSCents                    int64        `json:"nav_ars_cents,omitempty"`
	FileOwnerUID                   int          `json:"file_owner_uid,omitempty"`
	CuotapartistasCount            int          `json:"cuotapartistas_count,omitempty"`
	MaxCuotapartistaPct            int          `json:"max_cuotapartista_pct,omitempty"`
	AumARSCents                    int64        `json:"aum_ars_cents,omitempty"`
	ForeignCurrencyWeightPct       int          `json:"foreign_currency_weight_pct,omitempty"`
	FileSize                       int64        `json:"file_size,omitempty"`
	HasHighConcentration           bool         `json:"has_high_concentration"`
	HasForeignDominatedPortfolio   bool         `json:"has_foreign_dominated_portfolio"`
	HasCuotapartistasList          bool         `json:"has_cuotapartistas_list"`
	IsRecent                       bool         `json:"is_recent"`
	IsWorldReadable                bool         `json:"is_world_readable"`
	IsGroupReadable                bool         `json:"is_group_readable"`
	IsCredentialExposureRisk       bool         `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated FCI install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\CNV\FCI`,
		`C:\FCI`,
		`C:\Sociedad-Gerente`,
		`C:\CajaDeValores`,
		`/opt/fci`,
		`/srv/fci`,
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

// UserFCIDirs is the curated per-user relative path set.
func UserFCIDirs() [][]string {
	return [][]string{
		{"Documents", "FCI"},
		{"Documents", "CNV", "FCI"},
		{"Documents", "Sociedad-Gerente"},
		{"Documents", "CajaDeValores"},
		{"Documents", "Fondos"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateExt reports whether the extension carries an
// FCI artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".csv", ".xml", ".json", ".txt", ".cda", ".pdf":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the FCI catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"fci_", "fci-", "_fci.",
		"nav_", "nav-",
		"composicion_", "composicion-",
		"cuotapartistas", "cuotapartista",
		"prospecto_fci", "prospecto-fci",
		"regimen_informativo_fci", "regimen-informativo-fci",
		"fondo_comun", "fondo-comun", "fondocomun",
		"sociedad_gerente", "sociedad-gerente",
		"caja_de_valores", "cajadevalores",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return strings.HasSuffix(n, ".cda")
}

// ArtifactKindFromName classifies a filename heuristically.
func ArtifactKindFromName(name string) ArtifactKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch {
	case ext == ".cda":
		return KindCDAAccount
	case strings.Contains(n, "nav_") || strings.Contains(n, "_nav") ||
		strings.Contains(n, "nav-") || strings.Contains(n, "valor_cuotaparte") ||
		strings.Contains(n, "valorcuotaparte"):
		return KindNAVDiario
	case strings.Contains(n, "composicion") || strings.Contains(n, "cartera"):
		return KindComposicionCart
	case strings.Contains(n, "cuotapartistas") || strings.Contains(n, "cuotapartista"):
		return KindCuotapartistas
	case strings.Contains(n, "prospecto"):
		return KindProspecto
	case strings.Contains(n, "regimen_informativo") || strings.Contains(n, "regimen-informativo"):
		return KindRegimenInformativo
	case strings.Contains(n, "fci") || strings.Contains(n, "fondo_comun") ||
		strings.Contains(n, "fondo-comun"):
		return KindOther
	}
	return KindUnknown
}

// JuridicalPrefixes lists CUIT prefixes for juridical entities.
func JuridicalPrefixes() []string {
	return []string{"30", "33", "34"}
}

// IsValidJuridicalPrefix reports prefix membership.
func IsValidJuridicalPrefix(p string) bool {
	for _, v := range JuridicalPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// CuitEntityPrefixes mirrors AFIP collector list (includes
// natural-person prefixes for cuotapartistas).
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

// CuitFingerprint extracts (prefix, suffix4) — any valid CUIT
// prefix.
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

// JuridicalCuitFingerprint extracts (prefix, suffix4) only
// when the CUIT is juridical (30/33/34).
func JuridicalCuitFingerprint(text string) (prefix, suffix4 string) {
	p, s := CuitFingerprint(text)
	if !IsValidJuridicalPrefix(p) {
		return "", ""
	}
	return p, s
}

// matriculaRE matches FCI CNV matrícula in text.
var matriculaRE = regexp.MustCompile(`(?i)(?:matr[íi]cula(?:\s*fci|\s*cnv)?|fci[_-]?matricula|fci\s*n[°ºo])[\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// MatriculaFromText extracts the FCI CNV matrícula.
func MatriculaFromText(text string) string {
	m := matriculaRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
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

// fechaNAVRE matches YYYYMMDD in filename.
var fechaNAVRE = regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])`)

// FechaNAVFromName extracts a YYYYMMDD date from filename.
func FechaNAVFromName(name string) string {
	m := fechaNAVRE.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1] + "-" + m[2] + "-" + m[3]
}

// TruncateString shortens preserving UTF-8.
func TruncateString(s string, max int) string {
	t := strings.TrimSpace(s)
	if len(t) <= max {
		return t
	}
	r := []rune(t)
	if len(r) <= max {
		return t
	}
	return string(r[:max])
}

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.MaxCuotapartistaPct > HighConcentrationPct {
		r.HasHighConcentration = true
	}
	if r.ForeignCurrencyWeightPct > ForeignDominatedPct {
		r.HasForeignDominatedPortfolio = true
	}
	if r.ArtifactKind == KindCuotapartistas || r.CuotapartistasCount > 0 {
		r.HasCuotapartistasList = true
	}
	// PII exposure: cuotapartistas list present + readable.
	if r.HasCuotapartistasList && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].FciMatricula != rs[j].FciMatricula {
			return rs[i].FciMatricula < rs[j].FciMatricula
		}
		return rs[i].PeriodYYYYMM < rs[j].PeriodYYYYMM
	})
}
