// Package winargbeneficiarios audits Argentine AFIP / UIF
// "Beneficiario Final" (Ultimate Beneficial Owner) declaration
// files cached on accounting / compliance / risk workstations
// across Windows, Linux, and macOS.
//
// Every Argentine sociedad must file an annual UBO declaration
// naming the natural persons controlling ≥10 % of capital or
// votes (AFIP RG 4697/2020, UIF Res. 112/2021). These filings
// are the **canonical capital-entity ownership artifact** —
// they reveal the natural-person owners behind every juridical
// entity, which is exactly the chain of custody every AML
// investigation needs.
//
// File-based discovery is the deliberate design choice — the
// filing shapes are stable XML / JSON / fixed-width TXT and
// land in well-known per-CUIT cache dirs maintained by every
// accounting SDK (Tango, Bejerman, pyafipws, Afip.php SDKs).
//
// Headline finding shapes:
//
//   - `is_high_concentration=1` — at least one beneficiario
//     with >50 % capital. Single-owner entity; elevated AML.
//   - `has_indirect_control_chain=1` — declaration includes
//     intermediate juridical entities between obligado and the
//     final natural-person beneficiario.
//   - `has_extranjero_beneficiario=1` — UBO identified by DNI
//     extranjero / pasaporte rather than AFIP CUIL = cross-
//     border control.
//   - `is_borrador=1` — file is an unfiled DRAFT (compliance
//     gap; AFIP/UIF expect submission).
//   - `is_credential_exposure_risk=1` — readable file + UBO
//     PII = highest-tier Ley 25.326 exposure.
//
// CUITs (obligado juridical + beneficiario natural-person) are
// NEVER stored verbatim — only entity-type prefix + last 4
// digits.
//
// Read-only by intent — we walk candidate files only, never
// call AFIP. (Project guideline 4.2.)
package winargbeneficiarios

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// MaxRows bounds per-scan output.
const MaxRows = 8192

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 4 << 20 // 4 MiB

// HighConcentrationPct is the threshold above which
// is_high_concentration flips.
const HighConcentrationPct = 50

// MaxDenominacionChars bounds persisted strings.
const MaxDenominacionChars = 128

// FilingKind pinned to host_afip_beneficiario_final.filing_kind.
type FilingKind string

const (
	FilingAnual        FilingKind = "beneficiario-final-anual"
	FilingModificacion FilingKind = "beneficiario-final-modificacion"
	FilingDDJJBorrador FilingKind = "ddjj-borrador"
	FilingF8127        FilingKind = "f8127"
	FilingRISBF        FilingKind = "ris-bf"
	FilingOther        FilingKind = "other"
	FilingUnknown      FilingKind = "unknown"
)

// Estado pinned to host_afip_beneficiario_final.estado enum.
type Estado string

const (
	EstadoPresentada  Estado = "presentada"
	EstadoRectificada Estado = "rectificada"
	EstadoBorrador    Estado = "borrador"
	EstadoUnknown     Estado = "unknown"
)

// Row mirrors host_afip_beneficiario_final' column shape.
type Row struct {
	ObligadoDenominacion      string     `json:"obligado_denominacion,omitempty"`
	PeriodYYYY                string     `json:"period_yyyy,omitempty"`
	FilePath                  string     `json:"file_path"`
	FileHash                  string     `json:"file_hash"`
	ObligadoCuitSuffix4       string     `json:"obligado_cuit_suffix4,omitempty"`
	UserProfile               string     `json:"user_profile,omitempty"`
	FilingKind                FilingKind `json:"filing_kind"`
	Estado                    Estado     `json:"estado"`
	ObligadoCuitPrefix        string     `json:"obligado_cuit_prefix,omitempty"`
	FileOwnerUID              int        `json:"file_owner_uid,omitempty"`
	FileMode                  int        `json:"file_mode,omitempty"`
	BeneficiariosCount        int        `json:"beneficiarios_count,omitempty"`
	FileSize                  int64      `json:"file_size,omitempty"`
	MaxParticipacionPct       int        `json:"max_participacion_pct,omitempty"`
	HasIndirectControlChain   bool       `json:"has_indirect_control_chain"`
	HasExtranjeroBeneficiario bool       `json:"has_extranjero_beneficiario"`
	IsHighConcentration       bool       `json:"is_high_concentration"`
	IsBorrador                bool       `json:"is_borrador"`
	IsWorldReadable           bool       `json:"is_world_readable"`
	IsGroupReadable           bool       `json:"is_group_readable"`
	IsCredentialExposureRisk  bool       `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated set of UBO cache roots.
func DefaultInstallRoots() []string {
	return []string{
		`C:\AFIP\BeneficiarioFinal`,
		`C:\AFIP\RG4697`,
		`C:\UIF`,
		`C:\UIF\BeneficiarioFinal`,
		`/opt/afip/beneficiario_final`,
		`/srv/uif`,
	}
}

// DefaultUsersBases is the curated set of per-OS user-profile
// bases.
func DefaultUsersBases() []string {
	return []string{
		`C:\Users`,
		"/home",
		"/Users",
	}
}

// UserUBODirs is the curated per-user relative path catalogue.
func UserUBODirs() [][]string {
	return [][]string{
		{"Documents", "AFIP", "BeneficiarioFinal"},
		{"Documents", "UIF"},
		{"Documents", "Compliance"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateName reports whether a filename plausibly belongs
// to the UBO filing catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"beneficiario_final", "beneficiariofinal", "beneficiario-final",
		"beneficiario_", "ris_bf", "ris-bf",
		"f8127", "f.8127", "f_8127",
		"rg4697", "rg-4697", "rg_4697",
		"ubo_", "ddjj_bf", "ddjj-bf",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// FilingKindFromName classifies a filename heuristically.
func FilingKindFromName(name string) FilingKind {
	if strings.TrimSpace(name) == "" {
		return FilingUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "f8127") || strings.Contains(n, "f.8127") || strings.Contains(n, "f_8127"):
		return FilingF8127
	case strings.Contains(n, "ris_bf") || strings.Contains(n, "ris-bf"):
		return FilingRISBF
	case strings.Contains(n, "borrador") || strings.Contains(n, "draft"):
		return FilingDDJJBorrador
	case strings.Contains(n, "modificacion") || strings.Contains(n, "rectificat"):
		return FilingModificacion
	case strings.Contains(n, "beneficiario_final") || strings.Contains(n, "beneficiariofinal") ||
		strings.Contains(n, "beneficiario-final") || strings.Contains(n, "rg4697") ||
		strings.Contains(n, "ubo_") || strings.Contains(n, "ddjj_bf"):
		return FilingAnual
	}
	return FilingOther
}

// EstadoFromText classifies a textual estado label.
func EstadoFromText(s string) Estado {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case t == "":
		return EstadoUnknown
	case strings.Contains(t, "presentada") || strings.Contains(t, "submitted") ||
		strings.Contains(t, "transmitida"):
		return EstadoPresentada
	case strings.Contains(t, "rectificada") || strings.Contains(t, "rectif"):
		return EstadoRectificada
	case strings.Contains(t, "borrador") || strings.Contains(t, "draft"):
		return EstadoBorrador
	}
	return EstadoUnknown
}

// JuridicalPrefixes lists CUIT prefixes that identify
// juridical persons (sociedades, asociaciones). 30/33/34.
func JuridicalPrefixes() []string {
	return []string{"30", "33", "34"}
}

// NaturalPersonPrefixes lists CUIT prefixes for natural
// persons (personas físicas). 20/23/24/27.
func NaturalPersonPrefixes() []string {
	return []string{"20", "23", "24", "27"}
}

// CuitEntityPrefixes is the union — mirrors sibling collectors.
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

// IsJuridicalPrefix reports juridical-person prefix.
func IsJuridicalPrefix(p string) bool {
	for _, v := range JuridicalPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// IsNaturalPersonPrefix reports natural-person prefix.
func IsNaturalPersonPrefix(p string) bool {
	for _, v := range NaturalPersonPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches 11-digit CUIT (hyphen-optional).
var cuitRE = regexp.MustCompile(`(\d{2})-?(\d{8})-?(\d)`)

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

// periodRE matches a 4-digit year between 2010 and 2099 in
// filename context.
var periodRE = regexp.MustCompile(`(20\d{2})`)

// PeriodFromName extracts a YYYY period from filename.
func PeriodFromName(name string) string {
	m := periodRE.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1]
}

// TruncateString shortens a string preserving UTF-8.
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
	if r.MaxParticipacionPct > HighConcentrationPct {
		r.IsHighConcentration = true
	}
	r.IsBorrador = r.Estado == EstadoBorrador ||
		r.FilingKind == FilingDDJJBorrador
	// UBO PII exposure: obligado + natural-person beneficiario
	// present, file is readable.
	hasUBOPII := r.ObligadoCuitPrefix != "" || r.BeneficiariosCount > 0
	if hasUBOPII && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns a deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].ObligadoCuitPrefix != rs[j].ObligadoCuitPrefix {
			return rs[i].ObligadoCuitPrefix < rs[j].ObligadoCuitPrefix
		}
		if rs[i].ObligadoCuitSuffix4 != rs[j].ObligadoCuitSuffix4 {
			return rs[i].ObligadoCuitSuffix4 < rs[j].ObligadoCuitSuffix4
		}
		return rs[i].PeriodYYYY < rs[j].PeriodYYYY
	})
}
