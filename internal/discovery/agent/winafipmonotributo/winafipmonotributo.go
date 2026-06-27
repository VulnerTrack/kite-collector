// Package winafipmonotributo audits AFIP Monotributo
// (Régimen Simplificado — Ley 26.565, RG 4309) files
// cached on accountant / studio / contribuyente
// workstations across Windows, Linux, and macOS.
//
// Monotributo covers ~4 M Argentine taxpayers; every file
// leaks the monotributista CUIT (always natural-person
// prefix 20/23/24/27) + activity sector + declared income
// tier — direct PII under Ley 25.326.
//
// **Distinct from**:
//   - iter 89  winafipwsfev1  — CAE invoices (general régimen)
//   - iter 100 winafipexport  — export factura E
//   - iter 114 winafipsicore  — retenciones
//   - iter 116 winafipciti    — CITI Compras/Ventas (IVA)
//
// Headline finding shapes:
//
//   - `has_high_category=1` — categoría J/K (top tiers).
//   - `has_exclusion=1` — exclusión event in file.
//   - `has_recent_recategorization=1` — recat within 90d.
//   - `is_credential_exposure_risk=1` — readable file +
//     monotributista CUIT + (income OR categoría).
//
// Read-only by intent. (Project guideline 4.2.)
package winafipmonotributo

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

// MaxFileBytes bounds per-file read (8 MiB — monotributo
// artifacts are small).
const MaxFileBytes = 8 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// RecategorizacionWindow — has_recent_recategorization cutoff.
const RecategorizacionWindow = 90 * 24 * time.Hour

// ArtifactKind pinned to host_afip_monotributo.artifact_kind.
type ArtifactKind string

const (
	KindRecategorizacion ArtifactKind = "recategorizacion"
	KindPagoMensual      ArtifactKind = "pago-mensual"
	KindExclusionNotif   ArtifactKind = "exclusion-notif"
	KindCategoriaVigente ArtifactKind = "categoria-vigente"
	KindF184Adhesion     ArtifactKind = "f184-adhesion"
	KindIngresoAnual     ArtifactKind = "ingreso-anual"
	KindCredencialCard   ArtifactKind = "credencial-card"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// Categoria is the monotributo letter A–K (lowercased).
type Categoria string

const (
	CategoriaEmpty Categoria = ""
	CategoriaA     Categoria = "a"
	CategoriaB     Categoria = "b"
	CategoriaC     Categoria = "c"
	CategoriaD     Categoria = "d"
	CategoriaE     Categoria = "e"
	CategoriaF     Categoria = "f"
	CategoriaG     Categoria = "g"
	CategoriaH     Categoria = "h"
	CategoriaI     Categoria = "i"
	CategoriaJ     Categoria = "j"
	CategoriaK     Categoria = "k"
)

// Row mirrors host_afip_monotributo' column shape.
type Row struct {
	FilePath                  string       `json:"file_path"`
	FileHash                  string       `json:"file_hash"`
	UserProfile               string       `json:"user_profile,omitempty"`
	ArtifactKind              ArtifactKind `json:"artifact_kind"`
	MonotributistaCuitPrefix  string       `json:"monotributista_cuit_prefix,omitempty"`
	MonotributistaCuitSuffix4 string       `json:"monotributista_cuit_suffix4,omitempty"`
	Categoria                 Categoria    `json:"categoria"`
	CiiuActivityCode          string       `json:"ciiu_activity_code,omitempty"`
	CiiuSectorLetter          string       `json:"ciiu_sector_letter,omitempty"`
	RecategorizacionDate      string       `json:"recategorizacion_date,omitempty"`
	PeriodYYYYMM              string       `json:"period_yyyymm,omitempty"`
	IngresoAnualARSCents      int64        `json:"ingreso_anual_ars_cents,omitempty"`
	FileOwnerUID              int          `json:"file_owner_uid,omitempty"`
	FileMode                  int          `json:"file_mode,omitempty"`
	FileSize                  int64        `json:"file_size,omitempty"`
	HasHighCategory           bool         `json:"has_high_category"`
	HasExclusion              bool         `json:"has_exclusion"`
	HasRecentRecategorization bool         `json:"has_recent_recategorization"`
	IsRecent                  bool         `json:"is_recent"`
	IsWorldReadable           bool         `json:"is_world_readable"`
	IsGroupReadable           bool         `json:"is_group_readable"`
	IsCredentialExposureRisk  bool         `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated monotributo install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\AFIP\Monotributo`,
		`C:\SIAP\Monotributo`,
		`C:\Estudio\monotributo`,
		`C:\Contabilidad\monotributo`,
		`/opt/afip/monotributo`,
		`/var/lib/afip/monotributo`,
		`/srv/monotributo`,
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

// UserMonoDirs is the curated per-user relative path set.
func UserMonoDirs() [][]string {
	return [][]string{
		{"Documents", "AFIP", "Monotributo"},
		{"Documents", "Monotributo"},
		{"Documents", "Estudio", "monotributo"},
		{"Documents", "Contabilidad", "monotributo"},
		{"AppData", "Local", "AFIP", "Monotributo"},
		{"AppData", "Roaming", "AFIP", "Monotributo"},
	}
}

// IsCandidateExt reports whether the extension carries a
// monotributo artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".txt", ".csv", ".pdf":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the monotributo catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"monotributo", "monotributista",
		"recategorizacion", "recategorización",
		"exclusion_monotributo", "exclusion-monotributo",
		"categoria_monotrib", "categoria-monotrib",
		"f184_", "f184-", "f184.",
		"credencial_monotrib", "credencial-monotrib",
		"pago_monotrib", "pago-monotrib",
		"ingreso_anual_monotrib", "ingreso-anual-monotrib",
	} {
		if strings.Contains(n, tok) {
			return true
		}
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
	case strings.Contains(n, "recategorizacion") ||
		strings.Contains(n, "recategorización"):
		return KindRecategorizacion
	case strings.Contains(n, "exclusion_monotrib") ||
		strings.Contains(n, "exclusion-monotrib"):
		return KindExclusionNotif
	case strings.Contains(n, "f184"):
		return KindF184Adhesion
	case strings.Contains(n, "credencial_monotrib") ||
		strings.Contains(n, "credencial-monotrib"):
		return KindCredencialCard
	case strings.Contains(n, "pago_monotrib") ||
		strings.Contains(n, "pago-monotrib") ||
		strings.Contains(n, "pago_monotributo"):
		return KindPagoMensual
	case strings.Contains(n, "ingreso_anual"):
		return KindIngresoAnual
	case strings.Contains(n, "categoria_monotrib") ||
		strings.Contains(n, "categoria-monotrib"):
		return KindCategoriaVigente
	case strings.Contains(n, "monotributo") ||
		strings.Contains(n, "monotributista"):
		return KindOther
	}
	return KindOther
}

// MonotributistaCuitPrefixes — natural-person CUIT prefixes
// (monotributistas can only be natural persons).
func MonotributistaCuitPrefixes() []string {
	return []string{"20", "23", "24", "27"}
}

// IsValidMonotributistaCuitPrefix reports prefix membership.
func IsValidMonotributistaCuitPrefix(p string) bool {
	for _, v := range MonotributistaCuitPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches 11-digit CUIT bounded by non-digit / edges.
var cuitRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// CuitFingerprint extracts (prefix, suffix4) from text. Only
// natural-person prefixes are accepted; juridical prefixes
// return empty.
func CuitFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidMonotributistaCuitPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// CategoriaFromText normalises a categoría label (A-K) to its
// lowercase letter form.
func CategoriaFromText(s string) Categoria {
	t := strings.ToLower(strings.TrimSpace(s))
	t = strings.TrimPrefix(t, "categoria ")
	t = strings.TrimPrefix(t, "cat. ")
	t = strings.TrimPrefix(t, "cat ")
	if len(t) == 0 {
		return CategoriaEmpty
	}
	switch t[0] {
	case 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k':
		return Categoria(string(t[0]))
	}
	return CategoriaEmpty
}

// IsHighCategoria reports membership in top tiers (J/K).
func IsHighCategoria(c Categoria) bool {
	switch c {
	case CategoriaJ, CategoriaK:
		return true
	case CategoriaEmpty, CategoriaA, CategoriaB, CategoriaC,
		CategoriaD, CategoriaE, CategoriaF, CategoriaG,
		CategoriaH, CategoriaI:
		return false
	}
	return false
}

// CiiuSectorLetterFromCode reduces a 6-digit CIIU 2008 code
// to its top-level section letter (A–S). Empty if unparseable.
func CiiuSectorLetterFromCode(code string) string {
	t := strings.TrimSpace(code)
	if len(t) < 2 {
		return ""
	}
	// CIIU 2008 first two digits map to sections.
	division, err := parseTwoDigit(t[:2])
	if err != nil {
		return ""
	}
	switch {
	case division >= 1 && division <= 3:
		return "a"
	case division >= 5 && division <= 9:
		return "b"
	case division >= 10 && division <= 33:
		return "c"
	case division == 35:
		return "d"
	case division >= 36 && division <= 39:
		return "e"
	case division >= 41 && division <= 43:
		return "f"
	case division >= 45 && division <= 47:
		return "g"
	case division >= 49 && division <= 53:
		return "h"
	case division >= 55 && division <= 56:
		return "i"
	case division >= 58 && division <= 63:
		return "j"
	case division >= 64 && division <= 66:
		return "k"
	case division == 68:
		return "l"
	case division >= 69 && division <= 75:
		return "m"
	case division >= 77 && division <= 82:
		return "n"
	case division == 84:
		return "o"
	case division == 85:
		return "p"
	case division >= 86 && division <= 88:
		return "q"
	case division >= 90 && division <= 93:
		return "r"
	case division >= 94 && division <= 99:
		return "s"
	}
	return ""
}

func parseTwoDigit(s string) (int, error) {
	if len(s) < 2 {
		return 0, errBadDigit
	}
	a, b := s[0], s[1]
	if a < '0' || a > '9' || b < '0' || b > '9' {
		return 0, errBadDigit
	}
	return int(a-'0')*10 + int(b-'0'), nil
}

var errBadDigit = &simpleError{msg: "not a 2-digit number"}

type simpleError struct{ msg string }

func (e *simpleError) Error() string { return e.msg }

// PeriodFromFilename extracts YYYYMM from a filename.
func PeriodFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// AnnotateSecurity sets derived booleans. Time-sensitive
// flags use the injected clock.
func AnnotateSecurity(r *Row) {
	AnnotateSecurityWithClock(r, time.Now)
}

// AnnotateSecurityWithClock is the time-injectable variant.
func AnnotateSecurityWithClock(r *Row, now func() time.Time) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if IsHighCategoria(r.Categoria) {
		r.HasHighCategory = true
	}
	if r.ArtifactKind == KindExclusionNotif {
		r.HasExclusion = true
	}
	if r.RecategorizacionDate != "" {
		if t, err := time.Parse("2006-01-02", r.RecategorizacionDate); err == nil {
			if now().Sub(t) <= RecategorizacionWindow {
				r.HasRecentRecategorization = true
			}
		}
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	hasIncomeOrCat := r.IngresoAnualARSCents > 0 || r.Categoria != CategoriaEmpty
	if hasReadable && r.MonotributistaCuitPrefix != "" && hasIncomeOrCat {
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
