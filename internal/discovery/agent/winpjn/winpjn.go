// Package winpjn audits Argentine PJN (Poder Judicial de la
// Nación) electronic-notification files cached on lawyer /
// contador / risk-team workstations across Windows, Linux,
// and macOS. PJN's "Sistema de Notificaciones Electrónicas"
// delivers each providencia, sentencia, cédula, or oficio as
// a PDF + XML/HTML metadata bundle that lands in user
// Downloads or the install dirs of practice-management apps
// (LexDoctor, AbogadosOnline, Lex-Net).
//
// File-based discovery is the deliberate design choice — the
// PDFs are opaque but the filenames + sibling XML/HTML carry
// the legible metadata: CUIJ (Código Único de Identificación
// de Juzgados), party CUITs, tipo de proceso, juzgado.
//
// Capital-entity signals — the headline reason for this
// collector:
//
//   - `tipo_proceso="concurso-preventivo"` — Ley 24.522 art.5
//     reorganización voluntaria; lender alert.
//   - `tipo_proceso="quiebra"` — Ley 24.522 art.77 bankruptcy.
//   - `tipo_proceso="embargo"` — judicial asset seizure.
//   - `tipo_proceso="inhibicion"` — Ley 17.801 art.39 INHIBICIÓN
//     GENERAL DE BIENES; debtor cannot dispose of assets.
//
// Headline finding shapes:
//
//   - `is_insolvency_proceeding=1` — concurso-preventivo or
//     quiebra. Complements BCRA situación ≥ 4 (iter 95) as a
//     formal-vs-financial-insolvency cross-check.
//   - `is_asset_seizure=1` — embargo or inhibición.
//   - `is_recent=1` — file modified within 90 days.
//   - `is_credential_exposure_risk=1` — readable file +
//     judicial-PII (CUIT or carátula present).
//
// Read-only by intent — we walk candidate files only, never
// parse PDF content. (Project guideline 4.2.)
package winpjn

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

// MaxFileBytes bounds per-file read (for hashing + sibling XML
// content inspection).
const MaxFileBytes = 8 << 20 // 8 MiB

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// NotificationKind pinned to
// host_pjn_notifications.notification_kind enum.
type NotificationKind string

const (
	KindCedula        NotificationKind = "cedula"
	KindProvidencia   NotificationKind = "providencia"
	KindSentencia     NotificationKind = "sentencia"
	KindOficio        NotificationKind = "oficio"
	KindRequerimiento NotificationKind = "requerimiento"
	KindDemanda       NotificationKind = "demanda"
	KindContestacion  NotificationKind = "contestacion"
	KindOther         NotificationKind = "other"
	KindUnknown       NotificationKind = "unknown"
)

// TipoProceso pinned to host_pjn_notifications.tipo_proceso enum.
type TipoProceso string

const (
	ProcesoConcursoPreventivo TipoProceso = "concurso-preventivo"
	ProcesoQuiebra            TipoProceso = "quiebra"
	ProcesoEjecucion          TipoProceso = "ejecucion"
	ProcesoEmbargo            TipoProceso = "embargo"
	ProcesoInhibicion         TipoProceso = "inhibicion"
	ProcesoAlimentos          TipoProceso = "alimentos"
	ProcesoLaboral            TipoProceso = "laboral"
	ProcesoCivil              TipoProceso = "civil"
	ProcesoComercial          TipoProceso = "comercial"
	ProcesoPenal              TipoProceso = "penal"
	ProcesoOtro               TipoProceso = "otro"
	ProcesoUnknown            TipoProceso = "unknown"
)

// MaxStringLen bounds persisted juzgado / secretaría / carátula
// strings.
const (
	MaxJuzgadoChars    = 64
	MaxSecretariaChars = 32
)

// Row mirrors host_pjn_notifications' column shape.
type Row struct {
	CuijYear                 string           `json:"cuij_year,omitempty"`
	CuijSuffix4              string           `json:"cuij_suffix4,omitempty"`
	NotificationDate         string           `json:"notification_date,omitempty"`
	Secretaria               string           `json:"secretaria,omitempty"`
	FilePath                 string           `json:"file_path"`
	UserProfile              string           `json:"user_profile,omitempty"`
	NotificationKind         NotificationKind `json:"notification_kind"`
	TipoProceso              TipoProceso      `json:"tipo_proceso"`
	TargetCuitPrefix         string           `json:"target_cuit_prefix,omitempty"`
	TargetCuitSuffix4        string           `json:"target_cuit_suffix4,omitempty"`
	FileHash                 string           `json:"file_hash"`
	Juzgado                  string           `json:"juzgado,omitempty"`
	FileOwnerUID             int              `json:"file_owner_uid,omitempty"`
	FileMode                 int              `json:"file_mode,omitempty"`
	FileSize                 int64            `json:"file_size,omitempty"`
	IsInsolvencyProceeding   bool             `json:"is_insolvency_proceeding"`
	IsAssetSeizure           bool             `json:"is_asset_seizure"`
	IsRecent                 bool             `json:"is_recent"`
	IsWorldReadable          bool             `json:"is_world_readable"`
	IsGroupReadable          bool             `json:"is_group_readable"`
	IsCredentialExposureRisk bool             `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated set of practice-management
// install roots that drop PJN notifications.
func DefaultInstallRoots() []string {
	return []string{
		`C:\LexDoctor`,
		`C:\LexDoctor\Notificaciones`,
		`C:\PJN`,
		`C:\PJN\Cedulas`,
		`C:\AbogadosOnline`,
		`C:\LexNet`,
		`C:\Mendoza-Net`,
		`/opt/lexdoctor`,
		`/srv/pjn`,
	}
}

// DefaultUsersBases is the curated set of per-OS user-profile
// bases (we additionally walk Downloads + Documents/PJN).
func DefaultUsersBases() []string {
	return []string{
		`C:\Users`,
		"/home",
		"/Users",
	}
}

// UserNotificationDirs is the curated per-user relative path
// catalogue we walk under each profile.
func UserNotificationDirs() [][]string {
	return [][]string{
		{"Downloads"},
		{"Documents", "PJN"},
		{"Documents", "Notificaciones"},
		{"Documents", "LexDoctor"},
		{"Descargas"}, // Spanish locale equivalent of Downloads
	}
}

// IsCandidateName reports whether a filename plausibly belongs
// to the PJN notification catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"cedula", "cédula", "providencia", "sentencia",
		"oficio", "notif_", "notificacion", "notificación",
		"pjn_", "cuij_", "expte_", "expediente_",
		"requerimiento", "lex-doctor", "lexdoctor",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// NotificationKindFromName classifies a filename heuristically.
// Order matters: `contestacion` is checked before `demanda`
// because filenames like `contestacion_demandado.xml` contain
// both substrings.
func NotificationKindFromName(name string) NotificationKind {
	n := strings.ToLower(filepath.Base(name))
	switch {
	case n == "":
		return KindUnknown
	case strings.Contains(n, "cedula") || strings.Contains(n, "cédula"):
		return KindCedula
	case strings.Contains(n, "providencia"):
		return KindProvidencia
	case strings.Contains(n, "sentencia"):
		return KindSentencia
	case strings.Contains(n, "oficio"):
		return KindOficio
	case strings.Contains(n, "requerimiento"):
		return KindRequerimiento
	case strings.Contains(n, "contestacion") || strings.Contains(n, "contestación"):
		return KindContestacion
	case strings.Contains(n, "demanda"):
		return KindDemanda
	case strings.Contains(n, "notif") || strings.Contains(n, "pjn_") ||
		strings.Contains(n, "cuij") || strings.Contains(n, "expte"):
		return KindOther
	}
	return KindUnknown
}

// TipoProcesoFromText classifies a body of text (filename or
// XML metadata) into a tipo de proceso. Case-insensitive.
func TipoProcesoFromText(text string) TipoProceso {
	t := strings.ToLower(text)
	switch {
	case t == "":
		return ProcesoUnknown
	case strings.Contains(t, "concurso preventivo") ||
		strings.Contains(t, "concurso-preventivo") ||
		strings.Contains(t, "concursopreventivo"):
		return ProcesoConcursoPreventivo
	case strings.Contains(t, "quiebra"):
		return ProcesoQuiebra
	case strings.Contains(t, "inhibici") || strings.Contains(t, "inhibición"):
		return ProcesoInhibicion
	case strings.Contains(t, "embargo"):
		return ProcesoEmbargo
	case strings.Contains(t, "ejecuci") || strings.Contains(t, "ejecución"):
		return ProcesoEjecucion
	case strings.Contains(t, "alimentos"):
		return ProcesoAlimentos
	case strings.Contains(t, "laboral") || strings.Contains(t, "fuero del trabajo"):
		return ProcesoLaboral
	case strings.Contains(t, "comercial") || strings.Contains(t, "fuero comercial"):
		return ProcesoComercial
	case strings.Contains(t, "civil"):
		return ProcesoCivil
	case strings.Contains(t, "penal") || strings.Contains(t, "criminal"):
		return ProcesoPenal
	}
	return ProcesoUnknown
}

// IsInsolvencyKind reports whether the tipo represents formal
// insolvency proceedings.
func IsInsolvencyKind(t TipoProceso) bool {
	return t == ProcesoConcursoPreventivo || t == ProcesoQuiebra
}

// IsAssetSeizureKind reports whether the tipo represents an
// asset-seizure / disposition restriction.
func IsAssetSeizureKind(t TipoProceso) bool {
	return t == ProcesoEmbargo || t == ProcesoInhibicion
}

// CuitEntityPrefixes mirrors the AFIP collector list.
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

// cuitRE matches 11-digit CUIT (hyphen-optional).
var cuitRE = regexp.MustCompile(`(\d{2})-?(\d{8})-?(\d)`)

// CuitFingerprint extracts (prefix, suffix4) from any CUIT text.
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

// cuijRE matches the modern 13-digit CUIJ pattern: type(1) +
// circunscripción(2) + año(4) + correlativo(6). Also accepts
// the older `NNNNN/YYYY` form. We use `(?:^|\D)` instead of
// `\b` because Go's word-boundary treats `_` as a word
// character, so `expte_1012024...` would not match `\b`.
var (
	cuijModernRE = regexp.MustCompile(`(?:^|\D)(\d{13})(?:\D|$)`)
	cuijLegacyRE = regexp.MustCompile(`(?:^|\D)(\d{1,7})/(20\d{2})(?:\D|$)`)
)

// CuijFingerprint extracts (year, suffix4) from a CUIJ found
// in `text`. Empty/no-match returns "","".
func CuijFingerprint(text string) (year, suffix4 string) {
	if m := cuijModernRE.FindStringSubmatch(text); m != nil {
		// type(1) circunscripción(2) año(4) correlativo(6)
		digits := m[1]
		year = digits[3:7]
		corr := digits[7:]
		if len(corr) >= 4 {
			suffix4 = corr[len(corr)-4:]
		}
		return year, suffix4
	}
	if m := cuijLegacyRE.FindStringSubmatch(text); m != nil {
		year = m[2]
		corr := m[1]
		if len(corr) >= 4 {
			suffix4 = corr[len(corr)-4:]
		} else {
			suffix4 = corr
		}
		return year, suffix4
	}
	return "", ""
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
	r.IsInsolvencyProceeding = IsInsolvencyKind(r.TipoProceso)
	r.IsAssetSeizure = IsAssetSeizureKind(r.TipoProceso)
	// PII exposure: judicial-PII present (CUIT or carátula).
	hasPII := r.TargetCuitPrefix != "" || r.Juzgado != "" ||
		r.CuijYear != "" || r.NotificationKind != KindUnknown
	if hasPII && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns a deterministic ordering by file path then
// (target CUIT, CUIJ).
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].TargetCuitPrefix != rs[j].TargetCuitPrefix {
			return rs[i].TargetCuitPrefix < rs[j].TargetCuitPrefix
		}
		if rs[i].TargetCuitSuffix4 != rs[j].TargetCuitSuffix4 {
			return rs[i].TargetCuitSuffix4 < rs[j].TargetCuitSuffix4
		}
		return rs[i].CuijYear < rs[j].CuijYear
	})
}
