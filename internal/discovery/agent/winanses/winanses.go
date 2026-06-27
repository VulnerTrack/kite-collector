// Package winanses audits Argentine ANSES (Administración
// Nacional de la Seguridad Social) consultation cache + audit-
// log files on KYC / payroll / NGO / banking workstations
// across Windows, Linux, and macOS.
//
// ANSES holds the natural-person social-security identity:
// CUIL → aportes, grupo familiar, AUH, jubilación, planes
// sociales.
//
// **Pairs with iter 103 RENAPER on the natural-person identity
// axis.** RENAPER = civil registry; ANSES = social-security
// identity + benefit eligibility.
//
// Sensitivity tiers:
//
//   - Child dependents in grupo familiar → Ley 26.061
//   - AUH / means-tested status → socioeconomic-sensitive
//   - Jubilados / pensionados → financially-vulnerable cohort
//
// Headline finding shapes:
//
//   - `has_grupo_familiar=1` — file lists dependents.
//   - `has_minor_dependent=1` — dependent born within the
//     last 18 years. Ley 26.061 child tier.
//   - `has_auh_status=1` — AUH / plan social field present.
//   - `has_jubilacion_status=1` — pension field present.
//   - `is_credential_exposure_risk=1` — readable file + ANY
//     consultation kind. Natural-person social-security breach.
//
// CUILs NEVER stored verbatim — only entity-type prefix
// (20/23/24/27) + last 4 digits. Names, addresses, dependent
// DNIs NEVER stored.
//
// Read-only by intent. (Project guideline 4.2.)
package winanses

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
const MaxRows = 32768

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 4 << 20 // 4 MiB

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// BatchThreshold flips is_batch when consultation_count >.
const BatchThreshold = 5

// MinorYearThreshold defines the cutoff year for child
// dependent detection (relative to collector-commit time
// 2026). The audit pipeline re-evaluates downstream.
const MinorYearThreshold = 2008 // dependents born ≥ this year as of 2026 are < 18

// ConsultationKind pinned to host_anses_cache.consultation_kind.
type ConsultationKind string

const (
	KindCUILIndividual ConsultationKind = "cuil-individual"
	KindCUILBatch      ConsultationKind = "cuil-batch"
	KindAuditLog       ConsultationKind = "audit-log"
	KindAportesHist    ConsultationKind = "aportes-historial"
	KindGrupoFamiliar  ConsultationKind = "grupo-familiar"
	KindAUHStatus      ConsultationKind = "auh-status"
	KindJubilacion     ConsultationKind = "jubilacion-status"
	KindPadron         ConsultationKind = "padron"
	KindOther          ConsultationKind = "other"
	KindUnknown        ConsultationKind = "unknown"
)

// Row mirrors host_anses_cache' column shape.
type Row struct {
	LatestConsultation       string           `json:"latest_consultation,omitempty"`
	EarliestConsultation     string           `json:"earliest_consultation,omitempty"`
	FechaAcceso              string           `json:"fecha_acceso,omitempty"`
	FileHash                 string           `json:"file_hash"`
	FilePath                 string           `json:"file_path"`
	UserProfile              string           `json:"user_profile,omitempty"`
	ConsultationKind         ConsultationKind `json:"consultation_kind"`
	TargetCuilPrefix         string           `json:"target_cuil_prefix,omitempty"`
	TargetCuilSuffix4        string           `json:"target_cuil_suffix4,omitempty"`
	FileOwnerUID             int              `json:"file_owner_uid,omitempty"`
	DependentCount           int              `json:"dependent_count,omitempty"`
	ConsultationCount        int              `json:"consultation_count,omitempty"`
	FileMode                 int              `json:"file_mode,omitempty"`
	FileSize                 int64            `json:"file_size,omitempty"`
	IsRecent                 bool             `json:"is_recent"`
	HasMinorDependent        bool             `json:"has_minor_dependent"`
	HasAUHStatus             bool             `json:"has_auh_status"`
	HasJubilacionStatus      bool             `json:"has_jubilacion_status"`
	HasAportesHistorial      bool             `json:"has_aportes_historial"`
	IsAuditLog               bool             `json:"is_audit_log"`
	IsBatch                  bool             `json:"is_batch"`
	HasGrupoFamiliar         bool             `json:"has_grupo_familiar"`
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

// DefaultInstallRoots is the curated ANSES install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\ANSES`,
		`C:\KYC\ANSES`,
		`C:\Compliance\ANSES`,
		`C:\Sueldos\ANSES`,
		`/opt/anses`,
		`/srv/anses`,
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

// UserAnsesDirs is the curated per-user relative path set.
func UserAnsesDirs() [][]string {
	return [][]string{
		{"Documents", "ANSES"},
		{"Documents", "KYC", "ANSES"},
		{"Documents", "Compliance", "ANSES"},
		{"Documents", "Sueldos", "ANSES"},
		{"Documents", "RRHH"},
		{".anses"},
		{".afip", "anses_cache"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateName reports whether a filename plausibly belongs
// to the ANSES catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"anses", "consulta_cuil", "consulta-cuil",
		"cuil_consulta", "grupo_familiar", "grupo-familiar",
		"aportes_", "auh_", "auh-",
		"jubilacion", "jubilación", "pension",
		"mias_anses", "mi_anses", "mi-anses",
		"padron_anses", "rrhh_anses",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ConsultationKindFromName classifies a filename heuristically.
// Order: jubilacion > auh > grupo-familiar > aportes-historial
// > audit-log > batch > padron > individual > other.
func ConsultationKindFromName(name string) ConsultationKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "jubilacion") || strings.Contains(n, "jubilación") ||
		strings.Contains(n, "pension") || strings.Contains(n, "pensión"):
		return KindJubilacion
	case strings.Contains(n, "auh_") || strings.Contains(n, "auh-") ||
		strings.Contains(n, "_auh") || strings.Contains(n, "asignacion_universal"):
		return KindAUHStatus
	case strings.Contains(n, "grupo_familiar") || strings.Contains(n, "grupo-familiar"):
		return KindGrupoFamiliar
	case strings.Contains(n, "aportes_") || strings.Contains(n, "aportes-"):
		return KindAportesHist
	case strings.Contains(n, "audit") || strings.HasSuffix(n, ".jsonl") ||
		strings.Contains(n, "log_anses"):
		return KindAuditLog
	case strings.Contains(n, "batch") || strings.Contains(n, "lote_anses"):
		return KindCUILBatch
	case strings.Contains(n, "padron_anses") || strings.Contains(n, "padron-anses"):
		return KindPadron
	case strings.Contains(n, "anses") || strings.Contains(n, "consulta_cuil") ||
		strings.Contains(n, "consulta-cuil"):
		return KindCUILIndividual
	case strings.Contains(n, "rrhh") || strings.Contains(n, "mi_anses"):
		return KindOther
	}
	return KindUnknown
}

// NaturalPersonPrefixes lists CUIL prefixes (20/23/24/27).
func NaturalPersonPrefixes() []string {
	return []string{"20", "23", "24", "27"}
}

// IsValidCuilPrefix reports prefix membership.
func IsValidCuilPrefix(p string) bool {
	for _, v := range NaturalPersonPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuilRE matches 11-digit CUIL bounded by non-digit / edges.
// `\b` avoided because Go regex treats `_` as a word char.
var cuilRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// CuilFingerprint extracts (prefix, suffix4) from text.
// Returns "","" if no valid natural-person prefix.
func CuilFingerprint(text string) (prefix, suffix4 string) {
	m := cuilRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuilPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// AUHTokens lists narrative tokens that indicate AUH / plan-
// social signal in body content.
func AUHTokens() []string {
	return []string{
		"auh", "asignacion universal por hijo",
		"asignación universal por hijo",
		"plan social", "tarjeta alimentar",
		"potenciar trabajo", "progresar",
	}
}

// JubilacionTokens lists narrative tokens for retirement /
// pension signal.
func JubilacionTokens() []string {
	return []string{
		"jubilacion", "jubilación", "jubilado",
		"pensionado", "pension", "pensión",
		"haber previsional", "haber jubilatorio",
	}
}

// AportesTokens lists narrative tokens for aportes/contribuciones.
func AportesTokens() []string {
	return []string{
		"aporte_jubilatorio", "aporte personal",
		"contribucion patronal", "contribución patronal",
		"obra social", "historial_aportes",
		"\"aportes\":",
	}
}

// GrupoFamiliarTokens lists narrative tokens for dependents.
func GrupoFamiliarTokens() []string {
	return []string{
		"grupo_familiar", "grupo familiar",
		"dependientes", "hijos a cargo",
		"\"familiares\":", "\"dependientes\":",
	}
}

// MinorDateRE matches YYYY[-/]MM[-/]DD where YYYY ≥
// MinorYearThreshold.
var minorDateRE = regexp.MustCompile(`(20\d{2})[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])`)

// ContainsMinorDate scans body for a date string that puts a
// natural person under 18 (relative to MinorYearThreshold).
func ContainsMinorDate(body []byte) bool {
	matches := minorDateRE.FindAllStringSubmatch(string(body), -1)
	for _, m := range matches {
		if len(m) >= 2 {
			year, ok := parseYear(m[1])
			if ok && year >= MinorYearThreshold {
				return true
			}
		}
	}
	return false
}

func parseYear(s string) (int, bool) {
	if len(s) != 4 {
		return 0, false
	}
	year := 0
	for i := 0; i < 4; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		year = year*10 + int(c-'0')
	}
	return year, true
}

// ContainsAnyToken checks body for any case-insensitive
// substring token.
func ContainsAnyToken(body []byte, tokens []string) bool {
	lower := bytesToLower(body, 16384)
	for _, tok := range tokens {
		if containsString(lower, tok) {
			return true
		}
	}
	return false
}

// CountLinesAsLog approximates record-count for an audit log.
func CountLinesAsLog(body []byte) int {
	n := 0
	for _, c := range body {
		if c == '\n' {
			n++
		}
	}
	if len(body) > 0 && body[len(body)-1] != '\n' {
		n++
	}
	return n
}

// CountDependents approximates dependent count in an XML/JSON
// grupo-familiar body by `<dependiente>` / `"familiares":[…]`
// markers.
func CountDependents(body []byte) int {
	lower := bytesToLower(body, 65536)
	count := 0
	for _, marker := range []string{
		"<dependiente>", "<familiar>", "<hijo>",
		"\"dependiente\":", "\"familiar\":", "\"hijo\":",
	} {
		count += countOccurrences(lower, marker)
	}
	return count
}

// -- byte-walk helpers ---------------------------------------

func bytesToLower(b []byte, maxBytes int) []byte {
	n := len(b)
	if n > maxBytes {
		n = maxBytes
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

func containsString(haystack []byte, needle string) bool {
	nbytes := []byte(needle)
	if len(nbytes) == 0 || len(haystack) < len(nbytes) {
		return false
	}
outer:
	for i := 0; i <= len(haystack)-len(nbytes); i++ {
		for j, c := range nbytes {
			if haystack[i+j] != c {
				continue outer
			}
		}
		return true
	}
	return false
}

func countOccurrences(haystack []byte, needle string) int {
	nbytes := []byte(needle)
	if len(nbytes) == 0 || len(haystack) < len(nbytes) {
		return 0
	}
	count := 0
	for i := 0; i <= len(haystack)-len(nbytes); i++ {
		matched := true
		for j, c := range nbytes {
			if haystack[i+j] != c {
				matched = false
				break
			}
		}
		if matched {
			count++
			i += len(nbytes) - 1
		}
	}
	return count
}

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	r.IsAuditLog = r.ConsultationKind == KindAuditLog
	if r.ConsultationKind == KindCUILBatch || r.ConsultationCount > BatchThreshold {
		r.IsBatch = true
	}
	if r.ConsultationKind == KindGrupoFamiliar || r.DependentCount > 0 {
		r.HasGrupoFamiliar = true
	}
	if r.ConsultationKind == KindAportesHist {
		r.HasAportesHistorial = true
	}
	if r.ConsultationKind == KindAUHStatus {
		r.HasAUHStatus = true
	}
	if r.ConsultationKind == KindJubilacion {
		r.HasJubilacionStatus = true
	}
	// Any ANSES consultation cached on disk + readable beyond
	// owner = natural-person social-security PII breach.
	if (r.IsWorldReadable || r.IsGroupReadable) && r.ConsultationKind != "" &&
		r.ConsultationKind != KindUnknown {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].ConsultationKind != rs[j].ConsultationKind {
			return rs[i].ConsultationKind < rs[j].ConsultationKind
		}
		if rs[i].TargetCuilPrefix != rs[j].TargetCuilPrefix {
			return rs[i].TargetCuilPrefix < rs[j].TargetCuilPrefix
		}
		return rs[i].TargetCuilSuffix4 < rs[j].TargetCuilSuffix4
	})
}
