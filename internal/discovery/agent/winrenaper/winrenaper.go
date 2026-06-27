// Package winrenaper audits Argentine RENAPER (Registro
// Nacional de las Personas) consultation cache + audit-log
// files on KYC / compliance / onboarding workstations across
// Windows, Linux, and macOS.
//
// RENAPER is Argentina's national civil registry. Every
// empresa doing KYC, banking onboarding, mobile-phone signup,
// e-signature, or AML / UBO verification queries RENAPER for
// natural-person identity (DNI → name, birth, photo, sometimes
// biometric). SDKs cache responses on disk + emit
// transactional audit logs.
//
// **The most-sensitive PII class in the catalogue.** RENAPER
// data on disk = direct natural-person identity breach with
// criminal exposure under:
//
//   - Ley 25.326 Protección de Datos Personales
//   - Ley 26.951 acceso indebido a datos personales
//   - Ley 26.061 protección integral de NNyA (child tier)
//
// Headline finding shapes:
//
//   - `has_photo=1` — fotografía DNI cached. Highest tier.
//   - `has_biometric=1` — huella dactilar / iris / firma
//     digital cached. Ley 26.951 biometric tier.
//   - `is_audit_log=1` — transactional log of consultations.
//     Multiplies blast radius.
//   - `is_credential_exposure_risk=1` — readable file + ANY
//     consultation kind = highest-severity flag in the entire
//     collector suite.
//
// DNIs are NEVER stored verbatim — only the trailing 4 digits.
// Names, addresses, photos, biometrics NEVER stored — only
// presence booleans.
//
// Read-only by intent. (Project guideline 4.2.)
package winrenaper

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
const MaxFileBytes = 8 << 20 // 8 MiB — photo caches can be large

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// BatchThreshold is the consultation count above which
// is_batch flips to 1.
const BatchThreshold = 5

// ConsultationKind pinned to host_renaper_cache.consultation_kind.
type ConsultationKind string

const (
	KindDNIIndividual ConsultationKind = "dni-individual"
	KindDNIBatch      ConsultationKind = "dni-batch"
	KindAuditLog      ConsultationKind = "audit-log"
	KindPhotoCache    ConsultationKind = "photo-cache"
	KindBiometric     ConsultationKind = "biometric"
	KindOther         ConsultationKind = "other"
	KindUnknown       ConsultationKind = "unknown"
)

// Row mirrors host_renaper_cache' column shape.
type Row struct {
	LatestConsultation       string           `json:"latest_consultation,omitempty"`
	FechaAcceso              string           `json:"fecha_acceso,omitempty"`
	FilePath                 string           `json:"file_path"`
	FileHash                 string           `json:"file_hash"`
	EarliestConsultation     string           `json:"earliest_consultation,omitempty"`
	UserProfile              string           `json:"user_profile,omitempty"`
	ConsultationKind         ConsultationKind `json:"consultation_kind"`
	TargetDniSuffix4         string           `json:"target_dni_suffix4,omitempty"`
	FileSize                 int64            `json:"file_size,omitempty"`
	FileOwnerUID             int              `json:"file_owner_uid,omitempty"`
	FileMode                 int              `json:"file_mode,omitempty"`
	ConsultationCount        int              `json:"consultation_count,omitempty"`
	IsGroupReadable          bool             `json:"is_group_readable"`
	IsAuditLog               bool             `json:"is_audit_log"`
	HasBiometric             bool             `json:"has_biometric"`
	HasPhoto                 bool             `json:"has_photo"`
	IsBatch                  bool             `json:"is_batch"`
	IsRecent                 bool             `json:"is_recent"`
	IsWorldReadable          bool             `json:"is_world_readable"`
	HasDomicilio             bool             `json:"has_domicilio"`
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

// DefaultInstallRoots is the curated RENAPER install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\RENAPER`,
		`C:\KYC`,
		`C:\KYC\RENAPER`,
		`C:\Compliance\RENAPER`,
		`/opt/renaper`,
		`/srv/renaper`,
		`/srv/kyc`,
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

// UserRenaperDirs is the curated per-user relative path set.
func UserRenaperDirs() [][]string {
	return [][]string{
		{"Documents", "RENAPER"},
		{"Documents", "KYC"},
		{"Documents", "KYC", "RENAPER"},
		{"Documents", "Compliance", "RENAPER"},
		{".afip", "renaper_cache"},
		{".kyc"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateName reports whether a filename plausibly belongs
// to the RENAPER catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"renaper", "consulta_dni", "consulta-dni",
		"dni_consulta", "dni-consulta",
		"kyc_", "kyc-", "padron_renaper",
		"verificacion_identidad", "verificacion-identidad",
		"biometric", "biometria", "huella_",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ConsultationKindFromName classifies a filename heuristically.
//
// Order matters — biometric > photo > audit-log > batch >
// individual > other.
func ConsultationKindFromName(name string) ConsultationKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "biometric") || strings.Contains(n, "biometria") ||
		strings.Contains(n, "huella") || strings.Contains(n, "iris"):
		return KindBiometric
	case strings.Contains(n, "foto") || strings.Contains(n, "photo") ||
		strings.Contains(n, "_jpg") || strings.Contains(n, "_png"):
		return KindPhotoCache
	case strings.Contains(n, "audit") || strings.HasSuffix(n, ".jsonl") ||
		strings.Contains(n, "log_"):
		return KindAuditLog
	case strings.Contains(n, "batch") || strings.Contains(n, "lote_") ||
		strings.Contains(n, "_csv"):
		return KindDNIBatch
	case strings.Contains(n, "renaper") || strings.Contains(n, "consulta_dni") ||
		strings.Contains(n, "consulta-dni") || strings.Contains(n, "dni_consulta") ||
		strings.Contains(n, "verificacion_identidad"):
		return KindDNIIndividual
	case strings.Contains(n, "kyc"):
		return KindOther
	}
	return KindUnknown
}

// dniRE matches 7-8 digit DNI runs bounded by non-digit (or
// string edge). We avoid `\b` because Go regex treats `_` as
// a word character — `consulta_dni_12345678.xml` would not
// match `\b`.
var dniRE = regexp.MustCompile(`(?:^|\D)(\d{7,8})(?:\D|$)`)

// DniSuffix4 extracts the trailing 4 digits of a 7-8 digit
// DNI found in `text`. Returns "" if no match.
func DniSuffix4(text string) string {
	m := dniRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	dni := m[1]
	if len(dni) < 4 {
		return ""
	}
	return dni[len(dni)-4:]
}

// PhotoMimeBoundaries lists prefix bytes that indicate
// presence of an embedded photo blob.
func PhotoMimeBoundaries() [][]byte {
	return [][]byte{
		{0xFF, 0xD8, 0xFF},                // JPEG
		{0x89, 'P', 'N', 'G', 0x0D, 0x0A}, // PNG
		{'G', 'I', 'F', '8'},              // GIF
	}
}

// ContainsPhoto reports whether the body contains an embedded
// photo by binary-signature scan or base64 marker.
func ContainsPhoto(body []byte) bool {
	for _, sig := range PhotoMimeBoundaries() {
		if containsBytes(body, sig) {
			return true
		}
	}
	// base64 markers commonly used in JSON envelopes.
	lower := bytesToLower(body, 4096)
	for _, marker := range []string{
		"data:image/jpeg;base64,",
		"data:image/png;base64,",
		"\"foto\":",
		"\"photo\":",
		"\"fotografia\":",
		"\"imagen\":",
	} {
		if stringsContainsBytes(lower, marker) {
			return true
		}
	}
	return false
}

// ContainsBiometric reports whether the body references
// fingerprint or biometric content.
func ContainsBiometric(body []byte) bool {
	lower := bytesToLower(body, 4096)
	for _, marker := range []string{
		"\"huella\":", "\"fingerprint\":",
		"\"iris\":", "\"minutiae\":",
		"\"biometric\":", "\"biometria\":",
		"wsq", // standard fingerprint format
	} {
		if stringsContainsBytes(lower, marker) {
			return true
		}
	}
	return false
}

// ContainsDomicilio reports whether the body references
// domicilio fields.
func ContainsDomicilio(body []byte) bool {
	lower := bytesToLower(body, 4096)
	for _, marker := range []string{
		"\"domicilio\":", "\"calle\":", "\"direccion\":",
		"\"address\":", "<domicilio>", "<calle>",
	} {
		if stringsContainsBytes(lower, marker) {
			return true
		}
	}
	return false
}

// bytesToLower returns a lowercased copy of up to maxBytes of
// `b`, only converting ASCII-letter bytes.
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

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
outer:
	for i := 0; i <= len(haystack)-len(needle); i++ {
		for j, c := range needle {
			if haystack[i+j] != c {
				continue outer
			}
		}
		return true
	}
	return false
}

func stringsContainsBytes(haystack []byte, needle string) bool {
	return containsBytes(haystack, []byte(needle))
}

// CountLinesAsLog approximates the consultation-count for a
// JSONL / TSV / CSV audit log. Returns 0 if the file isn't
// structured.
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

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	r.IsAuditLog = r.ConsultationKind == KindAuditLog
	if r.ConsultationKind == KindDNIBatch || r.ConsultationCount > BatchThreshold {
		r.IsBatch = true
	}
	// **CRITICAL** — any RENAPER file readable beyond owner is
	// direct natural-person identity exposure under Ley 25.326 +
	// Ley 26.951. Flagged for ANY consultation kind (even
	// Unknown), because the filename alone implicating RENAPER is
	// enough to alert the audit pipeline.
	if (r.IsWorldReadable || r.IsGroupReadable) && r.ConsultationKind != "" {
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
		return rs[i].TargetDniSuffix4 < rs[j].TargetDniSuffix4
	})
}
