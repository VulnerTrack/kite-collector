// Package winafipsicore audits AFIP SICORE / SIRE retention-
// agent files (F744, retenciones / percepciones detail, SIRE
// CGS) cached on payroll, treasury, and compliance
// workstations across Windows, Linux, and macOS.
//
// SICORE/SIRE files enumerate every CUIT the agent withheld
// from in a given period — equivalent to a vendor / payroll
// roster + AML-grade transaction graph. Natural-person
// retained CUITs (prefix 20/23/24/27) carry Ley 25.326 PII.
//
// **Distinct from**:
//   - iter 89  winafipwsfev1 — outbound invoices
//   - iter 100 winafipexport — export factura E
//   - iter 87+ general AFIP collectors
//
// Headline finding shapes:
//
//   - `has_natural_person_retained=1` — at least one retenido
//     CUIT has natural-person prefix.
//   - `has_high_volume=1` — retained_count > 1000.
//   - `has_large_retention_total=1` — total > 100 M ARS.
//   - `is_credential_exposure_risk=1` — readable file +
//     agent CUIT + (natural-person retained OR large total).
//
// Read-only by intent. (Project guideline 4.2.)
package winafipsicore

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

// MaxFileBytes bounds per-file read (32 MiB — SICORE dumps
// can carry tens of thousands of retention rows).
const MaxFileBytes = 32 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// HighVolumeRetainedCount — retained_count threshold for
// has_high_volume.
const HighVolumeRetainedCount int64 = 1000

// LargeRetentionTotalCents — total threshold for
// has_large_retention_total (100 M ARS = 10 G cents).
const LargeRetentionTotalCents int64 = 10_000_000_000

// ArtifactKind pinned to host_afip_sicore.artifact_kind.
type ArtifactKind string

const (
	KindSICOREDDJJ      ArtifactKind = "sicore-ddjj"
	KindF744XML         ArtifactKind = "f744-xml"
	KindRetencionesCSV  ArtifactKind = "retenciones-csv"
	KindPercepcionesCSV ArtifactKind = "percepciones-csv"
	KindPagosCSV        ArtifactKind = "pagos-csv"
	KindSIRECGS         ArtifactKind = "sire-cgs"
	KindOther           ArtifactKind = "other"
	KindUnknown         ArtifactKind = "unknown"
)

// RegimenKind pinned to host_afip_sicore.regimen_kind.
type RegimenKind string

const (
	RegimenGananciasR6 RegimenKind = "ganancias-r6"
	RegimenIVAR1       RegimenKind = "iva-r1"
	RegimenIVAR2       RegimenKind = "iva-r2"
	RegimenIVAR3       RegimenKind = "iva-r3"
	RegimenSSocialR5   RegimenKind = "ssocial-r5"
	RegimenSUSSR10     RegimenKind = "suss-r10"
	RegimenIIBBCM      RegimenKind = "iibb-cm"
	RegimenMonotributo RegimenKind = "monotributo"
	RegimenOther       RegimenKind = "other"
	RegimenUnknown     RegimenKind = "unknown"
)

// Row mirrors host_afip_sicore' column shape.
type Row struct {
	FilePath                   string       `json:"file_path"`
	FileHash                   string       `json:"file_hash"`
	UserProfile                string       `json:"user_profile,omitempty"`
	ArtifactKind               ArtifactKind `json:"artifact_kind"`
	RegimenKind                RegimenKind  `json:"regimen_kind"`
	AgentCuitPrefix            string       `json:"agent_cuit_prefix,omitempty"`
	AgentCuitSuffix4           string       `json:"agent_cuit_suffix4,omitempty"`
	PeriodYYYYMM               string       `json:"period_yyyymm,omitempty"`
	RetainedCount              int64        `json:"retained_count,omitempty"`
	NaturalPersonRetainedCount int64        `json:"natural_person_retained_count,omitempty"`
	MaxRetentionARSCents       int64        `json:"max_retention_ars_cents,omitempty"`
	TotalRetentionARSCents     int64        `json:"total_retention_ars_cents,omitempty"`
	FileOwnerUID               int          `json:"file_owner_uid,omitempty"`
	FileMode                   int          `json:"file_mode,omitempty"`
	FileSize                   int64        `json:"file_size,omitempty"`
	HasNaturalPersonRetained   bool         `json:"has_natural_person_retained"`
	HasHighVolume              bool         `json:"has_high_volume"`
	HasLargeRetentionTotal     bool         `json:"has_large_retention_total"`
	IsRecent                   bool         `json:"is_recent"`
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

// DefaultInstallRoots is the curated SICORE install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\AFIP\SICORE`,
		`C:\AFIP\SIRE`,
		`C:\SIAP\SICORE`,
		`C:\Facturacion\sicore`,
		`C:\Tesoreria\sicore`,
		`/opt/afip/sicore`,
		`/opt/afip/sire`,
		`/var/lib/afip/sicore`,
		`/srv/sicore`,
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

// UserSICOREDirs is the curated per-user relative path set.
func UserSICOREDirs() [][]string {
	return [][]string{
		{"Documents", "AFIP", "SICORE"},
		{"Documents", "AFIP", "SIRE"},
		{"Documents", "Tesoreria", "sicore"},
		{"Documents", "Liquidacion", "sicore"},
		{"AppData", "Local", "AFIP", "SICORE"},
		{"AppData", "Roaming", "AFIP", "SICORE"},
	}
}

// IsCandidateExt reports whether the extension carries a
// SICORE artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".txt", ".csv", ".xml", ".dat":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the SICORE catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"sicore_", "sicore-", "_sicore", "-sicore",
		"sicore.",
		"sire_cgs", "sire-cgs", "sire_",
		"f744_", "f744-", "f744.",
		"retenciones_", "retenciones-",
		"percepciones_", "percepciones-",
		"pagos_retenciones", "pagos-retenciones",
		"ddjj_retenciones", "ddjj-retenciones",
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
	case strings.Contains(n, "f744"):
		return KindF744XML
	case strings.Contains(n, "sire_cgs") || strings.Contains(n, "sire-cgs"):
		return KindSIRECGS
	case strings.Contains(n, "ddjj_retenciones") || strings.Contains(n, "ddjj-retenciones"):
		return KindSICOREDDJJ
	case strings.Contains(n, "pagos_retenciones") || strings.Contains(n, "pagos-retenciones"):
		return KindPagosCSV
	case strings.Contains(n, "percepciones"):
		return KindPercepcionesCSV
	case strings.Contains(n, "retenciones"):
		return KindRetencionesCSV
	case strings.Contains(n, "sicore") || strings.Contains(n, "ddjj"):
		return KindSICOREDDJJ
	}
	return KindOther
}

// RegimenFromText classifies a régimen label.
func RegimenFromText(s string) RegimenKind {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case t == "":
		return RegimenUnknown
	case strings.Contains(t, "ganancias") || t == "r6" || strings.Contains(t, "r-6"):
		return RegimenGananciasR6
	case strings.Contains(t, "iva") && (strings.Contains(t, "r1") || strings.Contains(t, "r-1")):
		return RegimenIVAR1
	case strings.Contains(t, "iva") && (strings.Contains(t, "r2") || strings.Contains(t, "r-2")):
		return RegimenIVAR2
	case strings.Contains(t, "iva") && (strings.Contains(t, "r3") || strings.Contains(t, "r-3")):
		return RegimenIVAR3
	case strings.Contains(t, "iva"):
		return RegimenIVAR1
	case strings.Contains(t, "seguridad social") || t == "r5" || strings.Contains(t, "r-5"):
		return RegimenSSocialR5
	case strings.Contains(t, "suss") || t == "r10" || strings.Contains(t, "r-10"):
		return RegimenSUSSR10
	case strings.Contains(t, "iibb") || strings.Contains(t, "convenio multilateral"):
		return RegimenIIBBCM
	case strings.Contains(t, "monotributo"):
		return RegimenMonotributo
	}
	return RegimenOther
}

// RegimenFromName tries to classify the régimen from the
// filename itself.
func RegimenFromName(name string) RegimenKind {
	n := strings.ToLower(filepath.Base(name))
	return RegimenFromText(n)
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

// IsNaturalPersonPrefix reports whether the prefix is a
// natural-person CUIT type.
func IsNaturalPersonPrefix(p string) bool {
	switch p {
	case "20", "23", "24", "27":
		return true
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

// PeriodFromFilename extracts YYYYMM from a filename.
func PeriodFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.NaturalPersonRetainedCount > 0 {
		r.HasNaturalPersonRetained = true
	}
	if r.RetainedCount > HighVolumeRetainedCount {
		r.HasHighVolume = true
	}
	if r.TotalRetentionARSCents > LargeRetentionTotalCents {
		r.HasLargeRetentionTotal = true
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	if hasReadable && r.AgentCuitPrefix != "" {
		if r.HasNaturalPersonRetained || r.HasLargeRetentionTotal {
			r.IsCredentialExposureRisk = true
		}
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
