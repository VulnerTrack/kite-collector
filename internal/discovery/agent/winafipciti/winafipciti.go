// Package winafipciti audits AFIP CITI Compras/Ventas
// (RG 3685 / RG 1361) and F2002 IVA files cached on
// accounting, treasury, and compliance workstations
// across Windows, Linux, and macOS.
//
// CITI files dump the entity's full monthly supplier
// (Compras) + customer (Ventas) list with invoice
// detail — the single most sensitive AFIP disclosure
// surface after WSAA private keys.
//
// **Distinct from**:
//   - iter 89  winafipwsfev1  — individual CAE invoices
//   - iter 100 winafipexport  — export factura E
//   - iter 114 winafipsicore  — SICORE retenciones
//
// Headline finding shapes:
//
//   - `has_natural_person_counterparty=1` — at least one
//     counterparty CUIT is natural person (Ley 25.326).
//   - `has_high_invoice_count=1` — counterparty count > 1000.
//   - `has_large_total=1` — total neto > 500 M ARS.
//   - `is_credential_exposure_risk=1` — readable file +
//     declarant CUIT + (natural-person counterparty OR
//     large total).
//
// Read-only by intent. (Project guideline 4.2.)
package winafipciti

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

// MaxFileBytes bounds per-file read. CITI dumps for large
// entities can hold tens of thousands of lines; 48 MiB cap.
const MaxFileBytes = 48 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// HighInvoiceCount — counterparty_count threshold for
// has_high_invoice_count.
const HighInvoiceCount int64 = 1000

// LargeTotalCents — 500 M ARS = 50 G cents.
const LargeTotalCents int64 = 50_000_000_000

// ArtifactKind pinned to host_afip_citi.artifact_kind.
type ArtifactKind string

const (
	KindCITIVentas         ArtifactKind = "citi-ventas"
	KindCITICompras        ArtifactKind = "citi-compras"
	KindCITIAlicuotas      ArtifactKind = "citi-alicuotas"
	KindF2002IVA           ArtifactKind = "f2002-iva"
	KindF2002Alicuotas     ArtifactKind = "f2002-alicuotas"
	KindComprobantesExport ArtifactKind = "comprobantes-export"
	KindOther              ArtifactKind = "other"
	KindUnknown            ArtifactKind = "unknown"
)

// Row mirrors host_afip_citi' column shape.
type Row struct {
	FilePath                       string       `json:"file_path"`
	FileHash                       string       `json:"file_hash"`
	UserProfile                    string       `json:"user_profile,omitempty"`
	ArtifactKind                   ArtifactKind `json:"artifact_kind"`
	DeclarantCuitPrefix            string       `json:"declarant_cuit_prefix,omitempty"`
	DeclarantCuitSuffix4           string       `json:"declarant_cuit_suffix4,omitempty"`
	PeriodYYYYMM                   string       `json:"period_yyyymm,omitempty"`
	CounterpartyCount              int64        `json:"counterparty_count,omitempty"`
	NaturalPersonCounterpartyCount int64        `json:"natural_person_counterparty_count,omitempty"`
	TotalNetoARSCents              int64        `json:"total_neto_ars_cents,omitempty"`
	TotalIVAARSCents               int64        `json:"total_iva_ars_cents,omitempty"`
	MaxInvoiceARSCents             int64        `json:"max_invoice_ars_cents,omitempty"`
	FileOwnerUID                   int          `json:"file_owner_uid,omitempty"`
	FileMode                       int          `json:"file_mode,omitempty"`
	FileSize                       int64        `json:"file_size,omitempty"`
	HasNaturalPersonCounterparty   bool         `json:"has_natural_person_counterparty"`
	HasHighInvoiceCount            bool         `json:"has_high_invoice_count"`
	HasLargeTotal                  bool         `json:"has_large_total"`
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

// DefaultInstallRoots is the curated CITI install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\AFIP\CITI`,
		`C:\AFIP\IVA`,
		`C:\SIAP\CITI`,
		`C:\Facturacion\citi`,
		`C:\Contabilidad\citi`,
		`/opt/afip/citi`,
		`/opt/afip/iva`,
		`/var/lib/afip/citi`,
		`/srv/citi`,
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

// UserCITIDirs is the curated per-user relative path set.
func UserCITIDirs() [][]string {
	return [][]string{
		{"Documents", "AFIP", "CITI"},
		{"Documents", "AFIP", "IVA"},
		{"Documents", "Contabilidad", "citi"},
		{"Documents", "Facturacion", "citi"},
		{"AppData", "Local", "AFIP", "CITI"},
		{"AppData", "Roaming", "AFIP", "CITI"},
	}
}

// IsCandidateExt reports whether the extension carries CITI
// material.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".txt", ".csv", ".xml", ".dat":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the CITI catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"citi_", "citi-", "_citi", "-citi", "citi.",
		"citi_ventas", "citi-ventas",
		"citi_compras", "citi-compras",
		"citi_alicuotas", "citi-alicuotas",
		"f2002_", "f2002-", "f2002.",
		"iva_digital", "iva-digital",
		"comprobantes_export", "comprobantes-export",
		"regimen_compras_ventas",
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
	case strings.Contains(n, "citi_ventas") || strings.Contains(n, "citi-ventas"):
		return KindCITIVentas
	case strings.Contains(n, "citi_compras") || strings.Contains(n, "citi-compras"):
		return KindCITICompras
	case strings.Contains(n, "citi_alicuotas") || strings.Contains(n, "citi-alicuotas"):
		return KindCITIAlicuotas
	case strings.Contains(n, "f2002_alicuotas") || strings.Contains(n, "f2002-alicuotas"):
		return KindF2002Alicuotas
	case strings.Contains(n, "f2002"):
		return KindF2002IVA
	case strings.Contains(n, "comprobantes_export") || strings.Contains(n, "comprobantes-export"):
		return KindComprobantesExport
	case strings.Contains(n, "citi"):
		return KindOther
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
	if r.NaturalPersonCounterpartyCount > 0 {
		r.HasNaturalPersonCounterparty = true
	}
	if r.CounterpartyCount > HighInvoiceCount {
		r.HasHighInvoiceCount = true
	}
	if r.TotalNetoARSCents > LargeTotalCents {
		r.HasLargeTotal = true
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	if hasReadable && r.DeclarantCuitPrefix != "" {
		if r.HasNaturalPersonCounterparty || r.HasLargeTotal {
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
