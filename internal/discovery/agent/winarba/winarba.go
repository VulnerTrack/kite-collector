// Package winarba audits Argentine provincial tax-agency
// local-cache files (ARBA / AGIP / API / DGR provinciales) on
// Windows accounting workstations. Beyond AFIP-national, every
// empresa files province-level Ingresos Brutos + retención /
// percepción regimes via fixed-width TXT or CSV exports the
// accounting software produces and re-uploads.
//
// File-based discovery is the deliberate design choice — the
// flat-file formats are stable (RG 1361 CITI, RG 830 SICORE,
// ARBA DN 1/2004 Padrón IIBB) and consistently land under
// agency-named directories.
//
// Headline finding shapes (Tax-PII context):
//
//   - `is_high_value_file=1` — file > 1 MiB (operative
//     retention export, not a header stub).
//   - `is_credential_exposure_risk=1` — readable file +
//     sensitive file_kind (retention/perception or IIBB padrón
//     carrying recipient CUITs).
//
// CUIT (when discoverable from filename) is NEVER stored
// verbatim — only entity-type prefix + last 4 digits.
//
// Read-only by intent — we walk candidate files only, never
// parse the operative tax data. (Project guideline 4.2.)
package winarba

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

// HighValueFileBytes — files above this size are considered
// operative (not header / template).
const HighValueFileBytes int64 = 1 << 20 // 1 MiB

// MaxFileBytes bounds per-file read for hashing.
const MaxFileBytes = 64 << 20 // 64 MiB

// Agency pinned to host_arg_provincial_tax.agency CHECK enum.
type Agency string

const (
	AgencyARBA        Agency = "arba"
	AgencyAGIP        Agency = "agip"
	AgencyAPI         Agency = "api"
	AgencyDGRCordoba  Agency = "dgr-cordoba"
	AgencyDGRMendoza  Agency = "dgr-mendoza"
	AgencyDGRMisiones Agency = "dgr-misiones"
	AgencyAFIP        Agency = "afip"
	AgencyOther       Agency = "other"
	AgencyUnknown     Agency = "unknown"
)

// FileKind pinned to host_arg_provincial_tax.file_kind enum.
type FileKind string

const (
	KindCITIVentas         FileKind = "citi-ventas"
	KindCITICompras        FileKind = "citi-compras"
	KindSICORERetenciones  FileKind = "sicore-retenciones"
	KindSICOREPercepciones FileKind = "sicore-percepciones"
	KindPadronIIBB         FileKind = "padron-iibb"
	KindAlicuotas          FileKind = "alicuotas"
	KindCM05               FileKind = "cm05"
	KindIIBBDeclaracion    FileKind = "iibb-declaracion"
	KindOther              FileKind = "other"
	KindUnknown            FileKind = "unknown"
)

// Row mirrors host_arg_provincial_tax' column shape.
type Row struct {
	CuitSuffix4              string   `json:"cuit_suffix4,omitempty"`
	FileHash                 string   `json:"file_hash"`
	LastModified             string   `json:"last_modified,omitempty"`
	PeriodYYYYMM             string   `json:"period_yyyymm,omitempty"`
	FilePath                 string   `json:"file_path"`
	Agency                   Agency   `json:"agency"`
	FileKind                 FileKind `json:"file_kind"`
	CuitEntityPrefix         string   `json:"cuit_entity_prefix,omitempty"`
	FileOwnerUID             int      `json:"file_owner_uid,omitempty"`
	FileMode                 int      `json:"file_mode,omitempty"`
	RecordCount              int      `json:"record_count,omitempty"`
	FileSize                 int64    `json:"file_size,omitempty"`
	IsHighValueFile          bool     `json:"is_high_value_file"`
	IsWorldReadable          bool     `json:"is_world_readable"`
	IsGroupReadable          bool     `json:"is_group_readable"`
	IsCredentialExposureRisk bool     `json:"is_credential_exposure_risk"`
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

// AgencyRoot describes a curated install root + the agency it
// belongs to.
type AgencyRoot struct {
	Path   string
	Agency Agency
}

// DefaultAgencyRoots is the curated set of provincial-tax
// install roots across Windows locales.
func DefaultAgencyRoots() []AgencyRoot {
	return []AgencyRoot{
		{`C:\ARBA`, AgencyARBA},
		{`C:\Program Files\ARBA`, AgencyARBA},
		{`C:\Program Files (x86)\ARBA`, AgencyARBA},
		{`C:\AGIP`, AgencyAGIP},
		{`C:\Program Files\AGIP`, AgencyAGIP},
		{`C:\API-SantaFe`, AgencyAPI},
		{`C:\DGR-Cordoba`, AgencyDGRCordoba},
		{`C:\DGR-Mendoza`, AgencyDGRMendoza},
		{`C:\DGR-Misiones`, AgencyDGRMisiones},
		{`C:\AFIP\CITI`, AgencyAFIP},
		{`C:\AFIP\SICORE`, AgencyAFIP},
		// Non-Windows test mounts:
		{"/opt/arba", AgencyARBA},
		{"/srv/agip", AgencyAGIP},
	}
}

// agencyTokens maps lowercase path/name tokens → Agency for
// content-blind classification when path doesn't sit under a
// curated root.
func agencyTokens() map[string]Agency {
	return map[string]Agency{
		"arba":         AgencyARBA,
		"agip":         AgencyAGIP,
		"api-santafe":  AgencyAPI,
		"apisantafe":   AgencyAPI,
		"dgrcordoba":   AgencyDGRCordoba,
		"dgr-cordoba":  AgencyDGRCordoba,
		"dgrmendoza":   AgencyDGRMendoza,
		"dgr-mendoza":  AgencyDGRMendoza,
		"dgrmisiones":  AgencyDGRMisiones,
		"dgr-misiones": AgencyDGRMisiones,
		"sicore":       AgencyAFIP,
		"citi":         AgencyAFIP,
	}
}

// AgencyFromPath classifies path under a curated root or by
// path-name token.
//
// Path comparison normalises Windows backslashes to forward
// slashes (filepath.ToSlash is a no-op on Linux), so curated
// roots like `C:\ARBA` match against `C:\ARBA\export\file.txt`
// regardless of the host OS.
//
// Token fallback iterates the agencyTokens map in deterministic
// order — longest token first, then alphabetical — so paths that
// contain multiple agency tokens (e.g. `/opt/arba/citi-ventas.txt`)
// always resolve to the same Agency.
func AgencyFromPath(roots []AgencyRoot, path string) Agency {
	normPath := strings.ReplaceAll(filepath.ToSlash(path), `\`, "/")
	lowerNorm := strings.ToLower(normPath)
	for _, r := range roots {
		rootNorm := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(r.Path), `\`, "/"))
		if strings.HasPrefix(lowerNorm, rootNorm+"/") || lowerNorm == rootNorm {
			return r.Agency
		}
	}
	tokens := agencyTokens()
	keys := make([]string, 0, len(tokens))
	for k := range tokens {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	for _, token := range keys {
		if strings.Contains(lowerNorm, token) {
			return tokens[token]
		}
	}
	return AgencyUnknown
}

// FileKindFromName classifies a filename heuristically.
// Matched case-insensitively on basename.
func FileKindFromName(name string) FileKind {
	n := strings.ToLower(filepath.Base(name))
	switch {
	case n == "":
		return KindUnknown
	case strings.Contains(n, "citi") && strings.Contains(n, "venta"):
		return KindCITIVentas
	case strings.Contains(n, "citi") && strings.Contains(n, "compra"):
		return KindCITICompras
	case strings.Contains(n, "sicore") && strings.Contains(n, "retenc"):
		return KindSICORERetenciones
	case strings.Contains(n, "sicore") && strings.Contains(n, "percep"):
		return KindSICOREPercepciones
	case strings.Contains(n, "padron") && (strings.Contains(n, "iibb") || strings.Contains(n, "alicuota")):
		return KindPadronIIBB
	case strings.Contains(n, "alicuota"):
		return KindAlicuotas
	case strings.Contains(n, "cm05") || strings.Contains(n, "conv-multi"):
		return KindCM05
	case strings.Contains(n, "iibb") && strings.Contains(n, "ddjj"):
		return KindIIBBDeclaracion
	case strings.Contains(n, "iibb"):
		return KindIIBBDeclaracion
	case strings.Contains(n, "citi"):
		// Unspecified CITI direction.
		return KindOther
	case strings.Contains(n, "sicore"):
		return KindOther
	}
	return KindUnknown
}

// IsSensitiveKind returns true when the file_kind carries
// recipient-CUIT-bearing tax data.
func IsSensitiveKind(k FileKind) bool {
	switch k {
	case KindSICORERetenciones, KindSICOREPercepciones,
		KindPadronIIBB, KindCITIVentas, KindCITICompras,
		KindIIBBDeclaracion:
		return true
	case KindAlicuotas, KindCM05, KindOther, KindUnknown:
		return false
	default:
		return false
	}
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

// cuitRE matches 11-digit CUIT (hyphen-optional) embedded in
// filenames.
var cuitRE = regexp.MustCompile(`(\d{2})-?(\d{8})-?(\d)`)

// CuitFingerprintFromName scans a filename for an embedded
// 11-digit CUIT, returning (prefix, suffix4).
func CuitFingerprintFromName(name string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(name)
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

// periodRE matches YYYYMM embedded in filenames.
var periodRE = regexp.MustCompile(`(20\d{2})[-_]?(0[1-9]|1[0-2])`)

// PeriodFromName extracts a YYYYMM period from filename.
func PeriodFromName(name string) string {
	m := periodRE.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// AnnotateSecurity sets derived booleans.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.FileSize > HighValueFileBytes {
		r.IsHighValueFile = true
	}
	if IsSensitiveKind(r.FileKind) && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns deterministic ordering by file path.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].Agency != rs[j].Agency {
			return rs[i].Agency < rs[j].Agency
		}
		return rs[i].FileKind < rs[j].FileKind
	})
}

// CountLines counts \n-terminated lines in `data`. Last
// trailing fragment counts as a line if non-empty.
func CountLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := 0
	for _, c := range data {
		if c == '\n' {
			n++
		}
	}
	// Trailing fragment.
	if data[len(data)-1] != '\n' {
		n++
	}
	return n
}
