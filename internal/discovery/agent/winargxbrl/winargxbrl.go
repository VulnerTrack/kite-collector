// Package winargxbrl audits Argentine financial-statement
// XBRL filings cached on accounting / analyst workstations
// across Windows, Linux, and macOS. CNV (Comisión Nacional
// de Valores) operates the AIF — Autopista de la Información
// Financiera — where every public sociedad anónima cotizante
// files its `estados contables` as XBRL instance documents.
// IGJ (Inspección General de Justicia) accepts similar
// filings from non-listed entities.
//
// This is the **Capital Entity** companion to the AFIP Tax-
// side collectors. Where AFIP collectors surface invoice
// issuance per CUIT, XBRL filings surface the *entities* the
// workstation's owner has financial-data relationships with —
// their portfolio, their subsidiaries, the counterparties
// they audit, or the companies they own a stake in.
//
// File-based discovery is the deliberate design choice — XBRL
// instance documents have a stable, well-known shape
// (`xbrli:xbrl` root, `xbrli:context`, `xbrli:entity`,
// `xbrli:identifier` with scheme attribute, `xbrli:unit` with
// `xbrli:measure`). The collector extracts only the metadata
// needed to identify the entity and its blast-radius —
// individual fact values are out of scope.
//
// Headline finding shapes:
//
//   - `is_cnv_publicly_listed=1` — `schemaRef` points at a
//     CNV-AIF taxonomy URL (`*cnv.gov.ar*`). The entity is on
//     the BYMA / BCBA listing.
//   - `is_consolidated_statement=1` — at least one context
//     references a consolidated dimension (heuristic: filename
//     or context contains `consolid`).
//   - `is_foreign_currency_facts=1` — at least one
//     `xbrli:measure` resolves to a non-ARS ISO 4217 code.
//   - `is_credential_exposure_risk=1` — financial PII +
//     readable file rollup.
//
// CUIT is NEVER stored verbatim — only the entity-type prefix
// + last 4 digits. Fact values are not extracted.
//
// Read-only by intent — we walk candidate XML files only,
// never invoke any taxonomy resolver. (Project guideline 4.2.)
package winargxbrl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

// MaxFilings bounds per-scan output.
const MaxFilings = 4096

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 8 << 20 // 8 MiB — XBRL bundles can be large

// FilingKind tags the file's role.
type FilingKind string

const (
	FilingXBRLInstance FilingKind = "xbrl-instance"
	FilingXBRLSchema   FilingKind = "xbrl-schema"
	FilingXBRLLinkbase FilingKind = "xbrl-linkbase"
	FilingXBRLZip      FilingKind = "xbrl-zip"
	FilingUnknown      FilingKind = "unknown"
)

// TaxonomyLabel tags the recognised taxonomy family.
type TaxonomyLabel string

const (
	TaxonomyCNVAIF  TaxonomyLabel = "cnv-aif"
	TaxonomyIGJ     TaxonomyLabel = "igj"
	TaxonomyIFRS    TaxonomyLabel = "ifrs"
	TaxonomyARIFRS  TaxonomyLabel = "ar-ifrs"
	TaxonomyUSGAAP  TaxonomyLabel = "us-gaap"
	TaxonomyOther   TaxonomyLabel = "other"
	TaxonomyUnknown TaxonomyLabel = "unknown"
)

// Filing mirrors host_arg_xbrl_filings' column shape.
type Filing struct {
	EntityDenominacion       string        `json:"entity_denominacion,omitempty"`
	PeriodStart              string        `json:"period_start,omitempty"`
	ReportingCurrency        string        `json:"reporting_currency,omitempty"`
	FilePath                 string        `json:"file_path"`
	PeriodEnd                string        `json:"period_end,omitempty"`
	UserProfile              string        `json:"user_profile,omitempty"`
	FilingKind               FilingKind    `json:"filing_kind"`
	TaxonomyLabel            TaxonomyLabel `json:"taxonomy_label"`
	EntityCuitPrefix         string        `json:"entity_cuit_prefix,omitempty"`
	EntityCuitSuffix4        string        `json:"entity_cuit_suffix4,omitempty"`
	FileHash                 string        `json:"file_hash"`
	FileOwnerUID             int           `json:"file_owner_uid,omitempty"`
	FileMode                 int           `json:"file_mode,omitempty"`
	FileSize                 int64         `json:"file_size,omitempty"`
	FactCount                int           `json:"fact_count,omitempty"`
	IsConsolidatedStatement  bool          `json:"is_consolidated_statement"`
	IsForeignCurrencyFacts   bool          `json:"is_foreign_currency_facts"`
	IsCnvPubliclyListed      bool          `json:"is_cnv_publicly_listed"`
	IsWorldReadable          bool          `json:"is_world_readable"`
	IsGroupReadable          bool          `json:"is_group_readable"`
	IsCredentialExposureRisk bool          `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Filing, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// MaxDenominationChars bounds the entity-name string we
// persist; long taxonomy-derived names blow up storage.
const MaxDenominationChars = 128

// TruncateDenominacion shortens a denomination to
// MaxDenominationChars, preserving UTF-8 boundaries.
func TruncateDenominacion(s string) string {
	t := strings.TrimSpace(s)
	if len(t) <= MaxDenominationChars {
		return t
	}
	r := []rune(t)
	if len(r) <= MaxDenominationChars {
		return t
	}
	return string(r[:MaxDenominationChars])
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

// CuitFingerprint extracts prefix + suffix4 from a raw CUIT
// string. Accepts hyphenated and bare forms.
func CuitFingerprint(raw string) (prefix, suffix4 string) {
	t := strings.TrimSpace(raw)
	digits := make([]byte, 0, len(t))
	for i := 0; i < len(t); i++ {
		if c := t[i]; c >= '0' && c <= '9' {
			digits = append(digits, c)
		}
	}
	if len(digits) != 11 {
		return "", ""
	}
	prefix = string(digits[:2])
	suffix4 = string(digits[7:])
	if !IsValidCuitEntityPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// CurrencyFromMeasure extracts the ISO 4217 code from an
// `xbrli:measure` text like "iso4217:ARS" → "ARS".
func CurrencyFromMeasure(m string) string {
	t := strings.TrimSpace(m)
	if i := strings.LastIndexByte(t, ':'); i >= 0 {
		t = t[i+1:]
	}
	t = strings.ToUpper(t)
	if len(t) != 3 {
		return ""
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c < 'A' || c > 'Z' {
			return ""
		}
	}
	return t
}

// TaxonomyLabelFromSchemaRef inspects an XBRL `schemaRef` URL
// and reports the taxonomy family. Empty input or unknown URL
// returns TaxonomyUnknown.
func TaxonomyLabelFromSchemaRef(url string) TaxonomyLabel {
	u := strings.ToLower(strings.TrimSpace(url))
	switch {
	case u == "":
		return TaxonomyUnknown
	case strings.Contains(u, "cnv.gov.ar") || strings.Contains(u, "aif.cnv"):
		return TaxonomyCNVAIF
	case strings.Contains(u, "igj.gob.ar") || strings.Contains(u, "igj.gov.ar"):
		return TaxonomyIGJ
	case strings.Contains(u, "ar-ifrs") || strings.Contains(u, "argentina-ifrs"):
		return TaxonomyARIFRS
	case strings.Contains(u, "xbrl.ifrs.org") || strings.Contains(u, "/ifrs/"):
		return TaxonomyIFRS
	case strings.Contains(u, "us-gaap") || strings.Contains(u, "fasb.org"):
		return TaxonomyUSGAAP
	}
	return TaxonomyOther
}

// ClassifyByExtension maps a filename to a FilingKind. XML
// files are content-disambiguated by the parser.
func ClassifyByExtension(path string) FilingKind {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".xbrl":
		return FilingXBRLInstance
	case ".zip":
		return FilingXBRLZip
	case ".xsd":
		return FilingXBRLSchema
	case ".xml":
		return FilingUnknown // content-disambiguated
	}
	return FilingUnknown
}

// IsXBRLCandidatePath reports whether the path's name or
// directory hints at an Argentine XBRL filing. Matched
// case-insensitively anywhere in the path.
func IsXBRLCandidatePath(path string) bool {
	if path == "" {
		return false
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, t := range candidateTokens() {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

func candidateTokens() []string {
	return []string{
		"xbrl", "cnv", "aif", "igj", "estados-contables",
		"estadoscontables", "estados_contables", "balance",
		"memoria", "consolid",
	}
}

// AnnotateSecurity sets the derived booleans. Caller must
// populate FileMode + ReportingCurrency + path-aware fields
// first.
func AnnotateSecurity(f *Filing) {
	if f.FileMode != 0 {
		f.IsWorldReadable = f.FileMode&0o004 != 0
		f.IsGroupReadable = f.FileMode&0o040 != 0
	}
	if cur := strings.ToUpper(strings.TrimSpace(f.ReportingCurrency)); cur != "" && cur != "ARS" {
		f.IsForeignCurrencyFacts = true
	}
	lower := strings.ToLower(filepath.ToSlash(f.FilePath))
	if strings.Contains(lower, "consolid") {
		f.IsConsolidatedStatement = true
	}
	if f.TaxonomyLabel == TaxonomyCNVAIF {
		f.IsCnvPubliclyListed = true
	}
	if f.FilingKind == FilingXBRLInstance && (f.IsWorldReadable || f.IsGroupReadable) {
		f.IsCredentialExposureRisk = true
	}
}

// SortFilings returns a deterministic ordering by file path,
// CUIT fingerprint, then period_end.
func SortFilings(fs []Filing) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].FilePath != fs[j].FilePath {
			return fs[i].FilePath < fs[j].FilePath
		}
		if fs[i].EntityCuitPrefix != fs[j].EntityCuitPrefix {
			return fs[i].EntityCuitPrefix < fs[j].EntityCuitPrefix
		}
		return fs[i].PeriodEnd < fs[j].PeriodEnd
	})
}
