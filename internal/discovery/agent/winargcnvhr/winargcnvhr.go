// Package winargcnvhr audits Argentine CNV "Hechos Relevantes"
// material-event filings cached on analyst, risk-management,
// and asset-management workstations across Windows, Linux, and
// macOS.
//
// CNV (Comisión Nacional de Valores) requires every public
// sociedad anónima cotizante to file each material event via
// the AIF portal. These filings arrive as PDF + sibling XML
// metadata (`HR_<ticker>_<fecha>.pdf`,
// `comunicacion_<CUIT>.xml`).
//
// This is the **capital-entity event stream** that complements
// iter 90's periodic XBRL financial statements: periodic
// filings show position, hechos relevantes show change.
// Together they bracket the entity's lifecycle.
//
// Headline finding shapes:
//
//   - `is_high_impact_event=1` — tipo_hecho in
//     {default, mna, cambio-control, cesacion-pagos,
//     oferta-publica}. Immediate-attention capital event.
//   - `is_recent=1` — file modified within 90 days.
//   - `is_credential_exposure_risk=1` — readable file + filing-
//     PII (issuer CUIT + denominación present).
//
// CUIT (issuer + vinculado) reduced to entity-type prefix +
// last 4 digits. Tickers and denominaciones are public.
//
// Read-only by intent — we walk candidate files only, never
// parse PDF content. (Project guideline 4.2.)
package winargcnvhr

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

// MaxFileBytes bounds per-file read (for hashing + sibling XML).
const MaxFileBytes = 8 << 20 // 8 MiB

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// MaxStringLen bounds persisted strings.
const (
	MaxDenominacionChars = 128
	MaxTickerChars       = 12
)

// FilingKind pinned to host_cnv_hechos_relevantes.filing_kind.
type FilingKind string

const (
	FilingHechoRelevante FilingKind = "hecho-relevante"
	FilingComunicacion   FilingKind = "comunicacion"
	FilingInfoFinanciera FilingKind = "info-financiera"
	FilingAnuncio        FilingKind = "anuncio"
	FilingOther          FilingKind = "other"
	FilingUnknown        FilingKind = "unknown"
)

// TipoHecho pinned to host_cnv_hechos_relevantes.tipo_hecho.
type TipoHecho string

const (
	HechoAprobacionEECC     TipoHecho = "aprobacion-eecc"
	HechoDividendos         TipoHecho = "dividendos"
	HechoCapitalAumento     TipoHecho = "capital-aumento"
	HechoCapitalReduccion   TipoHecho = "capital-reduccion"
	HechoOfertaPublica      TipoHecho = "oferta-publica"
	HechoMNA                TipoHecho = "mna"
	HechoDefault            TipoHecho = "default"
	HechoCesacionPagos      TipoHecho = "cesacion-pagos"
	HechoCambioControl      TipoHecho = "cambio-control"
	HechoCambioManagement   TipoHecho = "cambio-management"
	HechoCalificacionRiesgo TipoHecho = "calificacion-riesgo"
	HechoOfertaCanje        TipoHecho = "oferta-canje"
	HechoAsamblea           TipoHecho = "asamblea"
	HechoSancion            TipoHecho = "sancion"
	HechoOther              TipoHecho = "other"
	HechoUnknown            TipoHecho = "unknown"
)

// Relevancia pinned to host_cnv_hechos_relevantes.relevancia.
type Relevancia string

const (
	RelevanciaAlta    Relevancia = "alta"
	RelevanciaMedia   Relevancia = "media"
	RelevanciaBaja    Relevancia = "baja"
	RelevanciaUnknown Relevancia = "unknown"
)

// Row mirrors host_cnv_hechos_relevantes' column shape.
type Row struct {
	IssuerCuitSuffix4        string     `json:"issuer_cuit_suffix4,omitempty"`
	IssuerTicker             string     `json:"issuer_ticker,omitempty"`
	FechaHecho               string     `json:"fecha_hecho,omitempty"`
	VinculadoCuitSuffix4     string     `json:"vinculado_cuit_suffix4,omitempty"`
	VinculadoCuitPrefix      string     `json:"vinculado_cuit_prefix,omitempty"`
	UserProfile              string     `json:"user_profile,omitempty"`
	FilingKind               FilingKind `json:"filing_kind"`
	TipoHecho                TipoHecho  `json:"tipo_hecho"`
	Relevancia               Relevancia `json:"relevancia"`
	IssuerCuitPrefix         string     `json:"issuer_cuit_prefix,omitempty"`
	FileHash                 string     `json:"file_hash"`
	IssuerDenominacion       string     `json:"issuer_denominacion,omitempty"`
	FilePath                 string     `json:"file_path"`
	FileOwnerUID             int        `json:"file_owner_uid,omitempty"`
	FileMode                 int        `json:"file_mode,omitempty"`
	FileSize                 int64      `json:"file_size,omitempty"`
	IsHighImpactEvent        bool       `json:"is_high_impact_event"`
	IsRecent                 bool       `json:"is_recent"`
	IsWorldReadable          bool       `json:"is_world_readable"`
	IsGroupReadable          bool       `json:"is_group_readable"`
	IsCredentialExposureRisk bool       `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated set of CNV install roots
// across Windows locales.
func DefaultInstallRoots() []string {
	return []string{
		`C:\CNV`,
		`C:\CNV\HechosRelevantes`,
		`C:\AIF`,
		`C:\AIF\HR`,
		`/opt/cnv`,
		`/srv/cnv`,
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

// UserHRDirs is the curated per-user relative path catalogue.
func UserHRDirs() [][]string {
	return [][]string{
		{"Downloads"},
		{"Descargas"},
		{"Documents", "CNV"},
		{"Documents", "HechosRelevantes"},
		{"Documents", "AIF"},
		{"Documents", "Analisis"},
	}
}

// IsCandidateName reports whether a filename plausibly belongs
// to the CNV HR catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"hecho_relevante", "hechorelevante", "hr_", "hr-",
		"cnv_", "cnv-", "aif_", "aif-",
		"comunicacion_", "comunicación_",
		"info_financiera", "info-financiera",
		"asamblea", "memoria_",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// FilingKindFromName classifies a filename heuristically.
func FilingKindFromName(name string) FilingKind {
	n := strings.ToLower(filepath.Base(name))
	switch {
	case n == "":
		return FilingUnknown
	case strings.Contains(n, "hecho_relevante") || strings.Contains(n, "hechorelevante") ||
		strings.Contains(n, "hr_") || strings.Contains(n, "hr-"):
		return FilingHechoRelevante
	case strings.Contains(n, "comunicacion") || strings.Contains(n, "comunicación"):
		return FilingComunicacion
	case strings.Contains(n, "info_financiera") || strings.Contains(n, "info-financiera") ||
		strings.Contains(n, "estados-contables") || strings.Contains(n, "memoria_"):
		return FilingInfoFinanciera
	case strings.Contains(n, "anuncio"):
		return FilingAnuncio
	case strings.Contains(n, "cnv") || strings.Contains(n, "aif"):
		return FilingOther
	}
	return FilingUnknown
}

// TipoHechoFromText classifies an arbitrary text body
// (filename or sibling XML/JSON) into a tipo de hecho. Matched
// case-insensitively. Returns HechoUnknown for empty / no-
// match input.
func TipoHechoFromText(text string) TipoHecho {
	t := strings.ToLower(text)
	switch {
	case t == "":
		return HechoUnknown
	case strings.Contains(t, "cesaci") && strings.Contains(t, "pago"):
		return HechoCesacionPagos
	case strings.Contains(t, "default") || strings.Contains(t, "incumplimiento de pago"):
		return HechoDefault
	case strings.Contains(t, "cambio de control") || strings.Contains(t, "cambio-control"):
		return HechoCambioControl
	// OPA must be tested BEFORE MNA because the OPA spelling
	// "oferta pública de adquisición" contains "adquisici".
	case strings.Contains(t, "opa") || strings.Contains(t, "oferta pública de adquisición") ||
		strings.Contains(t, "oferta publica de adquisicion") ||
		strings.Contains(t, "tender offer"):
		return HechoOfertaPublica
	case strings.Contains(t, "fusion") || strings.Contains(t, "fusión") ||
		strings.Contains(t, "adquisici") || strings.Contains(t, "m&a") ||
		strings.Contains(t, "absorci"):
		return HechoMNA
	case strings.Contains(t, "oferta") && strings.Contains(t, "canje"):
		return HechoOfertaCanje
	case strings.Contains(t, "aumento de capital") || strings.Contains(t, "capital-aumento"):
		return HechoCapitalAumento
	case strings.Contains(t, "reducción de capital") ||
		strings.Contains(t, "reduccion de capital") || strings.Contains(t, "capital-reduccion"):
		return HechoCapitalReduccion
	case strings.Contains(t, "dividendo"):
		return HechoDividendos
	case strings.Contains(t, "aprobaci") &&
		(strings.Contains(t, "eecc") || strings.Contains(t, "estados contables")):
		return HechoAprobacionEECC
	case strings.Contains(t, "calificaci") && strings.Contains(t, "riesgo"):
		return HechoCalificacionRiesgo
	case strings.Contains(t, "cambio") &&
		(strings.Contains(t, "directorio") || strings.Contains(t, "gerencia") ||
			strings.Contains(t, "ceo") || strings.Contains(t, "management")):
		return HechoCambioManagement
	case strings.Contains(t, "asamblea"):
		return HechoAsamblea
	case strings.Contains(t, "sanci") || strings.Contains(t, "multa"):
		return HechoSancion
	}
	return HechoUnknown
}

// HighImpactHechos is the curated set of tipo_hecho values
// that flip is_high_impact_event=1.
func HighImpactHechos() []TipoHecho {
	return []TipoHecho{
		HechoDefault,
		HechoCesacionPagos,
		HechoMNA,
		HechoCambioControl,
		HechoOfertaPublica,
	}
}

// IsHighImpact reports membership in HighImpactHechos.
func IsHighImpact(h TipoHecho) bool {
	for _, v := range HighImpactHechos() {
		if v == h {
			return true
		}
	}
	return false
}

// RelevanciaFromText classifies a text label into the
// canonical enum. Empty / no-match returns RelevanciaUnknown.
func RelevanciaFromText(s string) Relevancia {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "alta", "high", "alto":
		return RelevanciaAlta
	case "media", "medium", "medio":
		return RelevanciaMedia
	case "baja", "low", "bajo":
		return RelevanciaBaja
	}
	return RelevanciaUnknown
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

// tickerRE matches BYMA/MERVAL-style 2-6 char uppercase ticker
// embedded between underscores or dashes in filename context.
var tickerRE = regexp.MustCompile(`(?:^|[_-])([A-Z]{2,6})(?:[_-]|$)`)

// TickerFromName extracts a plausible ticker from filename.
// We scan a filename component-by-component to favour the
// canonical `HR_<TICKER>_<fecha>.pdf` shape. Common
// filename-prefix tokens (HR, CNV, AIF) are skipped because
// they're never tickers.
func TickerFromName(name string) string {
	base := filepath.Base(name)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	parts := strings.FieldsFunc(stem, func(r rune) bool {
		return r == '_' || r == '-' || r == ' '
	})
	for _, p := range parts {
		if isFilenamePrefixToken(p) {
			continue
		}
		// Pure uppercase letters, 2-6 chars, no digits.
		if len(p) >= 2 && len(p) <= 6 && isAllUpper(p) {
			return p
		}
	}
	// Fallback to the regex (start-of-string tickers).
	m := tickerRE.FindStringSubmatch(stem)
	if m != nil && !isFilenamePrefixToken(m[1]) {
		return m[1]
	}
	return ""
}

func isFilenamePrefixToken(s string) bool {
	switch strings.ToUpper(s) {
	case "HR", "CNV", "AIF":
		return true
	}
	return false
}

func isAllUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
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
	r.IsHighImpactEvent = IsHighImpact(r.TipoHecho)
	// PII exposure: issuer present + readable file.
	hasPII := r.IssuerCuitPrefix != "" || r.IssuerTicker != "" ||
		r.IssuerDenominacion != ""
	if hasPII && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns a deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].IssuerCuitPrefix != rs[j].IssuerCuitPrefix {
			return rs[i].IssuerCuitPrefix < rs[j].IssuerCuitPrefix
		}
		if rs[i].IssuerCuitSuffix4 != rs[j].IssuerCuitSuffix4 {
			return rs[i].IssuerCuitSuffix4 < rs[j].IssuerCuitSuffix4
		}
		return rs[i].FechaHecho < rs[j].FechaHecho
	})
}
