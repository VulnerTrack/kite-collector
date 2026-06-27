// Package winargpymebursatil audits Argentine PyME bursátil
// financing-instrument files cached on broker, SGR
// (Sociedad de Garantía Recíproca), and PyME-advisor
// workstations across Windows, Linux, and macOS.
//
// Argentine PyMEs access capital markets via specific
// bursátil-tradeable instruments: ChPD avalados, Pagaré
// Bursátil, ON-PyME (Obligaciones Negociables), FCE MiPyME
// (Factura de Crédito Electrónica), Letras de Tesoros
// Provinciales.
//
// **The PyME-issuer side of capital-markets financing.**
// Complements iter 107 ALYC broker-side + iter 108
// algotrading + iter 109 derivatives + iter 110 FCI.
//
// Headline finding shapes:
//
//   - `has_sgr_aval=1` — instrument carries SGR aval (risk-
//     mitigation indicator; the SGR guarantees payment).
//   - `has_default_risk=1` — vencimiento past + estado activo;
//     librador default surface.
//   - `is_high_value=1` — monto > 10 M ARS.
//   - `is_foreign_currency=1` — moneda != ARS.
//   - `is_credential_exposure_risk=1` — readable file +
//     librador or receptor CUIT present.
//
// All CUITs reduced to entity-type prefix + last 4.
//
// Read-only by intent. (Project guideline 4.2.)
package winargpymebursatil

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

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 4 << 20 // 4 MiB

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// HighValueARSCents — threshold for is_high_value (10M ARS).
const HighValueARSCents int64 = 1_000_000_000

// InstrumentKind pinned to host_arg_pyme_bursatil.instrument_kind.
type InstrumentKind string

const (
	KindChPDAvalado        InstrumentKind = "chpd-avalado"
	KindPagareBursatil     InstrumentKind = "pagare-bursatil"
	KindONPyME             InstrumentKind = "on-pyme"
	KindFCEMiPyME          InstrumentKind = "fce-mipyme"
	KindLetraTesoro        InstrumentKind = "letra-tesoro"
	KindNegociacionMensual InstrumentKind = "negociacion-mensual"
	KindOther              InstrumentKind = "other"
	KindUnknown            InstrumentKind = "unknown"
)

// Moneda pinned to host_arg_pyme_bursatil.moneda enum.
type Moneda string

const (
	MonedaARS   Moneda = "ars"
	MonedaUSD   Moneda = "usd"
	MonedaEUR   Moneda = "eur"
	MonedaBRL   Moneda = "brl"
	MonedaOther Moneda = "other"
	MonedaEmpty Moneda = ""
)

// Row mirrors host_arg_pyme_bursatil' column shape.
type Row struct {
	FilePath                 string         `json:"file_path"`
	FileHash                 string         `json:"file_hash"`
	FechaVencimiento         string         `json:"fecha_vencimiento,omitempty"`
	FechaEmision             string         `json:"fecha_emision,omitempty"`
	Moneda                   Moneda         `json:"moneda"`
	UserProfile              string         `json:"user_profile,omitempty"`
	InstrumentKind           InstrumentKind `json:"instrument_kind"`
	SgrMatricula             string         `json:"sgr_matricula,omitempty"`
	EmisorCuitPrefix         string         `json:"emisor_cuit_prefix,omitempty"`
	EmisorCuitSuffix4        string         `json:"emisor_cuit_suffix4,omitempty"`
	ReceptorCuitPrefix       string         `json:"receptor_cuit_prefix,omitempty"`
	ReceptorCuitSuffix4      string         `json:"receptor_cuit_suffix4,omitempty"`
	MontoARSCents            int64          `json:"monto_ars_cents,omitempty"`
	FileOwnerUID             int            `json:"file_owner_uid,omitempty"`
	FileMode                 int            `json:"file_mode,omitempty"`
	FileSize                 int64          `json:"file_size,omitempty"`
	DaysToVencimiento        int            `json:"days_to_vencimiento,omitempty"`
	HasSgrAval               bool           `json:"has_sgr_aval"`
	HasDefaultRisk           bool           `json:"has_default_risk"`
	IsHighValue              bool           `json:"is_high_value"`
	IsForeignCurrency        bool           `json:"is_foreign_currency"`
	IsRecent                 bool           `json:"is_recent"`
	IsWorldReadable          bool           `json:"is_world_readable"`
	IsGroupReadable          bool           `json:"is_group_readable"`
	IsCredentialExposureRisk bool           `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated PyME-bursátil root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\CNV\PyME`,
		`C:\PyMEBursatil`,
		`C:\PyME-Bursatil`,
		`C:\SGR`,
		`C:\FCE`,
		`/opt/pyme-bursatil`,
		`/srv/pyme-bursatil`,
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

// UserPyMEDirs is the curated per-user relative path set.
func UserPyMEDirs() [][]string {
	return [][]string{
		{"Documents", "PyMEBursatil"},
		{"Documents", "CNV", "PyME"},
		{"Documents", "SGR"},
		{"Documents", "FCE"},
		{"Documents", "Bursatil", "PyME"},
		{"Documents", "Financiamiento", "PyME"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateExt reports whether the extension carries a
// PyME bursátil artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json", ".csv", ".txt", ".pdf":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the PyME-bursátil catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"chpd_", "chpd-", "_chpd",
		"cheque_pago_diferido", "cheque-pago-diferido",
		"pagare_bursatil", "pagare-bursatil",
		"on_pyme", "on-pyme",
		"obligacion_negociable_pyme", "obligacion-negociable-pyme",
		"fce_mipyme", "fce-mipyme", "fce_",
		"factura_credito_electronica", "factura-credito-electronica",
		"letra_tesoro", "letra-tesoro",
		"pyme_bursatil", "pyme-bursatil",
		"sgr_aval", "sgr-aval",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// InstrumentKindFromName classifies a filename heuristically.
//
// Order matters: FCE before factura-credito-electronica to
// handle the FCE_ prefix on its own.
func InstrumentKindFromName(name string) InstrumentKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "chpd") || strings.Contains(n, "cheque_pago_diferido") ||
		strings.Contains(n, "cheque-pago-diferido"):
		return KindChPDAvalado
	case strings.Contains(n, "pagare_bursatil") || strings.Contains(n, "pagare-bursatil"):
		return KindPagareBursatil
	// negociacion_pyme must be checked BEFORE on_pyme since
	// "negociacion_pyme" contains "on_pyme" as a substring.
	case strings.Contains(n, "negociacion_mensual") ||
		strings.Contains(n, "negociacion-mensual") ||
		strings.Contains(n, "negociacion_pyme") ||
		strings.Contains(n, "negociacion-pyme"):
		return KindNegociacionMensual
	case strings.Contains(n, "on_pyme") || strings.Contains(n, "on-pyme") ||
		strings.Contains(n, "obligacion_negociable_pyme") ||
		strings.Contains(n, "obligacion-negociable-pyme"):
		return KindONPyME
	case strings.Contains(n, "fce_mipyme") || strings.Contains(n, "fce-mipyme") ||
		strings.Contains(n, "fce_") || strings.Contains(n, "fce-") ||
		strings.Contains(n, "factura_credito_electronica") ||
		strings.Contains(n, "factura-credito-electronica"):
		return KindFCEMiPyME
	case strings.Contains(n, "letra_tesoro") || strings.Contains(n, "letra-tesoro"):
		return KindLetraTesoro
	case strings.Contains(n, "negociacion_mensual") ||
		strings.Contains(n, "negociacion-mensual") ||
		strings.Contains(n, "negociacion_pyme"):
		return KindNegociacionMensual
	case strings.Contains(n, "pyme_bursatil") || strings.Contains(n, "pyme-bursatil") ||
		strings.Contains(n, "sgr"):
		return KindOther
	}
	return KindUnknown
}

// MonedaFromText classifies a moneda label.
func MonedaFromText(s string) Moneda {
	t := strings.ToUpper(strings.TrimSpace(s))
	switch t {
	case "":
		return MonedaEmpty
	case "ARS", "PES", "PESO", "PESOS":
		return MonedaARS
	case "USD", "DOL", "DOLAR":
		return MonedaUSD
	case "EUR", "EURO":
		return MonedaEUR
	case "BRL", "REAL":
		return MonedaBRL
	}
	return MonedaOther
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

// sgrMatriculaRE matches SGR matrícula tokens in text.
var sgrMatriculaRE = regexp.MustCompile(`(?i)(?:sgr|sgr[_-]?matricula|matricula[_-]?sgr)[\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// SgrMatriculaFromText extracts SGR matrícula.
func SgrMatriculaFromText(text string) string {
	m := sgrMatriculaRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// ParseTime parses a date string in DD/MM/YYYY or YYYY-MM-DD.
func ParseTime(s string) (time.Time, bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		"2006-01-02",
		"02/01/2006",
		"02-01-2006",
		"2006/01/02",
		time.RFC3339,
	} {
		if parsed, err := time.Parse(layout, t); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

// ClockFn is the injectable clock.
type ClockFn func() time.Time

// AnnotateSecurityWithClock sets derived booleans, computing
// vencimiento-relative flags with the provided clock.
func AnnotateSecurityWithClock(r *Row, now ClockFn) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	r.IsForeignCurrency = r.Moneda != MonedaARS && r.Moneda != MonedaEmpty
	if r.MontoARSCents > HighValueARSCents {
		r.IsHighValue = true
	}
	// Vencimiento-relative.
	if r.FechaVencimiento != "" && now != nil {
		if venc, ok := ParseTime(r.FechaVencimiento); ok {
			current := now()
			delta := venc.Sub(current)
			r.DaysToVencimiento = int(delta / (24 * time.Hour))
			if delta < 0 {
				r.HasDefaultRisk = true
			}
		}
	}
	// PII exposure: emisor or receptor CUIT + readable.
	hasPII := r.EmisorCuitPrefix != "" || r.ReceptorCuitPrefix != ""
	if hasPII && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// AnnotateSecurity is the time.Now convenience.
func AnnotateSecurity(r *Row) {
	AnnotateSecurityWithClock(r, time.Now)
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].InstrumentKind != rs[j].InstrumentKind {
			return rs[i].InstrumentKind < rs[j].InstrumentKind
		}
		return rs[i].EmisorCuitSuffix4 < rs[j].EmisorCuitSuffix4
	})
}
