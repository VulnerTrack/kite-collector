// Package winafipexport audits Argentine AFIP factura
// electrónica de exportación (Factura E) XML files cached on
// workstations issuing comprobantes para operaciones de
// exportación. Distinct from the domestic WSFEv1 / CAE
// collector (iter 89): these files come from WSMTXCA
// (mercado externo) or WSCT (otros — turismo, bonos fiscales)
// and carry export-only fields.
//
// Capital-outflow context: every Factura E represents foreign-
// currency revenue flowing through the entity. High-value or
// FATF-grey-country invoices materially shift AML risk
// posture.
//
// Headline finding shapes:
//
//   - `is_export_factura=1` — file is a Factura E / T (export
//     class).
//   - `is_high_value_usd=1` — imp_total_usd_cents > 1 M USD.
//   - `is_fatf_grey_country=1` — destino is on the curated
//     FATF grey-list snapshot. AML review hook.
//   - `is_incoterm_cif_cfr=1` — Argentine exporter handles
//     international freight = more capital-flight latitude.
//   - `is_credential_exposure_risk=1` — readable file + CAE
//     present (counterparty identifier on disk).
//
// CUIT (emisor) reduced to entity-type prefix + last 4. The
// receptor is foreign so AFIP doesn't assign a CUIT — only
// the destino country is persisted.
//
// Read-only by intent. (Project guideline 4.2.)
package winafipexport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

// MaxRows bounds per-scan output.
const MaxRows = 16384

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 1 << 20 // 1 MiB

// HighValueUSDCents — files above this monto flip
// is_high_value_usd (US$ 1 000 000 = 100 000 000 cents).
const HighValueUSDCents int64 = 100_000_000

// WSKind pinned to host_afip_factura_exportacion.ws_kind.
type WSKind string

const (
	WSMtxca   WSKind = "wsmtxca"
	WSCT      WSKind = "wsct"
	WSBfev1   WSKind = "wsbfev1"
	WSOther   WSKind = "other"
	WSUnknown WSKind = "unknown"
)

// Incoterm pinned to host_afip_factura_exportacion.incoterm.
type Incoterm string

const (
	IncoFOB     Incoterm = "fob"
	IncoCIF     Incoterm = "cif"
	IncoEXW     Incoterm = "exw"
	IncoFAS     Incoterm = "fas"
	IncoCFR     Incoterm = "cfr"
	IncoCPT     Incoterm = "cpt"
	IncoCIP     Incoterm = "cip"
	IncoDAP     Incoterm = "dap"
	IncoDPU     Incoterm = "dpu"
	IncoDDP     Incoterm = "ddp"
	IncoFCA     Incoterm = "fca"
	IncoOther   Incoterm = "other"
	IncoUnknown Incoterm = "unknown"
)

// Row mirrors host_afip_factura_exportacion' column shape.
type Row struct {
	Incoterm                 Incoterm `json:"incoterm"`
	Idioma                   string   `json:"idioma,omitempty"`
	Moneda                   string   `json:"moneda,omitempty"`
	PeriodYYYYMM             string   `json:"period_yyyymm,omitempty"`
	DestinoCountry           string   `json:"destino_country,omitempty"`
	UserProfile              string   `json:"user_profile,omitempty"`
	WSKind                   WSKind   `json:"ws_kind"`
	CuitEmisorPrefix         string   `json:"cuit_emisor_prefix,omitempty"`
	CuitEmisorSuffix4        string   `json:"cuit_emisor_suffix4,omitempty"`
	CaeCode                  string   `json:"cae_code,omitempty"`
	FilePath                 string   `json:"file_path"`
	CbteFch                  string   `json:"cbte_fch,omitempty"`
	FileHash                 string   `json:"file_hash"`
	FileSize                 int64    `json:"file_size,omitempty"`
	FileMode                 int      `json:"file_mode,omitempty"`
	CbteTipo                 int      `json:"cbte_tipo,omitempty"`
	FileOwnerUID             int      `json:"file_owner_uid,omitempty"`
	CotizacionARS            int64    `json:"cotizacion_ars,omitempty"`
	ImpTotalCents            int64    `json:"imp_total_cents,omitempty"`
	ImpTotalUSDCents         int64    `json:"imp_total_usd_cents,omitempty"`
	CbteNro                  int      `json:"cbte_nro,omitempty"`
	PtoVta                   int      `json:"pto_vta,omitempty"`
	IsHighValueUSD           bool     `json:"is_high_value_usd"`
	IsExportFactura          bool     `json:"is_export_factura"`
	IsFatfGreyCountry        bool     `json:"is_fatf_grey_country"`
	IsIncotermCifCfr         bool     `json:"is_incoterm_cif_cfr"`
	IsCaePresent             bool     `json:"is_cae_present"`
	IsWorldReadable          bool     `json:"is_world_readable"`
	IsGroupReadable          bool     `json:"is_group_readable"`
	IsCredentialExposureRisk bool     `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated set of export install roots.
func DefaultInstallRoots() []string {
	return []string{
		`C:\AFIP\WSMTXCA`,
		`C:\AFIP\WSCT`,
		`C:\AFIP\Export`,
		`C:\AFIP\FacturaExportacion`,
		`/opt/afip/export`,
		`/srv/afip/export`,
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

// UserExportDirs is the curated per-user relative path set.
func UserExportDirs() [][]string {
	return [][]string{
		{"Documents", "AFIP", "FacturaExportacion"},
		{"Documents", "AFIP", "Export"},
		{"Documents", "Facturas", "Exportacion"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateName reports whether a filename plausibly belongs
// to the export-invoice catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"wsmtxca", "wsmtx", "wsct", "wsbfev1",
		"factura_e", "factura-e", "factura_exportacion",
		"factura-exportacion", "comprobante_e", "comprobante-e",
		"export_afip", "export-afip", "factura_export",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// WSKindFromName classifies a filename heuristically.
func WSKindFromName(name string) WSKind {
	if strings.TrimSpace(name) == "" {
		return WSUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "wsmtxca") || strings.Contains(n, "wsmtx"):
		return WSMtxca
	case strings.Contains(n, "wsct"):
		return WSCT
	case strings.Contains(n, "wsbfev1") || strings.Contains(n, "bonos_fiscales"):
		return WSBfev1
	case strings.Contains(n, "factura_e") || strings.Contains(n, "factura-e") ||
		strings.Contains(n, "factura_exportacion") || strings.Contains(n, "factura-exportacion") ||
		strings.Contains(n, "comprobante_e") || strings.Contains(n, "comprobante-e"):
		return WSMtxca
	case strings.Contains(n, "export"):
		return WSOther
	}
	return WSUnknown
}

// IncotermFromText classifies the 3-letter incoterm code.
func IncotermFromText(s string) Incoterm {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "fob":
		return IncoFOB
	case "cif":
		return IncoCIF
	case "exw":
		return IncoEXW
	case "fas":
		return IncoFAS
	case "cfr":
		return IncoCFR
	case "cpt":
		return IncoCPT
	case "cip":
		return IncoCIP
	case "dap":
		return IncoDAP
	case "dpu":
		return IncoDPU
	case "ddp":
		return IncoDDP
	case "fca":
		return IncoFCA
	case "":
		return IncoUnknown
	}
	return IncoOther
}

// IsCifCfrIncoterm reports whether the exporter is responsible
// for international freight (CIF/CFR/CIP/CPT).
func IsCifCfrIncoterm(i Incoterm) bool {
	switch i {
	case IncoCIF, IncoCFR, IncoCIP, IncoCPT:
		return true
	case IncoFOB, IncoEXW, IncoFAS, IncoDAP, IncoDPU, IncoDDP,
		IncoFCA, IncoOther, IncoUnknown:
		return false
	}
	return false
}

// CountryCodeFromText normalises a 3-letter ISO country code,
// uppercased. Empty / non-3-letter returns "".
func CountryCodeFromText(s string) string {
	t := strings.ToUpper(strings.TrimSpace(s))
	if len(t) != 3 {
		return ""
	}
	for i := 0; i < 3; i++ {
		c := t[i]
		if c < 'A' || c > 'Z' {
			return ""
		}
	}
	return t
}

// FatfGreyCountries is the curated FATF grey-list snapshot at
// the collector commit time (2026-06). The audit pipeline can
// re-classify downstream.
func FatfGreyCountries() []string {
	return []string{
		"BFA", // Burkina Faso
		"CMR", // Cameroon
		"DOM", // Dominican Republic
		"HTI", // Haiti
		"KEN", // Kenya
		"MNG", // Mongolia
		"MMR", // Myanmar
		"NAM", // Namibia
		"NGA", // Nigeria
		"PHL", // Philippines
		"SEN", // Senegal
		"SSD", // South Sudan
		"SYR", // Syria
		"TZA", // Tanzania
		"VEN", // Venezuela
		"VNM", // Vietnam
		"YEM", // Yemen
		"ZAF", // South Africa
	}
}

// IsFatfGreyCountry reports membership in FatfGreyCountries.
func IsFatfGreyCountry(country string) bool {
	c := CountryCodeFromText(country)
	if c == "" {
		return false
	}
	for _, g := range FatfGreyCountries() {
		if g == c {
			return true
		}
	}
	return false
}

// ExportCbteTipos lists the AFIP CbteTipo codes that classify
// as factura-electrónica-exportación (Factura E + variants).
func ExportCbteTipos() []int {
	return []int{19, 20, 21, 22} // Factura E + NDE + NCE + Recibo E
}

// IsExportCbteTipo reports membership.
func IsExportCbteTipo(t int) bool {
	for _, v := range ExportCbteTipos() {
		if v == t {
			return true
		}
	}
	return false
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

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	r.IsCaePresent = strings.TrimSpace(r.CaeCode) != ""
	r.IsExportFactura = IsExportCbteTipo(r.CbteTipo) ||
		r.WSKind == WSMtxca
	r.IsIncotermCifCfr = IsCifCfrIncoterm(r.Incoterm)
	r.IsFatfGreyCountry = IsFatfGreyCountry(r.DestinoCountry)
	if r.ImpTotalUSDCents > HighValueUSDCents {
		r.IsHighValueUSD = true
	}
	if r.IsCaePresent && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns a deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].PtoVta != rs[j].PtoVta {
			return rs[i].PtoVta < rs[j].PtoVta
		}
		return rs[i].CbteNro < rs[j].CbteNro
	})
}
