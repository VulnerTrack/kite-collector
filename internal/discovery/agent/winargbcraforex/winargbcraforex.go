// Package winargbcraforex audits Argentine BCRA Comunicación
// "A" 8137 forex-operations files cached on broker, treasury,
// and compliance workstations across Windows, Linux, and
// macOS.
//
// BCRA Com. "A" 8137 (and successor Comunicaciones) governs
// the operational forex layer: MULC, CCL, MEP, Liquidación
// de Divisas, Dólar Soja, RIPCAA. Each operation is declared
// to BCRA via XML/CSV cached on the operator workstation.
//
// **Distinct from**:
//   - iter 100 winafipexport  — AFIP-side export-invoice receipt
//   - iter 95  winbcracendeu  — BCRA banking-solvency CENDEU
//   - iter 101 winbcracomunic — BCRA regulatory advisories cache
//
// This collector targets the *operational* forex declaration
// of capital flow (active transactions, not passive advisories).
//
// Headline finding shapes:
//
//   - `is_high_value_usd=1` — monto > 1 M USD.
//   - `is_fatf_grey_destination=1` — counterparty country on
//     FATF grey list.
//   - `has_concepto_speculative=1` — BCRA concepto for
//     atesoramiento (FX hoarding) or turismo exterior
//     (capital-flight via tourism quota).
//   - `is_credential_exposure_risk=1` — readable file +
//     declarant CUIT + monetary detail = financial-
//     surveillance leak surface.
//
// All CUITs reduced to entity-type prefix + last 4.
//
// Read-only by intent. (Project guideline 4.2.)
package winargbcraforex

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
const MaxFileBytes = 8 << 20 // 8 MiB

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// HighValueUSDCents — threshold for is_high_value_usd
// (1 M USD = 100 M cents).
const HighValueUSDCents int64 = 100_000_000

// DeclarationKind pinned to host_arg_bcra_forex.declaration_kind.
type DeclarationKind string

const (
	DeclMULCOperacion      DeclarationKind = "mulc-operacion"
	DeclCCLOperacion       DeclarationKind = "ccl-operacion"
	DeclMEPOperacion       DeclarationKind = "mep-operacion"
	DeclLiquidacionDivisas DeclarationKind = "liquidacion-divisas"
	DeclDolarSoja          DeclarationKind = "dolar-soja"
	DeclRIPCAA             DeclarationKind = "ripcaa"
	DeclOther              DeclarationKind = "other"
	DeclUnknown            DeclarationKind = "unknown"
)

// OperacionType pinned to host_arg_bcra_forex.operacion_type.
type OperacionType string

const (
	OpCompra                 OperacionType = "compra"
	OpVenta                  OperacionType = "venta"
	OpTransferencia          OperacionType = "transferencia"
	OpLiquidacionExportacion OperacionType = "liquidacion-exportacion"
	OpPagoImportacion        OperacionType = "pago-importacion"
	OpDividendosExterior     OperacionType = "dividendos-exterior"
	OpInteresesExterior      OperacionType = "intereses-exterior"
	OpAtesoramiento          OperacionType = "atesoramiento"
	OpTurismoExterior        OperacionType = "turismo-exterior"
	OpOther                  OperacionType = "other"
	OpUnknown                OperacionType = "unknown"
)

// Moneda pinned to host_arg_bcra_forex.moneda enum.
type Moneda string

const (
	MonedaARS   Moneda = "ars"
	MonedaUSD   Moneda = "usd"
	MonedaEUR   Moneda = "eur"
	MonedaBRL   Moneda = "brl"
	MonedaOther Moneda = "other"
	MonedaEmpty Moneda = ""
)

// Row mirrors host_arg_bcra_forex' column shape.
type Row struct {
	Moneda                   Moneda          `json:"moneda"`
	DeclarationKind          DeclarationKind `json:"declaration_kind"`
	FilePath                 string          `json:"file_path"`
	ConceptoBCRA             string          `json:"concepto_bcra,omitempty"`
	FechaOperacion           string          `json:"fecha_operacion,omitempty"`
	UserProfile              string          `json:"user_profile,omitempty"`
	CounterpartyCountry      string          `json:"counterparty_country,omitempty"`
	OperacionType            OperacionType   `json:"operacion_type"`
	DeclarantCuitPrefix      string          `json:"declarant_cuit_prefix,omitempty"`
	DeclarantCuitSuffix4     string          `json:"declarant_cuit_suffix4,omitempty"`
	FileHash                 string          `json:"file_hash"`
	BrokerMatricula          string          `json:"broker_matricula,omitempty"`
	FileOwnerUID             int             `json:"file_owner_uid,omitempty"`
	MontoUSDCents            int64           `json:"monto_usd_cents,omitempty"`
	MontoARSCents            int64           `json:"monto_ars_cents,omitempty"`
	FileMode                 int             `json:"file_mode,omitempty"`
	FileSize                 int64           `json:"file_size,omitempty"`
	IsHighValueUSD           bool            `json:"is_high_value_usd"`
	IsFatfGreyDestination    bool            `json:"is_fatf_grey_destination"`
	HasConceptoSpeculative   bool            `json:"has_concepto_speculative"`
	IsRecent                 bool            `json:"is_recent"`
	IsWorldReadable          bool            `json:"is_world_readable"`
	IsGroupReadable          bool            `json:"is_group_readable"`
	IsCredentialExposureRisk bool            `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated BCRA-forex install-root
// set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\BCRA\MULC`,
		`C:\BCRA\Forex`,
		`C:\Tesoreria\Forex`,
		`C:\Forex`,
		`/opt/bcra/mulc`,
		`/srv/bcra/forex`,
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

// UserForexDirs is the curated per-user relative path set.
func UserForexDirs() [][]string {
	return [][]string{
		{"Documents", "BCRA", "MULC"},
		{"Documents", "BCRA", "Forex"},
		{"Documents", "Tesoreria", "Forex"},
		{"Documents", "Forex"},
		{"Documents", "Compliance", "BCRA"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateExt reports whether the extension carries a
// BCRA-forex artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".csv", ".json", ".txt":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the BCRA-forex catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"mulc_", "mulc-", "_mulc",
		"ccl_", "ccl-", "_ccl",
		"mep_", "mep-", "_mep",
		"liquidacion_divisas", "liquidacion-divisas",
		"dolar_soja", "dolar-soja", "dolarsoja",
		"ripcaa", "ripcca",
		"forex_bcra", "forex-bcra",
		"declaracion_cambiaria", "declaracion-cambiaria",
		"pago_importacion", "pago-importacion",
		"cobro_exportacion", "cobro-exportacion",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// DeclarationKindFromName classifies a filename heuristically.
func DeclarationKindFromName(name string) DeclarationKind {
	if strings.TrimSpace(name) == "" {
		return DeclUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "mulc"):
		return DeclMULCOperacion
	case strings.Contains(n, "ccl"):
		return DeclCCLOperacion
	case strings.Contains(n, "mep_") || strings.Contains(n, "mep-") ||
		strings.Contains(n, "_mep"):
		return DeclMEPOperacion
	case strings.Contains(n, "liquidacion_divisas") ||
		strings.Contains(n, "liquidacion-divisas"):
		return DeclLiquidacionDivisas
	case strings.Contains(n, "dolar_soja") || strings.Contains(n, "dolar-soja") ||
		strings.Contains(n, "dolarsoja"):
		return DeclDolarSoja
	case strings.Contains(n, "ripcaa") || strings.Contains(n, "ripcca"):
		return DeclRIPCAA
	case strings.Contains(n, "forex") || strings.Contains(n, "declaracion_cambiaria") ||
		strings.Contains(n, "declaracion-cambiaria") ||
		strings.Contains(n, "pago_importacion") || strings.Contains(n, "cobro_exportacion"):
		return DeclOther
	}
	return DeclUnknown
}

// OperacionTypeFromText classifies an operacion-type label.
func OperacionTypeFromText(s string) OperacionType {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case t == "":
		return OpUnknown
	case strings.Contains(t, "atesoramiento"):
		return OpAtesoramiento
	case strings.Contains(t, "turismo") || strings.Contains(t, "viajes exterior"):
		return OpTurismoExterior
	case strings.Contains(t, "dividendos") && strings.Contains(t, "exterior"):
		return OpDividendosExterior
	case strings.Contains(t, "intereses") && strings.Contains(t, "exterior"):
		return OpInteresesExterior
	case strings.Contains(t, "liquidacion") && strings.Contains(t, "exportacion"):
		return OpLiquidacionExportacion
	case strings.Contains(t, "pago") && strings.Contains(t, "importacion"):
		return OpPagoImportacion
	case strings.Contains(t, "transferencia"):
		return OpTransferencia
	case strings.Contains(t, "compra"):
		return OpCompra
	case strings.Contains(t, "venta"):
		return OpVenta
	}
	return OpOther
}

// IsSpeculativeOperacion reports whether the operacion type
// is one of the capital-flight-suspect codes.
func IsSpeculativeOperacion(op OperacionType) bool {
	switch op {
	case OpAtesoramiento, OpTurismoExterior:
		return true
	case OpCompra, OpVenta, OpTransferencia, OpLiquidacionExportacion,
		OpPagoImportacion, OpDividendosExterior, OpInteresesExterior,
		OpOther, OpUnknown:
		return false
	}
	return false
}

// SpeculativeConceptos lists the curated BCRA concepto codes
// that flag capital-flight-suspect operations (atesoramiento +
// turismo).
func SpeculativeConceptos() []string {
	return []string{
		// Atesoramiento / formación de activos externos.
		"A01", "A02", "S04", "S15",
		// Turismo exterior / viajes / tarjeta.
		"S03", "S05", "S06", "S22",
	}
}

// IsSpeculativeConcepto reports membership in the curated
// list.
func IsSpeculativeConcepto(c string) bool {
	t := strings.ToUpper(strings.TrimSpace(c))
	for _, v := range SpeculativeConceptos() {
		if v == t {
			return true
		}
	}
	return false
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

// CountryCodeFromText normalises a 3-letter ISO country code.
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

// FatfGreyCountries mirrors iter 100's curated list.
func FatfGreyCountries() []string {
	return []string{
		"BFA", "CMR", "DOM", "HTI", "KEN", "MNG", "MMR",
		"NAM", "NGA", "PHL", "SEN", "SSD", "SYR", "TZA",
		"VEN", "VNM", "YEM", "ZAF",
	}
}

// IsFatfGreyCountry reports membership.
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

// matriculaRE matches CNV broker matrícula in text.
var matriculaRE = regexp.MustCompile(`(?i)(?:matr[íi]cula|mat[\.\-]?cnv|alyc[_-]matricula)[\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// MatriculaFromText extracts CNV broker matrícula.
func MatriculaFromText(text string) string {
	m := matriculaRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.MontoUSDCents > HighValueUSDCents {
		r.IsHighValueUSD = true
	}
	r.IsFatfGreyDestination = IsFatfGreyCountry(r.CounterpartyCountry)
	// Speculative if operacion type matches OR concepto matches.
	if IsSpeculativeOperacion(r.OperacionType) ||
		IsSpeculativeConcepto(r.ConceptoBCRA) {
		r.HasConceptoSpeculative = true
	}
	// Exposure: declarant CUIT + monetary detail + readable.
	hasFinancialPII := r.DeclarantCuitPrefix != "" &&
		(r.MontoUSDCents > 0 || r.MontoARSCents > 0)
	if hasFinancialPII && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].DeclarationKind != rs[j].DeclarationKind {
			return rs[i].DeclarationKind < rs[j].DeclarationKind
		}
		return rs[i].FechaOperacion < rs[j].FechaOperacion
	})
}
