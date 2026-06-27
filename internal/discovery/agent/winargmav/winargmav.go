// Package winargmav audits MAV (Mercado Argentino de Valores)
// terminal + SME-instrument files cached on ALYC broker, SGR
// (Sociedad de Garantía Recíproca), PyME issuer, fideicomiso
// admin, and PyME-advisor workstations across Windows, Linux,
// and macOS.
//
// MAV is Argentina's SME-focused exchange. Operated by
// Bolsa de Comercio de Rosario / Córdoba, it trades ChPD
// avalados (Cheques Pago Diferido SGR-guaranteed), pagaré
// bursátil, ON-PYME, FCE MiPyME (electronic credit invoice),
// Letras de Tesoros Provinciales, ON sustentables, and
// fideicomisos financieros.
//
// **The SME-exchange terminal + instrument layer.** Distinct
// from:
//
//   - iter 111 winargpymebursatil — PyME instrument file form
//   - iter 136 winargsiopel       — SIOPEL/MAE OTC terminal
//   - iter 137 winargbyma         — BYMA equity terminal
//   - iter 110 winargfci          — FCI mutual-fund layer
//
// Headline finding shapes:
//
//   - `has_sgr_aval=1` — entry carries SGR aval (credit-risk
//     transfer to SGR balance sheet).
//   - `has_default_risk=1` — vencido + still activo (librador
//     in pay-overdue, SGR must honor aval).
//   - `has_high_value=1` — total > 10 M ARS.
//   - `has_foreign_currency=1` — moneda != ARS.
//   - `has_provincial_default_risk=1` — provincia in default
//     mark.
//   - `has_overdue_libramiento=1` — ChPD past libramiento.
//   - `has_concentration=1` — single issuer/SGR > 50 %.
//   - `is_credential_exposure_risk=1` — readable file +
//     cliente CUIT + (SGR aval OR PYME body).
//
// Read-only by intent. (Project guideline 4.2.)
package winargmav

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
const MaxFileBytes = 24 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// HighValueCents — 10 M ARS = 1 G cents. CNV monitoring
// threshold for PyME instruments.
const HighValueCents int64 = 1_000_000_000

// ConcentrationPct — single-issuer / single-SGR concentration
// threshold (CNV RG 622 monitoring).
const ConcentrationPct = 50

// ArtifactKind pinned to host_arg_mav.artifact_kind.
type ArtifactKind string

const (
	KindTerminalConfig  ArtifactKind = "mav-terminal-config"
	KindRuedaData       ArtifactKind = "mav-rueda-data"
	KindInstrumentCache ArtifactKind = "mav-instrument-cache"
	KindSGRPortfolio    ArtifactKind = "mav-sgr-portfolio"
	KindAvalLetter      ArtifactKind = "mav-aval-letter"
	KindPyMEListing     ArtifactKind = "mav-pyme-listing"
	KindSettlement      ArtifactKind = "mav-settlement"
	KindFideicomiso     ArtifactKind = "mav-fideicomiso"
	KindInstaller       ArtifactKind = "mav-installer"
	KindOther           ArtifactKind = "other"
	KindUnknown         ArtifactKind = "unknown"
)

// MemberKind pinned to host_arg_mav.member_kind.
type MemberKind string

const (
	MemberALYC             MemberKind = "alyc-broker"
	MemberSGR              MemberKind = "sgr"
	MemberPyMEIssuer       MemberKind = "pyme-issuer"
	MemberFideicomisoAdmin MemberKind = "fideicomiso-admin"
	MemberOther            MemberKind = "other"
	MemberUnknown          MemberKind = "unknown"
)

// InstrumentClass pinned to host_arg_mav.instrument_class.
type InstrumentClass string

const (
	InstChPD                 InstrumentClass = "chpd"
	InstPagareBursatil       InstrumentClass = "pagare-bursatil"
	InstObligacionNegociable InstrumentClass = "obligacion-negociable"
	InstFCEMiPyME            InstrumentClass = "fce-mipyme"
	InstLetraProvincial      InstrumentClass = "letra-provincial"
	InstONSustentable        InstrumentClass = "on-sustentable"
	InstFideicomiso          InstrumentClass = "fideicomiso"
	InstOther                InstrumentClass = "other"
	InstUnknown              InstrumentClass = "unknown"
)

// Moneda pinned to host_arg_mav.moneda.
type Moneda string

const (
	MonedaNone  Moneda = ""
	MonedaARS   Moneda = "ARS"
	MonedaUSD   Moneda = "USD"
	MonedaEUR   Moneda = "EUR"
	MonedaUVA   Moneda = "UVA"
	MonedaCER   Moneda = "CER"
	MonedaOther Moneda = "other"
)

// Row mirrors host_arg_mav column shape.
type Row struct {
	FilePath                 string          `json:"file_path"`
	FileHash                 string          `json:"file_hash"`
	UserProfile              string          `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind    `json:"artifact_kind"`
	MemberKind               MemberKind      `json:"member_kind"`
	InstrumentClass          InstrumentClass `json:"instrument_class"`
	MemberMatricula          string          `json:"member_matricula,omitempty"`
	LibradorCuitPrefix       string          `json:"librador_cuit_prefix,omitempty"`
	LibradorCuitSuffix4      string          `json:"librador_cuit_suffix4,omitempty"`
	ReceptorCuitPrefix       string          `json:"receptor_cuit_prefix,omitempty"`
	ReceptorCuitSuffix4      string          `json:"receptor_cuit_suffix4,omitempty"`
	ClienteCuitPrefix        string          `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string          `json:"cliente_cuit_suffix4,omitempty"`
	SGRName                  string          `json:"sgr_name,omitempty"`
	Provincia                string          `json:"provincia,omitempty"`
	Moneda                   Moneda          `json:"moneda,omitempty"`
	FechaVencimiento         string          `json:"fecha_vencimiento,omitempty"`
	FechaLibramiento         string          `json:"fecha_libramiento,omitempty"`
	PeriodYYYYMM             string          `json:"period_yyyymm,omitempty"`
	MontoARSCents            int64           `json:"monto_ars_cents,omitempty"`
	TotalPortfolioARSCents   int64           `json:"total_portfolio_ars_cents,omitempty"`
	MaxConcentrationPct      int             `json:"max_concentration_pct,omitempty"`
	InstrumentCount          int64           `json:"instrument_count,omitempty"`
	FileOwnerUID             int             `json:"file_owner_uid,omitempty"`
	FileMode                 int             `json:"file_mode,omitempty"`
	FileSize                 int64           `json:"file_size,omitempty"`
	HasSGRAval               bool            `json:"has_sgr_aval"`
	HasDefaultRisk           bool            `json:"has_default_risk"`
	HasHighValue             bool            `json:"has_high_value"`
	HasForeignCurrency       bool            `json:"has_foreign_currency"`
	HasProvincialDefaultRisk bool            `json:"has_provincial_default_risk"`
	HasOverdueLibramiento    bool            `json:"has_overdue_libramiento"`
	HasConcentration         bool            `json:"has_concentration"`
	HasClienteCuit           bool            `json:"has_cliente_cuit"`
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

// DefaultInstallRoots is the curated MAV install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\MAV`,
		`C:\Program Files\MAV`,
		`C:\Broker\MAV`,
		`C:\SGR\MAV`,
		`C:\PyME\MAV`,
		`C:\Fideicomisos\MAV`,
		`/opt/mav`,
		`/srv/mav`,
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

// UserMAVDirs is the curated per-user relative path set.
func UserMAVDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "MAV"},
		{"AppData", "Local", "MAV"},
		{"Documents", "MAV"},
		{"Documents", "Broker", "MAV"},
		{"Documents", "SGR", "MAV"},
		{"Documents", "PyME", "MAV"},
		{"Documents", "Fideicomisos", "MAV"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// MAV artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".csv", ".tsv", ".json",
		".txt", ".log", ".pdf",
		".xlsx", ".xls",
		".ini", ".cfg", ".conf",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the MAV catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"mav_", "mav-", "_mav.", "-mav.", "/mav/", "mav.",
		"rueda_mav", "rueda-mav",
		"catalogo_mav", "catalogo-mav",
		"sgr_portfolio", "sgr-portfolio",
		"carta_aval", "carta-aval",
		"aval_letter", "aval-letter",
		"pyme_listing", "pyme-listing",
		"settlement_mav", "settlement-mav",
		"fideicomiso_",
		"chpd_", "chpd-",
		"pagare_bursatil", "pagare-bursatil",
		"on_pyme", "on-pyme",
		"fce_mipyme", "fce-mipyme",
		"letra_provincial", "letra-provincial",
		"on_sustentable", "on-sustentable",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ArtifactKindFromName classifies a filename heuristically.
//
// Order matters: more-specific tokens precede generic ones.
func ArtifactKindFromName(name string) ArtifactKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".msi", ".exe":
		if strings.Contains(n, "mav") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "rueda_mav") ||
		strings.Contains(n, "rueda-mav"):
		return KindRuedaData
	case strings.Contains(n, "catalogo_mav") ||
		strings.Contains(n, "catalogo-mav"):
		return KindInstrumentCache
	case strings.Contains(n, "sgr_portfolio") ||
		strings.Contains(n, "sgr-portfolio"):
		return KindSGRPortfolio
	case strings.Contains(n, "carta_aval") ||
		strings.Contains(n, "carta-aval") ||
		strings.Contains(n, "aval_letter") ||
		strings.Contains(n, "aval-letter"):
		return KindAvalLetter
	case strings.Contains(n, "pyme_listing") ||
		strings.Contains(n, "pyme-listing"):
		return KindPyMEListing
	case strings.Contains(n, "settlement"):
		return KindSettlement
	case strings.Contains(n, "fideicomiso"):
		return KindFideicomiso
	case strings.Contains(n, "mav") &&
		(ext == ".ini" || ext == ".cfg" || ext == ".conf"):
		return KindTerminalConfig
	}
	return KindOther
}

// MemberKindFromPath classifies the MAV member type from path
// tokens.
//
// On Linux CI, Windows-style paths still need to classify
// correctly, so we normalize backslashes to forward-slashes
// before token matching.
func MemberKindFromPath(path string) MemberKind {
	if path == "" {
		return MemberUnknown
	}
	lower := strings.ToLower(
		strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	switch {
	case strings.Contains(lower, "/sgr/") ||
		strings.Contains(lower, "sgr_") ||
		strings.Contains(lower, "garant[íi]a") ||
		strings.Contains(lower, "garantia_reciproca") ||
		strings.Contains(lower, "garantia-reciproca"):
		return MemberSGR
	case strings.Contains(lower, "/pyme/") ||
		strings.Contains(lower, "pyme_") ||
		strings.Contains(lower, "pyme-issuer"):
		return MemberPyMEIssuer
	case strings.Contains(lower, "/fideicomisos/") ||
		strings.Contains(lower, "fideicomiso_admin"):
		return MemberFideicomisoAdmin
	case strings.Contains(lower, "/broker/") ||
		strings.Contains(lower, "/alyc/") ||
		strings.Contains(lower, "alyc_"):
		return MemberALYC
	case strings.Contains(lower, "/mav/"):
		return MemberOther
	}
	return MemberUnknown
}

// InstrumentClassFromName classifies the instrument class
// from a filename + body tokens.
func InstrumentClassFromName(name string) InstrumentClass {
	if name == "" {
		return InstUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "chpd"):
		return InstChPD
	case strings.Contains(n, "pagare_bursatil") ||
		strings.Contains(n, "pagare-bursatil"):
		return InstPagareBursatil
	case strings.Contains(n, "on_pyme") ||
		strings.Contains(n, "on-pyme"):
		return InstObligacionNegociable
	case strings.Contains(n, "fce_mipyme") ||
		strings.Contains(n, "fce-mipyme"):
		return InstFCEMiPyME
	case strings.Contains(n, "letra_provincial") ||
		strings.Contains(n, "letra-provincial"):
		return InstLetraProvincial
	case strings.Contains(n, "on_sustentable") ||
		strings.Contains(n, "on-sustentable"):
		return InstONSustentable
	case strings.Contains(n, "fideicomiso"):
		return InstFideicomiso
	}
	return InstUnknown
}

// ArgentineProvinces returns the curated set of provincial
// abbreviations used in MAV Letras issuances.
func ArgentineProvinces() []string {
	return []string{
		"BUE", "CAT", "CBA", "COR", "CHA", "CHU",
		"ERI", "FOR", "JUJ", "LPA", "LRI", "MEN",
		"MIS", "NEU", "RNE", "SAL", "SJU", "SLU",
		"STC", "STA", "SDE", "TIE", "TUC", "CABA",
		"Buenos Aires", "Catamarca", "Córdoba", "Corrientes",
		"Chaco", "Chubut", "Entre Ríos", "Formosa", "Jujuy",
		"La Pampa", "La Rioja", "Mendoza", "Misiones",
		"Neuquén", "Río Negro", "Salta", "San Juan",
		"San Luis", "Santa Cruz", "Santa Fe",
		"Santiago del Estero", "Tierra del Fuego", "Tucumán",
	}
}

// IsArgentineProvince reports membership in the curated set.
func IsArgentineProvince(p string) bool {
	t := strings.TrimSpace(p)
	if t == "" {
		return false
	}
	for _, v := range ArgentineProvinces() {
		if strings.EqualFold(v, t) {
			return true
		}
	}
	return false
}

// NormalizeMoneda maps text tokens to canonical Moneda enum.
func NormalizeMoneda(s string) Moneda {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "ARS", "AR$", "PESOS", "PESO":
		if strings.TrimSpace(s) == "" {
			return MonedaNone
		}
		return MonedaARS
	case "USD", "U$S", "U$D", "DOLAR", "DÓLAR", "DOLLAR":
		return MonedaUSD
	case "EUR", "EURO", "€":
		return MonedaEUR
	case "UVA":
		return MonedaUVA
	case "CER":
		return MonedaCER
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

// matriculaRE matches MAV member matrícula.
var matriculaRE = regexp.MustCompile(`(?i)(?:matr[íi]cula|mav[_\- ]?matricula|member[_\- ]?matricula)[\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// MatriculaFromText extracts MAV member matrícula.
func MatriculaFromText(text string) string {
	m := matriculaRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
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

// IsHighSensitivityKind reports whether the kind carries PII /
// instrument-detail subject to the credential-exposure rollup.
func IsHighSensitivityKind(k ArtifactKind) bool {
	switch k {
	case KindAvalLetter, KindPyMEListing, KindSGRPortfolio,
		KindFideicomiso, KindRuedaData, KindSettlement:
		return true
	case KindTerminalConfig, KindInstrumentCache,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsOverdueDate reports whether `dateStr` (YYYY-MM-DD) is
// strictly before `now`.
func IsOverdueDate(dateStr string, now time.Time) bool {
	if dateStr == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return false
	}
	return t.Before(now)
}

// AnnotateSecurity sets derived booleans. Caller populates
// scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.ClienteCuitPrefix != "" {
		r.HasClienteCuit = true
	}
	if r.SGRName != "" {
		r.HasSGRAval = true
	}
	if r.MontoARSCents >= HighValueCents ||
		r.TotalPortfolioARSCents >= HighValueCents {
		r.HasHighValue = true
	}
	if r.Moneda != MonedaNone && r.Moneda != MonedaARS {
		r.HasForeignCurrency = true
	}
	if r.MaxConcentrationPct >= ConcentrationPct {
		r.HasConcentration = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	// Body-sensitivity signal: either the artifact-kind is
	// inherently high-sensitivity (aval letter, SGR portfolio,
	// pyme listing, rueda, settlement) OR the instrument class
	// carries PII (chpd, pagare, on-pyme, fideicomiso, etc.).
	bodySignal := IsHighSensitivityKind(r.ArtifactKind) ||
		(r.InstrumentClass != InstUnknown &&
			r.InstrumentClass != InstOther)
	if readable && r.HasClienteCuit && bodySignal {
		r.IsCredentialExposureRisk = true
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
