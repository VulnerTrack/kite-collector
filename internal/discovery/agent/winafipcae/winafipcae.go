// Package winafipcae audits Argentine AFIP/ARCA CAE
// (Comprobante Autorizado Electrónicamente) receipt XML files
// cached by billing/accounting workstations across Windows,
// Linux, and macOS. Every WSFEv1 / WSMTXCA response returns a
// CAE receipt the SDK persists to disk for accounting
// reconciliation, audit, and re-printing.
//
// The 14-digit `<CAE>` is the public authorisation code AFIP
// prints on the invoice itself — it is NOT a secret. The PII
// in the receipt is the recipient's `<DocTipo>` + `<DocNro>`
// (DNI/CUIT/Pasaporte), which falls under Argentina's Ley
// 25.326 (Protección de Datos Personales). The collector
// stores only the trailing 4 digits of `<DocNro>` so the
// audit pipeline can correlate repeat-recipient activity
// without retaining the full PII.
//
// File-based discovery is the deliberate design choice — every
// AFIP SDK (pyafipws, Afip.php, afipsdk-js, Tango Gestión,
// Bejerman, SIAP integrations) drops the same WSFE response
// XML shapes on disk. The audit pipeline correlates drift via
// the file SHA-256 without re-parsing.
//
// Headline finding shapes (capital-flow + AML/UIF context):
//
//   - `is_cae_present=1` — `<CAE>` non-empty, the file is a real
//     authorised invoice, not a request stub.
//   - `is_foreign_currency=1` — `<MonId>` != "PES". The headline
//     capital-flight detection signal.
//   - `is_high_value=1` — `<ImpTotal>` > 10,000,000 ARS. UIF
//     Res. 30-E reporting threshold for high-value transactions.
//   - `is_factura_m=1` — Factura M (CbteTipo 51/52/53), AFIP's
//     régimen especial for controlled / under-suspicion
//     taxpayers (RG 1575).
//   - `is_credential_exposure_risk=1` — CAE + readable file =
//     recipient-PII exposure surface.
//
// Read-only by intent — we walk candidate XMLs only, never
// invoke `openssl` or call WSFE. (Project guideline 4.2.)
package winafipcae

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

// MaxReceipts bounds per-scan output. A typical billing host
// retains weeks of receipts (hundreds per day); 32768 covers
// service-bureau hosts holding several CUITs' yearly archives.
const MaxReceipts = 32768

// HighValueARSCents is the threshold above which is_high_value
// flips (10,000,000 ARS = 1,000,000,000 cents). Pinned to
// UIF Res. 30-E/2017 reporting thresholds. The audit pipeline
// can re-evaluate downstream with current FX rates.
const HighValueARSCents int64 = 1_000_000_000

// MaxFileBytes bounds the size we'll read. AFIP CAE receipts
// are <128 KiB. The cap protects against huge unrelated XMLs.
const MaxFileBytes = 1 << 20 // 1 MiB

// CbteLetter classifies the invoice letter per AFIP's CbteTipo
// enum. Pinned to the host_afip_cae_receipts.cbte_letter
// CHECK enum.
type CbteLetter string

const (
	CbteA       CbteLetter = "A" // IVA-discriminated, between responsables inscriptos
	CbteB       CbteLetter = "B" // IVA-incluido, to monotributistas / consumidores finales
	CbteC       CbteLetter = "C" // emitida por monotributistas / exentos
	CbteE       CbteLetter = "E" // exportación
	CbteM       CbteLetter = "M" // régimen especial RG 1575
	CbteUnknown CbteLetter = "X"
)

// DocTipoLabel maps the AFIP DocTipo numeric code to a label.
// Pinned to the host_afip_cae_receipts.doc_tipo_label CHECK
// enum.
type DocTipoLabel string

const (
	DocCUIT      DocTipoLabel = "cuit"
	DocCUIL      DocTipoLabel = "cuil"
	DocDNI       DocTipoLabel = "dni"
	DocPasaporte DocTipoLabel = "pasaporte"
	DocCDI       DocTipoLabel = "cdi"
	DocLE        DocTipoLabel = "le"
	DocLC        DocTipoLabel = "lc"
	DocOther     DocTipoLabel = "other"
	DocUnknown   DocTipoLabel = "unknown"
)

// Receipt mirrors host_afip_cae_receipts' column shape.
type Receipt struct {
	CbteFch                  string       `json:"cbte_fch,omitempty"`
	FileHash                 string       `json:"file_hash"`
	MonID                    string       `json:"mon_id,omitempty"`
	DocNroSuffix4            string       `json:"doc_nro_suffix4,omitempty"`
	DocTipoLabel             DocTipoLabel `json:"doc_tipo_label"`
	UserProfile              string       `json:"user_profile,omitempty"`
	CaeCode                  string       `json:"cae_code,omitempty"`
	CaeVencimiento           string       `json:"cae_vencimiento,omitempty"`
	FilePath                 string       `json:"file_path"`
	CbteLetter               CbteLetter   `json:"cbte_letter"`
	CbteNro                  int          `json:"cbte_nro,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	CbteTipo                 int          `json:"cbte_tipo,omitempty"`
	DocTipo                  int          `json:"doc_tipo,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	ImpTotalCents            int64        `json:"imp_total_cents,omitempty"`
	PtoVta                   int          `json:"pto_vta,omitempty"`
	IsCaePresent             bool         `json:"is_cae_present"`
	IsForeignCurrency        bool         `json:"is_foreign_currency"`
	IsHighValue              bool         `json:"is_high_value"`
	IsFacturaM               bool         `json:"is_factura_m"`
	IsWorldReadable          bool         `json:"is_world_readable"`
	IsGroupReadable          bool         `json:"is_group_readable"`
	IsCredentialExposureRisk bool         `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Receipt, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// LetterFromCbteTipo maps AFIP's CbteTipo numeric code to a
// letter. Codes per AFIP's "Tabla de Tipos de Comprobante"
// (FECompUltimoAutorizado / FECAESolicitar docs).
func LetterFromCbteTipo(t int) CbteLetter {
	switch t {
	case 1, 2, 3, 4, 5: // Factura/ND/NC/Recibos A
		return CbteA
	case 6, 7, 8, 9, 10: // B variants
		return CbteB
	case 11, 12, 13, 15: // C variants (monotributo)
		return CbteC
	case 19, 20, 21, 22: // Exportación E
		return CbteE
	case 51, 52, 53: // M
		return CbteM
	}
	return CbteUnknown
}

// DocTipoLabelFromCode maps AFIP DocTipo codes to labels.
// Common codes: 80=CUIT, 86=CUIL, 96=DNI, 94=Pasaporte,
// 87=CDI, 89=LE, 90=LC, 91=CI Extranjera, 99=Sin identificar.
func DocTipoLabelFromCode(c int) DocTipoLabel {
	switch c {
	case 80:
		return DocCUIT
	case 86:
		return DocCUIL
	case 96:
		return DocDNI
	case 94:
		return DocPasaporte
	case 87:
		return DocCDI
	case 89:
		return DocLE
	case 90:
		return DocLC
	case 0, 99:
		return DocUnknown
	}
	return DocOther
}

// Suffix4 returns the last 4 chars of a numeric/alphanumeric
// DocNro. Empty/short input returns "".
func Suffix4(s string) string {
	t := strings.TrimSpace(s)
	if len(t) < 4 {
		return ""
	}
	return t[len(t)-4:]
}

// AfipNameTokens is the curated set of filename / path tokens
// that strongly indicate AFIP CAE receipts.
func AfipNameTokens() []string {
	return []string{
		"afip", "arca", "wsfe", "wsfev1", "wsmtxca",
		"pyafipws", "afipsdk", "facturador", "comprobante",
		"cae", "factura", "factu",
	}
}

// IsAfipPath reports whether the file plausibly belongs to an
// AFIP CAE export. Matched case-insensitively, anywhere in the
// path.
func IsAfipPath(path string) bool {
	if path == "" {
		return false
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, t := range AfipNameTokens() {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the derived booleans on a Receipt that
// has its raw fields populated. The caller must set FileMode +
// scalar invoice fields first.
func AnnotateSecurity(r *Receipt) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	r.IsCaePresent = strings.TrimSpace(r.CaeCode) != ""
	r.CbteLetter = LetterFromCbteTipo(r.CbteTipo)
	r.IsFacturaM = r.CbteLetter == CbteM
	mon := strings.ToUpper(strings.TrimSpace(r.MonID))
	if mon != "" && mon != "PES" {
		r.IsForeignCurrency = true
	}
	if r.ImpTotalCents > HighValueARSCents {
		r.IsHighValue = true
	}
	if r.DocTipoLabel == "" {
		r.DocTipoLabel = DocTipoLabelFromCode(r.DocTipo)
	}
	if r.IsCaePresent && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortReceipts returns a deterministic ordering by file path
// then comprobante number.
func SortReceipts(rs []Receipt) {
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
