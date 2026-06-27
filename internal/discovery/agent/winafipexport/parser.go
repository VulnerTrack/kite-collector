package winafipexport

import (
	"bytes"
	"encoding/xml"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// ExportFields captures the scalar export-invoice fields.
type ExportFields struct {
	IncotermRaw      string
	CAE              string
	CbteFch          string
	CuitEmisorRaw    string
	DestinoCountry   string
	Moneda           string
	Idioma           string
	CbteTipo         int
	PtoVta           int
	CbteNro          int
	CotizacionARS    int64
	ImpTotalCents    int64
	ImpTotalUSDCents int64
}

// genericNode mirrors the per-collector XML walker pattern.
type genericNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr    `xml:",any,attr"`
	Value    string        `xml:",chardata"`
	Children []genericNode `xml:",any"`
}

type xmlEnvelope struct {
	XMLName  xml.Name
	Children []genericNode `xml:",any"`
}

// ParseExportInvoice extracts ExportFields from XML body.
// Returns ok=false on garbage / non-AFIP input.
func ParseExportInvoice(body []byte) (ExportFields, bool) {
	var out ExportFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '<' {
		return out, false
	}
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out, false
	}
	walkXML(env.Children, &out)
	// If moneda is USD/DOL the ImpTotal is already in USD cents.
	// Cotización is informative (ARS/USD AFIP applied for VAT)
	// but not required for the USD-cents derivation. For other
	// foreign currencies we don't attempt cross-rate conversion;
	// the audit pipeline re-evaluates downstream with current FX.
	if out.ImpTotalCents > 0 && out.Moneda != "" {
		if strings.EqualFold(out.Moneda, "DOL") || strings.EqualFold(out.Moneda, "USD") {
			out.ImpTotalUSDCents = out.ImpTotalCents
		}
	}
	if hasAny(out) {
		return out, true
	}
	return out, false
}

func hasAny(f ExportFields) bool {
	return f.CuitEmisorRaw != "" || f.CAE != "" || f.CbteNro > 0 ||
		f.PtoVta > 0 || f.IncotermRaw != "" || f.DestinoCountry != "" ||
		f.ImpTotalCents > 0
}

func walkXML(nodes []genericNode, out *ExportFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuitemisor", "cuit_emisor", "cuitvendedor":
			if out.CuitEmisorRaw == "" && val != "" {
				out.CuitEmisorRaw = val
			}
		case "cae":
			if out.CAE == "" && val != "" {
				out.CAE = val
			}
		case "cbtetipo":
			if out.CbteTipo == 0 && val != "" {
				if n, err := strconv.Atoi(val); err == nil {
					out.CbteTipo = n
				}
			}
		case "cbtefch", "fechacomprobante":
			if out.CbteFch == "" && val != "" {
				out.CbteFch = val
			}
		case "ptovta":
			if out.PtoVta == 0 && val != "" {
				if n, err := strconv.Atoi(val); err == nil {
					out.PtoVta = n
				}
			}
		case "cbtedesde", "cbtenro", "numerocomprobante":
			if out.CbteNro == 0 && val != "" {
				if n, err := strconv.Atoi(val); err == nil {
					out.CbteNro = n
				}
			}
		case "incoterm", "incoterms":
			if out.IncotermRaw == "" && val != "" {
				out.IncotermRaw = val
			}
		case "dst_cmp", "dstcmp", "destino", "destino_country", "iddestino",
			"codigopaisdestino":
			if out.DestinoCountry == "" && val != "" {
				out.DestinoCountry = val
			}
		case "monid", "moneda", "monedasimb":
			if out.Moneda == "" && val != "" {
				out.Moneda = val
			}
		case "moncotiz", "cotizacion":
			if out.CotizacionARS == 0 && val != "" {
				out.CotizacionARS = arsToCents(val)
			}
		case "imptotal":
			if out.ImpTotalCents == 0 && val != "" {
				out.ImpTotalCents = arsToCents(val)
			}
		case "idiomacbte", "idioma", "idioma_cbte":
			if out.Idioma == "" && val != "" {
				out.Idioma = val
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

// countryMap converts the AFIP numeric country id (legacy
// field) to the modern ISO 3-letter code. We populate the
// most common ones; the audit pipeline can backfill the rest.
var afipCountryRE = regexp.MustCompile(`^\d{1,3}$`)

// NormaliseDestino maps the discovered destino_country to a
// 3-letter ISO code. AFIP often emits a numeric country code
// (e.g. 212 = USA, 200 = Brasil) — the table is upstream;
// here we only normalise the obvious string forms.
func NormaliseDestino(raw string) string {
	t := strings.TrimSpace(raw)
	if t == "" {
		return ""
	}
	if c := CountryCodeFromText(t); c != "" {
		return c
	}
	if !afipCountryRE.MatchString(t) {
		// e.g. "Estados Unidos" — leave to downstream.
		return ""
	}
	switch t {
	case "200":
		return "BRA"
	case "212":
		return "USA"
	case "203":
		return "CHL"
	case "208":
		return "MEX"
	case "997":
		return "ESP"
	case "218":
		return "DEU"
	}
	return ""
}

// arsToCents parses a decimal amount into integer cents.
func arsToCents(s string) int64 {
	v := strings.TrimSpace(s)
	if v == "" {
		return 0
	}
	v = strings.ReplaceAll(v, ",", ".")
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return int64(math.Round(f * 100))
}
