package winargpymebursatil

import (
	"bytes"
	"encoding/xml"
	"math"
	"strconv"
	"strings"
)

// PyMEFields captures the scalar instrument fields the audit
// pipeline cares about.
type PyMEFields struct {
	EmisorCuitRaw    string
	ReceptorCuitRaw  string
	SgrMatricula     string
	MonedaText       string
	FechaEmision     string
	FechaVencimiento string
	MontoARSCents    int64
	HasSgrAval       bool
}

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

// ParsePyMEInstrument extracts PyMEFields from XML body.
// Returns ok=false on garbage / empty input.
func ParsePyMEInstrument(body []byte) (PyMEFields, bool) {
	var out PyMEFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}
	if trimmed[0] == '<' {
		var env xmlEnvelope
		if err := xml.Unmarshal(body, &env); err != nil {
			return out, false
		}
		walkXML(env.Children, &out)
	}
	// Cross-format SGR-aval narrative scan.
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "sgr aval") ||
		strings.Contains(lower, "aval sgr") ||
		strings.Contains(lower, "avalada por sgr") {
		out.HasSgrAval = true
	}
	if hasAny(out) {
		return out, true
	}
	return out, false
}

func hasAny(f PyMEFields) bool {
	return f.EmisorCuitRaw != "" || f.ReceptorCuitRaw != "" ||
		f.SgrMatricula != "" || f.MontoARSCents > 0 ||
		f.FechaEmision != "" || f.FechaVencimiento != "" ||
		f.HasSgrAval
}

// -- XML --------------------------------------------------------

func walkXML(nodes []genericNode, out *PyMEFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuit_emisor", "cuit_librador", "cuitemisor",
			"cuitlibrador", "librador":
			if out.EmisorCuitRaw == "" && val != "" {
				out.EmisorCuitRaw = val
			}
		case "cuit_receptor", "cuit_beneficiario", "cuitreceptor",
			"receptor":
			if out.ReceptorCuitRaw == "" && val != "" {
				out.ReceptorCuitRaw = val
			}
		case "sgr_matricula", "sgrmatricula", "matricula_sgr":
			if out.SgrMatricula == "" && val != "" {
				out.SgrMatricula = val
			}
		case "sgr_aval", "aval_sgr", "tieneaval":
			if val != "" && val != "0" && val != "false" {
				out.HasSgrAval = true
			}
		case "monto", "importe", "valor", "valor_nominal":
			if out.MontoARSCents == 0 && val != "" {
				out.MontoARSCents = arsToCents(val)
			}
		case "moneda", "moneda_emision":
			if out.MonedaText == "" && val != "" {
				out.MonedaText = val
			}
		case "fecha_emision", "fechaemision":
			if out.FechaEmision == "" && val != "" {
				out.FechaEmision = val
			}
		case "fecha_vencimiento", "fechavencimiento", "vencimiento":
			if out.FechaVencimiento == "" && val != "" {
				out.FechaVencimiento = val
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

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
