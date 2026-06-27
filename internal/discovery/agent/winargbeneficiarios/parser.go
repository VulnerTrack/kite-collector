package winargbeneficiarios

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strconv"
	"strings"
)

// UBOFields captures the scalar fields the audit pipeline needs
// regardless of source format.
type UBOFields struct {
	ObligadoCuitRaw         string
	ObligadoDenominacion    string
	PeriodYYYY              string
	EstadoText              string
	BeneficiariosCount      int
	MaxParticipacionPct     int
	HasIndirectControlChain bool
	HasExtranjeroUBO        bool
}

// beneficiario represents one UBO row inside an XML / JSON
// envelope.
type beneficiario struct {
	CuilRaw          string
	TipoControl      string
	ParticipacionPct int
	DocExtranjero    bool
}

// ParseUBODeclaration extracts UBOFields from an XML / JSON /
// flat-text body. Returns ok=false on garbage input.
func ParseUBODeclaration(body []byte) (UBOFields, bool) {
	var out UBOFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}
	var benes []beneficiario
	switch trimmed[0] {
	case '<':
		ok := false
		out, benes, ok = parseXMLUBO(body)
		if !ok {
			return UBOFields{}, false
		}
	case '{', '[':
		ok := false
		out, benes, ok = parseJSONUBO(body)
		if !ok {
			return UBOFields{}, false
		}
	default:
		return out, false
	}
	out.BeneficiariosCount = len(benes)
	for _, b := range benes {
		if b.ParticipacionPct > out.MaxParticipacionPct {
			out.MaxParticipacionPct = b.ParticipacionPct
		}
		t := strings.ToLower(strings.TrimSpace(b.TipoControl))
		if strings.Contains(t, "indirect") || strings.Contains(t, "cadena") ||
			strings.Contains(t, "chain") {
			out.HasIndirectControlChain = true
		}
		if b.DocExtranjero {
			out.HasExtranjeroUBO = true
		}
		// Heuristic: if CUIL prefix is NOT a natural-person prefix,
		// the chain has a juridical intermediary → indirect control.
		if b.CuilRaw != "" {
			if prefix, _ := CuitFingerprint(b.CuilRaw); prefix != "" {
				if !IsNaturalPersonPrefix(prefix) {
					out.HasIndirectControlChain = true
				}
			}
		}
	}
	return out, true
}

// -- XML ------------------------------------------------------------

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

func parseXMLUBO(body []byte) (UBOFields, []beneficiario, bool) {
	var out UBOFields
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out, nil, false
	}
	var benes []beneficiario
	walkXML(env.Children, &out, &benes)
	return out, benes, true
}

func walkXML(nodes []genericNode, out *UBOFields, benes *[]beneficiario) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuitobligado", "cuit_obligado", "obligado", "cuitsociedad":
			if out.ObligadoCuitRaw == "" && val != "" {
				out.ObligadoCuitRaw = val
			}
		case "denominacion", "denominación", "razonsocial":
			if out.ObligadoDenominacion == "" && val != "" {
				out.ObligadoDenominacion = val
			}
		case "periodo", "ejercicio", "anio", "año":
			if out.PeriodYYYY == "" && val != "" {
				out.PeriodYYYY = trimYear(val)
			}
		case "estado", "estado_filing", "estadopresentacion":
			if out.EstadoText == "" && val != "" {
				out.EstadoText = val
			}
		case "beneficiario", "beneficiariofinal", "uborecord":
			b := readBeneficiarioNode(&n)
			*benes = append(*benes, b)
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out, benes)
		}
	}
}

func readBeneficiarioNode(n *genericNode) beneficiario {
	var b beneficiario
	for _, c := range n.Children {
		name := strings.ToLower(c.XMLName.Local)
		val := strings.TrimSpace(c.Value)
		switch name {
		case "cuil", "cuit", "cuitbeneficiario", "iddocumento":
			if b.CuilRaw == "" {
				b.CuilRaw = val
			}
		case "participacion", "participacionpct", "porcentaje", "percentage":
			if pct, ok := parsePercent(val); ok {
				b.ParticipacionPct = pct
			}
		case "tipocontrol", "tipo_control", "control":
			if b.TipoControl == "" {
				b.TipoControl = val
			}
		case "tipodocumento", "tipo_documento":
			if isForeignDocType(val) {
				b.DocExtranjero = true
			}
		case "paisresidencia", "paisresidente", "nacionalidad":
			if isForeignCountry(val) {
				b.DocExtranjero = true
			}
		}
	}
	return b
}

// -- JSON -----------------------------------------------------------

func parseJSONUBO(body []byte) (UBOFields, []beneficiario, bool) {
	var out UBOFields
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return out, nil, false
	}
	var benes []beneficiario
	walkJSON(raw, &out, &benes)
	return out, benes, true
}

func walkJSON(v any, out *UBOFields, benes *[]beneficiario) {
	switch t := v.(type) {
	case map[string]any:
		// Try to read this node as a beneficiario.
		if isBeneficiarioMap(t) {
			*benes = append(*benes, readBeneficiarioMap(t))
		}
		for k, vv := range t {
			lk := strings.ToLower(k)
			s, isStr := vv.(string)
			switch lk {
			case "cuitobligado", "cuit_obligado", "obligado", "cuitsociedad":
				if isStr && out.ObligadoCuitRaw == "" {
					out.ObligadoCuitRaw = s
				}
			case "denominacion", "denominación", "razonsocial":
				if isStr && out.ObligadoDenominacion == "" {
					out.ObligadoDenominacion = s
				}
			case "periodo", "ejercicio", "anio", "año":
				if isStr && out.PeriodYYYY == "" {
					out.PeriodYYYY = trimYear(s)
				} else if n, ok := vv.(float64); ok && out.PeriodYYYY == "" {
					out.PeriodYYYY = trimYear(strconv.Itoa(int(n)))
				}
			case "estado", "estadopresentacion":
				if isStr && out.EstadoText == "" {
					out.EstadoText = s
				}
			}
			walkJSON(vv, out, benes)
		}
	case []any:
		for _, x := range t {
			walkJSON(x, out, benes)
		}
	}
}

func isBeneficiarioMap(m map[string]any) bool {
	// Detect heuristically by presence of a participación field.
	for k := range m {
		lk := strings.ToLower(k)
		if lk == "participacion" || lk == "participacionpct" ||
			lk == "porcentaje" || lk == "percentage" {
			return true
		}
	}
	return false
}

func readBeneficiarioMap(m map[string]any) beneficiario {
	var b beneficiario
	for k, vv := range m {
		lk := strings.ToLower(k)
		s, isStr := vv.(string)
		switch lk {
		case "cuil", "cuit", "cuitbeneficiario", "iddocumento":
			if isStr && b.CuilRaw == "" {
				b.CuilRaw = s
			}
		case "participacion", "participacionpct", "porcentaje", "percentage":
			if isStr {
				if pct, ok := parsePercent(s); ok {
					b.ParticipacionPct = pct
				}
			} else if n, ok := vv.(float64); ok {
				b.ParticipacionPct = int(n)
			}
		case "tipocontrol", "tipo_control", "control":
			if isStr && b.TipoControl == "" {
				b.TipoControl = s
			}
		case "tipodocumento", "tipo_documento":
			if isStr && isForeignDocType(s) {
				b.DocExtranjero = true
			}
		case "paisresidencia", "paisresidente", "nacionalidad":
			if isStr && isForeignCountry(s) {
				b.DocExtranjero = true
			}
		}
	}
	return b
}

// -- helpers --------------------------------------------------------

func parsePercent(s string) (int, bool) {
	t := strings.TrimSpace(s)
	t = strings.TrimSuffix(t, "%")
	t = strings.TrimSpace(t)
	if t == "" {
		return 0, false
	}
	t = strings.ReplaceAll(t, ",", ".")
	f, err := strconv.ParseFloat(t, 64)
	if err != nil {
		return 0, false
	}
	pct := int(f + 0.5) // round half-up
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct, true
}

func isForeignDocType(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "pasaporte"), strings.Contains(t, "passport"),
		strings.Contains(t, "dni extranjero"), strings.Contains(t, "ci extranjero"),
		strings.Contains(t, "carnet extranjero"), strings.Contains(t, "foreign"):
		return true
	}
	return false
}

func isForeignCountry(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	switch t {
	case "ARGENTINA", "AR", "ARG":
		return false
	}
	return true
}

func trimYear(s string) string {
	t := strings.TrimSpace(s)
	if len(t) >= 4 {
		// Take first 4 chars if they're digits.
		for i := 0; i < 4; i++ {
			c := t[i]
			if c < '0' || c > '9' {
				return ""
			}
		}
		return t[:4]
	}
	return ""
}
