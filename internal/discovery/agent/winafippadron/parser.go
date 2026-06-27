package winafippadron

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
)

// padronFields captures the scalar fields we care about,
// regardless of whether the cache file is XML (raw WS response)
// or JSON (SDK-normalised form).
type padronFields struct {
	CUIT           string
	Denominacion   string
	SituacionRaw   string
	EstadoRaw      string
	ProvinciaDom   string
	ActividadCodes []string
}

// ParsePadronCache attempts XML first, JSON second, and
// returns ok=false if neither shape produces a meaningful row.
// Caller stamps file metadata afterwards.
func ParsePadronCache(body []byte) (Row, bool) {
	var out Row
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}

	var fields padronFields
	switch trimmed[0] {
	case '<':
		fields = parseXMLPadron(body)
	case '{', '[':
		fields = parseJSONPadron(body)
	default:
		return out, false
	}

	if fields.CUIT == "" && fields.Denominacion == "" {
		return out, false
	}

	out.TargetCuitPrefix, out.TargetCuitSuffix4 = CuitFingerprint(fields.CUIT)
	out.Denominacion = TruncateDenominacion(fields.Denominacion)
	out.SituacionIVA = SituacionFromText(fields.SituacionRaw)
	out.EstadoCUIT = EstadoFromText(fields.EstadoRaw)
	out.DomicilioProvincia = strings.TrimSpace(fields.ProvinciaDom)
	out.ActividadesCount = len(fields.ActividadCodes)
	if len(fields.ActividadCodes) > 0 {
		out.PrimaryActividadCLAE = fields.ActividadCodes[0]
	}
	for _, c := range fields.ActividadCodes {
		if IsRiskyCLAE(c) {
			out.HasRiskyActividades = true
			break
		}
	}
	return out, true
}

// -- XML --------------------------------------------------------

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

func parseXMLPadron(body []byte) padronFields {
	var out padronFields
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out
	}
	walkXMLPadron(env.Children, &out)
	return out
}

func walkXMLPadron(nodes []genericNode, out *padronFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "idpersona", "cuit", "nrocuit":
			if out.CUIT == "" && val != "" {
				out.CUIT = val
			}
		case "razonsocial", "nombre", "denominacion", "apellido":
			if out.Denominacion == "" && val != "" {
				out.Denominacion = val
			}
		case "situaciontributaria", "situacioniva", "categoriaautonomo":
			if out.SituacionRaw == "" && val != "" {
				out.SituacionRaw = val
			}
		case "descripcion":
			// `descripcion` shows up under multiple parent contexts;
			// only inherit it if we don't yet have a situación.
			if out.SituacionRaw == "" && val != "" && containsIVAWord(val) {
				out.SituacionRaw = val
			}
		case "estadoclave", "estadocuit":
			if out.EstadoRaw == "" && val != "" {
				out.EstadoRaw = val
			}
		case "descripcionprovincia", "provincia":
			if out.ProvinciaDom == "" && val != "" {
				out.ProvinciaDom = val
			}
		case "idactividad", "actividad", "codigoactividad", "claenumerico":
			if val != "" {
				out.ActividadCodes = append(out.ActividadCodes, val)
			}
		}
		if len(n.Children) > 0 {
			walkXMLPadron(n.Children, out)
		}
	}
}

func containsIVAWord(s string) bool {
	t := strings.ToLower(s)
	return strings.Contains(t, "iva") || strings.Contains(t, "monotrib") ||
		strings.Contains(t, "exento") || strings.Contains(t, "responsable")
}

// -- JSON -------------------------------------------------------

func parseJSONPadron(body []byte) padronFields {
	var out padronFields
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return out
	}
	walkJSON(raw, &out)
	return out
}

func walkJSON(v any, out *padronFields) {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			lk := strings.ToLower(k)
			s, isStr := vv.(string)
			switch lk {
			case "idpersona", "cuit", "nrocuit":
				if isStr && out.CUIT == "" && s != "" {
					out.CUIT = s
				} else if !isStr {
					if n, ok := numericToString(vv); ok && out.CUIT == "" {
						out.CUIT = n
					}
				}
			case "razonsocial", "nombre", "denominacion", "apellido":
				if isStr && out.Denominacion == "" && s != "" {
					out.Denominacion = s
				}
			case "situaciontributaria", "situacioniva", "categoriaautonomo":
				if isStr && out.SituacionRaw == "" && s != "" {
					out.SituacionRaw = s
				}
			case "estadoclave", "estadocuit":
				if isStr && out.EstadoRaw == "" && s != "" {
					out.EstadoRaw = s
				}
			case "descripcionprovincia", "provincia":
				if isStr && out.ProvinciaDom == "" && s != "" {
					out.ProvinciaDom = s
				}
			case "idactividad", "actividad", "codigoactividad", "claenumerico":
				if isStr && s != "" {
					out.ActividadCodes = append(out.ActividadCodes, s)
				} else if !isStr {
					if n, ok := numericToString(vv); ok && n != "" {
						out.ActividadCodes = append(out.ActividadCodes, n)
					}
				}
			}
			walkJSON(vv, out)
		}
	case []any:
		for _, x := range t {
			walkJSON(x, out)
		}
	}
}

func numericToString(v any) (string, bool) {
	switch n := v.(type) {
	case float64:
		// AFIP JSON encodes CLAE as integers; floats round
		// trivially since values are within int64 range.
		return formatInt(int64(n)), true
	case json.Number:
		return n.String(), true
	}
	return "", false
}

func formatInt(n int64) string {
	if n == 0 {
		return ""
	}
	// Simple stdlib-free conversion to avoid pulling strconv just
	// for this niche.
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
