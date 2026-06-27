package winargros

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"math"
	"strconv"
	"strings"
)

// ROSFields captures the scalar UIF fields the audit pipeline
// needs regardless of source format. Narrative content is
// NEVER stored — only its length.
type ROSFields struct {
	TargetCuitRaw         string
	SujetoObligadoCuitRaw string
	EstadoText            string
	FechaText             string
	MontoARSCents         int64
	DescripcionLength     int
	HasPEPSignal          bool
	HasTerrorismSignal    bool
}

// ParseROSReport extracts ROSFields from XML / JSON / text.
// Returns ok=false on garbage / non-UIF input.
func ParseROSReport(body []byte) (ROSFields, bool) {
	var out ROSFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}
	switch trimmed[0] {
	case '<':
		ok := false
		out, ok = parseXMLROS(body)
		if !ok {
			return out, false
		}
	case '{', '[':
		ok := false
		out, ok = parseJSONROS(body)
		if !ok {
			return out, false
		}
	default:
		return out, false
	}
	// Cross-format PEP / terrorism narrative scan.
	bodyText := string(body)
	if IsPEPText(bodyText) {
		out.HasPEPSignal = true
	}
	if IsTerrorismText(bodyText) {
		out.HasTerrorismSignal = true
	}
	return out, hasAny(out)
}

func hasAny(f ROSFields) bool {
	return f.TargetCuitRaw != "" || f.SujetoObligadoCuitRaw != "" ||
		f.MontoARSCents > 0 || f.DescripcionLength > 0 ||
		f.EstadoText != "" || f.FechaText != ""
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

func parseXMLROS(body []byte) (ROSFields, bool) {
	var out ROSFields
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out, false
	}
	walkXML(env.Children, &out)
	return out, true
}

func walkXML(nodes []genericNode, out *ROSFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuitreportado", "cuit_reportado", "cuit_target", "cuitsospechoso",
			"target", "cuitoperacion":
			if out.TargetCuitRaw == "" && val != "" {
				out.TargetCuitRaw = val
			}
		case "cuitsujetoobligado", "cuit_sujeto_obligado", "cuit_reportante",
			"reportante":
			if out.SujetoObligadoCuitRaw == "" && val != "" {
				out.SujetoObligadoCuitRaw = val
			}
		case "monto", "importe", "valor", "montoars":
			if out.MontoARSCents == 0 && val != "" {
				out.MontoARSCents = arsToCents(val)
			}
		case "estado", "estadoreporte":
			if out.EstadoText == "" && val != "" {
				out.EstadoText = val
			}
		case "fecha", "fecha_reporte", "fechareporte":
			if out.FechaText == "" && val != "" {
				out.FechaText = val
			}
		case "descripcion", "descripción", "narrativa", "narrative",
			"justificacion", "operacion":
			// Length only — NEVER store narrative.
			if val != "" && len(val) > out.DescripcionLength {
				out.DescripcionLength = len(val)
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

// -- JSON -----------------------------------------------------------

func parseJSONROS(body []byte) (ROSFields, bool) {
	var out ROSFields
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return out, false
	}
	walkJSON(raw, &out)
	return out, true
}

func walkJSON(v any, out *ROSFields) {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			lk := strings.ToLower(k)
			s, isStr := vv.(string)
			switch lk {
			case "cuitreportado", "cuit_reportado", "cuit_target",
				"cuitsospechoso", "target", "cuitoperacion":
				if isStr && out.TargetCuitRaw == "" {
					out.TargetCuitRaw = s
				}
			case "cuitsujetoobligado", "cuit_sujeto_obligado",
				"cuit_reportante", "reportante":
				if isStr && out.SujetoObligadoCuitRaw == "" {
					out.SujetoObligadoCuitRaw = s
				}
			case "monto", "importe", "valor", "montoars":
				if isStr && out.MontoARSCents == 0 {
					out.MontoARSCents = arsToCents(s)
				} else if n, ok := vv.(float64); ok && out.MontoARSCents == 0 {
					if !math.IsNaN(n) && !math.IsInf(n, 0) {
						out.MontoARSCents = int64(math.Round(n * 100))
					}
				}
			case "estado", "estadoreporte":
				if isStr && out.EstadoText == "" {
					out.EstadoText = s
				}
			case "fecha", "fecha_reporte", "fechareporte":
				if isStr && out.FechaText == "" {
					out.FechaText = s
				}
			case "descripcion", "descripción", "narrativa", "narrative",
				"justificacion", "operacion":
				if isStr && len(s) > out.DescripcionLength {
					out.DescripcionLength = len(s)
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

func arsToCents(s string) int64 {
	v := strings.TrimSpace(s)
	if v == "" {
		return 0
	}
	v = strings.ReplaceAll(v, ",", ".")
	// Drop currency markers like "$", "ARS".
	v = strings.TrimSpace(strings.TrimPrefix(v, "$"))
	if idx := strings.IndexFunc(v, func(r rune) bool {
		return r == 'A' || r == 'U' || r == 'a' || r == 'u' ||
			r == ' '
	}); idx >= 0 {
		v = v[:idx]
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return int64(math.Round(f * 100))
}
