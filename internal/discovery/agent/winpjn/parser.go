package winpjn

import (
	"bytes"
	"encoding/xml"
	"regexp"
	"strings"
)

// Sibling metadata XML emitted by PJN's notification system
// alongside each PDF. We accept any namespace prefix.
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

// PJNFields captures the scalar fields the audit pipeline cares
// about, regardless of whether we extract them from XML, HTML,
// or filename.
type PJNFields struct {
	TipoProcesoText string
	JuzgadoText     string
	SecretariaText  string
	CuitRaw         string
	CuijRaw         string
	Caratula        string
	FechaText       string
}

// ParseSiblingMetadata pulls fields out of an XML metadata
// envelope, an HTML page, or a flat key=value text. Returns
// ok=false on empty input.
func ParseSiblingMetadata(body []byte) (PJNFields, bool) {
	var out PJNFields
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
		// Could be XML or HTML.
		fields, ok := parseXMLMeta(body)
		if ok && hasAny(fields) {
			return fields, true
		}
		// Fall through to HTML / text scrape.
		fields = parseTextScrape(body)
		return fields, hasAny(fields)
	default:
		fields := parseTextScrape(body)
		return fields, hasAny(fields)
	}
}

func hasAny(f PJNFields) bool {
	return f.TipoProcesoText != "" || f.JuzgadoText != "" ||
		f.CuitRaw != "" || f.CuijRaw != "" || f.Caratula != ""
}

// -- XML metadata ---------------------------------------------------

func parseXMLMeta(body []byte) (PJNFields, bool) {
	var out PJNFields
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out, false
	}
	walkXMLMeta(env.Children, &out)
	return out, true
}

func walkXMLMeta(nodes []genericNode, out *PJNFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "tipoproceso", "tipo_proceso", "objeto", "fuero", "materia":
			if out.TipoProcesoText == "" && val != "" {
				out.TipoProcesoText = val
			}
		case "juzgado", "tribunal", "dependencia":
			if out.JuzgadoText == "" && val != "" {
				out.JuzgadoText = val
			}
		case "secretaria", "secretaría":
			if out.SecretariaText == "" && val != "" {
				out.SecretariaText = val
			}
		case "caratula", "carátula", "titulo", "título":
			if out.Caratula == "" && val != "" {
				out.Caratula = val
			}
		case "cuit", "cuit_demandado", "cuit_actor":
			if out.CuitRaw == "" && val != "" {
				out.CuitRaw = val
			}
		case "cuij", "numero_cuij", "expediente":
			if out.CuijRaw == "" && val != "" {
				out.CuijRaw = val
			}
		case "fecha", "fecha_notificacion", "fechanotificacion":
			if out.FechaText == "" && val != "" {
				out.FechaText = val
			}
		}
		if len(n.Children) > 0 {
			walkXMLMeta(n.Children, out)
		}
	}
}

// -- Text / HTML scrape --------------------------------------------

var (
	keyTipoRE       = regexp.MustCompile(`(?i)tipo\s*de\s*proceso\s*[:=]\s*([^\n<]{1,128})`)
	keyJuzgadoRE    = regexp.MustCompile(`(?i)juzgado\s*[:=]\s*([^\n<]{1,128})`)
	keySecretariaRE = regexp.MustCompile(`(?i)secretar[ií]a\s*[:=]\s*([^\n<]{1,64})`)
	keyCaratulaRE   = regexp.MustCompile(`(?i)car[áa]tula\s*[:=]\s*([^\n<]{1,256})`)
	keyCuitRE       = regexp.MustCompile(`(?i)cuit\s*[:=]\s*([\d-]{11,15})`)
	keyCuijRE       = regexp.MustCompile(`(?i)cuij\s*[:=]\s*([\d/-]{6,32})`)
	keyFechaRE      = regexp.MustCompile(`(?i)fecha\s*(?:de\s*notificaci[óo]n)?\s*[:=]\s*([\d/\-]{8,10})`)
)

func parseTextScrape(body []byte) PJNFields {
	var out PJNFields
	s := string(body)
	if m := keyTipoRE.FindStringSubmatch(s); m != nil {
		out.TipoProcesoText = strings.TrimSpace(m[1])
	}
	if m := keyJuzgadoRE.FindStringSubmatch(s); m != nil {
		out.JuzgadoText = strings.TrimSpace(m[1])
	}
	if m := keySecretariaRE.FindStringSubmatch(s); m != nil {
		out.SecretariaText = strings.TrimSpace(m[1])
	}
	if m := keyCaratulaRE.FindStringSubmatch(s); m != nil {
		out.Caratula = strings.TrimSpace(m[1])
	}
	if m := keyCuitRE.FindStringSubmatch(s); m != nil {
		out.CuitRaw = strings.TrimSpace(m[1])
	}
	if m := keyCuijRE.FindStringSubmatch(s); m != nil {
		out.CuijRaw = strings.TrimSpace(m[1])
	}
	if m := keyFechaRE.FindStringSubmatch(s); m != nil {
		out.FechaText = strings.TrimSpace(m[1])
	}
	return out
}
