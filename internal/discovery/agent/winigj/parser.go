package winigj

import (
	"bytes"
	"encoding/xml"
	"regexp"
	"strings"
)

// IGJFields captures the scalar fields the audit pipeline cares
// about across XML / HTML / text-scrape inputs.
type IGJFields struct {
	SociedadCuitRaw      string
	SociedadDenominacion string
	TipoSocietarioText   string
	EstadoText           string
	FechaActo            string
	FechaInscripcion     string
	IgjCorrelativo       string
	IgjLegajo            string
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

// ParseIGJActo extracts IGJFields from XML / HTML / text body.
// Returns ok=false on empty input.
func ParseIGJActo(body []byte) (IGJFields, bool) {
	var out IGJFields
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
		fields := parseXMLMeta(body)
		if hasAny(fields) {
			return fields, true
		}
		// HTML fall-through to text scrape.
		fields = parseTextScrape(body)
		return fields, hasAny(fields)
	default:
		fields := parseTextScrape(body)
		return fields, hasAny(fields)
	}
}

func hasAny(f IGJFields) bool {
	return f.SociedadCuitRaw != "" || f.SociedadDenominacion != "" ||
		f.IgjCorrelativo != "" || f.IgjLegajo != "" ||
		f.EstadoText != "" || f.FechaActo != ""
}

// -- XML --------------------------------------------------------

func parseXMLMeta(body []byte) IGJFields {
	var out IGJFields
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out
	}
	walkXML(env.Children, &out)
	return out
}

func walkXML(nodes []genericNode, out *IGJFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuitsociedad", "cuit_sociedad", "cuit":
			if out.SociedadCuitRaw == "" && val != "" {
				out.SociedadCuitRaw = val
			}
		case "denominacion", "denominación", "razonsocial",
			"razon_social", "sociedad":
			if out.SociedadDenominacion == "" && val != "" {
				out.SociedadDenominacion = val
			}
		case "tiposocietario", "tipo_societario", "tiposociedad":
			if out.TipoSocietarioText == "" && val != "" {
				out.TipoSocietarioText = val
			}
		case "estado", "estadoinscripcion":
			if out.EstadoText == "" && val != "" {
				out.EstadoText = val
			}
		case "fecha_acto", "fechaacto", "fecha":
			if out.FechaActo == "" && val != "" {
				out.FechaActo = val
			}
		case "fecha_inscripcion", "fechainscripcion":
			if out.FechaInscripcion == "" && val != "" {
				out.FechaInscripcion = val
			}
		case "igj_correlativo", "correlativo", "numerocorrelativo":
			if out.IgjCorrelativo == "" && val != "" {
				out.IgjCorrelativo = val
			}
		case "igj_legajo", "legajo":
			if out.IgjLegajo == "" && val != "" {
				out.IgjLegajo = val
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

// -- Text scrape (HTML + plain text) ----------------------------

var (
	scrapeCuitRE        = regexp.MustCompile(`(?i)cuit\s*[:=]\s*([\d-]{11,15})`)
	scrapeDenomRE       = regexp.MustCompile(`(?i)(?:denominaci[óo]n|raz[óo]n\s*social|sociedad)\s*[:=]\s*([^\n<]{1,256})`)
	scrapeTipoRE        = regexp.MustCompile(`(?i)tipo\s*societario\s*[:=]\s*([^\n<]{1,64})`)
	scrapeEstadoRE      = regexp.MustCompile(`(?i)estado\s*[:=]\s*([^\n<]{1,64})`)
	scrapeFechaRE       = regexp.MustCompile(`(?i)fecha\s*(?:del?\s*acto)?\s*[:=]\s*([\d/\-]{8,10})`)
	scrapeInscripcionRE = regexp.MustCompile(`(?i)inscripci[óo]n\s*[:=]\s*([\d/\-]{8,10})`)
	scrapeCorrelativoRE = regexp.MustCompile(`(?i)correlativo\s*(?:igj)?\s*[:=]\s*(\d{4,8})`)
	scrapeLegajoRE      = regexp.MustCompile(`(?i)legajo\s*[:=]\s*([\d-]{1,12})`)
)

func parseTextScrape(body []byte) IGJFields {
	var out IGJFields
	s := string(body)
	if m := scrapeCuitRE.FindStringSubmatch(s); m != nil {
		out.SociedadCuitRaw = strings.TrimSpace(m[1])
	}
	if m := scrapeDenomRE.FindStringSubmatch(s); m != nil {
		out.SociedadDenominacion = strings.TrimSpace(m[1])
	}
	if m := scrapeTipoRE.FindStringSubmatch(s); m != nil {
		out.TipoSocietarioText = strings.TrimSpace(m[1])
	}
	if m := scrapeEstadoRE.FindStringSubmatch(s); m != nil {
		out.EstadoText = strings.TrimSpace(m[1])
	}
	if m := scrapeFechaRE.FindStringSubmatch(s); m != nil {
		out.FechaActo = strings.TrimSpace(m[1])
	}
	if m := scrapeInscripcionRE.FindStringSubmatch(s); m != nil {
		out.FechaInscripcion = strings.TrimSpace(m[1])
	}
	if m := scrapeCorrelativoRE.FindStringSubmatch(s); m != nil {
		out.IgjCorrelativo = strings.TrimSpace(m[1])
	}
	if m := scrapeLegajoRE.FindStringSubmatch(s); m != nil {
		out.IgjLegajo = strings.TrimSpace(m[1])
	}
	return out
}
