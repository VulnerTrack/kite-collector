package winbcracomunic

import (
	"bytes"
	"encoding/xml"
	"regexp"
	"strings"
)

// ComFields captures the scalar fields the audit pipeline cares
// about across XML / HTML / text-scrape inputs.
type ComFields struct {
	Numero        string
	AsuntoText    string
	MateriaText   string
	FechaEmision  string
	FechaVigencia string
	SustituyeA    string
	ModificaA     string
}

// genericNode + xmlEnvelope mirror the sibling-collector
// pattern.
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

// ParseComunicacion extracts ComFields from an XML / HTML / text
// body. Returns ok=false on empty input.
func ParseComunicacion(body []byte) (ComFields, bool) {
	var out ComFields
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
		// Fall through to text scrape (handles HTML too).
		fields = parseTextScrape(body)
		return fields, hasAny(fields)
	default:
		fields := parseTextScrape(body)
		return fields, hasAny(fields)
	}
}

func hasAny(f ComFields) bool {
	return f.Numero != "" || f.AsuntoText != "" || f.MateriaText != "" ||
		f.FechaEmision != "" || f.SustituyeA != "" || f.ModificaA != ""
}

// -- XML --------------------------------------------------------

func parseXMLMeta(body []byte) ComFields {
	var out ComFields
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out
	}
	walkXML(env.Children, &out)
	return out
}

func walkXML(nodes []genericNode, out *ComFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "numero", "numerocom", "numero_com":
			if out.Numero == "" && val != "" {
				out.Numero = val
			}
		case "asunto", "titulo", "título", "subject":
			if out.AsuntoText == "" && val != "" {
				out.AsuntoText = val
			}
		case "materia", "area", "tema":
			if out.MateriaText == "" && val != "" {
				out.MateriaText = val
			}
		case "fecha", "fecha_emision", "fechaemision":
			if out.FechaEmision == "" && val != "" {
				out.FechaEmision = val
			}
		case "fecha_vigencia", "fechavigencia", "vigenciadesde":
			if out.FechaVigencia == "" && val != "" {
				out.FechaVigencia = val
			}
		case "sustituyea", "sustituye_a":
			if out.SustituyeA == "" && val != "" {
				out.SustituyeA = val
			}
		case "modificaa", "modifica_a":
			if out.ModificaA == "" && val != "" {
				out.ModificaA = val
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

// -- Text scrape (works on HTML + plain text) -----------------

var (
	scrapeNumeroRE    = regexp.MustCompile(`(?i)(?:com|comunicaci[óo]n)\s*"?([abcp])"?\s*(\d{2,6})`)
	scrapeAsuntoRE    = regexp.MustCompile(`(?i)asunto\s*[:=]\s*([^\n<]{1,256})`)
	scrapeMateriaRE   = regexp.MustCompile(`(?i)materia\s*[:=]\s*([^\n<]{1,128})`)
	scrapeFechaRE     = regexp.MustCompile(`(?i)fecha\s*(?:de\s*emisi[óo]n)?\s*[:=]\s*([\d/\-]{8,10})`)
	scrapeVigenciaRE  = regexp.MustCompile(`(?i)vigencia\s*(?:desde)?\s*[:=]\s*([\d/\-]{8,10})`)
	scrapeSustituyeRE = regexp.MustCompile(`(?i)sustituye\s*(?:a)?\s*[:=]\s*([abcp]\s*\d{2,6})`)
	scrapeModificaRE  = regexp.MustCompile(`(?i)modifica\s*(?:a)?\s*[:=]\s*([abcp]\s*\d{2,6})`)
)

func parseTextScrape(body []byte) ComFields {
	var out ComFields
	s := string(body)
	if m := scrapeNumeroRE.FindStringSubmatch(s); m != nil {
		out.Numero = strings.ToUpper(m[1]) + " " + m[2]
	}
	if m := scrapeAsuntoRE.FindStringSubmatch(s); m != nil {
		out.AsuntoText = strings.TrimSpace(m[1])
	}
	if m := scrapeMateriaRE.FindStringSubmatch(s); m != nil {
		out.MateriaText = strings.TrimSpace(m[1])
	}
	if m := scrapeFechaRE.FindStringSubmatch(s); m != nil {
		out.FechaEmision = strings.TrimSpace(m[1])
	}
	if m := scrapeVigenciaRE.FindStringSubmatch(s); m != nil {
		out.FechaVigencia = strings.TrimSpace(m[1])
	}
	if m := scrapeSustituyeRE.FindStringSubmatch(s); m != nil {
		out.SustituyeA = strings.ToUpper(strings.TrimSpace(m[1]))
	}
	if m := scrapeModificaRE.FindStringSubmatch(s); m != nil {
		out.ModificaA = strings.ToUpper(strings.TrimSpace(m[1]))
	}
	return out
}
