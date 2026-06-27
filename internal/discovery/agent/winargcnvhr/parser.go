package winargcnvhr

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"regexp"
	"strings"
)

// HRFields captures the scalar fields the audit pipeline cares
// about across XML / JSON / text-scrape inputs.
type HRFields struct {
	TipoHechoText      string
	RelevanciaText     string
	IssuerCuitRaw      string
	IssuerTicker       string
	IssuerDenominacion string
	VinculadoCuitRaw   string
	FechaText          string
}

// ParseSiblingMetadata pulls fields out of an XML envelope, a
// JSON envelope, or a flat text body. Returns ok=false on
// empty input.
func ParseSiblingMetadata(body []byte) (HRFields, bool) {
	var out HRFields
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
		// Fall through to text scrape.
		fields = parseTextScrape(body)
		return fields, hasAny(fields)
	case '{', '[':
		fields := parseJSONMeta(body)
		if hasAny(fields) {
			return fields, true
		}
		fields = parseTextScrape(body)
		return fields, hasAny(fields)
	default:
		fields := parseTextScrape(body)
		return fields, hasAny(fields)
	}
}

func hasAny(f HRFields) bool {
	return f.TipoHechoText != "" || f.IssuerCuitRaw != "" ||
		f.IssuerTicker != "" || f.IssuerDenominacion != "" ||
		f.VinculadoCuitRaw != ""
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

func parseXMLMeta(body []byte) HRFields {
	var out HRFields
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out
	}
	walkXML(env.Children, &out)
	return out
}

func walkXML(nodes []genericNode, out *HRFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "tipohecho", "tipo_hecho", "categoria", "asunto", "objeto":
			if out.TipoHechoText == "" && val != "" {
				out.TipoHechoText = val
			}
		case "relevancia", "impacto":
			if out.RelevanciaText == "" && val != "" {
				out.RelevanciaText = val
			}
		case "cuit", "cuit_emisor", "cuitemisor":
			if out.IssuerCuitRaw == "" && val != "" {
				out.IssuerCuitRaw = val
			}
		case "ticker", "simbolo", "símbolo", "sigla":
			if out.IssuerTicker == "" && val != "" {
				out.IssuerTicker = val
			}
		case "denominacion", "denominación", "razonsocial", "emisor", "issuer":
			if out.IssuerDenominacion == "" && val != "" {
				out.IssuerDenominacion = val
			}
		case "vinculado", "cuit_vinculado", "vinculadocuit":
			if out.VinculadoCuitRaw == "" && val != "" {
				out.VinculadoCuitRaw = val
			}
		case "fecha", "fecha_hecho", "fechahecho":
			if out.FechaText == "" && val != "" {
				out.FechaText = val
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

// -- JSON -----------------------------------------------------------

func parseJSONMeta(body []byte) HRFields {
	var out HRFields
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return out
	}
	walkJSON(raw, &out)
	return out
}

func walkJSON(v any, out *HRFields) {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			lk := strings.ToLower(k)
			s, isStr := vv.(string)
			if isStr {
				switch lk {
				case "tipohecho", "tipo_hecho", "categoria", "asunto", "objeto":
					if out.TipoHechoText == "" {
						out.TipoHechoText = s
					}
				case "relevancia", "impacto":
					if out.RelevanciaText == "" {
						out.RelevanciaText = s
					}
				case "cuit", "cuit_emisor", "cuitemisor":
					if out.IssuerCuitRaw == "" {
						out.IssuerCuitRaw = s
					}
				case "ticker", "simbolo", "símbolo", "sigla":
					if out.IssuerTicker == "" {
						out.IssuerTicker = s
					}
				case "denominacion", "denominación", "razonsocial", "emisor", "issuer":
					if out.IssuerDenominacion == "" {
						out.IssuerDenominacion = s
					}
				case "vinculado", "cuit_vinculado", "vinculadocuit":
					if out.VinculadoCuitRaw == "" {
						out.VinculadoCuitRaw = s
					}
				case "fecha", "fecha_hecho", "fechahecho":
					if out.FechaText == "" {
						out.FechaText = s
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

// -- Text scrape ----------------------------------------------------

var (
	scrapeTipoRE      = regexp.MustCompile(`(?i)tipo\s*de\s*hecho\s*[:=]\s*([^\n<]{1,128})`)
	scrapeRelvRE      = regexp.MustCompile(`(?i)relevancia\s*[:=]\s*(alta|media|baja|high|medium|low)`)
	scrapeCuitRE      = regexp.MustCompile(`(?i)cuit\s*[:=]\s*([\d-]{11,15})`)
	scrapeTickerRE    = regexp.MustCompile(`(?i)(?:ticker|simbolo|sigla)\s*[:=]\s*([A-Z]{2,6})`)
	scrapeDenomRE     = regexp.MustCompile(`(?i)(?:denominaci[óo]n|raz[óo]n\s*social|emisor)\s*[:=]\s*([^\n<]{1,256})`)
	scrapeFechaRE     = regexp.MustCompile(`(?i)fecha\s*(?:de\s*hecho)?\s*[:=]\s*([\d/\-]{8,10})`)
	scrapeVinculadoRE = regexp.MustCompile(`(?i)vinculado\s*[:=]\s*([\d-]{11,15})`)
)

func parseTextScrape(body []byte) HRFields {
	var out HRFields
	s := string(body)
	if m := scrapeTipoRE.FindStringSubmatch(s); m != nil {
		out.TipoHechoText = strings.TrimSpace(m[1])
	}
	if m := scrapeRelvRE.FindStringSubmatch(s); m != nil {
		out.RelevanciaText = strings.TrimSpace(m[1])
	}
	if m := scrapeCuitRE.FindStringSubmatch(s); m != nil {
		out.IssuerCuitRaw = strings.TrimSpace(m[1])
	}
	if m := scrapeTickerRE.FindStringSubmatch(s); m != nil {
		out.IssuerTicker = strings.TrimSpace(m[1])
	}
	if m := scrapeDenomRE.FindStringSubmatch(s); m != nil {
		out.IssuerDenominacion = strings.TrimSpace(m[1])
	}
	if m := scrapeFechaRE.FindStringSubmatch(s); m != nil {
		out.FechaText = strings.TrimSpace(m[1])
	}
	if m := scrapeVinculadoRE.FindStringSubmatch(s); m != nil {
		out.VinculadoCuitRaw = strings.TrimSpace(m[1])
	}
	return out
}
