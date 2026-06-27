package winafipdfe

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// DFEFields captures the scalar fields the audit pipeline cares
// about across XML / HTML / JSON / text-scrape inputs.
type DFEFields struct {
	TargetCuitRaw      string
	NumeroNotificacion string
	FechaNotificacion  string
	FechaVencimiento   string
	EstadoText         string
	Impuesto           string
	KindText           string
	MontoARSCents      int64
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

// ParseDFE extracts DFEFields from XML / JSON / HTML / text.
// Returns ok=false on empty input.
func ParseDFE(body []byte) (DFEFields, bool) {
	var out DFEFields
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
		out = parseXMLMeta(body)
		if hasAny(out) {
			return out, true
		}
		out = parseTextScrape(body)
		return out, hasAny(out)
	case '{', '[':
		out = parseJSONMeta(body)
		if hasAny(out) {
			return out, true
		}
		out = parseTextScrape(body)
		return out, hasAny(out)
	default:
		out = parseTextScrape(body)
		return out, hasAny(out)
	}
}

func hasAny(f DFEFields) bool {
	return f.TargetCuitRaw != "" || f.NumeroNotificacion != "" ||
		f.FechaNotificacion != "" || f.FechaVencimiento != "" ||
		f.EstadoText != "" || f.MontoARSCents > 0 ||
		f.Impuesto != "" || f.KindText != ""
}

// -- XML --------------------------------------------------------

func parseXMLMeta(body []byte) DFEFields {
	var out DFEFields
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out
	}
	walkXML(env.Children, &out)
	return out
}

func walkXML(nodes []genericNode, out *DFEFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuit", "cuit_contribuyente", "cuitcontribuyente":
			if out.TargetCuitRaw == "" && val != "" {
				out.TargetCuitRaw = val
			}
		case "numero", "numero_notificacion", "numeronotificacion", "id":
			if out.NumeroNotificacion == "" && val != "" {
				out.NumeroNotificacion = val
			}
		case "fecha_notificacion", "fechanotificacion", "fecha":
			if out.FechaNotificacion == "" && val != "" {
				out.FechaNotificacion = val
			}
		case "fecha_vencimiento", "fechavencimiento", "vencimiento":
			if out.FechaVencimiento == "" && val != "" {
				out.FechaVencimiento = val
			}
		case "estado", "estadonotificacion":
			if out.EstadoText == "" && val != "" {
				out.EstadoText = val
			}
		case "monto", "importe", "monto_ars":
			if out.MontoARSCents == 0 && val != "" {
				out.MontoARSCents = arsToCents(val)
			}
		case "impuesto", "tributo":
			if out.Impuesto == "" && val != "" {
				out.Impuesto = val
			}
		case "tipo", "tipo_notificacion", "tiponotificacion", "asunto":
			if out.KindText == "" && val != "" {
				out.KindText = val
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

// -- JSON -------------------------------------------------------

func parseJSONMeta(body []byte) DFEFields {
	var out DFEFields
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return out
	}
	walkJSON(raw, &out)
	return out
}

func walkJSON(v any, out *DFEFields) {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			lk := strings.ToLower(k)
			s, isStr := vv.(string)
			switch lk {
			case "cuit", "cuit_contribuyente", "cuitcontribuyente":
				if isStr && out.TargetCuitRaw == "" {
					out.TargetCuitRaw = s
				}
			case "numero", "numero_notificacion", "numeronotificacion", "id":
				if isStr && out.NumeroNotificacion == "" {
					out.NumeroNotificacion = s
				}
			case "fecha_notificacion", "fechanotificacion", "fecha":
				if isStr && out.FechaNotificacion == "" {
					out.FechaNotificacion = s
				}
			case "fecha_vencimiento", "fechavencimiento", "vencimiento":
				if isStr && out.FechaVencimiento == "" {
					out.FechaVencimiento = s
				}
			case "estado", "estadonotificacion":
				if isStr && out.EstadoText == "" {
					out.EstadoText = s
				}
			case "monto", "importe", "monto_ars":
				if isStr && out.MontoARSCents == 0 {
					out.MontoARSCents = arsToCents(s)
				} else if n, ok := vv.(float64); ok && out.MontoARSCents == 0 {
					if !math.IsNaN(n) && !math.IsInf(n, 0) {
						out.MontoARSCents = int64(math.Round(n * 100))
					}
				}
			case "impuesto", "tributo":
				if isStr && out.Impuesto == "" {
					out.Impuesto = s
				}
			case "tipo", "tipo_notificacion", "tiponotificacion", "asunto":
				if isStr && out.KindText == "" {
					out.KindText = s
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

// -- Text scrape (HTML + plain text) ----------------------------

var (
	scrapeCuitRE       = regexp.MustCompile(`(?i)cuit\s*[:=]\s*([\d-]{11,15})`)
	scrapeNumeroRE     = regexp.MustCompile(`(?i)(?:n[°ºo]|nro|numero)\s*(?:notificaci[óo]n)?\s*[:=]\s*([\d-]{4,15})`)
	scrapeFechaNotifRE = regexp.MustCompile(`(?i)fecha\s*(?:de\s*)?notificaci[óo]n\s*[:=]\s*([\d/\-]{8,10})`)
	scrapeFechaVencRE  = regexp.MustCompile(`(?i)fecha\s*(?:de\s*)?vencimiento\s*[:=]\s*([\d/\-]{8,10})`)
	scrapeEstadoRE     = regexp.MustCompile(`(?i)estado\s*[:=]\s*([^\n<]{1,64})`)
	scrapeMontoRE      = regexp.MustCompile(`(?i)(?:monto|importe)\s*[:=]\s*\$?\s*([\d\.,]+)`)
	scrapeImpuestoRE   = regexp.MustCompile(`(?i)(?:impuesto|tributo)\s*[:=]\s*([^\n<]{1,32})`)
	scrapeTipoRE       = regexp.MustCompile(`(?i)(?:tipo|asunto)\s*[:=]\s*([^\n<]{1,128})`)
)

func parseTextScrape(body []byte) DFEFields {
	var out DFEFields
	s := string(body)
	if m := scrapeCuitRE.FindStringSubmatch(s); m != nil {
		out.TargetCuitRaw = strings.TrimSpace(m[1])
	}
	if m := scrapeNumeroRE.FindStringSubmatch(s); m != nil {
		out.NumeroNotificacion = strings.TrimSpace(m[1])
	}
	if m := scrapeFechaNotifRE.FindStringSubmatch(s); m != nil {
		out.FechaNotificacion = strings.TrimSpace(m[1])
	}
	if m := scrapeFechaVencRE.FindStringSubmatch(s); m != nil {
		out.FechaVencimiento = strings.TrimSpace(m[1])
	}
	if m := scrapeEstadoRE.FindStringSubmatch(s); m != nil {
		out.EstadoText = strings.TrimSpace(m[1])
	}
	if m := scrapeMontoRE.FindStringSubmatch(s); m != nil {
		out.MontoARSCents = arsToCents(m[1])
	}
	if m := scrapeImpuestoRE.FindStringSubmatch(s); m != nil {
		out.Impuesto = strings.TrimSpace(m[1])
	}
	if m := scrapeTipoRE.FindStringSubmatch(s); m != nil {
		out.KindText = strings.TrimSpace(m[1])
	}
	return out
}

// arsToCents parses an ARS amount with optional thousand-sep
// dots / commas. "1.234.567,89" → 123456789.
func arsToCents(s string) int64 {
	v := strings.TrimSpace(s)
	if v == "" {
		return 0
	}
	v = strings.TrimPrefix(v, "$")
	v = strings.TrimSpace(v)
	// Detect format: if both "." and "," present, "." is
	// thousands and "," is decimal (Argentine convention).
	if strings.Contains(v, ".") && strings.Contains(v, ",") {
		v = strings.ReplaceAll(v, ".", "")
		v = strings.ReplaceAll(v, ",", ".")
	} else if strings.Contains(v, ",") {
		// Comma is decimal separator.
		v = strings.ReplaceAll(v, ",", ".")
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
