package winafipmonotributo

import (
	"bytes"
	"encoding/xml"
	"math"
	"strconv"
	"strings"
)

// MonotribFields captures scalar fields the audit pipeline
// needs.
type MonotribFields struct {
	MonotributistaCuitRaw string
	CategoriaText         string
	CiiuCode              string
	IngresoAnualText      string
	RecategorizacionDate  string
	Period                string
	HasExclusion          bool
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

// ParseMonotributo extracts MonotribFields from an XML body.
// Returns ok=false on empty / non-XML / unparseable input.
func ParseMonotributo(body []byte) (MonotribFields, bool) {
	var out MonotribFields
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
	// Narrative scan for exclusión marker.
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "exclusion del regimen") ||
		strings.Contains(lower, "exclusión del régimen") ||
		strings.Contains(lower, "exclusion del régimen") ||
		strings.Contains(lower, "excluido del monotributo") {
		out.HasExclusion = true
	}
	if !hasAny(out) {
		return out, false
	}
	return out, true
}

func hasAny(f MonotribFields) bool {
	return f.MonotributistaCuitRaw != "" || f.CategoriaText != "" ||
		f.CiiuCode != "" || f.IngresoAnualText != "" ||
		f.RecategorizacionDate != "" || f.Period != "" ||
		f.HasExclusion
}

func walkXML(nodes []genericNode, out *MonotribFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuit_monotributista", "cuit_contribuyente",
			"cuit_titular", "monotributista_cuit":
			if out.MonotributistaCuitRaw == "" && val != "" {
				out.MonotributistaCuitRaw = val
			}
		case "categoria", "categoria_actual",
			"categoria_vigente":
			if out.CategoriaText == "" && val != "" {
				out.CategoriaText = val
			}
		case "ciiu", "codigo_actividad", "actividad",
			"actividad_principal":
			if out.CiiuCode == "" && val != "" {
				out.CiiuCode = val
			}
		case "ingreso_anual", "ingresos_brutos_anuales",
			"facturacion_anual":
			if out.IngresoAnualText == "" && val != "" {
				out.IngresoAnualText = val
			}
		case "fecha_recategorizacion", "fecharecategorizacion",
			"recategorizacion_fecha":
			if out.RecategorizacionDate == "" && val != "" {
				out.RecategorizacionDate = val
			}
		case "periodo", "periodo_fiscal":
			if out.Period == "" && val != "" {
				out.Period = val
			}
		case "exclusion", "exclusion_motivo", "motivo_exclusion":
			if val != "" && val != "0" && val != "false" {
				out.HasExclusion = true
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

// IngresoToARSCents parses an ingreso-anual text decimal into
// ARS cents.
func IngresoToARSCents(s string) int64 {
	v := strings.TrimSpace(s)
	if v == "" {
		return 0
	}
	v = strings.ReplaceAll(v, "$", "")
	v = strings.ReplaceAll(v, ",", ".")
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	if f <= 0 {
		return 0
	}
	return int64(math.Round(f * 100))
}
