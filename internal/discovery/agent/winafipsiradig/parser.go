package winafipsiradig

import (
	"bytes"
	"encoding/xml"
	"math"
	"strconv"
	"strings"
)

// SiradigFields captures scalar fields the audit pipeline
// needs.
type SiradigFields struct {
	EmpleadoCuitRaw         string
	EmpleadorCuitRaw        string
	ConyugeCuitRaw          string
	LandlordCuitRaw         string
	Period                  string
	AlquilerARSText         string
	DeduccionesTotalARSText string
	DependientesCount       int64
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

// ParseSiradig extracts SiradigFields from an XML body.
// Returns ok=false on empty / non-XML / unparseable input.
func ParseSiradig(body []byte) (SiradigFields, bool) {
	var out SiradigFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}
	if trimmed[0] != '<' {
		return out, false
	}
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out, false
	}
	walkXML(env.Children, &out)
	if !hasAny(out) {
		return out, false
	}
	return out, true
}

func hasAny(f SiradigFields) bool {
	return f.EmpleadoCuitRaw != "" || f.EmpleadorCuitRaw != "" ||
		f.ConyugeCuitRaw != "" || f.LandlordCuitRaw != "" ||
		f.Period != "" || f.DependientesCount > 0 ||
		f.AlquilerARSText != "" || f.DeduccionesTotalARSText != ""
}

func walkXML(nodes []genericNode, out *SiradigFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuit_empleado", "cuit_trabajador", "empleado_cuit":
			if out.EmpleadoCuitRaw == "" && val != "" {
				out.EmpleadoCuitRaw = val
			}
		case "cuit_empleador", "cuit_agente_retencion",
			"empleador_cuit":
			if out.EmpleadorCuitRaw == "" && val != "" {
				out.EmpleadorCuitRaw = val
			}
		case "cuit_conyuge", "conyuge_cuit", "cuit_esposa",
			"cuit_esposo":
			if out.ConyugeCuitRaw == "" && val != "" {
				out.ConyugeCuitRaw = val
			}
		case "cuit_locador", "locador_cuit", "cuit_propietario",
			"propietario_cuit":
			if out.LandlordCuitRaw == "" && val != "" {
				out.LandlordCuitRaw = val
			}
		case "periodo", "periodo_fiscal":
			if out.Period == "" && val != "" {
				out.Period = val
			}
		case "dependiente", "hijo", "hijo_a_cargo":
			out.DependientesCount++
		case "monto_alquiler", "alquiler_mensual",
			"importe_alquiler":
			if out.AlquilerARSText == "" && val != "" {
				out.AlquilerARSText = val
			}
		case "total_deducciones", "deducciones_total",
			"monto_deducciones":
			if out.DeduccionesTotalARSText == "" && val != "" {
				out.DeduccionesTotalARSText = val
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

// DecimalToCents parses a decimal amount into cents.
func DecimalToCents(s string) int64 {
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
