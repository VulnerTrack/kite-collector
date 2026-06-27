package winargcnvaif

import (
	"bytes"
	"encoding/xml"
	"math"
	"strconv"
	"strings"
)

// AIFFields captures scalar fields the audit pipeline needs.
type AIFFields struct {
	EmisorCuitRaw        string
	Ticker               string
	DocumentoAIFID       string
	TipoEmisionText      string
	FechaAprobacion      string
	VigenciaDesde        string
	VigenciaHasta        string
	MontoARSText         string
	MontoUSDText         string
	BeneficialOwnerCount int64
	HasDirectorioChange  bool
	HasCapitalChange     bool
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

// ParseAIFArtifact extracts AIFFields from an XML body. PDF /
// .doc / .docx files are out-of-scope for structured parse;
// the collector keeps filename-derived fields only.
func ParseAIFArtifact(body []byte) (AIFFields, bool) {
	var out AIFFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}
	if trimmed[0] != '<' {
		// Narrative-only scan.
		scanNarrative(body, &out)
		if hasAny(out) {
			return out, true
		}
		return out, false
	}
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return out, false
	}
	walkXML(env.Children, &out)
	// Narrative-level rollup scan on the raw body.
	scanNarrative(body, &out)
	if !hasAny(out) {
		return out, false
	}
	return out, true
}

func hasAny(f AIFFields) bool {
	return f.EmisorCuitRaw != "" || f.Ticker != "" ||
		f.DocumentoAIFID != "" || f.TipoEmisionText != "" ||
		f.FechaAprobacion != "" || f.VigenciaDesde != "" ||
		f.VigenciaHasta != "" || f.MontoARSText != "" ||
		f.MontoUSDText != "" || f.BeneficialOwnerCount > 0 ||
		f.HasDirectorioChange || f.HasCapitalChange
}

func walkXML(nodes []genericNode, out *AIFFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuit_emisor", "cuitemisor", "emisor_cuit":
			if out.EmisorCuitRaw == "" && val != "" {
				out.EmisorCuitRaw = val
			}
		case "ticker", "simbolo", "símbolo":
			if out.Ticker == "" && val != "" {
				out.Ticker = strings.ToUpper(val)
			}
		case "documento_aif_id", "aif_id", "folio":
			if out.DocumentoAIFID == "" && val != "" {
				out.DocumentoAIFID = val
			}
		case "tipo_emision", "tipoemision":
			if out.TipoEmisionText == "" && val != "" {
				out.TipoEmisionText = val
			}
		case "fecha_aprobacion", "fechaaprobacion":
			if out.FechaAprobacion == "" && val != "" {
				out.FechaAprobacion = val
			}
		case "vigencia_desde", "fecha_desde", "desde":
			if out.VigenciaDesde == "" && val != "" {
				out.VigenciaDesde = val
			}
		case "vigencia_hasta", "fecha_hasta", "hasta":
			if out.VigenciaHasta == "" && val != "" {
				out.VigenciaHasta = val
			}
		case "monto_ars", "monto_emision_ars":
			if out.MontoARSText == "" && val != "" {
				out.MontoARSText = val
			}
		case "monto_usd", "monto_emision_usd":
			if out.MontoUSDText == "" && val != "" {
				out.MontoUSDText = val
			}
		case "beneficiario_final", "beneficiariofinal",
			"beneficial_owner":
			out.BeneficialOwnerCount++
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

// scanNarrative checks the raw body for high-level rollup
// markers across all artifact kinds.
func scanNarrative(body []byte, out *AIFFields) {
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "designacion de directorio") ||
		strings.Contains(lower, "designación de directorio") ||
		strings.Contains(lower, "designacion del directorio") ||
		strings.Contains(lower, "renuncia de director") ||
		strings.Contains(lower, "cesacion de director") {
		out.HasDirectorioChange = true
	}
	if strings.Contains(lower, "aumento de capital") ||
		strings.Contains(lower, "reduccion de capital") ||
		strings.Contains(lower, "reducción de capital") ||
		strings.Contains(lower, "capital aumentado") ||
		strings.Contains(lower, "emision de acciones") ||
		strings.Contains(lower, "emisión de acciones") {
		out.HasCapitalChange = true
	}
	if strings.Contains(lower, "beneficiario final") ||
		strings.Contains(lower, "beneficiarios finales") ||
		strings.Contains(lower, "beneficial owner") {
		if out.BeneficialOwnerCount == 0 {
			out.BeneficialOwnerCount = 1
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
