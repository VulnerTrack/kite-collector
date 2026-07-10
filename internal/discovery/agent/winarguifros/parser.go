package winarguifros

import (
	"bytes"
	"encoding/xml"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// UIFFields captures scalar fields the audit pipeline needs
// from a UIF artifact (ROS/ROI/PEP/sanctions/KYC).
type UIFFields struct {
	ClienteCuitRaw          string
	OfficerCuitRaw          string
	PEPName                 string
	HighRiskJurisdiction    string
	Period                  string
	Status                  string
	AlertCount              int64
	TransactionCount        int64
	MaxAmountCents          int64
	TotalAmountCents        int64
	HasPEPMarker            bool
	HasSanctionsMarker      bool
	HasHighRiskJurisdiction bool
	HasStructuringMarker    bool
	HasKYCBody              bool
}

// pepRE detects a PEP-list marker. UIF Resol. 134 mandates a
// "Persona Expuesta Políticamente" tag in the report body.
var pepRE = regexp.MustCompile(
	`(?i)(?:persona[_\s]+expuesta[_\s]+politicamente|politically[_\s]+exposed|\bpep\b\s*[:=])`,
)

// sanctionsRE detects an OFAC/UN/EU sanctions-list marker.
var sanctionsRE = regexp.MustCompile(
	`(?i)(?:ofac|sdn[_\s]+list|un[_\s]+consolidated|eu[_\s]+sanctions|sanctions[_\s]+match|listado[_\s]+sancion)`,
)

// structuringRE detects a smurfing / structuring marker.
var structuringRE = regexp.MustCompile(
	`(?i)(?:smurfing|structuring|fractionamiento|estructuraci[oó]n|sub[\s_-]*threshold)`,
)

// kycRE detects a KYC dossier body marker.
var kycRE = regexp.MustCompile(
	`(?i)(?:kyc|know[_\s\-]your[_\s\-]customer|due[_\s\-]diligence|debida[_\s]+diligencia|conocimiento[_\s]+cliente)`,
)

// statusRE matches a `<status>filed</status>` /
// `Status: rejected` row.
var statusRE = regexp.MustCompile(
	`(?i)(?:status|estado|estado_reporte)\s*[:=>]\s*([A-Za-z]+)`,
)

// alertRE matches an alert entry tag.
var alertRE = regexp.MustCompile(
	`(?i)<\s*(alert|alerta|monitoring[_\-]?alert)[\s>/]`,
)

// amountRE matches an `Importe=NN,NN` / `<importe>NN</importe>`
// in the body. Captures cents-equivalent.
var amountRE = regexp.MustCompile(
	`(?i)(?:importe|monto|valor|amount|nominal|total)\s*[:=>]\s*([0-9][0-9\.,]*)`,
)

// transactionRE matches a per-transaction tag.
var transactionRE = regexp.MustCompile(
	`(?i)<\s*(?:operacion|transaccion|transaction|movimiento)[\s>/]`,
)

// pepNameRE matches a `<pep_name>Nombre Apellido</pep_name>`
// or `pep_name: ...` line. We don't persist the raw name;
// only its hash.
var pepNameRE = regexp.MustCompile(
	`(?i)(?:pep[_\s]?name|nombre[_\s]?pep|nombre[_\s]?politico|persona[_\s]+expuesta)\s*[:=>]\s*"?([A-Za-z][A-Za-z\s\.\-']{3,80})"?`,
)

// jurisdictionRE matches a `country: VEN` / `<country>Iran</country>` /
// `jurisdiction: ...` row.
var jurisdictionRE = regexp.MustCompile(
	`(?i)(?:country|pais|jurisdiction|jurisdicci[oó]n|residencia[_\s]+fiscal|nacionalidad)\s*[:=>]\s*"?([A-Za-z][A-Za-z\s\-]{2,40})"?`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N` etc.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|client[_\- ]?cuit|titular[_\- ]?cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// officerCuitKeyRE matches `oficial_cumplimiento_cuit:...`.
var officerCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:oficial[_\- ]?cumplimiento[_\- ]?cuit|compliance[_\- ]?officer[_\- ]?cuit|cuit[_\- ]?(?:oficial|officer))"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParseUIFReport parses a UIF ROS / ROI / RFT / KYC body.
//
// Captures: cliente CUIT, officer CUIT, PEP/sanctions/HR
// jurisdiction markers, period, status, tx counts + amounts.
func ParseUIFReport(body []byte) UIFFields {
	var out UIFFields
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	// Try structured XML first.
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '<' {
		parseReportXML(body, &out)
	}

	// Regex scans run regardless of XML success — XML body
	// may not catch flat keys; CSV/text bodies need them.
	if pepRE.Match(body) {
		out.HasPEPMarker = true
	}
	if sanctionsRE.Match(body) {
		out.HasSanctionsMarker = true
	}
	if structuringRE.Match(body) {
		out.HasStructuringMarker = true
	}
	if kycRE.Match(body) {
		out.HasKYCBody = true
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	if m := officerCuitKeyRE.FindSubmatch(body); m != nil {
		out.OfficerCuitRaw = string(m[1])
	}
	if out.ClienteCuitRaw == "" && out.OfficerCuitRaw == "" {
		// Fall back to first-found CUIT in body.
		if m := cuitRE.FindSubmatch(body); m != nil {
			out.ClienteCuitRaw = string(m[1]) + string(m[2]) + string(m[3])
		}
	}
	if m := pepNameRE.FindSubmatch(body); m != nil {
		out.PEPName = string(m[1])
		out.HasPEPMarker = true
	}
	if m := jurisdictionRE.FindSubmatch(body); m != nil {
		j := strings.TrimSpace(string(m[1]))
		if IsHighRiskJurisdiction(j) {
			out.HighRiskJurisdiction = j
			out.HasHighRiskJurisdiction = true
		}
	}
	if m := statusRE.FindSubmatch(body); m != nil {
		out.Status = strings.ToLower(strings.TrimSpace(string(m[1])))
	}
	alerts := alertRE.FindAllIndex(body, -1)
	out.AlertCount += int64(len(alerts))
	tx := transactionRE.FindAllIndex(body, -1)
	out.TransactionCount += int64(len(tx))
	for _, m := range amountRE.FindAllSubmatch(body, -1) {
		cents := decimalToCents(string(m[1]))
		if cents <= 0 {
			continue
		}
		out.TotalAmountCents += cents
		if cents > out.MaxAmountCents {
			out.MaxAmountCents = cents
		}
	}
	return out
}

// ParseSanctionsList parses an OFAC SDN / UN / EU consolidated
// sanctions list body. Captures alert count = entry rows; per-
// row PII is NOT extracted (it's the list itself).
func ParseSanctionsList(body []byte) UIFFields {
	var out UIFFields
	if len(body) == 0 {
		return out
	}
	out.HasSanctionsMarker = true
	// Each non-empty non-comment line ≈ 1 sanctioned entity.
	lines := bytes.Split(body, []byte("\n"))
	for _, raw := range lines {
		line := bytes.TrimSpace(raw)
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' || line[0] == ';' {
			continue
		}
		out.AlertCount++
	}
	return out
}

// ParsePEPList parses a PEP listado body. Captures alert
// count = PEP entries; the per-name hash is NOT computed
// here (the PEPNameHash flag on Row is reserved for ROS/KYC
// bodies that name a specific PEP).
func ParsePEPList(body []byte) UIFFields {
	var out UIFFields
	if len(body) == 0 {
		return out
	}
	out.HasPEPMarker = true
	lines := bytes.Split(body, []byte("\n"))
	for _, raw := range lines {
		line := bytes.TrimSpace(raw)
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' || line[0] == ';' {
			continue
		}
		out.AlertCount++
	}
	return out
}

type reportXMLEnvelope struct {
	XMLName  xml.Name
	Children []reportXMLNode `xml:",any"`
}

type reportXMLNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr      `xml:",any,attr"`
	Value    string          `xml:",chardata"`
	Children []reportXMLNode `xml:",any"`
}

func parseReportXML(body []byte, out *UIFFields) {
	var env reportXMLEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return
	}
	walkReportNodes(env.Children, out)
}

func walkReportNodes(nodes []reportXMLNode, out *UIFFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cliente_cuit", "cuit_cliente":
			if out.ClienteCuitRaw == "" && val != "" {
				out.ClienteCuitRaw = val
			}
		case "oficial_cumplimiento_cuit", "compliance_officer_cuit",
			"cuit_oficial", "cuit_officer":
			if out.OfficerCuitRaw == "" && val != "" {
				out.OfficerCuitRaw = val
			}
		case "pep_name", "nombre_pep", "persona_expuesta_politicamente":
			if out.PEPName == "" && val != "" {
				out.PEPName = val
				out.HasPEPMarker = true
			}
		case "country", "pais", "jurisdiction", "residencia_fiscal":
			if val != "" && IsHighRiskJurisdiction(val) {
				out.HighRiskJurisdiction = val
				out.HasHighRiskJurisdiction = true
			}
		case "periodo":
			if out.Period == "" && val != "" {
				out.Period = val
			}
		case "estado", "status", "estado_reporte":
			if out.Status == "" && val != "" {
				out.Status = strings.ToLower(val)
			}
		}
		// Alert / tx / amount counters are computed by the
		// regex post-pass below (one source of truth — XML and
		// text bodies both feed the same counters).
		_ = val
		if len(n.Children) > 0 {
			walkReportNodes(n.Children, out)
		}
	}
}

// decimalToCents parses "1.234,56" or "1234.56" to cents.
func decimalToCents(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if strings.Count(s, ".") > 0 && strings.Count(s, ",") > 0 {
		s = strings.ReplaceAll(s, ".", "")
		s = strings.ReplaceAll(s, ",", ".")
	} else {
		s = strings.ReplaceAll(s, ",", ".")
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 {
		return 0
	}
	return int64(math.Round(f * 100))
}
