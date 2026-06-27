package winafipciti

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// CITISummary captures aggregate stats from a CITI body.
type CITISummary struct {
	DeclarantCuitRaw               string
	Period                         string
	CounterpartyCount              int64
	NaturalPersonCounterpartyCount int64
	TotalNetoCents                 int64
	TotalIVACents                  int64
	MaxInvoiceCents                int64
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

// ParseCITI extracts aggregate stats from a CITI body. CITI
// Compras/Ventas are typically fixed-width or pipe-delimited
// .txt — handled by line scan. F2002 is XML — handled by
// the XML walker.
func ParseCITI(body []byte) (CITISummary, bool) {
	var out CITISummary
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
	} else {
		scanLines(body, &out)
	}
	if !hasAny(out) {
		return out, false
	}
	return out, true
}

func hasAny(s CITISummary) bool {
	return s.DeclarantCuitRaw != "" || s.Period != "" ||
		s.CounterpartyCount > 0 || s.TotalNetoCents > 0
}

// scanLines walks each line, counts CUITs and sums the
// rightmost numeric column.
func scanLines(body []byte, out *CITISummary) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if isHeaderOnlyLine(line) {
			continue
		}
		if isDeclarantMetaLine(line) {
			if out.DeclarantCuitRaw == "" {
				if _, _ = CuitFingerprint(line); true {
					// Capture raw 11-digit CUIT if present.
					if raw := first11Digits(line); raw != "" {
						out.DeclarantCuitRaw = raw
					}
				}
			}
			continue
		}
		if prefix, _ := CuitFingerprint(line); prefix != "" {
			out.CounterpartyCount++
			if IsNaturalPersonPrefix(prefix) {
				out.NaturalPersonCounterpartyCount++
			}
			if cents := rightmostARSCents(line); cents > 0 {
				out.TotalNetoCents += cents
				if cents > out.MaxInvoiceCents {
					out.MaxInvoiceCents = cents
				}
			}
		}
	}
}

func isHeaderOnlyLine(line string) bool {
	hasDigit := false
	for _, c := range line {
		if c >= '0' && c <= '9' {
			hasDigit = true
			break
		}
	}
	return !hasDigit
}

func isDeclarantMetaLine(line string) bool {
	l := strings.ToLower(line)
	for _, tok := range []string{
		"cuit_declarante", "cuitdeclarante",
		"cuit_informante", "cuit informante",
		"cuit_titular", "cuittitular",
		"cuit_emisor", "cuit del declarante",
	} {
		if strings.Contains(l, tok) {
			return true
		}
	}
	return false
}

var elevenDigitsRE = regexp.MustCompile(`(\d{11})`)

func first11Digits(line string) string {
	m := elevenDigitsRE.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	return m[1]
}

func rightmostARSCents(line string) int64 {
	parts := strings.FieldsFunc(line, func(r rune) bool {
		switch r {
		case ',', ';', '|', '\t', ' ':
			return true
		}
		return false
	})
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if cents := decimalToCents(p); cents > 0 {
			return cents
		}
	}
	return 0
}

func decimalToCents(s string) int64 {
	s = strings.ReplaceAll(s, "$", "")
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// Reject pure integers that look like CUITs or periods.
	if !strings.ContainsAny(s, ".,") {
		if len(s) >= 6 {
			return 0
		}
	}
	s = strings.ReplaceAll(s, ",", ".")
	f, err := strconv.ParseFloat(s, 64)
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

// walkXML handles F2002 IVA XML.
func walkXML(nodes []genericNode, out *CITISummary) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuit_declarante", "cuitdeclarante", "cuit_titular":
			if out.DeclarantCuitRaw == "" && val != "" {
				out.DeclarantCuitRaw = val
			}
		case "periodo", "periodo_fiscal":
			if out.Period == "" && val != "" {
				out.Period = val
			}
		case "comprobante", "operacion", "factura":
			processComprobante(n, out)
		case "neto_total", "neto_gravado", "monto_neto":
			if cents := decimalToCents(val); cents > 0 {
				out.TotalNetoCents += cents
			}
		case "iva_total", "monto_iva":
			if cents := decimalToCents(val); cents > 0 {
				out.TotalIVACents += cents
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

func processComprobante(n genericNode, out *CITISummary) {
	var cuitRaw, importeRaw, ivaRaw string
	var walk func(nodes []genericNode)
	walk = func(nodes []genericNode) {
		for _, c := range nodes {
			cn := strings.ToLower(c.XMLName.Local)
			cv := strings.TrimSpace(c.Value)
			switch cn {
			case "cuit_contraparte", "cuit_cliente",
				"cuit_proveedor", "cuit":
				if cuitRaw == "" && cv != "" {
					cuitRaw = cv
				}
			case "importe_neto", "neto", "monto":
				if importeRaw == "" && cv != "" {
					importeRaw = cv
				}
			case "iva", "importe_iva":
				if ivaRaw == "" && cv != "" {
					ivaRaw = cv
				}
			}
			if len(c.Children) > 0 {
				walk(c.Children)
			}
		}
	}
	walk(n.Children)
	if cuitRaw == "" {
		return
	}
	out.CounterpartyCount++
	if prefix, _ := CuitFingerprint(cuitRaw); IsNaturalPersonPrefix(prefix) {
		out.NaturalPersonCounterpartyCount++
	}
	if cents := decimalToCents(importeRaw); cents > 0 {
		out.TotalNetoCents += cents
		if cents > out.MaxInvoiceCents {
			out.MaxInvoiceCents = cents
		}
	}
	if cents := decimalToCents(ivaRaw); cents > 0 {
		out.TotalIVACents += cents
	}
}
