package winafipsicore

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"math"
	"strconv"
	"strings"
)

// SicoreSummary captures aggregate stats from a SICORE file.
type SicoreSummary struct {
	AgentCuitRaw               string
	Period                     string
	RegimenHint                string
	RetainedCount              int64
	NaturalPersonRetainedCount int64
	MaxRetentionARSCents       int64
	TotalRetentionARSCents     int64
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

// ParseSicore extracts aggregate stats from a SICORE body.
// Handles XML (F744), CSV (retenciones detail), and SICORE
// fixed-width DDJJ dumps via a best-effort line scan.
func ParseSicore(body []byte) (SicoreSummary, bool) {
	var out SicoreSummary
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

func hasAny(s SicoreSummary) bool {
	return s.AgentCuitRaw != "" || s.Period != "" || s.RegimenHint != "" ||
		s.RetainedCount > 0 || s.TotalRetentionARSCents > 0
}

// scanLines walks each line, counting retained CUITs and
// summing the rightmost numeric column it can find. This
// covers CSV, fixed-width SICORE, and pipe-delimited SIRE.
func scanLines(body []byte, out *SicoreSummary) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Skip header lines that look like column names.
		if isHeaderLine(line) {
			continue
		}
		// Skip agent / period / regimen meta lines — those CUITs
		// belong to the agent, not to retained parties.
		if isAgentMetaLine(line) {
			continue
		}
		processed := false
		if prefix, _ := CuitFingerprint(line); prefix != "" {
			out.RetainedCount++
			processed = true
			if IsNaturalPersonPrefix(prefix) {
				out.NaturalPersonRetainedCount++
			}
		}
		// Pull rightmost ARS-looking decimal.
		if processed {
			if cents := rightmostARSCents(line); cents > 0 {
				out.TotalRetentionARSCents += cents
				if cents > out.MaxRetentionARSCents {
					out.MaxRetentionARSCents = cents
				}
			}
		}
	}
}

// isAgentMetaLine reports whether the line carries the agent's
// own CUIT (cuit_agente / cuit_emisor / agente_cuit). Such
// lines must not be counted as retained-party rows.
func isAgentMetaLine(line string) bool {
	l := strings.ToLower(line)
	for _, tok := range []string{
		"cuit_agente", "cuitagente", "agente_cuit",
		"cuit_emisor", "cuitemisor", "cuit del agente",
	} {
		if strings.Contains(l, tok) {
			return true
		}
	}
	return false
}

func isHeaderLine(line string) bool {
	l := strings.ToLower(line)
	// Treat any line without a digit as a header.
	hasDigit := false
	for _, c := range line {
		if c >= '0' && c <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return true
	}
	// Common CSV header tokens (only true headers — *bare*
	// column-name lines without any data digits anyway).
	_ = l
	return false
}

// rightmostARSCents extracts the trailing decimal number from
// a line.
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
	// Reject pure integers that look like CUITs (11 digits) or
	// periods (6/8 digits).
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

// -- XML ---------------------------------------------------------

func walkXML(nodes []genericNode, out *SicoreSummary) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "cuit_agente", "cuitagente", "agente_cuit":
			if out.AgentCuitRaw == "" && val != "" {
				out.AgentCuitRaw = val
			}
		case "periodo", "periodo_fiscal", "period":
			if out.Period == "" && val != "" {
				out.Period = val
			}
		case "regimen", "regimen_retencion", "codigo_regimen":
			if out.RegimenHint == "" && val != "" {
				out.RegimenHint = val
			}
		case "detalle", "retencion":
			processDetalle(n, out)
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

// processDetalle walks a single <detalle> / <retencion> block,
// extracting the retained CUIT and the importe.
func processDetalle(n genericNode, out *SicoreSummary) {
	var (
		cuitRaw    string
		importeRaw string
	)
	var walk func(nodes []genericNode)
	walk = func(nodes []genericNode) {
		for _, c := range nodes {
			cn := strings.ToLower(c.XMLName.Local)
			cv := strings.TrimSpace(c.Value)
			switch cn {
			case "cuit_retenido", "cuitretenido", "retenido":
				if cuitRaw == "" && cv != "" {
					cuitRaw = cv
				}
			case "importe", "monto", "importe_retencion":
				if importeRaw == "" && cv != "" {
					importeRaw = cv
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
	out.RetainedCount++
	if prefix, _ := CuitFingerprint(cuitRaw); IsNaturalPersonPrefix(prefix) {
		out.NaturalPersonRetainedCount++
	}
	if cents := decimalToCents(importeRaw); cents > 0 {
		out.TotalRetentionARSCents += cents
		if cents > out.MaxRetentionARSCents {
			out.MaxRetentionARSCents = cents
		}
	}
}
