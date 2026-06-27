package winafipcae

import (
	"bytes"
	"encoding/xml"
	"math"
	"strconv"
	"strings"
)

// caeDoc captures the FECAESolicitarResult shape returned by
// WSFEv1. Real WSFE responses are deeply nested SOAP envelopes;
// most SDKs persist the inner FECAEDetResponse element as a
// stand-alone XML. We accept either form by scanning for the
// relevant leaf elements regardless of namespace.
type caeDoc struct {
	XMLName xml.Name
	Token   []xmlField `xml:",any"`
}

// xmlField is a generic leaf-or-branch accumulator that
// preserves element names without requiring fixed schema.
type xmlField struct {
	XMLName  xml.Name
	Value    string     `xml:",chardata"`
	Children []xmlField `xml:",any"`
}

// scalars collects the fields the audit pipeline needs.
type scalars struct {
	CAE            string
	CAEVencimiento string
	CbteTipo       string
	CbteFch        string
	PtoVta         string
	CbteNro        string
	DocTipo        string
	DocNro         string
	ImpTotal       string
	MonID          string
}

// ParseCAEReceipt extracts the scalar fields the collector
// needs. Returns ok=false if the body does not look like an
// AFIP CAE receipt (no `<CAE>` and no `<FECAEDetResponse>`
// shape encountered).
func ParseCAEReceipt(body []byte) (Receipt, bool) {
	var out Receipt
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	var doc caeDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		return out, false
	}

	s := scalars{}
	walkXML(doc.Token, &s)

	// CAE alone isn't required (some receipts cache pre-auth
	// state); but if we found nothing at all that looks like a
	// receipt, reject.
	if s.CAE == "" && s.CbteNro == "" && s.PtoVta == "" {
		return out, false
	}

	out.CaeCode = strings.TrimSpace(s.CAE)
	out.CaeVencimiento = strings.TrimSpace(s.CAEVencimiento)
	out.CbteTipo, _ = strconv.Atoi(strings.TrimSpace(s.CbteTipo))
	out.CbteFch = strings.TrimSpace(s.CbteFch)
	out.PtoVta, _ = strconv.Atoi(strings.TrimSpace(s.PtoVta))
	out.CbteNro, _ = strconv.Atoi(strings.TrimSpace(s.CbteNro))
	out.DocTipo, _ = strconv.Atoi(strings.TrimSpace(s.DocTipo))
	out.DocNroSuffix4 = Suffix4(s.DocNro)
	out.ImpTotalCents = arsToCents(strings.TrimSpace(s.ImpTotal))
	out.MonID = strings.ToUpper(strings.TrimSpace(s.MonID))
	out.DocTipoLabel = DocTipoLabelFromCode(out.DocTipo)
	return out, true
}

// walkXML recursively collects the fields we care about,
// matching on local element name (case-insensitive) so
// SOAP-wrapped + bare receipts both work.
func walkXML(fields []xmlField, s *scalars) {
	for _, f := range fields {
		name := strings.ToLower(f.XMLName.Local)
		val := strings.TrimSpace(f.Value)
		switch name {
		case "cae":
			if s.CAE == "" {
				s.CAE = val
			}
		case "caefchvto", "caevencimiento", "fchvto":
			if s.CAEVencimiento == "" {
				s.CAEVencimiento = val
			}
		case "cbtetipo":
			if s.CbteTipo == "" {
				s.CbteTipo = val
			}
		case "cbtefch":
			if s.CbteFch == "" {
				s.CbteFch = val
			}
		case "ptovta":
			if s.PtoVta == "" {
				s.PtoVta = val
			}
		case "cbtedesde", "cbtenro":
			if s.CbteNro == "" {
				s.CbteNro = val
			}
		case "doctipo":
			if s.DocTipo == "" {
				s.DocTipo = val
			}
		case "docnro":
			if s.DocNro == "" {
				s.DocNro = val
			}
		case "imptotal":
			if s.ImpTotal == "" {
				s.ImpTotal = val
			}
		case "monid":
			if s.MonID == "" {
				s.MonID = val
			}
		}
		if len(f.Children) > 0 {
			walkXML(f.Children, s)
		}
	}
}

// arsToCents parses an AFIP money string (decimal point, up to
// 2 fractional digits) into integer cents. "1234.56" → 123456.
// Empty/malformed → 0.
func arsToCents(s string) int64 {
	v := strings.TrimSpace(s)
	if v == "" {
		return 0
	}
	v = strings.ReplaceAll(v, ",", ".")
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return int64(math.Round(f * 100))
}
