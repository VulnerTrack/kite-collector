package winargxbrl

import (
	"bytes"
	"encoding/xml"
	"strings"
)

// XBRL grammar (subset we care about):
//
//	<xbrli:xbrl
//	  xmlns:xbrli="http://www.xbrl.org/2003/instance"
//	  xmlns:link="http://www.xbrl.org/2003/linkbase"
//	  xmlns:xlink="http://www.w3.org/1999/xlink">
//	  <link:schemaRef xlink:href="https://aif.cnv.gov.ar/.../cnv-aif.xsd"/>
//	  <xbrli:context id="C-2026">
//	    <xbrli:entity>
//	      <xbrli:identifier scheme="http://www.cnv.gov.ar/cuit">30712345678</xbrli:identifier>
//	      <xbrli:segment>...</xbrli:segment>
//	    </xbrli:entity>
//	    <xbrli:period>
//	      <xbrli:startDate>2025-01-01</xbrli:startDate>
//	      <xbrli:endDate>2025-12-31</xbrli:endDate>
//	    </xbrli:period>
//	  </xbrli:context>
//	  <xbrli:unit id="U-ARS">
//	    <xbrli:measure>iso4217:ARS</xbrli:measure>
//	  </xbrli:unit>
//	  <ar-ifrs:EntityRegistrantName contextRef="C-2026">ACME S.A.</ar-ifrs:EntityRegistrantName>
//	  <ar-ifrs:Equity contextRef="C-2026" unitRef="U-ARS" decimals="0">...</ar-ifrs:Equity>
//	</xbrli:xbrl>
//
// We accept any namespace prefix — the walker matches on local
// element names.

type genericNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr    `xml:",any,attr"`
	Value    string        `xml:",chardata"`
	Children []genericNode `xml:",any"`
}

type xbrlRoot struct {
	XMLName  xml.Name
	Attrs    []xml.Attr    `xml:",any,attr"`
	Children []genericNode `xml:",any"`
}

// ParseXBRLInstance extracts the metadata the audit pipeline
// needs. Returns ok=false if the body does not look like an
// XBRL instance.
func ParseXBRLInstance(body []byte) (Filing, bool) {
	var out Filing
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	var root xbrlRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return out, false
	}
	if strings.ToLower(root.XMLName.Local) != "xbrl" {
		return out, false
	}

	st := &xbrlState{}
	for i := range root.Children {
		walkXBRL(&root.Children[i], st)
	}

	out.FilingKind = FilingXBRLInstance
	out.TaxonomyLabel = st.taxonomyFromSchemaRefs()
	out.PeriodStart = st.firstStart
	out.PeriodEnd = st.lastEnd
	out.ReportingCurrency = st.firstNonEmptyCurrency()
	out.FactCount = st.factCount
	out.EntityDenominacion = TruncateDenominacion(st.entityName)
	if st.cuitRaw != "" {
		out.EntityCuitPrefix, out.EntityCuitSuffix4 = CuitFingerprint(st.cuitRaw)
	}
	return out, true
}

type xbrlState struct {
	cuitRaw    string
	firstStart string
	lastEnd    string
	entityName string
	schemaRefs []string
	currencies []string
	factCount  int
}

func (s *xbrlState) firstNonEmptyCurrency() string {
	for _, c := range s.currencies {
		if c != "" {
			return c
		}
	}
	return ""
}

func (s *xbrlState) taxonomyFromSchemaRefs() TaxonomyLabel {
	for _, u := range s.schemaRefs {
		if lbl := TaxonomyLabelFromSchemaRef(u); lbl != TaxonomyUnknown && lbl != TaxonomyOther {
			return lbl
		}
	}
	if len(s.schemaRefs) > 0 {
		return TaxonomyLabelFromSchemaRef(s.schemaRefs[0])
	}
	return TaxonomyUnknown
}

func walkXBRL(node *genericNode, st *xbrlState) {
	name := strings.ToLower(node.XMLName.Local)
	val := strings.TrimSpace(node.Value)

	switch name {
	case "schemaref":
		if href := findAttr(node.Attrs, "href"); href != "" {
			st.schemaRefs = append(st.schemaRefs, href)
		}
	case "identifier":
		if st.cuitRaw == "" && val != "" {
			st.cuitRaw = val
		}
	case "startdate":
		if st.firstStart == "" {
			st.firstStart = val
		}
	case "enddate":
		st.lastEnd = val
	case "measure":
		cur := CurrencyFromMeasure(val)
		if cur != "" {
			st.currencies = append(st.currencies, cur)
		}
	case "entityregistrantname", "denominacion", "denominacionlegal", "nombrelegal":
		if st.entityName == "" {
			st.entityName = val
		}
	}

	// Any leaf with a contextRef + chardata counts as a fact.
	if len(node.Children) == 0 && val != "" {
		if findAttr(node.Attrs, "contextRef") != "" || findAttr(node.Attrs, "contextref") != "" {
			st.factCount++
		}
	}

	for i := range node.Children {
		walkXBRL(&node.Children[i], st)
	}
}

func findAttr(attrs []xml.Attr, local string) string {
	target := strings.ToLower(local)
	for _, a := range attrs {
		if strings.EqualFold(a.Name.Local, target) {
			return a.Value
		}
	}
	return ""
}
