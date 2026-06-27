package winofficec2r

import (
	"bytes"
	"encoding/xml"
	"strings"
)

// ConfigurationFields captures Configuration.xml metadata.
type ConfigurationFields struct {
	Properties          map[string]string
	Channel             string
	OfficeClientEdition string
	Products            []string
	Languages           []string
	ExcludedApps        []string
}

// configurationXML models the Office Deployment Tool
// Configuration.xml schema.
type configurationXML struct {
	XMLName xml.Name     `xml:"Configuration"`
	Add     configAdd    `xml:"Add"`
	Props   []configProp `xml:"Property"`
}

type configAdd struct {
	OfficeClientEdition string          `xml:"OfficeClientEdition,attr"`
	Channel             string          `xml:"Channel,attr"`
	Products            []configProduct `xml:"Product"`
}

type configProduct struct {
	ID          string             `xml:"ID,attr"`
	Languages   []configLanguage   `xml:"Language"`
	ExcludeApps []configExcludeApp `xml:"ExcludeApp"`
}

type configLanguage struct {
	ID string `xml:"ID,attr"`
}

type configExcludeApp struct {
	ID string `xml:"ID,attr"`
}

type configProp struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:"Value,attr"`
}

// ParseConfiguration extracts ConfigurationFields from a
// Configuration.xml body.
func ParseConfiguration(body []byte) (ConfigurationFields, bool) {
	var out ConfigurationFields
	out.Properties = map[string]string{}
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '<' {
		return out, false
	}
	var doc configurationXML
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	if err := dec.Decode(&doc); err != nil {
		return out, false
	}
	out.Channel = strings.TrimSpace(doc.Add.Channel)
	out.OfficeClientEdition = strings.TrimSpace(doc.Add.OfficeClientEdition)
	langSet := make(map[string]struct{})
	exclSet := make(map[string]struct{})
	for _, p := range doc.Add.Products {
		if id := strings.TrimSpace(p.ID); id != "" {
			out.Products = append(out.Products, id)
		}
		for _, l := range p.Languages {
			if id := strings.TrimSpace(l.ID); id != "" {
				langSet[id] = struct{}{}
			}
		}
		for _, e := range p.ExcludeApps {
			if id := strings.TrimSpace(e.ID); id != "" {
				exclSet[id] = struct{}{}
			}
		}
	}
	for k := range langSet {
		out.Languages = append(out.Languages, k)
	}
	for k := range exclSet {
		out.ExcludedApps = append(out.ExcludedApps, k)
	}
	for _, p := range doc.Props {
		out.Properties[strings.TrimSpace(p.Name)] = strings.TrimSpace(p.Value)
	}
	if !configHasAny(out) {
		return out, false
	}
	return out, true
}

func configHasAny(f ConfigurationFields) bool {
	return f.Channel != "" || f.OfficeClientEdition != "" ||
		len(f.Products) > 0 || len(f.Languages) > 0 ||
		len(f.ExcludedApps) > 0 || len(f.Properties) > 0
}

// HasSharedComputerLicensingFromProps reports whether the
// SharedComputerLicensing property is set to "1" / "true".
func HasSharedComputerLicensingFromProps(props map[string]string) bool {
	for k, v := range props {
		if strings.EqualFold(k, "SharedComputerLicensing") {
			v = strings.ToLower(strings.TrimSpace(v))
			return v == "1" || v == "true" || v == "yes"
		}
	}
	return false
}
