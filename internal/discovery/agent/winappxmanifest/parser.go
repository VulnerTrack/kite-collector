package winappxmanifest

import (
	"bytes"
	"encoding/xml"
	"strings"
)

// AppxManifestFields captures AppxManifest.xml metadata.
type AppxManifestFields struct {
	PackageName          string
	PackagePublisher     string // CN-stripped
	Version              string
	DisplayName          string
	PublisherDisplayName string
	Description          string
	LogoPath             string
	Capabilities         []string
}

// appxPackage models the top-level <Package> element of an
// AppxManifest. We capture only the elements we need; Go's
// encoding/xml is namespace-tolerant when the XMLName uses
// just the local name.
type appxPackage struct {
	XMLName      xml.Name       `xml:"Package"`
	Identity     appxIdentity   `xml:"Identity"`
	Properties   appxProperties `xml:"Properties"`
	Capabilities appxCapBlock   `xml:"Capabilities"`
}

type appxIdentity struct {
	Name      string `xml:"Name,attr"`
	Publisher string `xml:"Publisher,attr"`
	Version   string `xml:"Version,attr"`
}

type appxProperties struct {
	DisplayName          string `xml:"DisplayName"`
	PublisherDisplayName string `xml:"PublisherDisplayName"`
	Description          string `xml:"Description"`
	Logo                 string `xml:"Logo"`
}

type appxCapBlock struct {
	Capabilities       []appxCap `xml:"Capability"`
	DeviceCapabilities []appxCap `xml:"DeviceCapability"`
	UAPCapabilities    []appxCap `xml:"uap:Capability"`
}

type appxCap struct {
	Name string `xml:"Name,attr"`
}

// ParseAppxManifest extracts AppxManifestFields from an XML
// body. Returns ok=false on empty / non-XML input.
func ParseAppxManifest(body []byte) (AppxManifestFields, bool) {
	var out AppxManifestFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '<' {
		return out, false
	}
	var doc appxPackage
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	if err := dec.Decode(&doc); err != nil {
		return out, false
	}
	out.PackageName = strings.TrimSpace(doc.Identity.Name)
	out.PackagePublisher = PublisherCN(doc.Identity.Publisher)
	out.Version = strings.TrimSpace(doc.Identity.Version)
	out.DisplayName = strings.TrimSpace(doc.Properties.DisplayName)
	out.PublisherDisplayName = strings.TrimSpace(doc.Properties.PublisherDisplayName)
	out.Description = strings.TrimSpace(doc.Properties.Description)
	out.LogoPath = strings.TrimSpace(doc.Properties.Logo)
	caps := make(map[string]struct{})
	for _, c := range doc.Capabilities.Capabilities {
		if v := strings.TrimSpace(c.Name); v != "" {
			caps[v] = struct{}{}
		}
	}
	for _, c := range doc.Capabilities.DeviceCapabilities {
		if v := strings.TrimSpace(c.Name); v != "" {
			caps[v] = struct{}{}
		}
	}
	for _, c := range doc.Capabilities.UAPCapabilities {
		if v := strings.TrimSpace(c.Name); v != "" {
			caps[v] = struct{}{}
		}
	}
	// Manifests may use namespaced elements that the
	// fixed-field unmarshal misses (e.g.
	// `<rescap:Capability Name="...">`). Fall back to a
	// permissive scan over the raw body to catch them.
	caps = mergeCapsFromBody(body, caps)
	for name := range caps {
		out.Capabilities = append(out.Capabilities, name)
	}
	if !hasAny(out) {
		return out, false
	}
	return out, true
}

// mergeCapsFromBody scans the raw XML for Capability /
// DeviceCapability elements regardless of namespace prefix
// and adds any Name= attribute value to the set.
func mergeCapsFromBody(body []byte, set map[string]struct{}) map[string]struct{} {
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		local := se.Name.Local
		if local != "Capability" && local != "DeviceCapability" {
			continue
		}
		for _, attr := range se.Attr {
			if strings.EqualFold(attr.Name.Local, "Name") {
				if v := strings.TrimSpace(attr.Value); v != "" {
					set[v] = struct{}{}
				}
			}
		}
	}
	return set
}

func hasAny(f AppxManifestFields) bool {
	return f.PackageName != "" || f.PackagePublisher != "" ||
		f.Version != "" || f.DisplayName != "" ||
		f.PublisherDisplayName != "" || f.Description != "" ||
		f.LogoPath != "" || len(f.Capabilities) > 0
}
