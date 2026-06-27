package winmsix

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ParseAppxManifest walks one AppxManifest.xml body and returns a
// populated Package (without FilePath / PackageDir / install_scope
// fields — those are stamped by the collector). The XML is
// namespace-heavy (foundation, uap, rescap, etc.); we parse with
// xml.Decoder.Strict=false and match elements by local name so a
// `<rescap:Capability>` resolves the same as `<Capability>`.
func ParseAppxManifest(body []byte) (Package, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return Package{}, fmt.Errorf("empty manifest")
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	dec.Entity = xml.HTMLEntity

	out := Package{}
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return Package{}, fmt.Errorf("xml token: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "Identity":
			fillIdentity(&out, start.Attr)
		case "Properties":
			if err := walkProperties(dec, &out); err != nil {
				return Package{}, err
			}
		case "Application":
			out.ApplicationCount++
			if out.PrimaryExecutable == "" {
				if v := attrValue(start.Attr, "Executable"); v != "" {
					out.PrimaryExecutable = v
				}
			}
		case "Capability":
			if name := attrValue(start.Attr, "Name"); name != "" {
				out.Capabilities = append(out.Capabilities, qualifiedName(start, name))
			}
		}
	}
	AnnotateSecurity(&out)
	return out, nil
}

// walkProperties consumes the body of `<Properties>` and harvests
// the DisplayName / PublisherDisplayName scalar text. Other
// children (Logo, Description, etc.) flow past.
func walkProperties(dec *xml.Decoder, out *Package) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("xml token: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			body, _ := readCharData(dec)
			switch t.Name.Local {
			case "DisplayName":
				out.DisplayName = strings.TrimSpace(body)
			case "PublisherDisplayName":
				out.PublisherDisplayName = strings.TrimSpace(body)
			}
		case xml.EndElement:
			if t.Name.Local == "Properties" {
				return nil
			}
		}
	}
}

// readCharData returns the accumulated character data inside the
// current element and consumes the matching end tag.
func readCharData(dec *xml.Decoder) (string, error) {
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return sb.String(), fmt.Errorf("xml token: %w", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.EndElement:
			return sb.String(), nil
		}
	}
}

func fillIdentity(out *Package, attrs []xml.Attr) {
	out.IdentityName = attrValue(attrs, "Name")
	out.IdentityVersion = attrValue(attrs, "Version")
	out.IdentityPublisher = attrValue(attrs, "Publisher")
	out.IdentityArchitecture = attrValue(attrs, "ProcessorArchitecture")
}

// attrValue returns the value of the first attribute whose local
// name matches `local` (case-insensitive). Returns "" when absent.
func attrValue(attrs []xml.Attr, local string) string {
	for _, a := range attrs {
		if strings.EqualFold(a.Name.Local, local) {
			return strings.TrimSpace(a.Value)
		}
	}
	return ""
}

// qualifiedName returns `<namespace-prefix>:<name>` when the
// element name carries a namespace; otherwise `name` unchanged.
// We use it so AnnotateSecurity can distinguish `rescap:` from
// the bare capability namespace (both legal, the latter for the
// foundation Capability element).
func qualifiedName(start xml.StartElement, name string) string {
	if start.Name.Space != "" {
		// Map well-known namespace URIs to their canonical short
		// prefix. The Decoder strips xmlns: prefixes when
		// Strict=false; we re-attach the rescap: marker when we
		// recognise the URI.
		ns := strings.ToLower(start.Name.Space)
		if strings.Contains(ns, "restrictedcapabilities") {
			return "rescap:" + name
		}
		if strings.Contains(ns, "/uap/") {
			return "uap:" + name
		}
	}
	return name
}
