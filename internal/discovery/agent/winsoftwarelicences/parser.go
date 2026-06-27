package winsoftwarelicences

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
)

// LicenceFields captures scalar metadata the audit pipeline
// needs.
type LicenceFields struct {
	ProductTitle   string
	Publisher      string
	ProductURL     string
	InstallDate    string
	ExpiryDate     string
	LicenseType    LicenseType
	LicenseKeyRaw  string
	LicensePurpose string
}

// ParseLicence extracts metadata from a licence file body.
// Handles JSON, XML, plist, and free-form text licence files.
// Returns ok=false on empty / unparseable input that yields
// no fields at all.
func ParseLicence(body []byte) (LicenceFields, bool) {
	var out LicenceFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}
	switch trimmed[0] {
	case '{', '[':
		parseJSON(body, &out)
	case '<':
		parseXML(body, &out)
	default:
		parseText(body, &out)
	}
	// Final URL + key + type from raw text always.
	if out.ProductURL == "" {
		out.ProductURL = ProductURLFromText(string(body))
	}
	if out.LicenseKeyRaw == "" {
		out.LicenseKeyRaw = ExtractLicenseKey(string(body))
	}
	if out.LicenseType == "" || out.LicenseType == LicenseUnknown {
		out.LicenseType = ClassifyLicenseTypeFromText(string(body))
	}
	if out.ExpiryDate == "" {
		out.ExpiryDate = ExpiryDateFromText(string(body))
	}
	if !hasAny(out) {
		return out, false
	}
	return out, true
}

func hasAny(f LicenceFields) bool {
	return f.ProductTitle != "" || f.Publisher != "" ||
		f.ProductURL != "" || f.InstallDate != "" ||
		f.ExpiryDate != "" || f.LicenseType != "" ||
		f.LicenseKeyRaw != "" || f.LicensePurpose != ""
}

// jsonLicence is the canonical shape commonly used by vendor
// licence JSON files.
type jsonLicence struct {
	ProductTitle string `json:"product_title,omitempty"`
	Product      string `json:"product,omitempty"`
	Name         string `json:"name,omitempty"`
	Title        string `json:"title,omitempty"`
	Publisher    string `json:"publisher,omitempty"`
	Vendor       string `json:"vendor,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	URL          string `json:"url,omitempty"`
	ProductURL   string `json:"product_url,omitempty"`
	Website      string `json:"website,omitempty"`
	InstallDate  string `json:"install_date,omitempty"`
	Installed    string `json:"installed,omitempty"`
	ExpiryDate   string `json:"expiry,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	ValidUntil   string `json:"valid_until,omitempty"`
	LicenseType  string `json:"license_type,omitempty"`
	Type         string `json:"type,omitempty"`
	License      string `json:"license,omitempty"`
	LicenseKey   string `json:"license_key,omitempty"`
	Key          string `json:"key,omitempty"`
	Serial       string `json:"serial,omitempty"`
	Purpose      string `json:"purpose,omitempty"`
	Description  string `json:"description,omitempty"`
}

func parseJSON(body []byte, out *LicenceFields) {
	var doc jsonLicence
	if err := json.Unmarshal(body, &doc); err != nil {
		return
	}
	out.ProductTitle = firstNonEmpty(doc.ProductTitle, doc.Product, doc.Title, doc.Name)
	out.Publisher = firstNonEmpty(doc.Publisher, doc.Vendor, doc.Manufacturer)
	out.ProductURL = firstNonEmpty(doc.ProductURL, doc.URL, doc.Website)
	out.InstallDate = firstNonEmpty(doc.InstallDate, doc.Installed)
	out.ExpiryDate = firstNonEmpty(doc.ExpiryDate, doc.ExpiresAt, doc.ValidUntil)
	out.LicenseType = mapLicenseTypeString(firstNonEmpty(doc.LicenseType, doc.Type, doc.License))
	out.LicenseKeyRaw = firstNonEmpty(doc.LicenseKey, doc.Key, doc.Serial)
	out.LicensePurpose = firstNonEmpty(doc.Purpose, doc.Description)
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

func parseXML(body []byte, out *LicenceFields) {
	var env xmlEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return
	}
	walkXML(env.Children, out)
}

func walkXML(nodes []genericNode, out *LicenceFields) {
	for _, n := range nodes {
		name := strings.ToLower(n.XMLName.Local)
		val := strings.TrimSpace(n.Value)
		switch name {
		case "product", "product_title", "title", "name":
			if out.ProductTitle == "" && val != "" {
				out.ProductTitle = val
			}
		case "publisher", "vendor", "manufacturer":
			if out.Publisher == "" && val != "" {
				out.Publisher = val
			}
		case "url", "product_url", "website":
			if out.ProductURL == "" && val != "" {
				out.ProductURL = val
			}
		case "install_date", "installed":
			if out.InstallDate == "" && val != "" {
				out.InstallDate = val
			}
		case "expiry", "expires_at", "valid_until":
			if out.ExpiryDate == "" && val != "" {
				out.ExpiryDate = val
			}
		case "license_type", "type", "license":
			if (out.LicenseType == "" || out.LicenseType == LicenseUnknown) && val != "" {
				out.LicenseType = mapLicenseTypeString(val)
			}
		case "license_key", "key", "serial":
			if out.LicenseKeyRaw == "" && val != "" {
				out.LicenseKeyRaw = val
			}
		case "purpose", "description":
			if out.LicensePurpose == "" && val != "" {
				out.LicensePurpose = val
			}
		}
		if len(n.Children) > 0 {
			walkXML(n.Children, out)
		}
	}
}

func parseText(body []byte, out *LicenceFields) {
	text := string(body)
	out.LicenseType = ClassifyLicenseTypeFromText(text)
	// First non-empty short line is often the product/header.
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		if len(l) > 0 && len(l) < 200 {
			if out.ProductTitle == "" &&
				!strings.HasPrefix(strings.ToLower(l), "copyright") &&
				!strings.HasPrefix(strings.ToLower(l), "license") {
				out.ProductTitle = l
				break
			}
		}
	}
	// Copyright N+ "Publisher" pattern.
	if out.Publisher == "" {
		if idx := strings.Index(strings.ToLower(text), "copyright"); idx >= 0 {
			rest := text[idx:]
			if eol := strings.IndexAny(rest, "\n\r"); eol > 0 {
				rest = rest[:eol]
			}
			// Heuristic: split into tokens, take alphanumeric suffix.
			tokens := strings.Fields(rest)
			if len(tokens) > 1 {
				cand := tokens[len(tokens)-1]
				cand = strings.Trim(cand, ".,;:'\"()")
				if cand != "" && !isYear(cand) {
					out.Publisher = cand
				}
			}
		}
	}
	if out.InstallDate == "" {
		out.InstallDate = FirstDateFromText(text)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func mapLicenseTypeString(s string) LicenseType {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "":
		return LicenseUnknown
	case "perpetual":
		return LicensePerpetual
	case "subscription":
		return LicenseSubscription
	case "mit":
		return LicenseOSSMIT
	case "apache", "apache-2.0", "apache 2.0":
		return LicenseOSSApache
	case "bsd", "bsd-3-clause", "bsd-2-clause":
		return LicenseOSSBSD
	case "gpl", "gpl-3.0", "gpl-2.0":
		return LicenseOSSGPL
	case "lgpl", "lgpl-3.0":
		return LicenseOSSLGPL
	case "mpl", "mpl-2.0":
		return LicenseOSSMPL
	case "freeware", "free":
		return LicenseFreeware
	case "trial":
		return LicenseTrial
	case "evaluation":
		return LicenseEvaluation
	case "oem":
		return LicenseOEM
	case "enterprise":
		return LicenseEnterprise
	}
	return LicenseOther
}

func isYear(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 4 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
