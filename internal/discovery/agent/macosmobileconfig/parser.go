package macosmobileconfig

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// ProfileFields captures top-level Configuration profile
// metadata plus an enumeration of the PayloadType values
// found in PayloadContent sub-payloads.
type ProfileFields struct {
	PayloadIdentifier   string
	PayloadDisplayName  string
	PayloadOrganization string
	PayloadUUID         string
	PayloadDescription  string
	PayloadVersion      string
	SubPayloadTypes     []string
}

// ParseMobileconfig walks an XML-form .mobileconfig / plist
// body and extracts ProfileFields. PKCS#7-wrapped signed
// profiles are out of scope (the inner XML payload requires
// CMS unwrapping before parsing) — those are recorded with
// hash-only by the collector. Returns ok=false on empty /
// non-XML / binary-plist input.
func ParseMobileconfig(body []byte) (ProfileFields, bool) {
	var out ProfileFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}
	if bytes.HasPrefix(trimmed, []byte("bplist")) {
		return out, false
	}
	if trimmed[0] != '<' {
		return out, false
	}
	if err := walkTokens(body, &out); err != nil {
		return out, false
	}
	if !hasAny(out) {
		return out, false
	}
	return out, true
}

func hasAny(f ProfileFields) bool {
	return f.PayloadIdentifier != "" || f.PayloadDisplayName != "" ||
		f.PayloadOrganization != "" || f.PayloadUUID != "" ||
		f.PayloadDescription != "" || f.PayloadVersion != "" ||
		len(f.SubPayloadTypes) > 0
}

// walkTokens iterates the plist's XML token stream. It pairs
// each <key>NAME</key> with the immediately following sibling
// value element (string/integer/array/dict/true/false) at the
// outermost <dict> level (depth 1). For PayloadContent
// (an array of dict), it descends into each child dict and
// collects every nested <key>PayloadType</key> → string
// pair regardless of depth, since sub-payloads can nest
// arbitrarily for complex profiles.
func walkTokens(body []byte, out *ProfileFields) error {
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false

	var (
		dictDepth        int
		pendingKey       string
		expectingVal     bool
		inPayloadContent bool
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("plist token: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			if name == "dict" {
				dictDepth++
				continue
			}
			if dictDepth == 0 {
				continue
			}
			// PayloadContent capture: an array containing dicts,
			// each of which has its own PayloadType. We greedily
			// pick up every PayloadType value seen anywhere
			// during the PayloadContent subtree.
			if dictDepth == 1 {
				// Outermost dict — pair keys with values.
				switch name {
				case "key":
					text, err := readCharData(dec, name)
					if err != nil {
						return fmt.Errorf("plist key: %w", err)
					}
					pendingKey = strings.TrimSpace(text)
					expectingVal = true
				case "array":
					if pendingKey == "PayloadContent" {
						inPayloadContent = true
					}
					// Don't skip — we want to descend so the
					// nested dicts can be walked.
					pendingKey = ""
					expectingVal = false
				case "string", "integer", "real", "true", "false", "data", "date":
					if expectingVal {
						text, err := readCharData(dec, name)
						if err != nil {
							return fmt.Errorf("plist value: %w", err)
						}
						applyTopLevel(out, pendingKey,
							strings.TrimSpace(text))
						pendingKey = ""
						expectingVal = false
					} else {
						if err := dec.Skip(); err != nil {
							return fmt.Errorf("plist skip value: %w", err)
						}
					}
				}
				continue
			}
			// dictDepth >= 2 — inside a sub-payload dict.
			if inPayloadContent {
				if name == "key" {
					text, err := readCharData(dec, name)
					if err != nil {
						return fmt.Errorf("plist subkey: %w", err)
					}
					pendingKey = strings.TrimSpace(text)
					expectingVal = true
					continue
				}
				if expectingVal && name == "string" {
					text, err := readCharData(dec, name)
					if err != nil {
						return fmt.Errorf("plist substring: %w", err)
					}
					if pendingKey == "PayloadType" {
						v := strings.TrimSpace(text)
						if v != "" {
							out.SubPayloadTypes = append(out.SubPayloadTypes, v)
						}
					}
					pendingKey = ""
					expectingVal = false
					continue
				}
			}
			// Default: skip the element to avoid mis-pairing.
			if err := dec.Skip(); err != nil {
				return fmt.Errorf("plist skip nested: %w", err)
			}
		case xml.EndElement:
			if t.Name.Local == "dict" {
				dictDepth--
				if dictDepth == 0 {
					inPayloadContent = false
				}
			} else if t.Name.Local == "array" && dictDepth == 1 {
				inPayloadContent = false
			}
		}
	}
	return nil
}

// readCharData returns the character data immediately
// contained in `<elem>...</elem>`. For self-closing booleans
// (`<true/>`, `<false/>`), returns the element name itself.
func readCharData(dec *xml.Decoder, elem string) (string, error) {
	var sb strings.Builder
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err == io.EOF {
			return sb.String(), nil
		}
		if err != nil {
			return "", fmt.Errorf("plist chardata: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if err := dec.Skip(); err != nil {
				return "", fmt.Errorf("plist chardata skip: %w", err)
			}
			depth--
		case xml.EndElement:
			depth--
			if depth == 0 {
				v := sb.String()
				if v == "" {
					switch elem {
					case "true":
						return "true", nil
					case "false":
						return "false", nil
					}
				}
				return v, nil
			}
		case xml.CharData:
			sb.Write(t)
		}
	}
	return sb.String(), nil
}

// applyTopLevel populates the top-level Payload* fields.
func applyTopLevel(out *ProfileFields, key, value string) {
	if value == "" {
		return
	}
	switch key {
	case "PayloadIdentifier":
		if out.PayloadIdentifier == "" {
			out.PayloadIdentifier = value
		}
	case "PayloadDisplayName":
		if out.PayloadDisplayName == "" {
			out.PayloadDisplayName = value
		}
	case "PayloadOrganization":
		if out.PayloadOrganization == "" {
			out.PayloadOrganization = value
		}
	case "PayloadUUID":
		if out.PayloadUUID == "" {
			out.PayloadUUID = value
		}
	case "PayloadDescription":
		if out.PayloadDescription == "" {
			out.PayloadDescription = value
		}
	case "PayloadVersion":
		if out.PayloadVersion == "" {
			out.PayloadVersion = value
		}
	}
}
