package macosinfoplist

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// PlistFields captures the canonical Info.plist fields the
// audit pipeline cares about. Privacy keys are walked into
// the Row directly by the collector via PrivacyKeyToField.
type PlistFields struct {
	BundleID    string
	DisplayName string
	Version     string
	Copyright   string
	Category    string
	PrivacyKeys []string
}

// ParseInfoPlist extracts PlistFields from an XML plist body.
// Returns ok=false on empty / non-XML / unparseable input
// that yields no fields at all. Binary plists (bplist00 magic)
// are out of scope for this pure-Go reader.
//
// macOS plists pair <key>NAME</key> with the following sibling
// value element inside the top-level <dict>. We walk tokens in
// order with xml.Decoder so the key/value pairing is reliable
// across schema-tolerant value kinds (string / true / false /
// integer / dict / array).
func ParseInfoPlist(body []byte) (PlistFields, bool) {
	var out PlistFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}
	// Binary plist starts with `bplist00`; out of scope.
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

func hasAny(f PlistFields) bool {
	return f.BundleID != "" || f.DisplayName != "" ||
		f.Version != "" || f.Copyright != "" || f.Category != "" ||
		len(f.PrivacyKeys) > 0
}

// walkTokens iterates the plist's XML token stream and pairs
// each top-level <key>NAME</key> with the immediately
// following value element inside the outermost <dict>.
// Nested dicts/arrays are skipped so unrelated text inside
// per-app config sections doesn't pollute the inventory.
func walkTokens(body []byte, out *PlistFields) error {
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false

	var (
		dictDepth    int
		pendingKey   string
		expectingVal bool
	)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
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
				// Still at the plist root (e.g. inside <plist>),
				// descend into the next element so we can reach
				// the outermost <dict>.
				continue
			}
			if dictDepth >= 2 {
				// Nested dict — skip the entire subtree.
				if err := dec.Skip(); err != nil {
					return fmt.Errorf("plist skip nested: %w", err)
				}
				continue
			}
			// dictDepth == 1: this is the outermost dict whose
			// key/value pairs we capture.
			if name == "array" {
				if err := dec.Skip(); err != nil {
					return fmt.Errorf("plist skip array: %w", err)
				}
				if expectingVal {
					pendingKey = ""
					expectingVal = false
				}
				continue
			}
			text, err := readCharData(dec, name)
			if err != nil {
				return fmt.Errorf("plist readCharData: %w", err)
			}
			switch {
			case name == "key":
				pendingKey = strings.TrimSpace(text)
				expectingVal = true
			case expectingVal:
				applyKeyValue(pendingKey, strings.TrimSpace(text), name, out)
				pendingKey = ""
				expectingVal = false
			}
		case xml.EndElement:
			if t.Name.Local == "dict" {
				dictDepth--
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
		if errors.Is(err, io.EOF) {
			return sb.String(), nil
		}
		if err != nil {
			return "", fmt.Errorf("plist value token: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if err := dec.Skip(); err != nil {
				return "", fmt.Errorf("plist value skip: %w", err)
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

// applyKeyValue populates PlistFields from one key/value pair.
func applyKeyValue(key, value, valKind string, out *PlistFields) {
	if key == "" {
		return
	}
	switch key {
	case "CFBundleIdentifier":
		if out.BundleID == "" && value != "" {
			out.BundleID = value
		}
	case "CFBundleDisplayName":
		if out.DisplayName == "" && value != "" {
			out.DisplayName = value
		}
	case "CFBundleName":
		if out.DisplayName == "" && value != "" {
			out.DisplayName = value
		}
	case "CFBundleShortVersionString":
		if out.Version == "" && value != "" {
			out.Version = value
		}
	case "CFBundleVersion":
		if out.Version == "" && value != "" {
			out.Version = value
		}
	case "NSHumanReadableCopyright":
		if out.Copyright == "" && value != "" {
			out.Copyright = value
		}
	case "LSApplicationCategoryType":
		if out.Category == "" && value != "" {
			out.Category = value
		}
	default:
		if strings.HasPrefix(key, "NS") &&
			strings.HasSuffix(key, "UsageDescription") {
			out.PrivacyKeys = append(out.PrivacyKeys, key)
		}
	}
	_ = valKind
}
