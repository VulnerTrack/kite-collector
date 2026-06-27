package launchd

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ParsePlist walks a launchd plist body and returns a populated
// Service. We hand-roll the XML walker because plist's `<key>X</key><Y/>`
// alternation doesn't map cleanly onto encoding/xml's struct tags.
//
// Only the security-relevant keys are extracted. Unknown keys are
// skipped without error so a plist with extra vendor extensions
// still produces a usable row.
func ParsePlist(body []byte) (Service, error) {
	body = bytes.TrimPrefix(bytes.TrimSpace(body), []byte{0xEF, 0xBB, 0xBF})
	if len(body) == 0 {
		return Service{}, fmt.Errorf("empty plist")
	}

	dec := xml.NewDecoder(bytes.NewReader(body))
	// Some plists declare a DOCTYPE that loads an external DTD; we
	// must not fetch the network. Disable entity resolution entirely.
	dec.Entity = xml.HTMLEntity
	dec.Strict = false

	// Skip ahead to the root `<dict>`.
	if err := skipToDict(dec); err != nil {
		return Service{}, fmt.Errorf("locate root dict: %w", err)
	}

	m, err := parseDict(dec)
	if err != nil {
		return Service{}, err
	}

	out := Service{}
	if v, ok := m["Label"].(string); ok {
		out.Label = strings.TrimSpace(v)
	}
	if v, ok := m["Program"].(string); ok {
		out.Program = strings.TrimSpace(v)
	}
	if v, ok := m["UserName"].(string); ok {
		out.UserName = strings.TrimSpace(v)
	}
	if v, ok := m["GroupName"].(string); ok {
		out.GroupName = strings.TrimSpace(v)
	}
	if v, ok := m["WorkingDirectory"].(string); ok {
		out.WorkingDirectory = strings.TrimSpace(v)
	}
	if v, ok := m["StandardOutPath"].(string); ok {
		out.StandardOutPath = strings.TrimSpace(v)
	}
	if v, ok := m["StandardErrorPath"].(string); ok {
		out.StandardErrorPath = strings.TrimSpace(v)
	}
	if v, ok := m["RunAtLoad"].(bool); ok {
		out.IsRunAtLoad = v
	}
	if v, ok := m["KeepAlive"].(bool); ok {
		out.IsKeepAlive = v
	}
	if _, ok := m["KeepAlive"].(map[string]any); ok {
		// KeepAlive can also be a dict of conditions; the presence
		// alone means launchd will keep restarting.
		out.IsKeepAlive = true
	}
	if v, ok := m["Disabled"].(bool); ok {
		out.IsDisabled = v
	}
	if v, ok := m["StartInterval"].(int64); ok {
		out.StartIntervalSeconds = int(v)
	}
	if _, ok := m["StartCalendarInterval"]; ok {
		out.HasStartCalendarInterval = true
	}
	if v, ok := m["ProgramArguments"].([]any); ok {
		out.ProgramArguments = stringSlice(v)
	}
	if v, ok := m["WatchPaths"].([]any); ok {
		out.WatchPaths = stringSlice(v)
	}
	return out, nil
}

// skipToDict consumes tokens until the root `<dict>` opens.
func skipToDict(dec *xml.Decoder) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("xml token: %w", err)
		}
		if start, ok := tok.(xml.StartElement); ok && start.Name.Local == "dict" {
			return nil
		}
	}
}

// parseDict reads a single `<dict>` body and returns a Go map keyed
// by the `<key>` elements. The current decoder position must already
// be inside the dict's opening tag.
func parseDict(dec *xml.Decoder) (map[string]any, error) {
	out := make(map[string]any)
	var pendingKey string
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, fmt.Errorf("xml token: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "key" {
				k, err := readCharData(dec)
				if err != nil {
					return nil, err
				}
				pendingKey = k
				continue
			}
			val, err := parseValue(dec, t)
			if err != nil {
				return nil, err
			}
			if pendingKey != "" {
				out[pendingKey] = val
				pendingKey = ""
			}
		case xml.EndElement:
			if t.Name.Local == "dict" {
				return out, nil
			}
		}
	}
}

// parseValue dispatches on the start element name to read a single
// plist value. Returns the Go-native form for that element.
func parseValue(dec *xml.Decoder, start xml.StartElement) (any, error) {
	switch start.Name.Local {
	case "string":
		return readCharData(dec)
	case "integer":
		s, err := readCharData(dec)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 0, 64)
		if err != nil {
			return int64(0), nil //nolint:nilerr // best-effort tolerance
		}
		return n, nil
	case "real":
		s, err := readCharData(dec)
		if err != nil {
			return nil, err
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return 0.0, nil //nolint:nilerr // best-effort tolerance
		}
		return f, nil
	case "true":
		return true, consumeEnd(dec, "true")
	case "false":
		return false, consumeEnd(dec, "false")
	case "array":
		return parseArray(dec)
	case "dict":
		return parseDict(dec)
	case "data", "date":
		// Skip past the closing tag — we don't currently need these.
		return "", skipElement(dec, start.Name.Local)
	}
	return "", skipElement(dec, start.Name.Local)
}

func parseArray(dec *xml.Decoder) ([]any, error) {
	out := make([]any, 0, 4)
	for {
		tok, err := dec.Token()
		if err != nil {
			return out, fmt.Errorf("xml token: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			val, err := parseValue(dec, t)
			if err != nil {
				return nil, err
			}
			out = append(out, val)
		case xml.EndElement:
			if t.Name.Local == "array" {
				return out, nil
			}
		}
	}
}

// readCharData returns the accumulated text inside the current
// element and consumes the matching end tag.
func readCharData(dec *xml.Decoder) (string, error) {
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return sb.String(), err
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.EndElement:
			return sb.String(), nil
		}
	}
}

// consumeEnd reads tokens until the matching end tag for `name`.
// Used for self-closing tags like `<true/>` where the decoder still
// emits the EndElement separately when not self-closed.
func consumeEnd(dec *xml.Decoder, name string) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("xml token: %w", err)
		}
		if end, ok := tok.(xml.EndElement); ok && end.Name.Local == name {
			return nil
		}
	}
}

func skipElement(dec *xml.Decoder, name string) error {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("xml token: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == name {
				depth++
			}
		case xml.EndElement:
			if t.Name.Local == name {
				depth--
			}
		}
	}
	return nil
}

// stringSlice coerces an []any of XML-text values into []string.
// Non-string entries become their string-form via fmt.
func stringSlice(in []any) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		default:
			out = append(out, fmt.Sprint(v))
		}
	}
	return out
}
