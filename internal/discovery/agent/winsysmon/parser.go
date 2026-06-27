package winsysmon

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ParseConfigXML walks a Sysmon config XML body and returns a
// populated State (without Source set — the collector tags it).
// Empty body returns an error so the collector can distinguish "no
// probe ran" from "running with built-in defaults".
//
// We don't decode into a strict struct shape because Sysmon's XML
// is deep and irregular (RuleGroups can be nested, EventFiltering
// can host bare ProcessCreate / NetworkConnect / etc. elements
// without an outer RuleGroup wrapping). Instead we token-walk and
// extract just the security-relevant fields.
func ParseConfigXML(body []byte) (State, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return State{}, fmt.Errorf("empty sysmon config")
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	dec.Entity = xml.HTMLEntity

	out := State{}
	depth := 0
	var inEventFiltering bool

	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return State{}, fmt.Errorf("xml token: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			name := t.Name.Local
			switch name {
			case "Sysmon":
				for _, attr := range t.Attr {
					if strings.EqualFold(attr.Name.Local, "schemaversion") {
						out.SchemaVersion = strings.TrimSpace(attr.Value)
					}
				}
			case "HashAlgorithms":
				body, err := readCharData(dec)
				if err != nil {
					return State{}, err
				}
				out.HashAlgorithms = strings.TrimSpace(body)
				depth--
			case "CheckRevocation":
				out.CheckRevocationEnabled = true
				if err := dec.Skip(); err != nil {
					return State{}, fmt.Errorf("xml skip: %w", err)
				}
				depth--
			case "DnsLookup":
				body, err := readCharData(dec)
				if err != nil {
					return State{}, err
				}
				out.DNSLookupEnabled = parseBool(body)
				depth--
			case "ArchiveDirectory":
				body, err := readCharData(dec)
				if err != nil {
					return State{}, err
				}
				out.ArchiveDirectory = strings.TrimSpace(body)
				depth--
			case "EventFiltering":
				inEventFiltering = true
			case "RuleGroup":
				if inEventFiltering {
					recordRuleGroupFromAttrs(&out, t.Attr)
				}
			default:
				if inEventFiltering && isEventTypeName(name) {
					recordRuleGroup(&out, name)
					// Walk inside this event-type element to harvest
					// any Image exclusion entries.
					excl := collectImageExclusions(dec, name, t.Attr)
					out.ExclusionImagePaths = append(out.ExclusionImagePaths, excl...)
					depth--
				}
			}
		case xml.EndElement:
			depth--
			if t.Name.Local == "EventFiltering" {
				inEventFiltering = false
			}
		}
	}

	AnnotateSecurity(&out)
	SortLists(&out)
	return out, nil
}

// isEventTypeName reports whether an element name matches one of
// the Sysmon event-type tags. Used inside EventFiltering walks to
// detect "bare" rule definitions (those not wrapped in RuleGroup).
//
// Reference: Sysmon schema 4.83 documentation.
func isEventTypeName(name string) bool {
	switch name {
	case "ProcessCreate", "FileCreateTime", "NetworkConnect",
		"ProcessTerminate", "DriverLoad", "ImageLoad",
		"CreateRemoteThread", "RawAccessRead", "ProcessAccess",
		"FileCreate", "RegistryEvent", "FileCreateStreamHash",
		"PipeEvent", "WmiEvent", "DnsQuery",
		"FileDelete", "ClipboardChange", "ProcessTampering",
		"FileDeleteDetected", "FileBlockExecutable",
		"FileBlockShredding", "FileExecutableDetected":
		return true
	}
	return false
}

// recordRuleGroupFromAttrs harvests the `name` attribute on a
// `<RuleGroup>` element to record what event-type the group covers.
// Many configs name the group after the event-type for clarity.
func recordRuleGroupFromAttrs(s *State, attrs []xml.Attr) {
	for _, a := range attrs {
		if strings.EqualFold(a.Name.Local, "name") {
			v := strings.TrimSpace(a.Value)
			if v != "" && isEventTypeName(v) {
				recordRuleGroup(s, v)
			}
		}
	}
}

func recordRuleGroup(s *State, name string) {
	for _, g := range s.RuleGroups {
		if g == name {
			return
		}
	}
	s.RuleGroups = append(s.RuleGroups, name)
}

// collectImageExclusions walks the body of an event-type rule
// element (e.g. `<ProcessCreate onmatch="exclude">…</ProcessCreate>`)
// and collects every `<Image …>path</Image>` value found. Only
// exclusion rules (`onmatch="exclude"`) contribute to the
// suspicious-exclusion finding.
func collectImageExclusions(dec *xml.Decoder, openName string, attrs []xml.Attr) []string {
	onmatch := ""
	for _, a := range attrs {
		if strings.EqualFold(a.Name.Local, "onmatch") {
			onmatch = strings.ToLower(strings.TrimSpace(a.Value))
		}
	}
	var out []string
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "Image" && onmatch == "exclude" {
				body, err := readCharData(dec)
				if err != nil {
					return out
				}
				if v := strings.TrimSpace(body); v != "" {
					out = append(out, v)
				}
				continue
			}
			// Skip nested unknown elements.
			if err := dec.Skip(); err != nil {
				return out
			}
		case xml.EndElement:
			if t.Name.Local == openName {
				return out
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

// parseBool maps "true"/"yes"/"on"/"1" to true. Everything else is
// false.
func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "on", "1":
		return true
	}
	return false
}
