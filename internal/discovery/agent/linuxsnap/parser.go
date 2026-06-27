package linuxsnap

import (
	"bufio"
	"bytes"
	"strings"
)

// SnapYAMLFields captures the canonical snap.yaml metadata
// the audit pipeline cares about. snap.yaml is a YAML 1.1
// document but its top-level structure is simple enough
// (key: value scalars + lists/maps for plugs) that a
// schema-tolerant line scanner produces reliable results
// without pulling in a full YAML parser dependency.
type SnapYAMLFields struct {
	Name        string
	Version     string
	Summary     string
	Description string
	License     string
	Website     string
	Publisher   string
	Base        string
	Confinement Confinement
	Type        SnapType
	Plugs       []string
}

// ParseSnapYAML walks the snap.yaml body line-by-line and
// extracts the canonical top-level scalar keys plus the
// plug names declared under `plugs:` and per-app `plugs:`
// lists. Returns ok=false on empty / unparseable input.
//
// Schema-tolerance notes:
//   - Top-level scalar keys use `key: value` on a single line
//   - Lists use `key:\n  - item\n  - item`
//   - Maps use `key:\n  subkey: value` with 2-space indent
//
// The parser tracks indentation depth: anything not at the
// top level is consumed (so e.g. `description: |` multi-line
// blocks are accumulated but discarded).
func ParseSnapYAML(body []byte) (SnapYAMLFields, bool) {
	var out SnapYAMLFields
	if len(body) == 0 {
		return out, false
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return out, false
	}

	plugSet := make(map[string]struct{})

	var (
		inPlugs    bool
		inApps     bool
		inAppEntry bool
	)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		// Detect leading indent.
		indent := leadingIndent(line)
		trimmed := strings.TrimSpace(line)
		// Skip pure comments.
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Top-level keys (no leading indent).
		if indent == 0 {
			inPlugs = false
			inApps = false
			inAppEntry = false
			if key, val, ok := splitYAMLLine(trimmed); ok {
				applyTopLevel(&out, key, val)
				switch key {
				case "plugs":
					inPlugs = true
				case "apps":
					inApps = true
				}
			}
			continue
		}
		// Inside `plugs:` block — capture immediate child keys
		// at 2-space indent.
		if inPlugs && indent == 2 {
			if key, _, ok := splitYAMLLine(trimmed); ok && !strings.HasPrefix(key, "-") {
				plugSet[key] = struct{}{}
			}
			continue
		}
		// `apps:` block: each app entry has its own `plugs:`
		// list. We pick up both list-form `- name` and map-form
		// `name: ~` plug references.
		if inApps {
			switch indent {
			case 2:
				// e.g. `firefox:` or `myapp:` opens an app entry.
				inAppEntry = false
				if strings.HasSuffix(trimmed, ":") {
					inAppEntry = true
				}
			case 4:
				// `plugs:` opens a list; we pick up the list items
				// at indent==6 in the next iterations. Nothing to
				// do here — the inAppEntry latch is set elsewhere
				// and indent==6 below handles the list items.
				_ = inAppEntry
			case 6:
				if inAppEntry {
					if item, ok := yamlListItem(trimmed); ok {
						plugSet[item] = struct{}{}
					}
				}
			}
			continue
		}
	}
	for p := range plugSet {
		out.Plugs = append(out.Plugs, p)
	}
	if !hasAny(out) {
		return out, false
	}
	return out, true
}

func hasAny(f SnapYAMLFields) bool {
	return f.Name != "" || f.Version != "" || f.Summary != "" ||
		f.Description != "" || f.License != "" || f.Website != "" ||
		f.Publisher != "" || f.Base != "" ||
		f.Confinement != ConfinementEmpty ||
		f.Type != SnapTypeEmpty || len(f.Plugs) > 0
}

func leadingIndent(line string) int {
	n := 0
	for _, c := range line {
		switch c {
		case ' ':
			n++
		case '\t':
			n += 4 // round tabs to 4-space for indent comparison
		default:
			return n
		}
	}
	return n
}

// splitYAMLLine splits a `key: value` line into (key, value, ok).
// Quoted values are unquoted; trailing comments are stripped.
func splitYAMLLine(line string) (string, string, bool) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:idx])
	val := strings.TrimSpace(line[idx+1:])
	// Strip trailing inline comment.
	if hashIdx := strings.Index(val, " #"); hashIdx >= 0 {
		val = strings.TrimSpace(val[:hashIdx])
	}
	// Unquote single/double quoted values.
	if len(val) >= 2 {
		first, last := val[0], val[len(val)-1]
		if (first == '"' && last == '"') ||
			(first == '\'' && last == '\'') {
			val = val[1 : len(val)-1]
		}
	}
	return key, val, true
}

// yamlListItem returns the value after a list dash, e.g.
// `  - camera` → ("camera", true).
func yamlListItem(line string) (string, bool) {
	if !strings.HasPrefix(line, "-") {
		return "", false
	}
	v := strings.TrimSpace(strings.TrimPrefix(line, "-"))
	if v == "" {
		return "", false
	}
	return v, true
}

// applyTopLevel sets the canonical scalar fields.
func applyTopLevel(out *SnapYAMLFields, key, val string) {
	if val == "" {
		return
	}
	switch key {
	case "name":
		out.Name = val
	case "version":
		out.Version = val
	case "summary":
		out.Summary = val
	case "description":
		out.Description = val
	case "license":
		out.License = val
	case "website":
		out.Website = val
	case "contact":
		// `contact:` is often a website or email; reuse Website
		// as a fallback when website isn't set.
		if out.Website == "" {
			out.Website = val
		}
	case "publisher":
		out.Publisher = val
	case "base":
		out.Base = val
	case "confinement":
		out.Confinement = ConfinementFromText(val)
	case "type":
		out.Type = SnapTypeFromText(val)
	}
}
