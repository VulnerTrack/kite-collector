package polkit

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"regexp"
	"strings"
)

// ParseActionPolicy walks a polkit .policy XML file. Schema (per
// polkit-action-policy(5)):
//
//	<policyconfig>
//	  <action id="org.freedesktop.policykit.exec">
//	    <description>...</description>
//	    <defaults>
//	      <allow_any>auth_admin</allow_any>
//	      <allow_inactive>auth_admin</allow_inactive>
//	      <allow_active>auth_admin</allow_active>
//	    </defaults>
//	  </action>
//	</policyconfig>
//
// We emit one Rule per <action>.
func ParseActionPolicy(raw []byte, filePath string) []Rule {
	hash := HashContents(raw)

	var pc policyConfig
	if err := xml.Unmarshal(raw, &pc); err != nil {
		// Malformed XML — return empty rather than fail.
		return nil
	}

	out := make([]Rule, 0, len(pc.Actions))
	for i, a := range pc.Actions {
		r := Rule{
			Source:            SourceActionPolicy,
			ActionID:          strings.TrimSpace(a.ID),
			ActionDescription: strings.TrimSpace(a.Description),
			AllowAny:          strings.TrimSpace(a.Defaults.AllowAny),
			AllowInactive:     strings.TrimSpace(a.Defaults.AllowInactive),
			AllowActive:       strings.TrimSpace(a.Defaults.AllowActive),
			FilePath:          filePath,
			FileHash:          hash,
			LineNo:            i + 1, // ordinal within the file
		}
		AnnotateActionPolicy(&r)
		out = append(out, r)
		if len(out) >= MaxRules {
			break
		}
	}
	return out
}

type policyConfig struct {
	XMLName xml.Name       `xml:"policyconfig"`
	Actions []policyAction `xml:"action"`
}

type policyAction struct {
	ID          string         `xml:"id,attr"`
	Description string         `xml:"description"`
	Defaults    policyDefaults `xml:"defaults"`
}

type policyDefaults struct {
	AllowAny      string `xml:"allow_any"`
	AllowInactive string `xml:"allow_inactive"`
	AllowActive   string `xml:"allow_active"`
}

// ParseJSRules walks a polkit .rules JS file with a regex-based
// extractor. We can't fully evaluate JS — the policy engine is duktape
// inside polkitd — but we can identify the action id every rule
// matches against and whether the rule body returns `YES`.
//
// The conventional polkit rule shape is:
//
//	polkit.addRule(function(action, subject) {
//	    if (action.id == "org.libvirt.unix.manage" &&
//	        subject.isInGroup("libvirt")) {
//	        return polkit.Result.YES;
//	    }
//	});
//
// Each matched (action_id, returns_YES?) pair becomes one Rule. When
// a rule body has no recognisable action.id check, we emit a single
// no-action row capturing the rule snippet for forensic review.
func ParseJSRules(raw []byte, filePath string, source Source) []Rule {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var (
		out         []Rule
		currentRule strings.Builder
		ruleStart   int
		inRule      bool
		braceDepth  int
	)

	flushRule := func() {
		body := currentRule.String()
		if body == "" {
			return
		}
		actionIDs := extractActionIDs(body)
		returnsYES := jsReturnsYES.MatchString(body)
		snippet := compactSnippet(body)

		if len(actionIDs) == 0 {
			r := Rule{
				Source:      source,
				ActionID:    "",
				RuleSnippet: snippet,
				GrantsYES:   returnsYES,
				FilePath:    filePath,
				FileHash:    hash,
				LineNo:      ruleStart,
			}
			AnnotateJSRule(&r)
			out = append(out, r)
		} else {
			for _, id := range actionIDs {
				r := Rule{
					Source:      source,
					ActionID:    id,
					RuleSnippet: snippet,
					GrantsYES:   returnsYES,
					FilePath:    filePath,
					FileHash:    hash,
					LineNo:      ruleStart,
				}
				AnnotateJSRule(&r)
				out = append(out, r)
				if len(out) >= MaxRules {
					break
				}
			}
		}
		currentRule.Reset()
		inRule = false
		braceDepth = 0
		ruleStart = 0
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(stripJSLineComment(line))
		if trimmed == "" && !inRule {
			continue
		}
		if !inRule {
			if jsAddRuleStart.MatchString(trimmed) {
				inRule = true
				ruleStart = i + 1
				currentRule.WriteString(trimmed)
				currentRule.WriteByte('\n')
				braceDepth = strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
				if braceDepth <= 0 && strings.Contains(trimmed, "}") {
					// single-line rule
					flushRule()
				}
				continue
			}
			continue
		}
		// in-rule
		currentRule.WriteString(trimmed)
		currentRule.WriteByte('\n')
		braceDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if braceDepth <= 0 {
			flushRule()
		}
		if len(out) >= MaxRules {
			break
		}
	}
	if inRule && currentRule.Len() > 0 {
		flushRule()
	}
	return out
}

var (
	jsAddRuleStart = regexp.MustCompile(`^polkit\.(?:addRule|addAdminRule)\s*\(`)
	// Two shapes:
	//   action.id == "literal"
	//   action.id.indexOf("literal") | .startsWith("literal")
	jsActionID = regexp.MustCompile(
		`action\.id\s*(?:===?|\.(?:indexOf|startsWith)\s*\()\s*["']([^"']+)["']`,
	)
	jsReturnsYES = regexp.MustCompile(`return\s+polkit\.Result\.YES\b`)
)

// extractActionIDs pulls every literal action.id string the rule
// body checks against. We accept both `action.id == "..."` and
// `action.id.indexOf("...")` patterns.
func extractActionIDs(body string) []string {
	matches := jsActionID.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		id := strings.TrimSpace(m[1])
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// compactSnippet returns a one-line summary of the rule body for
// raw_line storage. Keeps the audit-pipeline display readable
// without forcing a multi-line column.
func compactSnippet(body string) string {
	s := strings.ReplaceAll(body, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// stripJSLineComment strips an inline `// ...` comment from a JS line.
// We don't try to handle `/* ... */` blocks — the regex pass over the
// rule body is tolerant of them.
func stripJSLineComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}

// -- shared helpers -----------------------------------------------------

func splitLines(raw []byte) []string {
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	var out []string
	for scan.Scan() {
		out = append(out, scan.Text())
	}
	return out
}
