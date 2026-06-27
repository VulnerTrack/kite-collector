package udevrules

import (
	"bufio"
	"bytes"
	"strings"
)

// Parse walks one udev .rules body. Grammar per udev(7):
//
//	# comment
//	KEY OP "value", KEY OP "value", KEY OP "value"
//
//	Match ops:   ==, !=
//	Action ops:  =, +=, :=, -=
//
//	Common keys:
//	    SUBSYSTEM=="usb"
//	    KERNEL=="sd*"
//	    ACTION=="add"
//	    ATTR{idVendor}=="0bda"
//	    ENV{ID_FS_LABEL}=="MYUSB"
//	    RUN+="/usr/local/bin/x"
//	    IMPORT{program}="/usr/local/bin/probe"
//	    MODE="0660"
//	    OWNER="root"
//	    GROUP="disk"
//	    SYMLINK+="my-disk"
//
// Lines may continue with a trailing `\`; we merge them per udev's
// own grammar.
func Parse(raw []byte, filePath string, scope Scope) []Rule {
	hash := HashContents(raw)
	lines := mergeContinuations(splitLines(raw))

	out := make([]Rule, 0, 8)
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		r := parseRuleLine(clean)
		r.Scope = scope
		r.FilePath = filePath
		r.FileHash = hash
		r.LineNo = i + 1
		r.RawLine = collapseWhitespace(clean)
		AnnotateSecurity(&r)
		out = append(out, r)
		if len(out) >= MaxRules {
			break
		}
	}
	return out
}

// parseRuleLine tokenises a single rule line into match + action keys.
// We respect the `"..."` quoting and the brace-attribute syntax
// (`ATTR{idVendor}`). Tokens are split on `,` at depth 0.
func parseRuleLine(line string) Rule {
	r := Rule{}
	tokens := splitOnTopLevelComma(line)
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		key, op, value, ok := splitKeyOpValue(tok)
		if !ok {
			continue
		}
		entry := key + op + `"` + value + `"`
		isAction := op == "=" || op == "+=" || op == ":=" || op == "-="
		if isAction {
			r.ActionKeys = append(r.ActionKeys, entry)
		} else {
			r.MatchKeys = append(r.MatchKeys, entry)
		}
		// Pull out the well-known columns the audit pipeline needs
		// directly indexed.
		switch strings.ToUpper(key) {
		case "SUBSYSTEM":
			if op == "==" {
				r.Subsystem = value
			}
		case "KERNEL":
			if op == "==" {
				r.Kernel = value
			}
		case "ACTION":
			if op == "==" {
				r.Action = value
			}
		case "RUN":
			if op == "+=" || op == "=" {
				r.HasRun = true
				r.RunCommand = value
			}
		case "MODE":
			if op == "=" || op == ":=" {
				r.ModeValue = value
			}
		case "OWNER":
			if op == "=" || op == ":=" {
				r.Owner = value
			}
		case "GROUP":
			if op == "=" || op == ":=" {
				r.GroupName = value
			}
		}
		// IMPORT{program}=... runs an external program too.
		if strings.HasPrefix(strings.ToUpper(key), "IMPORT") &&
			(op == "+=" || op == "=") {
			r.HasImport = true
		}
	}
	return r
}

// splitKeyOpValue extracts (KEY, OP, VALUE) from a single token like
//
//	SUBSYSTEM=="usb"
//	ATTR{idVendor}=="0bda"
//	RUN+="/usr/local/bin/x"
//
// The key may contain `{...}` so we look for the first operator
// AFTER the closing brace (or just the first `==`/`!=`/`+=`/`:=`/`=`).
func splitKeyOpValue(tok string) (string, string, string, bool) {
	// Find the start of the operator. Skip past any `{...}` block
	// embedded in the key.
	idx := -1
	depth := 0
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch c {
		case '{':
			depth++
			continue
		case '}':
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 {
			continue
		}
		// Recognise operators in priority order so `==` isn't read as `=`.
		if c == '=' || c == '+' || c == ':' || c == '-' || c == '!' {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return "", "", "", false
	}
	// Determine the full operator string.
	var op string
	switch {
	case strings.HasPrefix(tok[idx:], "=="):
		op = "=="
	case strings.HasPrefix(tok[idx:], "!="):
		op = "!="
	case strings.HasPrefix(tok[idx:], "+="):
		op = "+="
	case strings.HasPrefix(tok[idx:], ":="):
		op = ":="
	case strings.HasPrefix(tok[idx:], "-="):
		op = "-="
	case tok[idx] == '=':
		op = "="
	default:
		return "", "", "", false
	}
	key := strings.TrimSpace(tok[:idx])
	rest := strings.TrimSpace(tok[idx+len(op):])
	// rest is the value, normally double-quoted.
	value := rest
	if len(rest) >= 2 && rest[0] == '"' && rest[len(rest)-1] == '"' {
		value = rest[1 : len(rest)-1]
	}
	return key, op, value, true
}

// splitOnTopLevelComma splits a rule line on commas that are NOT
// inside double-quoted strings.
func splitOnTopLevelComma(line string) []string {
	var (
		out     []string
		cur     strings.Builder
		inQuote bool
	)
	flush := func() {
		out = append(out, cur.String())
		cur.Reset()
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			cur.WriteByte(c)
		case c == ',' && !inQuote:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
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

// mergeContinuations folds lines ending in `\` into the next.
func mergeContinuations(lines []string) []string {
	out := make([]string, 0, len(lines))
	var pending strings.Builder
	for _, line := range lines {
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, "\\") {
			body := strings.TrimRight(trimmed[:len(trimmed)-1], " \t")
			pending.WriteString(body)
			pending.WriteByte(' ')
			continue
		}
		if pending.Len() > 0 {
			pending.WriteString(strings.TrimLeft(trimmed, " \t"))
			out = append(out, pending.String())
			pending.Reset()
		} else {
			out = append(out, line)
		}
	}
	if pending.Len() > 0 {
		out = append(out, pending.String())
	}
	return out
}

func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

func collapseWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		switch r {
		case ' ', '\t':
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		default:
			b.WriteRune(r)
			prevSpace = false
		}
	}
	return strings.TrimSpace(b.String())
}
