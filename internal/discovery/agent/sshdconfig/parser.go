package sshdconfig

import (
	"bufio"
	"bytes"
	"strings"
)

// Parse walks one sshd_config body. Grammar per sshd_config(5):
//
//	# comment
//	Keyword value
//	Match User alice Host *.corp.local
//	    Keyword value      # inherits Match scope until next Match or EOF
//
// We track Match state across lines so directives inside the block
// get scope=match + the Match criteria. Note: sshd treats whitespace
// around `=` and bare-space-separated `key value` identically — we
// accept both.
func Parse(raw []byte, filePath string) []Setting {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var (
		out           []Setting
		scope         = ScopeGlobal
		matchCriteria string
	)
	for i, line := range lines {
		clean := stripComment(line)
		trimmed := strings.TrimSpace(clean)
		if trimmed == "" {
			continue
		}
		key, value, ok := splitKV(trimmed)
		if !ok {
			continue
		}
		if normalizeKey(key) == "match" {
			scope = ScopeMatch
			matchCriteria = strings.TrimSpace(value)
			continue
		}
		s := Setting{
			Scope:         scope,
			MatchCriteria: matchCriteria,
			Key:           key,
			Value:         value,
			FilePath:      filePath,
			FileHash:      hash,
			LineNo:        i + 1,
			RawLine:       collapseWhitespace(trimmed),
		}
		AnnotateSecurity(&s)
		out = append(out, s)
		if len(out) >= MaxSettings {
			break
		}
	}
	return out
}

// splitKV splits a sshd directive line into (key, value, ok). sshd
// accepts both `Key value` (whitespace separator) and `Key=value`
// — the whitespace form is far more common, but the `=` form is used
// in some Match-block one-liners and CIS-generated configs.
func splitKV(line string) (string, string, bool) {
	// `Key=value` (no whitespace) — handle before strings.Fields so the
	// single-token case still parses.
	if i := strings.IndexByte(line, '='); i > 0 {
		// Reject when whitespace appears before the `=` (that's the
		// `Key value=…` shape, not `Key=value`).
		if !strings.ContainsAny(line[:i], " \t") {
			return strings.TrimSpace(line[:i]),
				strings.TrimSpace(line[i+1:]), true
		}
	}
	// Whitespace-separated form.
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", false
	}
	key := fields[0]
	value := strings.TrimSpace(strings.TrimPrefix(line, key))
	// `Key = value` form (whitespace before `=`).
	if strings.HasPrefix(value, "=") {
		value = strings.TrimSpace(value[1:])
	}
	return key, value, true
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

// stripComment removes `#`-introduced trailing comments. sshd_config(5)
// recognises only `#` as a comment leader.
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
