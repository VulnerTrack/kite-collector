package sysctl

import (
	"bufio"
	"bytes"
	"strings"
)

// Parse walks one sysctl.conf-style body and produces one Setting per
// non-comment line. Grammar per sysctl.conf(5):
//
//	# comment
//	; comment
//	-key = value         # leading hyphen means "ignore-if-missing"
//	key = value
//
// We strip the leading `-` (it doesn't affect the recorded value);
// `=` is the separator with optional surrounding whitespace.
func Parse(raw []byte, source Source, filePath string) []Setting {
	hash := HashContents(raw)
	lines := splitLines(raw)

	out := make([]Setting, 0, 16)
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		// Drop the optional "ignore-if-missing" prefix.
		clean = strings.TrimPrefix(clean, "-")
		key, value, ok := splitKV(clean)
		if !ok {
			continue
		}
		s := Setting{
			Source:       source,
			Key:          key,
			CurrentValue: value,
			FilePath:     filePath,
			FileHash:     hash,
			LineNo:       i + 1,
			RawLine:      collapseWhitespace(clean),
		}
		AnnotateSecurity(&s)
		out = append(out, s)
		if len(out) >= MaxSettings {
			break
		}
	}
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

// stripComment drops trailing `#` or `;` comments. Both leaders are
// accepted by sysctl(8), distros use them interchangeably.
func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	if i := strings.IndexByte(line, ';'); i >= 0 {
		line = line[:i]
	}
	return line
}

func splitKV(line string) (string, string, bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// collapseWhitespace normalises tabs+spaces into single spaces so
// raw_line doesn't trigger cosmetic-only drift events.
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
