package kernelcmdline

import (
	"bufio"
	"bytes"
	"strings"
)

// ParseProcCmdline walks the /proc/cmdline file (a single line of
// whitespace-separated tokens). Each token is either a bare flag
// (`quiet`) or a key=value pair (`root=UUID=…`). Values may be
// double-quoted to embed spaces (`module.parm="a b c"`).
func ParseProcCmdline(raw []byte, filePath string) []Param {
	hash := HashContents(raw)
	// /proc/cmdline is single-line in practice but tolerate multi-line.
	line := strings.TrimSpace(strings.ReplaceAll(string(raw), "\n", " "))
	if line == "" {
		return nil
	}
	tokens := tokenize(line)

	out := make([]Param, 0, len(tokens))
	for _, tok := range tokens {
		k, v, hasV := splitKV(tok)
		p := Param{
			Source:   SourceProcCmdline,
			Key:      k,
			Value:    v,
			HasValue: hasV,
			FilePath: filePath,
			FileHash: hash,
			LineNo:   1,
			RawLine:  tok,
		}
		AnnotateSecurity(&p)
		out = append(out, p)
		if len(out) >= MaxParams {
			break
		}
	}
	return out
}

// ParseGrubDefault walks /etc/default/grub looking for the cmdline
// keys: GRUB_CMDLINE_LINUX and GRUB_CMDLINE_LINUX_DEFAULT. Their
// values are shell-quoted strings holding the same whitespace-
// separated token list as /proc/cmdline.
//
// Example:
//
//	GRUB_CMDLINE_LINUX_DEFAULT="quiet splash mitigations=off"
//	GRUB_CMDLINE_LINUX="audit=1"
func ParseGrubDefault(raw []byte, filePath string) []Param {
	hash := HashContents(raw)
	lines := splitLines(raw)

	out := make([]Param, 0, 8)
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		key, value, ok := splitShellAssignment(clean)
		if !ok {
			continue
		}
		if key != "GRUB_CMDLINE_LINUX" && key != "GRUB_CMDLINE_LINUX_DEFAULT" {
			continue
		}
		for _, tok := range tokenize(value) {
			k, v, hasV := splitKV(tok)
			p := Param{
				Source:   SourceGrubDefault,
				Key:      k,
				Value:    v,
				HasValue: hasV,
				FilePath: filePath,
				FileHash: hash,
				LineNo:   i + 1,
				RawLine:  tok,
			}
			AnnotateSecurity(&p)
			out = append(out, p)
			if len(out) >= MaxParams {
				return out
			}
		}
	}
	return out
}

// tokenize splits a cmdline string on whitespace while respecting
// double-quoted values (`key="a b"` → one token).
func tokenize(line string) []string {
	var (
		out     []string
		cur     strings.Builder
		inQuote bool
	)
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			cur.WriteByte(c)
		case (c == ' ' || c == '\t') && !inQuote:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// splitKV splits a single cmdline token into (key, value, hasValue).
// Bare flags return ("flag", "", false). Quoted values have the outer
// quotes stripped so the audit pipeline doesn't have to.
func splitKV(tok string) (string, string, bool) {
	i := strings.IndexByte(tok, '=')
	if i < 0 {
		return tok, "", false
	}
	key := tok[:i]
	val := tok[i+1:]
	// Strip outer double quotes when symmetric.
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	return key, val, true
}

// splitShellAssignment splits `KEY="value with spaces"` into
// (KEY, "value with spaces", true). Only the simplest shell shape is
// supported — we don't need a full parser.
func splitShellAssignment(line string) (string, string, bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:i])
	val := strings.TrimSpace(line[i+1:])
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	} else if len(val) >= 2 && val[0] == '\'' && val[len(val)-1] == '\'' {
		val = val[1 : len(val)-1]
	}
	return key, val, true
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

func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}
