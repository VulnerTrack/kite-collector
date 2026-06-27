package pkgrepo

import (
	"bufio"
	"bytes"
	"strings"
)

// splitLines is a thin scanner wrapper so the parsers share a single
// buffer-sized line-reader.
func splitLines(raw []byte) []string {
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	var out []string
	for scan.Scan() {
		out = append(out, scan.Text())
	}
	return out
}

// stripHashComment removes a `#`-introduced trailing comment. Repo
// definition files universally use `#` for comments; quoted-string
// edge cases aren't part of the grammar.
func stripHashComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

// splitKV splits a `key=value` (or `key: value`) line. Whitespace is
// trimmed from both sides. Returns ok=false when no separator is found.
func splitKV(line string) (string, string, bool) {
	// Prefer `=` over `:` so deb822 lines that happen to contain `:`
	// in URIs don't get misclassified.
	for _, sep := range []byte{'=', ':'} {
		if i := strings.IndexByte(line, sep); i > 0 {
			return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
		}
	}
	return "", "", false
}
