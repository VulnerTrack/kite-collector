package nsswitch

import (
	"bufio"
	"bytes"
	"strings"
)

// Parse walks one /etc/nsswitch.conf body. Grammar per nsswitch.conf(5):
//
//	# comment
//	<database>: <source> [<action>] [<source> [<action>]]...
//
//	Examples:
//	    passwd:    files systemd
//	    group:     files systemd
//	    hosts:     files mdns4_minimal [NOTFOUND=return] dns
//	    passwd:    sss files
//
// The action tokens are bracketed; they don't change the database
// classification but we keep them in raw_line for forensic clarity.
// The sources slice contains only the bare source names (no actions).
func Parse(raw []byte, filePath string) []Entry {
	hash := HashContents(raw)
	lines := splitLines(raw)

	out := make([]Entry, 0, 16)
	for i, line := range lines {
		clean := stripComment(line)
		trimmed := strings.TrimSpace(clean)
		if trimmed == "" {
			continue
		}
		dbToken, chain, ok := splitDatabase(trimmed)
		if !ok {
			continue
		}
		e := Entry{
			Database:    NormalizeDatabase(dbToken),
			SourceChain: collapseWhitespace(chain),
			Sources:     extractSources(chain),
			FilePath:    filePath,
			FileHash:    hash,
			LineNo:      i + 1,
			RawLine:     collapseWhitespace(trimmed),
		}
		AnnotateSecurity(&e)
		out = append(out, e)
		if len(out) >= MaxEntries {
			break
		}
	}
	return out
}

// splitDatabase splits `passwd: files sss` into (`passwd`, `files sss`, true).
func splitDatabase(line string) (string, string, bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// extractSources walks a source chain and returns only the bare
// source names (everything outside `[ ... ]` action blocks).
func extractSources(chain string) []string {
	var (
		out   []string
		depth int
		cur   strings.Builder
	)
	flush := func() {
		s := strings.TrimSpace(cur.String())
		if s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	for i := 0; i < len(chain); i++ {
		c := chain[i]
		switch {
		case c == '[':
			flush()
			depth++
		case c == ']':
			if depth > 0 {
				depth--
			}
			cur.Reset() // discard action contents
		case (c == ' ' || c == '\t') && depth == 0:
			flush()
		case depth == 0:
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

// stripComment drops trailing `#` comments. nsswitch.conf(5) treats
// `#` anywhere on a line as the comment leader.
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
