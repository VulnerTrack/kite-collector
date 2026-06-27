package nfsexports

import (
	"bufio"
	"bytes"
	"strings"
)

// Parse walks one exports body. Grammar per exports(5):
//
//	# comment
//	/path/to/share   client1(opt,opt) client2(opt,opt) ...
//
// A single line can grant access to multiple clients with different
// option sets. We emit one Row per client tuple so the audit pipeline
// joins on (export_path, client) without string-splitting at query
// time.
//
// Continuation lines (`\` at EOL) are folded — they're conventional
// when an export has many client tuples.
func Parse(raw []byte, filePath string) []Row {
	hash := HashContents(raw)
	lines := mergeContinuations(splitLines(raw))

	out := make([]Row, 0, 16)
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		exportPath, tuples, ok := parseLine(clean)
		if !ok {
			continue
		}
		raw := collapseWhitespace(clean)
		for _, tup := range tuples {
			r := Row{
				FilePath:    filePath,
				FileHash:    hash,
				LineNo:      i + 1,
				RawLine:     raw,
				ExportPath:  exportPath,
				Client:      tup.client,
				Options:     strings.Join(tup.options, ","),
				OptionsList: tup.options,
			}
			AnnotateSecurity(&r)
			out = append(out, r)
			if len(out) >= MaxRows {
				return out
			}
		}
	}
	return out
}

// clientOptions pairs a client token with its parenthesised option
// list (already split on `,`).
type clientOptions struct {
	client  string
	options []string
}

// parseLine splits `/path  client1(opt,opt) client2(opt,opt)` into
// (export_path, []{client, options}).
//
// The grammar tolerates spaces inside `(...)` (e.g. `*(rw, async)`)
// — exports(5) doesn't strictly allow them but operators write it
// that way and modern nfs-utils accepts it. We collapse internal
// whitespace inside the parens before splitting on `,`.
func parseLine(line string) (string, []clientOptions, bool) {
	// First whitespace-bounded token is the export path. If the path
	// is quoted (rare — used when it contains spaces), accept the
	// quoted form.
	exportPath, rest, ok := splitExportPath(line)
	if !ok {
		return "", nil, false
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		// Export with no client tuple — exports(5) treats it as
		// `*(default-options)`. We surface it as a single client="*"
		// row so the audit pipeline sees the wide exposure.
		return exportPath, []clientOptions{{client: "*", options: nil}}, true
	}
	tuples := splitClientTuples(rest)
	if len(tuples) == 0 {
		return "", nil, false
	}
	return exportPath, tuples, true
}

// splitExportPath returns (path, remainder, ok). Quoted paths use
// double quotes; unquoted paths end at the first whitespace.
func splitExportPath(line string) (string, string, bool) {
	if strings.HasPrefix(line, `"`) {
		end := strings.IndexByte(line[1:], '"')
		if end < 0 {
			return "", "", false
		}
		return line[1 : 1+end], strings.TrimSpace(line[2+end:]), true
	}
	if i := strings.IndexAny(line, " \t"); i > 0 {
		return line[:i], strings.TrimSpace(line[i+1:]), true
	}
	// Whole line is just the path (no clients).
	return line, "", true
}

// splitClientTuples parses zero-or-more `client(opt,opt)` tokens.
// Whitespace between tuples separates them; whitespace inside `(...)`
// is preserved-then-stripped during option splitting.
func splitClientTuples(s string) []clientOptions {
	var (
		out      []clientOptions
		i        int
		inOpt    bool
		curStart = 0
	)
	for i = 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '(':
			inOpt = true
		case c == ')':
			inOpt = false
		case (c == ' ' || c == '\t') && !inOpt:
			tok := strings.TrimSpace(s[curStart:i])
			if tok != "" {
				out = append(out, parseClientTuple(tok))
			}
			curStart = i + 1
		}
	}
	tail := strings.TrimSpace(s[curStart:])
	if tail != "" {
		out = append(out, parseClientTuple(tail))
	}
	return out
}

// parseClientTuple decodes one `client(opt,opt)` token. When the
// parens are missing the whole token is the client with no options.
func parseClientTuple(tok string) clientOptions {
	tok = strings.TrimSpace(tok)
	open := strings.IndexByte(tok, '(')
	if open < 0 {
		return clientOptions{client: tok}
	}
	client := strings.TrimSpace(tok[:open])
	close := strings.IndexByte(tok[open:], ')')
	if close < 0 {
		// Malformed — keep what we have.
		return clientOptions{client: client}
	}
	body := tok[open+1 : open+close]
	opts := []string{}
	for _, o := range strings.Split(body, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			opts = append(opts, o)
		}
	}
	return clientOptions{client: client, options: opts}
}

// -- shared helpers --------------------------------------------------

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
