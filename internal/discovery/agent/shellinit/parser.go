package shellinit

import (
	"regexp"
	"strings"
)

// Parse extracts the audit-relevant fields from a shell-init file's
// contents. We deliberately use a line-walker rather than a real shell
// parser:
//
//   - Real shell grammar requires evaluating command substitution,
//     parameter expansion, and conditionals to know what assignments
//     actually run. That would mean importing the bash runtime
//     semantics — which would be a read/execute split, violating
//     guideline 4.2.
//   - The simple regex catches the static cases that cover ~95% of
//     real-world T1546.004 modifications. Sophisticated obfuscation
//     (assignments via `eval` of base64-decoded blobs etc.) are caught
//     by `contains_eval=1` instead.
//
// The returned InitFile has FilePath, OwnerUser, Scope, Shell, etc.
// left zero — the caller fills those.
func Parse(raw []byte) InitFile {
	if len(raw) > MaxFileBytes {
		raw = raw[:MaxFileBytes]
	}
	out := InitFile{
		FileHash:      HashContents(raw),
		FileSizeBytes: len(raw),
		Aliases:       map[string]string{},
		Exports:       map[string]string{},
	}
	text := string(raw)
	for _, raw := range strings.Split(text, "\n") {
		line := stripComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if name, val, ok := matchAlias(line); ok {
			out.Aliases[name] = val
			if IsShadowedBinary(name) {
				out.HasShadowAlias = true
			}
			continue
		}
		if name, val, ok := matchExport(line); ok {
			if name == "PATH" {
				prepends := extractPathPrepends(val)
				out.PathPrepends = append(out.PathPrepends, prepends...)
				for _, p := range prepends {
					if IsUntrustedPathDir(p) {
						out.HasUntrustedPath = true
					}
				}
			} else {
				out.Exports[name] = val
			}
			continue
		}
		if path, ok := matchSource(line); ok {
			out.SourcedFiles = append(out.SourcedFiles, path)
			continue
		}
		if matchEval(line) {
			out.ContainsEval = true
			continue
		}
		if matchCurlPipe(line) {
			out.ContainsCurlPipe = true
			continue
		}
	}
	// Stable serialisation order for the JSON columns.
	sortStrings(out.PathPrepends)
	sortStrings(out.SourcedFiles)
	return out
}

var (
	// alias name=value  /  alias name='value'  /  alias name="value"
	reAlias = regexp.MustCompile(`^alias\s+([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*('([^']*)'|"((?:\\.|[^"])*)"|([^\s]+))$`)

	// export NAME=value  /  NAME=value (with no leading `export`)
	reExportPrefixed = regexp.MustCompile(`^(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$`)

	// source path  /  . path  (both with optional trailing args we don't care about)
	reSource = regexp.MustCompile(`^(?:source|\.)\s+([^\s]+)`)

	// eval at command position: line start, after a statement separator
	// (`;`, `&&`, `||`), or after a control-flow keyword
	// (`then`, `do`, `else`, `elif`, `fi`).
	reEval = regexp.MustCompile(`(?:^|[;&|]\s*|\b(?:then|do|else|elif|fi)\s+)eval\s+`)

	// curl/wget at command position, followed by a pipe to a shell.
	// Anchoring at command position prevents `echo curl x | sh` from
	// matching — there `curl` is an echo arg, not an invocation.
	reCurlPipe = regexp.MustCompile(`(?:^|[;&|]\s*)\s*(?:curl|wget)\b[^|]*\|\s*(?:sh|bash|zsh|ksh|dash)\b`)
)

func matchAlias(line string) (string, string, bool) {
	m := reAlias.FindStringSubmatch(line)
	if m == nil {
		return "", "", false
	}
	val := m[3]
	if val == "" {
		val = m[4]
	}
	if val == "" {
		val = m[5]
	}
	return m[1], val, true
}

func matchExport(line string) (string, string, bool) {
	m := reExportPrefixed.FindStringSubmatch(line)
	if m == nil {
		return "", "", false
	}
	val := strings.TrimSpace(m[2])
	// Trim surrounding quotes if symmetric.
	val = unquote(val)
	return m[1], val, true
}

func matchSource(line string) (string, bool) {
	m := reSource.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func matchEval(line string) bool {
	return reEval.MatchString(line) || strings.HasPrefix(line, "eval ")
}

func matchCurlPipe(line string) bool {
	return reCurlPipe.MatchString(line)
}

// extractPathPrepends returns the literal entries appended/prepended to
// $PATH in an assignment like:
//
//	PATH=/usr/local/bin:$PATH
//	PATH="$HOME/bin:/tmp/exploit:$PATH"
//
// We skip the `$PATH` reference itself; everything else (after splitting
// on `:`) is recorded. Variable references (`$HOME`) are kept literally
// — the audit pipeline correlates them against ${HOME} at consumption
// time when needed.
func extractPathPrepends(rhs string) []string {
	rhs = unquote(strings.TrimSpace(rhs))
	parts := strings.Split(rhs, ":")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == "$PATH" || p == "${PATH}" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// stripComment removes `#`-introduced trailing comments. Respects
// single-quoted strings (so a `#` inside `alias x='foo # bar'` isn't
// taken as a comment).
func stripComment(line string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}

// unquote removes a single matched layer of `'` or `"` around s.
// Returns s unchanged when there's no symmetric outer quote pair.
func unquote(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// sortStrings is a tiny dep-free in-place sort.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j-1] > s[j] {
			s[j-1], s[j] = s[j], s[j-1]
			j--
		}
	}
}
