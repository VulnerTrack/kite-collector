package pam

import (
	"path/filepath"
	"strings"
)

// Parse extracts directives from a /etc/pam.d/<service> file's body.
// The grammar (per pam.conf(5)):
//
//	type control module-path [module-args ...]
//
// `type` is one of: auth, account, session, password (+ rare:
// include, substack).
//
// `control` is either a single keyword (required, requisite, sufficient,
// optional, include, substack) OR a bracketed action list like
// `[success=2 default=ignore new_authtok_reqd=ok]`. Brackets contain
// spaces, so we use a small state-machine splitter instead of
// strings.Fields.
//
// `module-path` is either a bare basename (resolved via PAM's search
// path, typically /lib/security or /usr/lib/security) OR an absolute
// path. Bare names = standard install; absolute paths in non-standard
// trees = CWE-829.
//
// `service` comes from the file basename (the caller passes it).
// Includes (`@include otherfile`) are recorded but not followed —
// the audit pipeline does the include-graph resolution at query time.
func Parse(raw []byte, service, filePath string) []Directive {
	hash := HashContents(raw)
	lines := splitMergeContinuations(string(raw))

	out := make([]Directive, 0, len(lines))
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		d, ok := parseLine(clean)
		if !ok {
			continue
		}
		d.FilePath = filePath
		d.FileHash = hash
		d.LineNo = i + 1
		d.Service = service
		d.RawLine = collapseWhitespace(clean)
		// Compute the indexed booleans.
		d.IsUnconditionalPass = IsUnconditionalPassModule(d.Module) &&
			(d.Type == TypeAuth || d.Type == TypeAccount)
		d.IsNullok = argsContain(d.Arguments, "nullok")
		d.IsNonstandardPath = !IsStandardModulePath(d.ModulePath)
		d.ShortCircuitsStack = strings.EqualFold(d.Control, "sufficient") &&
			d.IsUnconditionalPass
		out = append(out, d)
		if len(out) >= MaxDirectives {
			break
		}
	}
	return out
}

// parseLine walks one cleaned PAM directive line and returns the
// projected fields. Recognises both `@include otherfile` shorthand and
// the canonical `type control module [args...]` form.
func parseLine(line string) (Directive, bool) {
	if strings.HasPrefix(line, "@include") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return Directive{}, false
		}
		return Directive{
			Type:    TypeInclude,
			Control: "include",
			Module:  fields[1],
		}, true
	}

	tokens := splitTokensRespectingBrackets(line)
	if len(tokens) < 3 {
		return Directive{}, false
	}
	d := Directive{
		Type:    normalizeType(tokens[0]),
		Control: tokens[1],
		Module:  tokens[2],
	}
	if strings.HasPrefix(d.Module, "/") {
		d.ModulePath = d.Module
		d.Module = filepath.Base(d.Module)
	}
	if len(tokens) > 3 {
		d.Arguments = append([]string(nil), tokens[3:]...)
	}
	return d, true
}

// normalizeType maps the lowercase `type` token to our pinned enum.
// Unknown types collapse to `unknown` rather than being dropped — the
// caller still wants to see the raw line for forensics.
func normalizeType(s string) Type {
	switch strings.ToLower(s) {
	case "auth":
		return TypeAuth
	case "account":
		return TypeAccount
	case "session":
		return TypeSession
	case "password":
		return TypePassword
	case "@include":
		return TypeInclude
	case "substack":
		return TypeSubstack
	}
	return TypeUnknown
}

// splitTokensRespectingBrackets is a tiny state-machine splitter. It
// splits on whitespace EXCEPT when inside `[...]` (the PAM bracketed
// control syntax). Quoted arguments are not part of the PAM grammar so
// we don't handle them.
func splitTokensRespectingBrackets(line string) []string {
	var (
		tokens []string
		cur    strings.Builder
		depth  int
	)
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '[':
			depth++
			cur.WriteByte(c)
		case c == ']':
			depth--
			cur.WriteByte(c)
		case (c == ' ' || c == '\t') && depth == 0:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return tokens
}

// splitMergeContinuations splits text into lines, merging lines that
// end with `\` into the next. PAM configs in distros like Arch and
// Fedora use continuations heavily in /etc/pam.d/system-auth.
func splitMergeContinuations(text string) []string {
	rawLines := strings.Split(text, "\n")
	out := make([]string, 0, len(rawLines))
	var pending strings.Builder
	for _, line := range rawLines {
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

// stripComment removes `#`-introduced trailing comments. PAM doesn't
// have quoted strings to worry about — `#` always starts a comment.
func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

// collapseWhitespace normalises tabs+spaces into single spaces. Used
// for raw_line so cosmetic re-formats don't trigger false drift events.
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

// argsContain reports whether arg appears in the PAM module argument
// list. Used to flag pam_unix `nullok`, pam_listfile `onerr=succeed`,
// etc. Case-sensitive (PAM arguments are conventionally lowercase).
func argsContain(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
		// Tolerate the `=`-suffix form: `nullok_secure`, `try_first_pass`.
		if i := strings.IndexByte(a, '='); i > 0 && a[:i] == want {
			return true
		}
	}
	return false
}
