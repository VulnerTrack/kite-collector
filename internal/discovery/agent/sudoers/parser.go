package sudoers

import (
	"strings"
)

// Parse walks a sudoers file's contents and returns one Entry per
// recognised, non-comment, non-blank line. Line continuations (`\` at
// end of line) are merged. Comments (`#`) terminate a line — except
// `#includedir` / `#include` which are sudo directives, not comments.
//
// The grammar we implement (from sudoers(5)):
//
//	line :=
//	    Defaults_entry
//	  | Alias_decl
//	  | User_spec
//	  | Include
//	  | comment | empty
//
//	Alias_decl  := (User|Runas|Host|Cmnd)_Alias NAME = MEMBER, MEMBER, …
//	User_spec   := USER  HOST=(RUNAS) [TAG:] CMND, CMND, …
//	Defaults    := Defaults[@host] KEY[=VALUE] [, KEY[=VALUE], …]
//	Include     := @includedir PATH | #includedir PATH | @include PATH | #include PATH
//
// We DON'T resolve aliases (an audit rule that wants "is alice in the
// User_Alias for ADMINS?" does the resolution at query time against
// the alias rows). We DO compute the security-relevant booleans
// (is_passwordless, is_total_privilege) per user-spec.
func Parse(raw []byte, filePath string) []Entry {
	hash := HashContents(raw)
	text := string(raw)
	lines := splitMergeContinuations(text)

	out := make([]Entry, 0, len(lines))
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// sudo include directives are written as `#include` or `#includedir`
		// — they look like comments but aren't.
		if strings.HasPrefix(trimmed, "#") &&
			!strings.HasPrefix(trimmed, "#include") {
			continue
		}

		entry := parseLine(trimmed)
		entry.FilePath = filePath
		entry.FileHash = hash
		entry.LineNo = i + 1
		entry.RawLine = collapseWhitespace(trimmed)
		out = append(out, entry)
		if len(out) >= MaxEntries {
			break
		}
	}
	return out
}

// parseLine routes a single trimmed line to the right sub-parser based
// on its leading token.
func parseLine(line string) Entry {
	switch {
	case strings.HasPrefix(line, "Defaults"):
		return parseDefaults(line)
	case strings.HasPrefix(line, "User_Alias"):
		return parseAlias(line, "User_Alias", EntryUserAlias)
	case strings.HasPrefix(line, "Runas_Alias"):
		return parseAlias(line, "Runas_Alias", EntryRunasAlias)
	case strings.HasPrefix(line, "Host_Alias"):
		return parseAlias(line, "Host_Alias", EntryHostAlias)
	case strings.HasPrefix(line, "Cmnd_Alias"), strings.HasPrefix(line, "Cmd_Alias"):
		kw := "Cmnd_Alias"
		if strings.HasPrefix(line, "Cmd_Alias") {
			kw = "Cmd_Alias"
		}
		return parseAlias(line, kw, EntryCmndAlias)
	case strings.HasPrefix(line, "@include"), strings.HasPrefix(line, "#include"):
		return parseInclude(line)
	}
	// Fall through: try a user-spec.
	return parseUserSpec(line)
}

// parseDefaults parses `Defaults[@host] key[=value][, key[=value]]…`.
// Multi-key Defaults lines emit a single Entry with the first key/value
// captured + the raw line preserved — the audit pipeline can re-parse
// when it needs every pair. The first key being security-relevant is
// what we index for the partial-index fast path.
func parseDefaults(line string) Entry {
	// Strip the `Defaults` prefix + optional `@host` qualifier.
	rest := strings.TrimSpace(strings.TrimPrefix(line, "Defaults"))
	if strings.HasPrefix(rest, "@") {
		// Skip until the next whitespace token.
		if i := strings.IndexAny(rest, " \t"); i >= 0 {
			rest = strings.TrimSpace(rest[i:])
		}
	}
	// Strip leading `:user` form (Defaults:user …) similarly.
	if strings.HasPrefix(rest, ":") {
		if i := strings.IndexAny(rest, " \t"); i >= 0 {
			rest = strings.TrimSpace(rest[i:])
		}
	}

	// First key/value pair drives the indexed columns.
	first := firstCSV(rest)
	key, val := splitKV(first)
	e := Entry{
		EntryType:     EntryDefaults,
		DefaultsKey:   key,
		DefaultsValue: val,
	}
	if IsDangerousDefault(key) || strings.HasPrefix(key, "!") {
		e.IsDangerousDefault = true
	}
	return e
}

// parseAlias parses `<Kind>_Alias NAME = m1, m2, …`.
func parseAlias(line, kw string, entryType EntryType) Entry {
	rest := strings.TrimSpace(strings.TrimPrefix(line, kw))
	eq := strings.IndexByte(rest, '=')
	if eq < 0 {
		return Entry{EntryType: EntryUnknown}
	}
	name := strings.TrimSpace(rest[:eq])
	members := splitCommaTrim(rest[eq+1:])
	sortStrings(members)
	return Entry{
		EntryType:    entryType,
		AliasName:    name,
		AliasMembers: members,
	}
}

// parseInclude parses `@includedir DIR` / `#include FILE` etc.
func parseInclude(line string) Entry {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Entry{EntryType: EntryInclude}
	}
	return Entry{
		EntryType:    EntryInclude,
		IncludesPath: fields[1],
	}
}

// parseUserSpec parses `USER HOST=(RUNAS:GROUP) [TAG:]... CMND, CMND…`.
//
// Examples:
//
//	alice    ALL=(ALL:ALL) NOPASSWD: ALL
//	%sudo    ALL=(ALL)     ALL
//	%dev     ALL=(root)    NOPASSWD: /usr/bin/systemctl restart nginx
//	bot      web1,web2=(srv) SETENV: /opt/bin/deploy
//
// The grammar's official form is messy because hosts can be a list and
// commands can have `:`-tag prefixes. We split on `=` to separate the
// principal from the rest, then walk the right-hand side token-by-token.
func parseUserSpec(line string) Entry {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return Entry{EntryType: EntryUnknown}
	}
	lhs := strings.TrimSpace(line[:eq])
	rhs := strings.TrimSpace(line[eq+1:])

	// LHS: principal + host list. Split on first whitespace.
	var principal, hosts string
	if i := strings.IndexAny(lhs, " \t"); i >= 0 {
		principal = strings.TrimSpace(lhs[:i])
		hosts = collapseWhitespace(strings.TrimSpace(lhs[i:]))
	} else {
		// Bare principal with no host? Treat principal as principal.
		principal = lhs
	}

	e := Entry{
		EntryType: EntryUserSpec,
		Principal: principal,
		Hosts:     hosts,
	}

	// RHS: optional (runas[:group]) then optional TAG: prefixes then commands.
	rest := rhs
	if strings.HasPrefix(rest, "(") {
		end := strings.IndexByte(rest, ')')
		if end > 0 {
			runas := rest[1:end]
			if colon := strings.IndexByte(runas, ':'); colon >= 0 {
				e.RunasUser = strings.TrimSpace(runas[:colon])
				e.RunasGroup = strings.TrimSpace(runas[colon+1:])
			} else {
				e.RunasUser = strings.TrimSpace(runas)
			}
			rest = strings.TrimSpace(rest[end+1:])
		}
	}

	// TAG: prefixes. Tags are uppercase keywords like NOPASSWD, SETENV,
	// NOEXEC, LOG_INPUT, LOG_OUTPUT, MAIL, FOLLOW, NOTBEFORE=date,
	// TIMEOUT=duration. They may chain: "NOPASSWD: SETENV: /bin/ls".
	for {
		colon := strings.IndexByte(rest, ':')
		if colon < 0 {
			break
		}
		head := strings.TrimSpace(rest[:colon])
		if !isTag(head) {
			break
		}
		e.Tags = append(e.Tags, head)
		if head == "NOPASSWD" {
			e.IsPasswordless = true
		}
		rest = strings.TrimSpace(rest[colon+1:])
	}

	// Commands: comma-separated. The literal token "ALL" means "any
	// command" — combined with hosts=ALL + runas=ALL it's total
	// privilege.
	e.Commands = splitCommaTrim(rest)
	sortStrings(e.Commands)
	e.IsTotalPrivilege = isTotalPrivilege(e)
	return e
}

// isTag reports whether s looks like a sudo tag keyword. Tags are
// ALL-CAPS letters with optional "=value" payloads.
func isTag(s string) bool {
	if s == "" {
		return false
	}
	// Allow tag=value form (TIMEOUT=5m).
	if i := strings.IndexByte(s, '='); i > 0 {
		s = s[:i]
	}
	for _, r := range s {
		if (r < 'A' || r > 'Z') && r != '_' {
			return false
		}
	}
	return true
}

// isTotalPrivilege reports whether the user-spec grants unrestricted
// root-equivalent power. The canonical pattern is `ALL=(ALL[:ALL]) ALL`.
func isTotalPrivilege(e Entry) bool {
	if e.Hosts != "ALL" && e.Hosts != "" {
		// Empty hosts means the original line had no host before '=' —
		// unusual but treat conservatively as non-total.
		if e.Hosts != "ALL" {
			return false
		}
	}
	if e.RunasUser != "" && e.RunasUser != "ALL" {
		return false
	}
	if len(e.Commands) != 1 {
		return false
	}
	return e.Commands[0] == "ALL"
}

// splitMergeContinuations splits text into lines, merging any line that
// ends with `\` into the next. Continuations are common in sudoers
// drop-in files generated by configuration-management tools.
func splitMergeContinuations(text string) []string {
	rawLines := strings.Split(text, "\n")
	out := make([]string, 0, len(rawLines))
	var pending strings.Builder
	for _, line := range rawLines {
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, "\\") {
			// Drop the backslash plus any whitespace immediately before
			// it — we'll insert exactly one separator space below.
			body := strings.TrimRight(trimmed[:len(trimmed)-1], " \t")
			pending.WriteString(body)
			pending.WriteByte(' ')
			continue
		}
		if pending.Len() > 0 {
			// Trim leading whitespace: continuation lines are usually
			// indented for readability, but we already inserted a single
			// separating space when consuming the backslash.
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

// splitKV splits `key=value` (or `!key`) into its parts.
//
//	"timestamp_timeout=30"  → ("timestamp_timeout", "30")
//	"!requiretty"           → ("!requiretty", "")
//	"env_keep += \"FOO\""   → ("env_keep", `+= "FOO"`)
func splitKV(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if i := strings.IndexAny(s, "=+-"); i > 0 {
		// `key += value` is a sudoers operator — keep the operator in
		// the value side, key is just the bare identifier.
		key := strings.TrimSpace(s[:i])
		val := strings.TrimSpace(s[i:])
		val = strings.TrimPrefix(val, "=")
		val = strings.TrimSpace(val)
		return key, val
	}
	return s, ""
}

// firstCSV returns the part of s before the first unquoted comma.
func firstCSV(s string) string {
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if c == ',' && !inQuote {
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}

// splitCommaTrim splits on comma and trims each element. Quoted
// commas are preserved.
func splitCommaTrim(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			cur.WriteByte(c)
			continue
		}
		if c == ',' && !inQuote {
			if t := strings.TrimSpace(cur.String()); t != "" {
				out = append(out, t)
			}
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if t := strings.TrimSpace(cur.String()); t != "" {
		out = append(out, t)
	}
	return out
}

// collapseWhitespace normalises tabs+spaces into single spaces. Used
// for the raw_line column so visual diffs across scans don't trigger
// false drift events on cosmetic re-formats.
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

// sortStrings is a tiny dep-free in-place insertion sort.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j-1] > s[j] {
			s[j-1], s[j] = s[j], s[j-1]
			j--
		}
	}
}
