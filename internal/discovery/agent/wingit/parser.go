package wingit

import (
	"bufio"
	"bytes"
	"strings"
)

// ParseGitConfig walks a git config file body and emits one
// Entry per `key = value` line. Git config uses INI with
// subsection support — `[remote "origin"]` becomes section
// "remote", subsection "origin". The normalised `Key` is
// `section.subsection.name` (lowercased) so it matches the
// `git config --get` namespace.
func ParseGitConfig(body []byte) []Entry {
	out := make([]Entry, 0, 16)
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)

	section := ""
	subsection := ""
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section, subsection = parseSectionHeader(line[1 : len(line)-1])
			continue
		}
		key, value, ok := splitKV(line)
		if !ok || section == "" {
			continue
		}
		entry := Entry{
			EntryKind:  EntryKindSetting,
			Section:    strings.ToLower(section),
			Subsection: subsection,
			Key:        normaliseKey(section, subsection, key),
			Value:      value,
		}
		out = append(out, entry)
		if len(out) >= MaxRows {
			return out
		}
	}
	return out
}

// parseSectionHeader splits an INI section header. Git permits
// two subsection notations:
//
//	[remote "origin"]    → section=remote, subsection=origin
//	[remote.origin]      → section=remote, subsection=origin (deprecated)
//
// Plain `[core]` yields ("core", "").
func parseSectionHeader(s string) (string, string) {
	t := strings.TrimSpace(s)
	// Quoted-subsection form.
	if i := strings.IndexByte(t, '"'); i >= 0 {
		section := strings.TrimSpace(t[:i])
		rest := t[i:]
		// Strip leading + trailing `"`.
		rest = strings.TrimPrefix(rest, `"`)
		rest = strings.TrimSuffix(rest, `"`)
		return section, rest
	}
	// Dotted-subsection form.
	if i := strings.IndexByte(t, '.'); i > 0 {
		return strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+1:])
	}
	return t, ""
}

// normaliseKey returns "section.subsection.name" (lowercased on
// section + name; subsection is case-preserved per git's rules).
func normaliseKey(section, subsection, name string) string {
	section = strings.ToLower(strings.TrimSpace(section))
	name = strings.ToLower(strings.TrimSpace(name))
	if subsection == "" {
		return section + "." + name
	}
	return section + "." + subsection + "." + name
}

// splitKV separates `key = value`. Git config accepts trailing
// inline `;` and `#` comments — we strip them while respecting
// double-quoted values.
func splitKV(line string) (string, string, bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		// A bare key with no `=` is a boolean-true shortcut in
		// git config. Emit `key = true`.
		key := strings.TrimSpace(line)
		if key == "" {
			return "", "", false
		}
		return key, "true", true
	}
	key := strings.TrimSpace(line[:i])
	value := strings.TrimSpace(stripInlineComment(line[i+1:]))
	// Unquote double-quoted values.
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	return key, value, true
}

// stripInlineComment removes `#`/`;` tails outside double quotes.
func stripInlineComment(s string) string {
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQ = !inQ
			continue
		}
		if !inQ && (c == '#' || c == ';') {
			return s[:i]
		}
	}
	return s
}

// ParseGitCredentialsStore walks a `~/.git-credentials` body and
// emits one Entry per non-comment, non-blank line. Each line is
// a URL of the form `https://user:token@host/path` — we record
// the host (the credential location) and the entry kind, never
// the secret.
func ParseGitCredentialsStore(body []byte) []Entry {
	out := make([]Entry, 0, 4)
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host := CredentialRecordHost(line)
		if host == "" {
			continue
		}
		out = append(out, Entry{
			EntryKind: EntryKindCredentialRecord,
			Key:       "credential." + host,
			Value:     host,
		})
		if len(out) >= MaxRows {
			return out
		}
	}
	return out
}
