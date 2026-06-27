package winnpmrc

import (
	"bufio"
	"bytes"
	"strings"
)

// ParseNpmrc walks one `.npmrc` file body and emits one Entry
// per `key = value` line. npm's grammar is plain `key = value`
// per line with `#` and `;` comments; no sections.
func ParseNpmrc(body []byte) []Entry {
	out := make([]Entry, 0, 8)
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := splitKV(line)
		if !ok {
			continue
		}
		e := classifyEntry(key, value)
		out = append(out, e)
		if len(out) >= MaxEntries {
			return out
		}
	}
	return out
}

// classifyEntry inspects the key shape to assign EntryKind +
// auxiliary fields (registry_host, scope). Secrets are NOT
// stored verbatim — for auth tokens we keep only the
// AuthTokenPrefix (4 chars) so the audit pipeline can
// distinguish `npm_…` vs `oauth_…` vs `ghp_…` without holding
// the secret.
func classifyEntry(key, value string) Entry {
	e := Entry{Key: key, Value: value}
	switch {
	case strings.HasPrefix(key, "//"):
		host := RegistryHostFromKey(key)
		setting := strings.ToLower(SettingFromKey(key))
		e.RegistryHost = host
		switch setting {
		case "_authtoken", "_auth":
			e.EntryKind = EntryAuthToken
			// Replace token with its 4-char family prefix.
			e.Value = AuthTokenPrefix(value)
		case "_password":
			e.EntryKind = EntryPassword
			e.Value = "" // never persist
		case "username":
			e.EntryKind = EntryUsername
		case "always-auth", "email":
			e.EntryKind = EntrySetting
		default:
			e.EntryKind = EntrySetting
		}
	case strings.HasPrefix(key, "@"):
		// `@scope:registry=https://...` — scoped-registry override.
		e.EntryKind = EntryScopeRegistry
		if i := strings.IndexByte(key, ':'); i > 0 {
			e.Scope = key[:i]
		}
	case strings.EqualFold(key, "registry"):
		e.EntryKind = EntryRegistry
	default:
		e.EntryKind = EntrySetting
	}
	return e
}

// splitKV separates `key = value` (whitespace tolerated around
// `=`). Bare keys without `=` get value "true" (npm's boolean
// shortcut).
func splitKV(line string) (string, string, bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		key := strings.TrimSpace(line)
		if key == "" {
			return "", "", false
		}
		return key, "true", true
	}
	key := strings.TrimSpace(line[:i])
	value := strings.TrimSpace(line[i+1:])
	if key == "" {
		return "", "", false
	}
	// Strip outer double-quotes around values.
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	return key, value, true
}
