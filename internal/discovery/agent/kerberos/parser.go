package kerberos

import (
	"bufio"
	"bytes"
	"strings"
)

// Parse walks a krb5.conf body. The grammar (per krb5.conf(5)) is
// INI-like with **nested** sections:
//
//	[libdefaults]
//	    default_realm = EXAMPLE.COM
//	    dns_lookup_realm = false
//	    ticket_lifetime = 24h
//
//	[realms]
//	    EXAMPLE.COM = {
//	        kdc = kdc1.example.com
//	        kdc = kdc2.example.com
//	        admin_server = admin.example.com
//	    }
//
//	[domain_realm]
//	    .example.com = EXAMPLE.COM
//
// `[realms]/EXAMPLE.COM/{...}` nesting is what makes a naive INI
// parser wrong here — we maintain a (section, realm) state pair
// so each kdc/admin_server inside the brace block surfaces with its
// realm context attached.
func Parse(raw []byte, filePath string) []Setting {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var (
		section Section
		realm   string
		inBrace bool
		out     []Setting
	)
	for i, line := range lines {
		clean := stripComment(line)
		trimmed := strings.TrimSpace(clean)
		if trimmed == "" {
			continue
		}
		// Top-level [section] header.
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = normalizeSection(strings.Trim(trimmed, "[]"))
			realm = ""
			inBrace = false
			continue
		}
		// Brace close terminates a realm sub-block.
		if trimmed == "}" {
			realm = ""
			inBrace = false
			continue
		}
		// Realm-opening line: `EXAMPLE.COM = {`. Sometimes formatted
		// as just `EXAMPLE.COM = {` on one line, sometimes with the
		// brace alone on the next line.
		if section == SectionRealms && !inBrace {
			r, openBrace, ok := parseRealmHeader(trimmed)
			if ok {
				realm = r
				inBrace = openBrace
				continue
			}
		}
		// Standalone `{` on its own line — open brace deferred from the
		// preceding realm header.
		if trimmed == "{" && realm != "" {
			inBrace = true
			continue
		}
		// Regular `key = value` directive.
		key, value, ok := splitKV(trimmed)
		if !ok {
			continue
		}
		s := Setting{
			Section:  section,
			Realm:    realm,
			Key:      key,
			Value:    value,
			FilePath: filePath,
			FileHash: hash,
			LineNo:   i + 1,
			RawLine:  collapseWhitespace(trimmed),
		}
		AnnotateSecurity(&s)
		out = append(out, s)
		if len(out) >= MaxSettings {
			break
		}
	}
	return out
}

// parseRealmHeader detects `REALM = {` and returns (realm, openBrace, ok).
// openBrace=true means the brace was on the same line; otherwise the
// caller should treat the next `{` line as the block open.
func parseRealmHeader(line string) (string, bool, bool) {
	// Strip trailing brace (with possible space).
	openBrace := false
	if strings.HasSuffix(line, "{") {
		openBrace = true
		line = strings.TrimSpace(strings.TrimSuffix(line, "{"))
		line = strings.TrimSpace(strings.TrimSuffix(line, "="))
	} else if !strings.Contains(line, "=") {
		return "", false, false
	} else if strings.HasSuffix(line, "=") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "="))
	} else {
		// `KEY = value` rather than `REALM = {`.
		return "", false, false
	}
	if line == "" {
		return "", false, false
	}
	// Realm names are conventionally uppercase A-Z + . + dashes.
	return line, openBrace, true
}

func normalizeSection(s string) Section {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "libdefaults":
		return SectionLibdefaults
	case "realms":
		return SectionRealms
	case "domain_realm":
		return SectionDomainRealm
	case "appdefaults":
		return SectionAppdefaults
	case "capaths":
		return SectionCAPaths
	case "plugins":
		return SectionPlugins
	case "logging":
		return SectionLogging
	case "login":
		return SectionLogin
	}
	return SectionUnknown
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

// stripComment removes trailing `#`/`;` comments. krb5.conf accepts
// both per krb5.conf(5).
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
