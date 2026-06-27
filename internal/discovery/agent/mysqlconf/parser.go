package mysqlconf

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// ParseResult bundles the section rows extracted from one my.cnf
// body and the !include / !includedir directives we should follow
// next. The collector handles recursion; the parser stays pure.
type ParseResult struct {
	Rows        []Row
	Includes    []string
	IncludeDirs []string
}

// Parse walks one my.cnf body. `filePath` is recorded verbatim into
// every Row and does not have to exist on disk.
func Parse(raw []byte, filePath string) ParseResult {
	hash := HashContents(raw)
	res := ParseResult{}

	var current *Row
	finalize := func() {
		if current == nil {
			return
		}
		AnnotateSecurity(current)
		res.Rows = append(res.Rows, *current)
		current = nil
	}

	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || isComment(line) {
			continue
		}
		// !include / !includedir don't belong to any section; they
		// run regardless of where they appear in the file.
		if strings.HasPrefix(line, "!include ") {
			res.Includes = append(res.Includes, strings.TrimSpace(line[len("!include "):]))
			continue
		}
		if strings.HasPrefix(line, "!includedir ") {
			res.IncludeDirs = append(res.IncludeDirs, strings.TrimSpace(line[len("!includedir "):]))
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			finalize()
			if len(res.Rows) >= MaxRows {
				return res
			}
			name := strings.TrimSpace(line[1 : len(line)-1])
			kind := NormalizeSectionKind(name)
			current = &Row{
				FilePath:    filePath,
				FileHash:    hash,
				SectionName: name,
				SectionKind: kind,
				// MySQL 8 defaults secure_file_priv to a scoped dir;
				// MariaDB leaves it empty (= unrestricted). We can't
				// tell the binary apart from the config alone, so we
				// pessimise the default: assume unrestricted unless
				// the operator explicitly sets the directive.
				HasUnrestrictedSecureFilePriv: kind == SectionServer,
			}
			continue
		}
		if current == nil {
			continue
		}
		applyDirective(current, line)
	}
	finalize()
	return res
}

// applyDirective routes a single key[=value] or boolean-shortcut
// line into the active Row's fields.
func applyDirective(r *Row, line string) {
	// Trim inline `#`/`;` comments.
	if i := indexOfInlineComment(line); i >= 0 {
		line = strings.TrimRight(line[:i], " \t")
	}
	key, value, present := splitKV(line)
	canonical := normalizeKey(key)

	// Boolean-shortcut handling: `skip-grant-tables` alone is
	// equivalent to `skip-grant-tables = 1`.
	if !present {
		value = "1"
	}
	value = unquote(strings.TrimSpace(value))

	switch r.SectionKind {
	case SectionServer:
		applyServer(r, canonical, value, present)
	case SectionClient:
		applyClient(r, canonical, value)
	case SectionCommon, SectionUnknown:
		// Some installs put bind-address etc into [client-server];
		// route through the server applier as well.
		applyServer(r, canonical, value, present)
	}
}

func applyServer(r *Row, key, value string, present bool) {
	switch key {
	case "bind_address":
		r.BindAddress = value
	case "port":
		if n, err := strconv.Atoi(value); err == nil {
			r.Port = n
		}
	case "socket":
		r.SocketPath = value
	case "datadir":
		r.Datadir = value
	case "user":
		r.UserName = value
	case "secure_file_priv":
		r.SecureFilePriv = value
		r.HasUnrestrictedSecureFilePriv = IsUnrestrictedSecureFilePriv(value, present)
	case "tls_version":
		r.TLSVersion = value
	case "log_error":
		r.LogErrorPath = value
	case "general_log":
		r.GeneralLog = value
	case "plugin_load", "plugin_load_add":
		if r.PluginLoad == "" {
			r.PluginLoad = value
		} else {
			r.PluginLoad += ";" + value
		}
	case "skip_grant_tables":
		r.IsGrantTablesSkipped = IsBoolTrue(value)
	case "skip_networking":
		r.IsNetworkingSkipped = IsBoolTrue(value)
	case "skip_name_resolve":
		r.IsNameResolveSkipped = IsBoolTrue(value)
	case "local_infile":
		r.IsLocalInfileEnabled = IsBoolTrue(value)
	case "require_secure_transport":
		r.IsSecureTransportRequired = IsBoolTrue(value)
	}
}

func applyClient(r *Row, key, value string) {
	switch key {
	case "password":
		r.HasCleartextClientPassword = strings.TrimSpace(value) != ""
	case "user":
		r.UserName = value
	case "host":
		r.BindAddress = value
	case "port":
		if n, err := strconv.Atoi(value); err == nil {
			r.Port = n
		}
	case "socket":
		r.SocketPath = value
	}
}

// splitKV separates `key = value`. MySQL accepts `key=value`,
// `key = value`, and bare `key` (boolean shortcut). When no `=` is
// present, returns (key, "", false).
func splitKV(line string) (key, value string, present bool) {
	if i := strings.IndexByte(line, '='); i > 0 {
		return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
	}
	return strings.TrimSpace(line), "", false
}

// normalizeKey collapses MySQL's dash/underscore tolerance and
// case-insensitivity: `skip-grant-tables`, `skip_grant_tables`,
// `SKIP-GRANT-TABLES` all canonicalise to `skip_grant_tables`.
func normalizeKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.ReplaceAll(s, "-", "_")
}

// isComment reports whether a trimmed line is purely a comment.
func isComment(line string) bool {
	return strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";")
}

// indexOfInlineComment finds the first `#` or `;` that begins an
// inline comment, respecting double-quoted strings. Returns -1 if
// the line carries no comment.
func indexOfInlineComment(line string) int {
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && (c == '#' || c == ';') {
			return i
		}
	}
	return -1
}

// unquote strips outer single- or double-quotes from a value if
// present.
func unquote(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
