package rsyslog

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// Parse walks one rsyslog config-file body and returns a slice of
// Forwarder rows. We handle both grammars:
//
//   - Legacy single-line:  `*.* @host:514` (UDP) or `@@host:6514` (TCP).
//   - Modern action() block (possibly multi-line):
//     action(type="omfwd" target="host" port="6514" protocol="tcp"
//     StreamDriver="gtls")
//
// Multi-line action() blocks are folded into one logical line by
// scanning for the matching `)`. Comment lines (# leader) and module
// loads are ignored.
func Parse(raw []byte, filePath string) []Forwarder {
	hash := HashContents(raw)
	logical := joinActionBlocks(raw)

	out := make([]Forwarder, 0, 4)
	scan := bufio.NewScanner(bytes.NewReader(logical))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	lineNo := 0
	for scan.Scan() {
		lineNo++
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if f, ok := parseActionBlock(line); ok {
			f.FilePath = filePath
			f.FileHash = hash
			f.LineNo = lineNo
			AnnotateSecurity(&f)
			out = append(out, f)
			if len(out) >= MaxRows {
				return out
			}
			continue
		}
		if f, ok := parseLegacyDirective(line); ok {
			f.FilePath = filePath
			f.FileHash = hash
			f.LineNo = lineNo
			AnnotateSecurity(&f)
			out = append(out, f)
			if len(out) >= MaxRows {
				return out
			}
		}
	}
	return out
}

// joinActionBlocks normalises multi-line `action(...)` blocks into
// one logical line each. We walk byte-by-byte tracking parenthesis
// depth — when depth > 0 we replace newlines with spaces.
func joinActionBlocks(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	depth := 0
	for _, b := range raw {
		switch b {
		case '(':
			depth++
			out = append(out, b)
		case ')':
			if depth > 0 {
				depth--
			}
			out = append(out, b)
		case '\n':
			if depth > 0 {
				out = append(out, ' ')
			} else {
				out = append(out, b)
			}
		default:
			out = append(out, b)
		}
	}
	return out
}

// parseLegacyDirective handles the `SELECTOR @host[:port]` style.
// Returns ok=false for anything else (module loads, ruleset
// definitions, expressions).
func parseLegacyDirective(line string) (Forwarder, bool) {
	// Skip lines that don't contain a forwarder marker.
	atIdx := indexUnquoted(line, '@')
	if atIdx < 0 {
		return Forwarder{}, false
	}
	// Tokenise the selector + action.
	selector, rest := splitFirstField(line)
	if rest == "" || !strings.HasPrefix(rest, "@") {
		return Forwarder{}, false
	}
	kind := KindLegacyUDP
	transport := "udp"
	addr := rest[1:]
	if strings.HasPrefix(addr, "@") {
		kind = KindLegacyTCP
		transport = "tcp"
		addr = addr[1:]
	}
	// Strip any trailing tokens (eg. `;RSYSLOG_TraditionalFileFormat`).
	if i := strings.IndexAny(addr, " \t;"); i >= 0 {
		addr = addr[:i]
	}
	host, port := splitHostPort(addr)
	return Forwarder{
		RawDirective:      line,
		DirectiveKind:     kind,
		Selector:          selector,
		Destination:       host,
		DestinationPort:   port,
		TransportProtocol: transport,
	}, true
}

// parseActionBlock handles `action(type="..." key="value" ...)`.
// Only `omfwd` and `omhttp` produce forwarder rows; other action
// types (omfile, omkafka — we could extend later) return ok=false.
func parseActionBlock(line string) (Forwarder, bool) {
	open := indexUnquoted(line, '(')
	close := lastIndexByte(line, ')')
	if open < 0 || close < 0 || close < open {
		return Forwarder{}, false
	}
	prefix := strings.ToLower(strings.TrimSpace(line[:open]))
	if prefix != "action" {
		return Forwarder{}, false
	}
	body := line[open+1 : close]
	kv := parseKVPairs(body)
	t := strings.ToLower(kv["type"])
	switch t {
	case "omfwd":
		host := firstNonEmpty(kv["target"], kv["address"])
		port := parsePortString(kv["port"])
		return Forwarder{
			RawDirective:      line,
			DirectiveKind:     KindActionOmfwd,
			Destination:       host,
			DestinationPort:   port,
			TransportProtocol: firstNonEmpty(kv["protocol"], "tcp"),
			TLSDriver:         kv["streamdriver"],
			QueueType:         kv["queue.type"],
		}, true
	case "omhttp":
		dst := firstNonEmpty(kv["server"], kv["serverurl"], kv["url"])
		return Forwarder{
			RawDirective:      line,
			DirectiveKind:     KindActionOmhttp,
			Destination:       dst,
			TransportProtocol: "https",
		}, true
	}
	return Forwarder{}, false
}

// parseKVPairs returns the `key="value"` pairs inside an action()
// body. Keys are lowercased; values keep their case. Bare booleans
// (`omfwd_TCP_force_force=true`) are accepted as `"true"`.
func parseKVPairs(body string) map[string]string {
	out := make(map[string]string, 8)
	tokens := tokenize(body)
	for _, t := range tokens {
		eq := strings.IndexByte(t, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(t[:eq]))
		val := strings.TrimSpace(t[eq+1:])
		val = strings.Trim(val, `"`)
		out[key] = val
	}
	return out
}

// tokenize splits a whitespace-separated string while respecting
// double-quoted segments (values may contain spaces).
func tokenize(s string) []string {
	out := make([]string, 0, 4)
	var sb strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQ = !inQ
			sb.WriteByte(c)
		case (c == ' ' || c == '\t' || c == ',' || c == '\n') && !inQ:
			if sb.Len() > 0 {
				out = append(out, sb.String())
				sb.Reset()
			}
		default:
			sb.WriteByte(c)
		}
	}
	if sb.Len() > 0 {
		out = append(out, sb.String())
	}
	return out
}

// splitFirstField returns the first whitespace-delimited token and
// the remaining trimmed string.
func splitFirstField(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return s[:i], strings.TrimLeft(s[i:], " \t")
		}
	}
	return s, ""
}

// splitHostPort returns (host, port) from `host:port` or (host, 0)
// if no port is set. IPv6 brackets are stripped.
func splitHostPort(s string) (string, int) {
	if s == "" {
		return "", 0
	}
	// Handle bracketed IPv6: `[::1]:514`.
	if strings.HasPrefix(s, "[") {
		if end := strings.IndexByte(s, ']'); end > 0 {
			host := s[1:end]
			rest := s[end+1:]
			if strings.HasPrefix(rest, ":") {
				if n, err := strconv.Atoi(rest[1:]); err == nil {
					return host, n
				}
			}
			return host, 0
		}
	}
	if i := strings.LastIndexByte(s, ':'); i > 0 {
		if n, err := strconv.Atoi(s[i+1:]); err == nil {
			return s[:i], n
		}
	}
	return s, 0
}

func parsePortString(s string) int {
	if s == "" {
		return 0
	}
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return 0
}

// indexUnquoted returns the first index of `c` in `s` that isn't
// inside double-quoted content. Returns -1 if not found.
func indexUnquoted(s string, c byte) int {
	inQ := false
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			inQ = !inQ
			continue
		}
		if !inQ && s[i] == c {
			return i
		}
	}
	return -1
}

// lastIndexByte mirrors strings.LastIndexByte but is named locally
// for readability alongside indexUnquoted.
func lastIndexByte(s string, c byte) int {
	return strings.LastIndexByte(s, c)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
