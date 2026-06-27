package redisconf

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// Parse walks one redis.conf body and returns a populated Config.
// `filePath` is recorded verbatim into the Config; it does not need
// to exist on disk (collector-injected for tests).
//
// Grammar (from redis-cli docs):
//
//	# comment
//	bind 127.0.0.1 ::1
//	port 6379
//	requirepass "value with spaces"
//	include /etc/redis/local.conf
//
// Directives are whitespace-tokenised, one per line. Quoted values
// (`"..."`) preserve spaces; we strip the outer quotes only.
func Parse(raw []byte, filePath string) Config {
	out := Config{
		FilePath:               filePath,
		FileHash:               HashContents(raw),
		ConfigRole:             NormalizeRole(filePath),
		IsProtectedModeEnabled: true, // redis-server default since 3.2
	}

	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, rest := splitFirstToken(line)
		switch strings.ToLower(key) {
		case "bind":
			out.BindAddresses = append(out.BindAddresses, parseBindList(rest)...)
		case "port":
			if n, err := strconv.Atoi(strings.TrimSpace(rest)); err == nil {
				out.Port = n
			}
		case "tls-port":
			if n, err := strconv.Atoi(strings.TrimSpace(rest)); err == nil {
				out.TLSPort = n
			}
		case "protected-mode":
			out.IsProtectedModeEnabled = parseYesNo(rest, true)
		case "requirepass":
			out.Requirepass = unquote(strings.TrimSpace(rest))
		case "masterauth":
			out.MasterauthPresent = strings.TrimSpace(rest) != ""
		case "dir":
			out.Dir = unquote(strings.TrimSpace(rest))
		case "dbfilename":
			out.DBFilename = unquote(strings.TrimSpace(rest))
		case "appendonly":
			out.AppendOnly = strings.TrimSpace(rest)
		case "appendfilename":
			out.AppendFilename = unquote(strings.TrimSpace(rest))
		case "aclfile":
			out.ACLFile = unquote(strings.TrimSpace(rest))
		case "rename-command":
			if from, to, ok := splitRename(rest); ok {
				out.RenamedCommands = append(out.RenamedCommands, RenamedCommand{From: from, To: to})
			}
		case "include":
			if p := unquote(strings.TrimSpace(rest)); p != "" {
				out.Includes = append(out.Includes, p)
			}
		}
	}
	AnnotateSecurity(&out)
	return out
}

// splitFirstToken splits a line into its first whitespace-token and
// the trailing remainder.
func splitFirstToken(line string) (string, string) {
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' || line[i] == '\t' {
			return line[:i], strings.TrimLeft(line[i:], " \t")
		}
	}
	return line, ""
}

// parseBindList tokenises the value side of a `bind` directive. The
// grammar permits multiple addresses on one line separated by
// whitespace. A trailing `-::*` style suffix is dropped — that's a
// Redis 7+ "optional" annotation, not an address.
func parseBindList(value string) []string {
	out := make([]string, 0, 2)
	for _, tok := range strings.Fields(value) {
		tok = strings.TrimSpace(tok)
		// Drop the optional "::*"-suffix marker for IPv6 fallback.
		tok = strings.TrimSuffix(tok, "-::*")
		if tok == "" {
			continue
		}
		out = append(out, tok)
	}
	return out
}

// parseYesNo maps "yes"/"no" to true/false. Anything else falls
// back to `def`.
func parseYesNo(s string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yes", "true", "on", "1":
		return true
	case "no", "false", "off", "0":
		return false
	}
	return def
}

// splitRename tokenises `rename-command FROM TO`. `TO` may be the
// empty quoted string ("") meaning the command is disabled.
func splitRename(value string) (string, string, bool) {
	fields := tokenize(value)
	if len(fields) < 2 {
		return "", "", false
	}
	return strings.ToUpper(fields[0]), unquote(fields[1]), true
}

// tokenize splits a whitespace-separated line while respecting
// quoted segments (`"value with spaces"`).
func tokenize(value string) []string {
	out := make([]string, 0, 4)
	var sb strings.Builder
	inQuotes := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == '"':
			inQuotes = !inQuotes
			sb.WriteByte(c)
		case (c == ' ' || c == '\t') && !inQuotes:
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

// unquote strips outer double-quotes from a token if present.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
