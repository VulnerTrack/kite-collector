package pghba

import (
	"bufio"
	"bytes"
	"strings"
)

// Parse walks one pg_hba.conf body. Grammar per pg_hba.conf(5):
//
//	# comment
//	local      DATABASE  USER             METHOD [OPTIONS]
//	host       DATABASE  USER  ADDRESS    METHOD [OPTIONS]
//	hostssl    DATABASE  USER  ADDRESS    METHOD [OPTIONS]
//	hostnossl  DATABASE  USER  ADDRESS    METHOD [OPTIONS]
//	hostgssenc DATABASE  USER  ADDRESS    METHOD [OPTIONS]
//	hostnogssenc DATABASE USER ADDRESS    METHOD [OPTIONS]
//
// `local` has 4 mandatory columns, `host*` has 5. We tolerate
// continuation lines (`\` at EOL) the same way PostgreSQL does;
// they're rare but allowed. ADDRESS may be a CIDR (10.0.0.0/24),
// hostname, or one of the wildcards "all" / "samehost" / "samenet".
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
		r, ok := parseLine(clean)
		if !ok {
			continue
		}
		r.FilePath = filePath
		r.FileHash = hash
		r.LineNo = i + 1
		r.RawLine = collapseWhitespace(clean)
		AnnotateSecurity(&r)
		out = append(out, r)
		if len(out) >= MaxRows {
			break
		}
	}
	return out
}

// parseLine tokenises one rule. The format is whitespace-separated;
// we don't try to honour quoted database/user lists because the
// quoting rules are rare enough that we'd rather surface the raw
// line for forensic queries than risk mis-parsing.
func parseLine(line string) (Row, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Row{}, false
	}
	r := Row{ConnectionType: NormalizeConnectionType(fields[0])}
	if r.ConnectionType == ConnectionUnknown {
		return Row{}, false
	}
	r.Database = fields[1]
	r.DBRole = fields[2]

	if r.ConnectionType == ConnectionLocal {
		// local DATABASE USER METHOD [OPTIONS]
		r.Method = NormalizeMethod(fields[3])
		if len(fields) > 4 {
			r.Options = strings.Join(fields[4:], " ")
		}
		return r, true
	}
	// host* DATABASE USER ADDRESS METHOD [OPTIONS]
	if len(fields) < 5 {
		return Row{}, false
	}
	r.Address = fields[3]
	// An ADDRESS without a CIDR can be followed by a separate MASK
	// token (legacy form: `host all all 10.0.0.0 255.255.255.0 md5`).
	// Detect: if fields[4] looks like a dotted-quad mask, fold it.
	if looksDottedQuadMask(fields[4]) && len(fields) >= 6 {
		r.Address = fields[3] + "/" + maskToPrefix(fields[4])
		r.Method = NormalizeMethod(fields[5])
		if len(fields) > 6 {
			r.Options = strings.Join(fields[6:], " ")
		}
	} else {
		r.Method = NormalizeMethod(fields[4])
		if len(fields) > 5 {
			r.Options = strings.Join(fields[5:], " ")
		}
	}
	return r, true
}

// looksDottedQuadMask reports whether `s` is an IPv4 netmask in
// dotted-quad form (255.255.255.0 / 255.0.0.0 etc).
func looksDottedQuadMask(s string) bool {
	if !strings.HasPrefix(s, "255") && !strings.HasPrefix(s, "0") {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// maskToPrefix converts a dotted-quad mask into a CIDR prefix length.
// Returns "32" on parse failure so the resulting CIDR is harmless.
func maskToPrefix(mask string) string {
	parts := strings.Split(mask, ".")
	if len(parts) != 4 {
		return "32"
	}
	bits := 0
	for _, p := range parts {
		v := atoiSimple(p)
		for v != 0 {
			bits += v & 1
			v >>= 1
		}
	}
	switch bits {
	case 32:
		return "32"
	case 24:
		return "24"
	case 16:
		return "16"
	case 8:
		return "8"
	case 0:
		return "0"
	}
	// Fall through: emit the popcount as a string. This handles
	// non-standard masks (/25 = 255.255.255.128) without a lookup
	// table.
	return itoaSimple(bits)
}

func atoiSimple(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func itoaSimple(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
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
