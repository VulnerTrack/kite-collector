package smbshares

import (
	"bufio"
	"bytes"
	"strings"
)

// Parse walks one smb.conf body. Grammar per smb.conf(5):
//
//	# comment    or    ; comment
//	[section name]
//	   key with spaces = value with spaces
//	   another key = value
//
// Continuation lines (`\` at EOL) are folded. Keys are
// case-insensitive and whitespace-tolerant — `Read Only` /
// `READ_ONLY` / `readonly` all canonicalise to `readonly`.
func Parse(raw []byte, filePath string) []Share {
	hash := HashContents(raw)
	lines := mergeContinuations(splitLines(raw))

	var (
		out      []Share
		current  *Share
		startLn  int
		rawLines []string
	)

	finalize := func() {
		if current == nil {
			return
		}
		current.LineNo = startLn
		current.RawLine = strings.TrimSpace(strings.Join(rawLines, " "))
		AnnotateSecurity(current)
		out = append(out, *current)
		current = nil
		rawLines = nil
	}

	for i, line := range lines {
		clean := stripComment(line)
		trimmed := strings.TrimSpace(clean)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			finalize()
			name := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			current = &Share{
				FilePath:    filePath,
				FileHash:    hash,
				SectionName: name,
				SectionKind: NormalizeSectionKind(name),
			}
			startLn = i + 1
			rawLines = append(rawLines, trimmed)
			continue
		}
		if current == nil {
			// Pre-section content (Samba allows nothing here, but be tolerant).
			continue
		}
		key, value, ok := splitKV(trimmed)
		if !ok {
			continue
		}
		rawLines = append(rawLines, trimmed)
		applyKey(current, key, value)
		if len(out) >= MaxShares {
			break
		}
	}
	finalize()

	if len(out) > MaxShares {
		out = out[:MaxShares]
	}
	return out
}

// applyKey routes the (key, value) into the Share fields. The key
// arrives already-canonicalised (lowercase, no whitespace).
func applyKey(s *Share, key, value string) {
	switch CanonicalKey(key) {
	case "path":
		s.Path = value
	case "comment":
		s.Comment = value
	case "validusers":
		s.ValidUsers = value
	case "invalidusers":
		s.InvalidUsers = value
	case "adminusers":
		s.AdminUsers = value
	case "readlist":
		s.ReadList = value
	case "writelist":
		s.WriteList = value
	case "hostsallow", "allowhosts":
		s.HostsAllow = value
	case "hostsdeny", "denyhosts":
		s.HostsDeny = value
	case "createmask", "createmode":
		s.CreateMask = value
	case "directorymask", "directorymode":
		s.DirectoryMask = value
	case "forceuser":
		s.ForceUser = value
	case "forcegroup":
		s.ForceGroup = value
	case "browseable", "browsable":
		s.IsBrowseable = ParseBool(value)
	case "guestok":
		s.IsGuestOK = ParseBool(value)
	case "writable", "writeable":
		s.IsWritable = ParseBool(value)
		// Mirror to IsReadOnly when explicit.
		if !s.IsWritable {
			s.IsReadOnly = true
		}
	case "readonly":
		s.IsReadOnly = ParseBool(value)
		s.IsWritable = !s.IsReadOnly
	case "public":
		// `public` is an alias for `guest ok` (per smb.conf(5)).
		s.IsPublic = ParseBool(value)
		if s.IsPublic {
			s.IsGuestOK = true
		}
	}
}

// splitKV splits `key = value` (the `=` may be surrounded by any
// amount of whitespace). Bare booleans (`writable` with no `=`) are
// not part of smb.conf grammar, so we return ok=false there.
func splitKV(line string) (string, string, bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
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

// stripComment drops trailing `#` or `;` comments (both accepted by
// smb.conf(5)).
func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	if i := strings.IndexByte(line, ';'); i >= 0 {
		line = line[:i]
	}
	return line
}
