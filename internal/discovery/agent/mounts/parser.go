package mounts

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// ParseFstab walks an /etc/fstab body. Grammar per fstab(5):
//
//	<device>  <mountpoint>  <fstype>  <options>  <dump>  <fsck_pass>
//
// Fields are whitespace-separated. Comments start with `#`. The
// optional dump + fsck_pass columns default to 0 when omitted.
func ParseFstab(raw []byte, filePath string) []Mount {
	hash := HashContents(raw)
	lines := splitLines(raw)

	out := make([]Mount, 0, 16)
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		fields := strings.Fields(clean)
		if len(fields) < 3 {
			continue
		}
		m := Mount{
			Source:     SourceFstab,
			Device:     fields[0],
			Mountpoint: fields[1],
			FSType:     fields[2],
			FilePath:   filePath,
			FileHash:   hash,
			LineNo:     i + 1,
			RawLine:    collapseWhitespace(clean),
		}
		if len(fields) > 3 {
			m.Options = splitOptions(fields[3])
		}
		if len(fields) > 4 {
			m.Dump = atoi(fields[4])
		}
		if len(fields) > 5 {
			m.FsckPass = atoi(fields[5])
		}
		AnnotateSecurity(&m)
		out = append(out, m)
		if len(out) >= MaxMounts {
			break
		}
	}
	return out
}

// ParseProcMounts walks /proc/self/mountinfo (preferred — more data) or
// the older /proc/mounts. Grammar per proc_mountinfo(5):
//
//	36 35 98:0 /mnt1 /mnt/parent rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//	|  |  |    |     |           |             |     |  |    |          |
//	id par dev root  mountpoint  opts          tags  -  fst  source     super_opts
//
// We only need a few columns; the rest are skipped. The legacy
// /proc/mounts format is simpler:
//
//	<device> <mountpoint> <fstype> <options> <dump> <fsck>
//
// ParseProcMounts auto-detects by checking for the " - " separator
// characteristic of mountinfo.
func ParseProcMounts(raw []byte, filePath string) []Mount {
	lines := splitLines(raw)

	out := make([]Mount, 0, 16)
	for i, line := range lines {
		clean := strings.TrimSpace(line)
		if clean == "" {
			continue
		}
		var m Mount
		if strings.Contains(clean, " - ") {
			m = parseMountinfoLine(clean)
		} else {
			m = parseLegacyMountsLine(clean)
		}
		if m.Mountpoint == "" {
			continue
		}
		m.Source = SourceProcMounts
		m.FilePath = filePath
		m.LineNo = i + 1
		m.RawLine = collapseWhitespace(clean)
		AnnotateSecurity(&m)
		out = append(out, m)
		if len(out) >= MaxMounts {
			break
		}
	}
	return out
}

// parseMountinfoLine handles one /proc/self/mountinfo line.
func parseMountinfoLine(line string) Mount {
	// Split on " - " to separate the mount-side fields from the
	// fs-side fields.
	parts := strings.SplitN(line, " - ", 2)
	if len(parts) != 2 {
		return Mount{}
	}
	left := strings.Fields(parts[0])
	right := strings.Fields(parts[1])
	if len(left) < 6 || len(right) < 3 {
		return Mount{}
	}
	// left[4] = mountpoint, left[5] = mount options (csv).
	m := Mount{
		Mountpoint: unescapeOctal(left[4]),
		Options:    splitOptions(left[5]),
		FSType:     right[0],
		Device:     unescapeOctal(right[1]),
	}
	// Merge super-block options (right[2]) into the option set so
	// `ro` declared at the super level surfaces too.
	if len(right) > 2 {
		for _, o := range splitOptions(right[2]) {
			if !containsString(m.Options, o) {
				m.Options = append(m.Options, o)
			}
		}
	}
	return m
}

// parseLegacyMountsLine handles one /proc/mounts (legacy) line.
func parseLegacyMountsLine(line string) Mount {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Mount{}
	}
	m := Mount{
		Device:     unescapeOctal(fields[0]),
		Mountpoint: unescapeOctal(fields[1]),
		FSType:     fields[2],
		Options:    splitOptions(fields[3]),
	}
	if len(fields) > 4 {
		m.Dump = atoi(fields[4])
	}
	if len(fields) > 5 {
		m.FsckPass = atoi(fields[5])
	}
	return m
}

// unescapeOctal decodes the `\040`-style escapes the kernel uses to
// embed spaces and other whitespace in path fields. We handle the
// common cases (\040 space, \011 tab, \012 LF, \134 backslash).
func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+3 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		// Look for three octal digits.
		if !isOctal(s[i+1]) || !isOctal(s[i+2]) || !isOctal(s[i+3]) {
			b.WriteByte(s[i])
			continue
		}
		val, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(byte(val))
		i += 3
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

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

func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

func splitOptions(s string) []string {
	var out []string
	for _, o := range strings.Split(s, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			out = append(out, o)
		}
	}
	return out
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
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

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
