package fail2ban

import (
	"bufio"
	"bytes"
	"strings"
)

// Parse walks one fail2ban config-file body and returns the section
// rows it contains. fail2ban uses Python's INI grammar:
//
//	# comment  or  ; comment
//	[section]
//	    key = value
//	    multi-line = first
//	                 continuation
//
// Continuation lines are indented and folded into the previous value.
// `[DEFAULT]` is reserved for inheritance — we emit it as its own
// row (section_kind=default) and propagate its values into every
// other section's empty fields so per-jail audit queries don't need
// to join.
func Parse(raw []byte, filePath string) []Jail {
	hash := HashContents(raw)
	lines := mergeContinuations(splitLines(raw))

	rows := make([]Jail, 0, 4)
	var current *Jail
	var defaults Jail

	finalize := func() {
		if current == nil {
			return
		}
		if current.SectionKind == SectionJail {
			applyDefaultInheritance(current, &defaults)
		}
		AnnotateSecurity(current)
		rows = append(rows, *current)
		current = nil
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || isComment(trimmed) {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			finalize()
			if len(rows) >= MaxRows {
				return rows
			}
			name := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			kind := NormalizeSectionKind(name)
			current = &Jail{
				FilePath:    filePath,
				FileHash:    hash,
				SectionName: name,
				SectionKind: kind,
			}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := splitKV(trimmed)
		if !ok {
			continue
		}
		applyDirective(current, key, value)
		// Track DEFAULT separately so per-jail rows can inherit.
		if current.SectionKind == SectionDefault {
			applyDirective(&defaults, key, value)
		}
	}
	finalize()
	return rows
}

// applyDefaultInheritance fills in empty per-jail fields from the
// [DEFAULT] row. fail2ban's actual inheritance is more nuanced
// (interpolation of `%(known/section)s` etc), but for the security
// findings we care about, "field unset → use DEFAULT" is correct.
func applyDefaultInheritance(j, d *Jail) {
	if j.Enabled == "" {
		j.Enabled = d.Enabled
	}
	if j.Port == "" {
		j.Port = d.Port
	}
	if j.FilterName == "" {
		j.FilterName = d.FilterName
	}
	if j.LogPath == "" {
		j.LogPath = d.LogPath
	}
	if j.Backend == "" {
		j.Backend = d.Backend
	}
	if j.MaxRetry == 0 {
		j.MaxRetry = d.MaxRetry
	}
	if j.FindTimeSeconds == 0 {
		j.FindTimeSeconds = d.FindTimeSeconds
	}
	if j.BanTimeSeconds == 0 {
		j.BanTimeSeconds = d.BanTimeSeconds
	}
	if j.IgnoreIP == "" {
		j.IgnoreIP = d.IgnoreIP
	}
	if j.Action == "" {
		j.Action = d.Action
		j.ActionCount = d.ActionCount
	}
}

func applyDirective(j *Jail, key, value string) {
	switch strings.ToLower(key) {
	case "enabled":
		j.Enabled = value
	case "port":
		j.Port = value
	case "filter":
		j.FilterName = value
	case "logpath":
		j.LogPath = value
	case "backend":
		j.Backend = value
	case "maxretry":
		j.MaxRetry = parseUint(value)
	case "findtime":
		j.FindTimeSeconds = ParseDuration(value)
	case "bantime":
		j.BanTimeSeconds = ParseDuration(value)
	case "ignoreip":
		j.IgnoreIP = value
	case "action":
		j.Action = value
		j.ActionCount = countActions(value)
	}
}

// countActions tokenises the `action =` value to count the distinct
// action calls. fail2ban accepts multiple actions separated by
// newlines (folded by the continuation logic) or just whitespace.
func countActions(value string) int {
	if strings.TrimSpace(value) == "" {
		return 0
	}
	return len(strings.Fields(value))
}

// parseUint reads an unsigned integer or returns 0 on any error
// (including signed values — fail2ban doesn't use negatives here).
func parseUint(s string) int {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0
	}
	n := 0
	for _, c := range t {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// splitKV splits `key = value` (optional whitespace around `=`).
// Bare boolean shortcuts aren't accepted by fail2ban.
func splitKV(line string) (string, string, bool) {
	if i := strings.IndexByte(line, '='); i > 0 {
		return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
	}
	return "", "", false
}

func isComment(line string) bool {
	return strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";")
}

func splitLines(raw []byte) []string {
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	var out []string
	for scan.Scan() {
		out = append(out, scan.Text())
	}
	return out
}

// mergeContinuations folds indented continuation lines into the
// previous logical line. Python's INI grammar treats any line
// starting with whitespace as a continuation of the previous one,
// EXCEPT comment-only lines (whose leading whitespace doesn't make
// them part of the previous value).
func mergeContinuations(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Pure-comment lines are dropped without affecting the
		// continuation chain — they would otherwise glue themselves
		// onto a section header and break parsing.
		if isComment(trimmed) {
			continue
		}
		if len(out) > 0 && len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			out[len(out)-1] = out[len(out)-1] + " " + trimmed
			continue
		}
		out = append(out, line)
	}
	return out
}
