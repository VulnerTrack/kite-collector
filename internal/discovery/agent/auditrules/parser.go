package auditrules

import (
	"bufio"
	"bytes"
	"strings"
)

// Parse walks one audit.rules body and produces one Rule per non-
// comment line. Each line is a single auditctl invocation per the
// auditctl(8) grammar:
//
//	-w /etc/passwd -p wa -k identity        # file-watch
//	-a always,exit -F arch=b64 -S openat -k file_access
//	-e 2                                     # control
//	-D                                       # control (clear)
//	-f 2                                     # control (panic on error)
//	-b 8192                                  # control (backlog)
//
// We tolerate continuation lines (`\` at EOL) the same way auditctl
// does — they're rare in practice but appear in some CIS rulesets.
func Parse(raw []byte, filePath string) []Rule {
	hash := HashContents(raw)
	lines := mergeContinuations(splitLines(raw))

	out := make([]Rule, 0, 64)
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
		annotate(&r)
		out = append(out, r)
		if len(out) >= MaxRules {
			break
		}
	}
	return out
}

// parseLine routes the line to the right sub-parser. We use the first
// token to dispatch; auditctl is strict-positional, so even `-a` lines
// must start at byte 0.
func parseLine(line string) (Rule, bool) {
	tokens := tokenize(line)
	if len(tokens) == 0 {
		return Rule{}, false
	}
	switch tokens[0] {
	case "-w":
		return parseFileWatch(tokens)
	case "-a":
		return parseSyscall(tokens, ActionUnknown)
	case "-A":
		// -A prepends to the list; semantics for us are the same as -a.
		return parseSyscall(tokens, ActionUnknown)
	case "-e", "-f", "-b", "-D", "-r":
		return parseControl(tokens)
	}
	return Rule{RuleKind: RuleKindUnknown}, true
}

// parseFileWatch handles `-w path -p perm -k key`. perm and key are
// optional.
func parseFileWatch(tokens []string) (Rule, bool) {
	r := Rule{RuleKind: RuleKindFileWatch}
	for i := 1; i < len(tokens); i++ {
		switch tokens[i] {
		case "-w":
			if i+1 < len(tokens) {
				r.Path = tokens[i+1]
				i++
			}
		case "-p":
			if i+1 < len(tokens) {
				r.Perm = tokens[i+1]
				i++
			}
		case "-k", "-F":
			if i+1 < len(tokens) {
				if tokens[i] == "-k" {
					r.Key = tokens[i+1]
				} else {
					r.Filters = append(r.Filters, tokens[i+1])
				}
				i++
			}
		}
	}
	if i := len(tokens); i > 1 && tokens[0] == "-w" {
		// First "-w" already consumed at top — but the for-loop above
		// only catches subsequent ones. Pick up the very first.
		if r.Path == "" {
			r.Path = tokens[1]
		}
	}
	return r, true
}

// parseSyscall handles `-a action,list -S syscall1 -S syscall2 -F filter -k key`.
// Multiple -S flags are concatenated. -F appears repeatedly with one
// filter per occurrence.
func parseSyscall(tokens []string, _ Action) (Rule, bool) {
	r := Rule{RuleKind: RuleKindSyscall}
	// First token is "-a" or "-A"; the next token is action,list.
	// We consume them up-front so the main loop can treat the rest
	// as positional options.
	startIdx := 1
	if len(tokens) >= 2 && (tokens[0] == "-a" || tokens[0] == "-A") {
		action, list := parseActionList(tokens[1])
		r.Action = action
		r.List = list
		startIdx = 2
	}
	for i := startIdx; i < len(tokens); i++ {
		switch tokens[i] {
		case "-a", "-A":
			if i+1 < len(tokens) {
				action, list := parseActionList(tokens[i+1])
				r.Action = action
				r.List = list
				i++
			}
		case "-S":
			if i+1 < len(tokens) {
				// auditctl accepts comma-separated lists in a single -S.
				for _, sc := range strings.Split(tokens[i+1], ",") {
					sc = strings.TrimSpace(sc)
					if sc != "" {
						r.Syscalls = append(r.Syscalls, sc)
					}
				}
				i++
			}
		case "-F":
			if i+1 < len(tokens) {
				filter := tokens[i+1]
				r.Filters = append(r.Filters, filter)
				// Pull the arch out into a dedicated column so downstream
				// queries don't have to LIKE-scan the filter list.
				if strings.HasPrefix(filter, "arch=") {
					r.Arch = strings.TrimPrefix(filter, "arch=")
				}
				i++
			}
		case "-k":
			if i+1 < len(tokens) {
				r.Key = tokens[i+1]
				i++
			}
		}
	}
	return r, true
}

// parseActionList splits `always,exit` into (action, list).
func parseActionList(s string) (Action, List) {
	parts := strings.SplitN(s, ",", 2)
	if len(parts) != 2 {
		return ActionUnknown, ListUnknown
	}
	var (
		a Action
		l List
	)
	switch strings.ToLower(parts[0]) {
	case "always":
		a = ActionAlways
	case "never":
		a = ActionNever
	default:
		a = ActionUnknown
	}
	switch strings.ToLower(parts[1]) {
	case "exit":
		l = ListExit
	case "exclude":
		l = ListExclude
	case "user":
		l = ListUser
	case "task":
		l = ListTask
	default:
		l = ListUnknown
	}
	return a, l
}

// parseControl handles `-e N`, `-f N`, `-b N`, `-D`, `-r N`.
func parseControl(tokens []string) (Rule, bool) {
	r := Rule{RuleKind: RuleKindControl}
	if len(tokens) == 0 {
		return r, false
	}
	r.ControlFlag = strings.TrimPrefix(tokens[0], "-")
	if len(tokens) > 1 {
		r.ControlValue = tokens[1]
	}
	if r.ControlFlag == "e" && r.ControlValue == "2" {
		r.IsImmutable = true
	}
	return r, true
}

// annotate sets the indexed booleans after the per-kind parsing.
// Centralised so the flags don't drift between code paths.
func annotate(r *Rule) {
	switch r.RuleKind {
	case RuleKindFileWatch:
		r.IsSensitivePathWatch = IsSensitivePathTarget(r.Path)
	case RuleKindSyscall:
		r.IsSelfDestructive = IsSelfDestructiveSyscallExclude(
			r.Action, r.List, r.Syscalls)
	case RuleKindControl, RuleKindUnknown:
		// Nothing extra to annotate; IsImmutable is set in-place.
	}
}

// -- helpers -------------------------------------------------------------

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

// tokenize splits on whitespace. auditctl doesn't quote arguments, so
// strings.Fields is correct.
func tokenize(line string) []string {
	return strings.Fields(line)
}

// collapseWhitespace normalises tabs+spaces into single spaces so
// raw_line doesn't trigger cosmetic-only drift events.
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
