package gitrepos

import (
	"bufio"
	"bytes"
	"strings"
)

// ConfigSnapshot holds the security-relevant fields we extract from a
// single .git/config body. One snapshot is produced per file, then
// the collector fans it out into one Repo row per remote.
type ConfigSnapshot struct {
	Remotes          map[string]string
	HeadBranch       string
	UserEmail        string
	UserName         string
	CredentialHelper string
	SSHCommand       string
	InsteadOfPairs   []string
	IsBare           bool
}

// ParseConfig walks a .git/config body. Grammar per git-config(1):
//
//	# comment
//	[section]
//	    key = value
//	[section "subsection"]
//	    key = value
//
// We care about:
//
//	[core]
//	    bare = true
//	    sshCommand = ssh -i /alt/key
//	[user]
//	    name  = Alice
//	    email = alice@corp.local
//	[remote "origin"]
//	    url = https://github.com/owner/repo.git
//	[url "git@github.com:"]
//	    insteadOf = https://github.com/
//	[credential]
//	    helper = store
//	    helper = manager-core   (last-write wins per git semantics)
func ParseConfig(raw []byte) ConfigSnapshot {
	snap := ConfigSnapshot{
		Remotes: map[string]string{},
	}
	lines := splitLines(raw)

	var (
		section    string
		subsection string
	)
	for _, line := range lines {
		clean := stripComment(line)
		trimmed := strings.TrimSpace(clean)
		if trimmed == "" {
			continue
		}
		if sec, sub, ok := parseSectionHeader(trimmed); ok {
			section = strings.ToLower(sec)
			subsection = sub
			continue
		}
		k, v, ok := splitKV(trimmed)
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := unquoteValue(strings.TrimSpace(v))
		switch section {
		case "core":
			switch key {
			case "bare":
				snap.IsBare = parseBool(val)
			case "sshcommand":
				snap.SSHCommand = val
			}
		case "user":
			switch key {
			case "email":
				snap.UserEmail = val
			case "name":
				snap.UserName = val
			}
		case "credential":
			if key == "helper" {
				// Last-write wins per git's evaluation order.
				snap.CredentialHelper = val
			}
		case "remote":
			if subsection != "" && key == "url" {
				if len(snap.Remotes) >= MaxRemotesPerRepo {
					continue
				}
				snap.Remotes[subsection] = val
			}
		case "url":
			if subsection != "" && key == "insteadof" {
				snap.InsteadOfPairs = append(snap.InsteadOfPairs,
					subsection+" -> "+val)
			}
		}
	}
	return snap
}

// parseSectionHeader splits `[section]` or `[section "subsection"]`
// into (section, subsection, ok).
func parseSectionHeader(line string) (string, string, bool) {
	if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
		return "", "", false
	}
	inner := strings.TrimSpace(line[1 : len(line)-1])
	if inner == "" {
		return "", "", false
	}
	// Sub-section form: `section "sub"`
	if i := strings.IndexByte(inner, ' '); i > 0 {
		sec := strings.TrimSpace(inner[:i])
		sub := strings.TrimSpace(inner[i+1:])
		sub = strings.Trim(sub, `"`)
		return sec, sub, true
	}
	if i := strings.IndexByte(inner, '\t'); i > 0 {
		sec := strings.TrimSpace(inner[:i])
		sub := strings.TrimSpace(inner[i+1:])
		sub = strings.Trim(sub, `"`)
		return sec, sub, true
	}
	return inner, "", true
}

// splitKV splits `key = value` (= separator with optional whitespace).
// Git config also accepts bare flags (`bool-key` alone == true) but
// they're rare; we return ok=false there.
func splitKV(line string) (string, string, bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		// Bare bool: `key` alone implies key=true.
		k := strings.TrimSpace(line)
		if k == "" {
			return "", "", false
		}
		return k, "true", true
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// unquoteValue strips outer `"..."` quotes when symmetric. Git config
// allows quoted values to embed leading/trailing whitespace.
func unquoteValue(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}

// parseBool follows git-config bool semantics (per git-config(1)):
//
//	true  : true, yes, on, 1
//	false : false, no, off, 0, ""
func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "on", "1":
		return true
	}
	return false
}

// ParseHead extracts the branch name from a .git/HEAD body. Two shapes:
//
//	ref: refs/heads/main      → returns "main"
//	a1b2c3d4...               → returns "" (detached)
func ParseHead(raw []byte) string {
	line := strings.TrimSpace(string(raw))
	const prefix = "ref: refs/heads/"
	if strings.HasPrefix(line, prefix) {
		return strings.TrimSpace(line[len(prefix):])
	}
	return ""
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

// stripComment drops trailing `#` or `;` comments. git-config(1)
// accepts both.
func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	if i := strings.IndexByte(line, ';'); i >= 0 {
		line = line[:i]
	}
	return line
}
