package macpolicies

import (
	"bufio"
	"bytes"
	"strings"
)

// ParseSELinuxConfig walks /etc/selinux/config. Grammar (per
// selinux-config(5)):
//
//	# This file controls the state of SELinux on the system.
//	SELINUX=enforcing
//	SELINUXTYPE=targeted
//
// We emit one Policy row for the subsystem with `mode` set from
// SELINUX= and `policy_type` set from SELINUXTYPE=.
func ParseSELinuxConfig(raw []byte, filePath string) []Policy {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var (
		mode       = ModeUnknown
		policyType string
		modeLine   int
		modeRaw    string
	)
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		key, value, ok := splitKV(clean)
		if !ok {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(key)) {
		case "SELINUX":
			mode = NormalizeSELinuxMode(value)
			modeLine = i + 1
			modeRaw = clean
		case "SELINUXTYPE":
			policyType = strings.TrimSpace(value)
		}
	}

	if mode == ModeUnknown {
		// File parsed but no SELINUX= directive — still emit a row so
		// drift detection has something to compare against.
		return []Policy{{
			Subsystem:  SubsystemSELinux,
			Mode:       ModeUnknown,
			PolicyType: policyType,
			FilePath:   filePath,
			FileHash:   hash,
		}}
	}
	p := Policy{
		Subsystem:  SubsystemSELinux,
		Mode:       mode,
		PolicyType: policyType,
		FilePath:   filePath,
		FileHash:   hash,
		LineNo:     modeLine,
		RawLine:    collapseWhitespace(modeRaw),
	}
	AnnotateSecurity(&p)
	return []Policy{p}
}

// ParseAppArmorProfile walks a single /etc/apparmor.d/<file> body.
// AppArmor profiles look like:
//
//	#include <tunables/global>
//	profile firefox /usr/bin/firefox flags=(complain) {
//	  ...
//	}
//
// or with the legacy form (no `profile` keyword, the binary path
// is the profile name itself):
//
//	/usr/bin/firefox {
//	  ...
//	}
//
// We only need the profile-header line. The first non-comment line
// whose first token is either `profile` or a path is treated as the
// header; flags=(...) inside that header set the Mode.
func ParseAppArmorProfile(raw []byte, filePath string) []Policy {
	hash := HashContents(raw)
	lines := splitLines(raw)

	out := make([]Policy, 0, 1)
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		// Skip `#include`, `abi`, `if` directives — they're not headers.
		if strings.HasPrefix(clean, "#") || strings.HasPrefix(clean, "abi ") ||
			strings.HasPrefix(clean, "if ") {
			continue
		}
		// Profile header? Two shapes: "profile <name> [<path>] [flags=()]"
		// or "<path> [flags=()] {".
		name, path, flags, ok := parseAppArmorHeader(clean)
		if !ok {
			continue
		}
		p := Policy{
			Subsystem:   SubsystemAppArmor,
			ProfileName: name,
			Mode:        NormalizeAppArmorMode(flags),
			TargetPath:  path,
			FilePath:    filePath,
			FileHash:    hash,
			LineNo:      i + 1,
			RawLine:     collapseWhitespace(clean),
		}
		AnnotateSecurity(&p)
		out = append(out, p)
		if len(out) >= MaxPolicies {
			break
		}
	}
	return out
}

// parseAppArmorHeader extracts (profile_name, binary_path, flags)
// from a header line. The flags slice contains the comma-separated
// tokens inside `flags=(...)` when present. We require the line to
// end with `{` so rule lines like `/etc/passwd r,` (which start with
// `/`) don't get misclassified as legacy-form profile headers.
func parseAppArmorHeader(line string) (string, string, []string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasSuffix(trimmed, "{") {
		return "", "", nil, false
	}
	rest := strings.TrimSuffix(trimmed, "{")
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", "", nil, false
	}

	// Carve off flags=(...) tail when present.
	var flags []string
	if i := strings.Index(rest, "flags="); i >= 0 {
		tail := rest[i+len("flags="):]
		tail = strings.TrimSpace(tail)
		if strings.HasPrefix(tail, "(") {
			end := strings.IndexByte(tail, ')')
			if end > 0 {
				for _, f := range strings.Split(tail[1:end], ",") {
					f = strings.TrimSpace(f)
					if f != "" {
						flags = append(flags, f)
					}
				}
			}
		}
		rest = strings.TrimSpace(rest[:i])
	}

	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", "", nil, false
	}
	if strings.EqualFold(fields[0], "profile") {
		// `profile <name> [<path>]`
		if len(fields) < 2 {
			return "", "", nil, false
		}
		name := strings.Trim(fields[1], `"`)
		path := ""
		if len(fields) >= 3 {
			path = strings.Trim(fields[2], `"`)
		}
		return name, path, flags, true
	}
	// Legacy `<path> {`: the path IS the profile name.
	if strings.HasPrefix(fields[0], "/") || strings.HasPrefix(fields[0], `"`) {
		path := strings.Trim(fields[0], `"`)
		return path, path, flags, true
	}
	return "", "", nil, false
}

// ParseLSMList walks /sys/kernel/security/lsm. The file is a single
// comma-separated line listing every loaded LSM in the order the
// kernel composed them, e.g. "lockdown,capability,landlock,yama,
// apparmor,bpf". We emit one Policy row per entry (subsystem=lsm-list,
// mode=enabled) so the audit pipeline can correlate missing LSMs
// against the host's expected baseline.
func ParseLSMList(raw []byte, filePath string) []Policy {
	hash := HashContents(raw)
	line := strings.TrimSpace(string(raw))
	if line == "" {
		return nil
	}
	parts := strings.Split(line, ",")
	out := make([]Policy, 0, len(parts))
	for _, name := range parts {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		p := Policy{
			Subsystem:   SubsystemLSMList,
			ProfileName: name,
			Mode:        ModeEnabled,
			FilePath:    filePath,
			FileHash:    hash,
		}
		AnnotateSecurity(&p)
		out = append(out, p)
		if len(out) >= MaxPolicies {
			break
		}
	}
	return out
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

func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
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
