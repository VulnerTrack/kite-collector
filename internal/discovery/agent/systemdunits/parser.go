package systemdunits

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
)

// Parse walks one systemd unit-file body and returns a populated
// Unit. systemd's grammar is essentially INI with one twist: a key
// can repeat (e.g. multiple ExecStart= lines or
// `Environment=A=1`+`Environment=B=2`); the last value wins for our
// purposes since we only persist a single string per field.
//
// We honour line continuations (`\` at EOL — uncommon but supported).
func Parse(raw []byte, filePath string) Unit {
	out := Unit{
		FilePath:  filePath,
		FileHash:  HashContents(raw),
		UnitName:  filepath.Base(filePath),
		UnitKind:  NormalizeUnitKind(filePath),
		SourceDir: NormalizeSourceDir(filepath.Dir(filePath)),
	}

	lines := mergeContinuations(splitLines(raw))
	currentSection := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			currentSection = strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			continue
		}
		key, value, ok := splitKV(trimmed)
		if !ok {
			continue
		}
		applyDirective(&out, currentSection, key, value)
	}

	AnnotateSecurity(&out)
	return out
}

func applyDirective(u *Unit, section, key, value string) {
	switch section {
	case "unit":
		applyUnit(u, key, value)
	case "service":
		applyService(u, key, value)
	}
}

func applyUnit(u *Unit, key, value string) {
	if strings.EqualFold(key, "Description") {
		u.Description = value
	}
}

func applyService(u *Unit, key, value string) {
	switch key {
	case "Type":
		u.ServiceType = value
	case "ExecStart":
		u.ExecStart = value
	case "User":
		u.UserName = value
	case "Group":
		u.GroupName = value
	case "WorkingDirectory":
		u.WorkingDirectory = value
	case "CapabilityBoundingSet":
		u.CapabilityBoundingSet = value
	case "AmbientCapabilities":
		u.AmbientCapabilities = value
	case "SystemCallFilter":
		u.SystemCallFilter = value
	case "RestrictAddressFamilies":
		u.RestrictAddressFamilies = value
	case "NoNewPrivileges":
		u.NoNewPrivileges = value
	case "PrivateTmp":
		u.PrivateTmp = value
	case "PrivateDevices":
		u.PrivateDevices = value
	case "PrivateNetwork":
		u.PrivateNetwork = value
	case "ProtectSystem":
		u.ProtectSystem = value
	case "ProtectHome":
		u.ProtectHome = value
	case "ProtectKernelTunables":
		u.ProtectKernelTunables = value
	case "ProtectKernelModules":
		u.ProtectKernelModules = value
	case "ProtectControlGroups":
		u.ProtectControlGroups = value
	case "RestrictNamespaces":
		u.RestrictNamespaces = value
	case "LockPersonality":
		u.LockPersonality = value
	case "MemoryDenyWriteExecute":
		u.MemoryDenyWriteExecute = value
	}
}

// splitKV separates `key = value`. systemd accepts `key=value`,
// `key = value`, and trims surrounding whitespace.
func splitKV(line string) (string, string, bool) {
	if i := strings.IndexByte(line, '='); i > 0 {
		return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
	}
	return "", "", false
}

// splitLines reads one logical line per scanner step. We keep raw
// content so the continuation walker can re-join when it sees `\`.
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
		trimmedR := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmedR, "\\") {
			body := strings.TrimRight(trimmedR[:len(trimmedR)-1], " \t")
			pending.WriteString(body)
			pending.WriteByte(' ')
			continue
		}
		if pending.Len() > 0 {
			pending.WriteString(strings.TrimLeft(trimmedR, " \t"))
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
