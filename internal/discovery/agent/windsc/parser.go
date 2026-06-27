package windsc

import (
	"bufio"
	"bytes"
	"strings"
)

// ParseMOF walks one MOF body and emits one Resource per
// `instance of <Type> [as $...]` block. We don't try to be a
// full MOF parser — we just track block boundaries and harvest
// the scalar key/value pairs we care about.
//
// MOF grammar (per DMTF DSP0004):
//
//	instance of MSFT_FileDirectoryConfiguration as $f1ref
//	{
//	  ResourceID = "[File]EnsureFooExists";
//	  ModuleName = "PSDesiredStateConfiguration";
//	  ModuleVersion = "1.1";
//	  ConfigurationName = "MyConfig";
//	  SourceInfo = "C:\path\config.ps1::15::3";
//	};
//
// The instance lines, `{`, `};`, and the inner key=value pairs
// are line-oriented; values may be quoted strings, bare numbers,
// or arrays. We extract scalar quoted strings only — non-scalar
// values flow past without flagging.
//
// `mofKind` is stamped onto every emitted row by the caller; the
// parser doesn't infer it from filename.
func ParseMOF(body []byte, filePath string, mofKind MOFKind) []Resource {
	hash := HashContents(body)
	out := make([]Resource, 0, 8)

	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)

	var current *Resource
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "//") ||
			strings.HasPrefix(line, "#") {
			continue
		}
		if instType, ok := parseInstanceHeader(line); ok {
			// Finalise previous resource (in case of malformed MOF
			// without a closing `};`).
			if current != nil {
				AnnotateSecurity(current)
				out = append(out, *current)
				if len(out) >= MaxResources {
					return out
				}
			}
			current = &Resource{
				FilePath:     filePath,
				FileHash:     hash,
				MOFKind:      mofKind,
				InstanceType: instType,
			}
			continue
		}
		if line == "};" || line == "}" {
			if current != nil {
				AnnotateSecurity(current)
				out = append(out, *current)
				current = nil
				if len(out) >= MaxResources {
					return out
				}
			}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := splitKV(line)
		if !ok {
			continue
		}
		applyScalar(current, key, value)
	}
	if current != nil {
		AnnotateSecurity(current)
		out = append(out, *current)
	}
	return out
}

// parseInstanceHeader returns the instance type name from a line
// like `instance of MSFT_FileDirectoryConfiguration as $foo`.
// Returns ok=false when the line doesn't match the pattern.
func parseInstanceHeader(line string) (string, bool) {
	lower := strings.ToLower(line)
	if !strings.HasPrefix(lower, "instance of ") {
		return "", false
	}
	rest := strings.TrimSpace(line[len("instance of "):])
	// Strip optional ` as $name`.
	if i := strings.Index(strings.ToLower(rest), " as "); i >= 0 {
		rest = rest[:i]
	}
	return strings.TrimSpace(rest), true
}

// splitKV returns (key, value) from `key = value;` lines. Strips
// trailing `;` and outer double-quotes from the value.
func splitKV(line string) (string, string, bool) {
	eq := strings.IndexByte(line, '=')
	if eq <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:eq])
	value := strings.TrimSpace(line[eq+1:])
	value = strings.TrimSuffix(value, ";")
	value = strings.TrimSpace(value)
	// Strip outer double-quotes when present.
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = unescapeMOFString(value[1 : len(value)-1])
	}
	return key, value, true
}

// unescapeMOFString reverses the MOF backslash-escape sequences
// commonly seen in DSC-emitted strings: `\\` → `\`, `\"` → `"`,
// `\n` → newline. Other escape sequences pass through unchanged.
func unescapeMOFString(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			sb.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case '\\':
			sb.WriteByte('\\')
		case '"':
			sb.WriteByte('"')
		case 'n':
			sb.WriteByte('\n')
		case 't':
			sb.WriteByte('\t')
		default:
			sb.WriteByte('\\')
			sb.WriteByte(s[i+1])
		}
		i++
	}
	return sb.String()
}

// applyScalar routes a parsed key into the Resource fields we
// care about. Unknown keys flow past without flagging — the MOF
// grammar permits arbitrary resource-specific keys.
func applyScalar(r *Resource, key, value string) {
	switch key {
	case "ResourceID":
		r.ResourceID = value
	case "ModuleName":
		r.ModuleName = value
	case "ModuleVersion":
		r.ModuleVersion = value
	case "ConfigurationName":
		r.ConfigurationName = value
	case "SourceInfo":
		r.SourceInfo = value
	case "ConfigurationMode":
		// Surfaces only on MetaConfig MOFs.
		if strings.EqualFold(value, "ApplyAndAutoCorrect") {
			r.IsAutoCorrectMode = true
		}
	}
}
