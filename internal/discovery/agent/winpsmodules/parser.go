package winpsmodules

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// ParsePSD1 walks a PowerShell module manifest (.psd1) body and
// returns a populated Module. PSD1 is a constrained PowerShell
// expression returning a hash-table; we don't try to evaluate it.
// Instead we scan for `<key> = <scalar>` lines at any indent
// depth and harvest the security-relevant scalar fields.
//
// Array values (`@('a', 'b')`) and nested hash-tables (`@{...}`)
// are tolerated but not extracted — every field we care about is a
// top-level scalar.
//
// `filePath` is recorded verbatim and seeds the module-name derived
// from the parent directory.
func ParsePSD1(body []byte, filePath string) (Module, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return Module{}, fmt.Errorf("empty psd1")
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	m := Module{
		FilePath:   filePath,
		FileHash:   HashContents(body),
		ModuleName: moduleNameFromPath(filePath),
	}

	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)

	for scan.Scan() {
		raw := scan.Text()
		line, _ := stripLineComment(raw)
		// PowerShell allows multiple statements per line separated
		// by `;` — split first so single-line manifests parse the
		// same as multi-line ones.
		for _, stmt := range splitStatements(line) {
			trimmed := strings.TrimSpace(stmt)
			// Strip the leading `@{` opener and trailing `}` closer
			// — they can latch onto the first/last statement when
			// the manifest is written on one line.
			trimmed = strings.TrimPrefix(trimmed, "@{")
			trimmed = strings.TrimSuffix(trimmed, "}")
			trimmed = strings.TrimSpace(trimmed)
			if trimmed == "" {
				continue
			}
			key, value, ok := splitTopLevelAssignment(trimmed)
			if !ok {
				continue
			}
			// Only assign once per key (PSD1 doesn't permit repeat
			// keys; first-wins matches PowerShell semantics).
			assignScalar(&m, key, unquoteScalar(value))
		}
	}
	AnnotateSecurity(&m)
	return m, nil
}

// assignScalar routes a key/value into the corresponding Module
// field. Returns true if the key matched a known field — used so
// the parser can short-circuit duplicate-key handling.
func assignScalar(m *Module, key, value string) bool {
	switch strings.ToLower(key) {
	case "moduleversion":
		if m.ModuleVersion == "" {
			m.ModuleVersion = value
		}
	case "guid":
		if m.GUID == "" {
			m.GUID = value
		}
	case "author":
		if m.Author == "" {
			m.Author = value
		}
	case "companyname":
		if m.CompanyName == "" {
			m.CompanyName = value
		}
	case "copyright":
		if m.Copyright == "" {
			m.Copyright = value
		}
	case "description":
		if m.Description == "" {
			m.Description = value
		}
	case "powershellversion":
		if m.PowerShellVersion == "" {
			m.PowerShellVersion = value
		}
	case "clrversion":
		if m.CLRVersion == "" {
			m.CLRVersion = value
		}
	case "dotnetframeworkversion":
		if m.DotNetFrameworkVersion == "" {
			m.DotNetFrameworkVersion = value
		}
	case "rootmodule", "modulefile":
		// Older manifests use ModuleFile; both name the same thing.
		if m.RootModule == "" {
			m.RootModule = value
		}
	default:
		return false
	}
	return true
}

// splitTopLevelAssignment finds the first `=` that isn't inside a
// quoted string and returns (key, value, ok). Values like
// `@('a','b')` come back verbatim — assignScalar ignores them
// because they don't match the known scalar fields.
func splitTopLevelAssignment(line string) (string, string, bool) {
	inSingle := false
	inDouble := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '=':
			if !inSingle && !inDouble {
				key := strings.TrimSpace(line[:i])
				val := strings.TrimSpace(line[i+1:])
				if key == "" || strings.ContainsAny(key, " \t") {
					return "", "", false
				}
				return key, val, true
			}
		}
	}
	return "", "", false
}

// unquoteScalar strips the outer quotes from a PSD1 scalar value
// and drops a trailing comma if present. Array/hash-table values
// (`@(...)`, `@{...}`) are returned unchanged — assignScalar will
// see something that isn't a known field shape and ignore.
func unquoteScalar(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, ",")
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		first, last := v[0], v[len(v)-1]
		if first == '\'' && last == '\'' {
			return v[1 : len(v)-1]
		}
		if first == '"' && last == '"' {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// stripLineComment removes a trailing `#` comment from `line` while
// respecting quoted segments. PowerShell uses `#` for line comments
// and `<# ... #>` for block comments — we don't handle block
// comments because they're rare in .psd1 files.
func stripLineComment(line string) (string, string) {
	inSingle := false
	inDouble := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i], line[i+1:]
			}
		}
	}
	return line, ""
}

// splitStatements splits a line on `;` characters that aren't
// inside quoted strings or `(...)` array groups. We deliberately
// allow splits inside `{...}` so the outer `@{ a=1; b=2 }` hash
// flattens to two statements; nested hash values produce spurious
// (key, value) pairs that assignScalar ignores by name match.
func splitStatements(line string) []string {
	out := make([]string, 0, 2)
	inSingle := false
	inDouble := false
	parenDepth := 0
	start := 0
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '(':
			if !inSingle && !inDouble {
				parenDepth++
			}
		case ')':
			if !inSingle && !inDouble && parenDepth > 0 {
				parenDepth--
			}
		case ';':
			if !inSingle && !inDouble && parenDepth == 0 {
				out = append(out, line[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, line[start:])
	return out
}

// moduleNameFromPath returns the canonical module name from a
// manifest path. Standard layouts:
//
//	Modules\<Name>\<Version>\<Name>.psd1   (versioned)
//	Modules\<Name>\<Name>.psd1             (unversioned)
//
// We prefer the .psd1 basename (less the extension) — that matches
// what PowerShell's module loader keys by. Manual split-on-both-
// separators because filepath.Base is OS-aware and we cross-parse
// Windows paths on Linux CI.
func moduleNameFromPath(filePath string) string {
	if i := strings.LastIndexAny(filePath, `/\`); i >= 0 {
		filePath = filePath[i+1:]
	}
	if dot := strings.LastIndexByte(filePath, '.'); dot > 0 &&
		strings.EqualFold(filePath[dot:], ".psd1") {
		return filePath[:dot]
	}
	return filePath
}
