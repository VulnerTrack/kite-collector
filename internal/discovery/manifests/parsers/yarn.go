package parsers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
)

// YarnLockParser handles yarn.lock files (v1 format).
type YarnLockParser struct{}

func (p *YarnLockParser) Patterns() []string { return []string{"yarn.lock"} }
func (p *YarnLockParser) Ecosystem() string  { return "node.js" }

func (p *YarnLockParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	result := &ParseResult{
		LockfileUsed: true,
		ManifestPath: path,
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	var currentName string

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and blank lines.
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Package header line: "name@version:" or "@scope/name@version:"
		// These lines start at column 0 (not indented).
		if len(line) > 0 && line[0] != ' ' {
			currentName = yarnPackageName(line)
			continue
		}

		// Indented "version" line under a package header.
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "version ") && currentName != "" {
			version := strings.TrimPrefix(trimmed, "version ")
			version = strings.Trim(version, `"`)
			result.Dependencies = append(result.Dependencies, Dependency{
				Name:    currentName,
				Version: version,
				Vendor:  nodeVendor(currentName),
				Scope:   "runtime",
				Direct:  false,
			})
			currentName = ""
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan yarn.lock: %w", err)
	}

	return result, nil
}

// yarnPackageName extracts the package name from a yarn.lock header line.
// "express@^4.18.2:" → "express"
// "@scope/pkg@^1.0.0, @scope/pkg@^1.0.1:" → "@scope/pkg"
func yarnPackageName(line string) string {
	// Remove trailing colon.
	line = strings.TrimSuffix(strings.TrimSpace(line), ":")
	// Take first entry if comma-separated.
	if i := strings.IndexByte(line, ','); i > 0 {
		line = line[:i]
	}
	// Remove quotes.
	line = strings.Trim(line, `"`)

	// Find the last @ that separates name from version.
	// For scoped packages (@scope/name@version), we need the second @.
	name := line
	if strings.HasPrefix(name, "@") {
		// Scoped package: find @ after the slash.
		if slashIdx := strings.IndexByte(name, '/'); slashIdx > 0 {
			if atIdx := strings.IndexByte(name[slashIdx:], '@'); atIdx > 0 {
				name = name[:slashIdx+atIdx]
			}
		}
	} else {
		if atIdx := strings.IndexByte(name, '@'); atIdx > 0 {
			name = name[:atIdx]
		}
	}

	return name
}
