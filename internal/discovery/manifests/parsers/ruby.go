package parsers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
)

// GemfileParser handles Gemfile files.
type GemfileParser struct{}

func (p *GemfileParser) Patterns() []string { return []string{"Gemfile"} }
func (p *GemfileParser) Ecosystem() string  { return "ruby" }

var gemRe = regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?`)

func (p *GemfileParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	result := &ParseResult{ManifestPath: path}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		m := gemRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		version := ""
		if m[2] != "" {
			version = cleanVersion(m[2])
		}
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    m[1],
			Version: version,
			Vendor:  m[1],
			Scope:   "runtime",
			Direct:  true,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan Gemfile: %w", err)
	}

	return result, nil
}

// GemfileLockParser handles Gemfile.lock files.
type GemfileLockParser struct{}

func (p *GemfileLockParser) Patterns() []string { return []string{"Gemfile.lock"} }
func (p *GemfileLockParser) Ecosystem() string  { return "ruby" }

func (p *GemfileLockParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	result := &ParseResult{
		LockfileUsed: true,
		ManifestPath: path,
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	inSpecs := false

	for scanner.Scan() {
		line := scanner.Text()

		// Detect the "specs:" section under GEM
		trimmed := strings.TrimSpace(line)
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}

		// Exit specs on a non-indented line (section boundary)
		if inSpecs && len(line) > 0 && line[0] != ' ' {
			inSpecs = false
			continue
		}

		if !inSpecs {
			continue
		}

		// Specs lines are indented with exactly 4 spaces for top-level gems,
		// 6+ for transitive dependencies.
		// "    rails (7.0.8)"       → top-level
		// "      actioncable (= 7.0.8)" → transitive (sub-dep of rails)
		if !strings.HasPrefix(line, "    ") {
			continue
		}

		// Only parse lines with exactly 4 leading spaces (top-level in specs)
		// or all gem lines for completeness.
		name, version := parseGemLockLine(trimmed)
		if name == "" {
			continue
		}

		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    name,
			Version: version,
			Vendor:  name,
			Scope:   "runtime",
			Direct:  false,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan Gemfile.lock: %w", err)
	}

	return result, nil
}

// parseGemLockLine extracts name and version from "name (version)".
func parseGemLockLine(line string) (string, string) {
	line = strings.TrimSpace(line)
	i := strings.IndexByte(line, ' ')
	if i < 0 {
		return "", ""
	}
	name := line[:i]
	rest := strings.TrimSpace(line[i:])

	// Extract version from "(version)"
	if strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
		version := rest[1 : len(rest)-1]
		// Remove operator prefix if present (e.g., "= 7.0.8" → "7.0.8")
		version = strings.TrimSpace(version)
		for _, op := range []string{"= ", "~> ", ">= ", "<= ", "!= ", "> ", "< "} {
			version = strings.TrimPrefix(version, op)
		}
		return name, version
	}

	return name, ""
}
