package parsers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
)

// CpanfileParser handles cpanfile files.
type CpanfileParser struct{}

func (p *CpanfileParser) Patterns() []string { return []string{"cpanfile"} }
func (p *CpanfileParser) Ecosystem() string  { return "perl" }

// Matches: requires 'Module::Name', '1.00';
// Matches: requires "Module::Name";
var cpanReqRe = regexp.MustCompile(`requires\s+['"]([^'"]+)['"](?:\s*,\s*['"]?([^'";,\s]+)['"]?)?`)

func (p *CpanfileParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	result := &ParseResult{ManifestPath: path}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		matches := cpanReqRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			version := ""
			if len(m) > 2 {
				version = m[2]
			}
			result.Dependencies = append(result.Dependencies, Dependency{
				Name:    m[1],
				Version: version,
				Vendor:  m[1],
				Scope:   "runtime",
				Direct:  true,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan cpanfile: %w", err)
	}

	return result, nil
}
