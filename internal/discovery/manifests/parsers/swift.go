package parsers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
)

// SwiftPackageParser handles Package.swift files.
// Extracts .package declarations via regex — no Swift evaluation.
type SwiftPackageParser struct{}

func (p *SwiftPackageParser) Patterns() []string { return []string{"Package.swift"} }
func (p *SwiftPackageParser) Ecosystem() string  { return "swift" }

// Matches: .package(url: "https://github.com/owner/repo.git", from: "1.0.0")
// Matches: .package(url: "https://github.com/owner/repo", .upToNextMajor(from: "2.0.0"))
var swiftPkgRe = regexp.MustCompile(`\.package\s*\(\s*(?:name:\s*"[^"]*"\s*,\s*)?url:\s*"([^"]+)"[^)]*?(?:from:\s*"([^"]+)"|"([^"]+)"\s*\.\.\.)`)

func (p *SwiftPackageParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	result := &ParseResult{ManifestPath: path}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		matches := swiftPkgRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			repoURL := m[1]
			version := m[2]
			if version == "" {
				version = m[3]
			}
			name := repoNameFromSwiftURL(repoURL)
			result.Dependencies = append(result.Dependencies, Dependency{
				Name:    name,
				Version: version,
				Vendor:  name,
				Scope:   "runtime",
				Direct:  true,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan Package.swift: %w", err)
	}

	return result, nil
}

func repoNameFromSwiftURL(u string) string {
	if i := strings.LastIndexByte(u, '/'); i >= 0 {
		u = u[i+1:]
	}
	return strings.TrimSuffix(u, ".git")
}
