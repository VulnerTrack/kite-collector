package parsers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
)

// GradleParser handles build.gradle and build.gradle.kts files.
// It extracts dependency declarations via regex — no Groovy/Kotlin evaluation.
type GradleParser struct{}

func (p *GradleParser) Patterns() []string { return []string{"build.gradle", "build.gradle.kts"} }
func (p *GradleParser) Ecosystem() string  { return "java" }

// Matches: implementation 'group:artifact:version'
// Matches: implementation("group:artifact:version")
// Matches: api "group:artifact:version"
// Also: testImplementation, runtimeOnly, compileOnly, etc.
var gradleDepRe = regexp.MustCompile(
	`(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|testCompileOnly|annotationProcessor|kapt)\s*[\(]?\s*['"]([^'"]+)['"]`,
)

func (p *GradleParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	result := &ParseResult{ManifestPath: path}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments.
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
			continue
		}

		matches := gradleDepRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			dep := parseGradleCoordinate(m[1], line)
			if dep != nil {
				result.Dependencies = append(result.Dependencies, *dep)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan build.gradle: %w", err)
	}

	return result, nil
}

// parseGradleCoordinate parses "group:artifact:version" format.
func parseGradleCoordinate(coord, line string) *Dependency {
	parts := strings.SplitN(coord, ":", 3)
	if len(parts) < 2 {
		return nil
	}

	scope := "runtime"
	lower := strings.ToLower(line)
	if strings.Contains(lower, "testimplementation") || strings.Contains(lower, "testruntimeonly") || strings.Contains(lower, "testcompileonly") {
		scope = "test"
	} else if strings.Contains(lower, "compileonly") {
		scope = "optional"
	}

	version := ""
	if len(parts) == 3 {
		version = parts[2]
	}

	return &Dependency{
		Name:    parts[0] + ":" + parts[1],
		Version: version,
		Vendor:  parts[0],
		Scope:   scope,
		Direct:  true,
	}
}
