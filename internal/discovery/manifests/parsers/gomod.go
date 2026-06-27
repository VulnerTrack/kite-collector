package parsers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
)

// GoModParser handles go.mod files.
type GoModParser struct{}

func (p *GoModParser) Patterns() []string { return []string{"go.mod"} }
func (p *GoModParser) Ecosystem() string  { return "go" }

func (p *GoModParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	result := &ParseResult{ManifestPath: path}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	inRequire := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Extract module name
		if strings.HasPrefix(line, "module ") {
			result.ProjectName = strings.TrimSpace(strings.TrimPrefix(line, "module"))
			continue
		}

		// Start of require block
		if strings.HasPrefix(line, "require (") || line == "require (" {
			inRequire = true
			continue
		}
		// End of block
		if line == ")" {
			inRequire = false
			continue
		}

		// Single-line require
		if strings.HasPrefix(line, "require ") && !strings.Contains(line, "(") {
			dep := parseGoRequireLine(strings.TrimPrefix(line, "require "))
			if dep != nil {
				result.Dependencies = append(result.Dependencies, *dep)
			}
			continue
		}

		// Inside require block
		if inRequire && line != "" {
			dep := parseGoRequireLine(line)
			if dep != nil {
				result.Dependencies = append(result.Dependencies, *dep)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan go.mod: %w", err)
	}

	return result, nil
}

// parseGoRequireLine parses a single require line like "github.com/foo/bar v1.2.3 // indirect"
func parseGoRequireLine(line string) *Dependency {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "//") {
		return nil
	}

	indirect := strings.Contains(line, "// indirect")
	// Remove comments
	if i := strings.Index(line, "//"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	module := parts[0]
	version := strings.TrimPrefix(parts[1], "v")

	return &Dependency{
		Name:    module,
		Version: version,
		Vendor:  goModuleVendor(module),
		Scope:   "runtime",
		Direct:  !indirect,
	}
}

// goModuleVendor extracts the first path segment as vendor.
// "github.com/gin-gonic/gin" → "github.com/gin-gonic"
// "golang.org/x/sync" → "golang.org/x"
func goModuleVendor(module string) string {
	parts := strings.SplitN(module, "/", 3)
	if len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return module
}
