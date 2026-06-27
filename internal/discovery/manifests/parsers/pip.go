package parsers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// RequirementsParser handles requirements.txt files.
type RequirementsParser struct{}

func (p *RequirementsParser) Patterns() []string { return []string{"requirements.txt"} }
func (p *RequirementsParser) Ecosystem() string  { return "python" }

func (p *RequirementsParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	result := &ParseResult{ManifestPath: path}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip options and includes
		if strings.HasPrefix(line, "-") {
			continue
		}
		// Remove inline comments
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Remove environment markers
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}

		name, version := parseRequirement(line)
		if name == "" {
			continue
		}
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    name,
			Version: version,
			Vendor:  name,
			Scope:   "runtime",
			Direct:  true,
		})
	}

	return result, nil
}

// parseRequirement splits "package==1.0" into name and version.
func parseRequirement(line string) (string, string) {
	for _, op := range []string{"===", "~=", "==", "!=", ">=", "<=", ">", "<"} {
		if i := strings.Index(line, op); i > 0 {
			name := strings.TrimSpace(line[:i])
			version := strings.TrimSpace(line[i+len(op):])
			// Handle multiple version specs: "pkg>=1.0,<2.0" — take the first version
			if j := strings.IndexByte(version, ','); j >= 0 {
				version = version[:j]
			}
			return normalizePyPIName(name), version
		}
	}
	return normalizePyPIName(line), ""
}

// normalizePyPIName normalises a Python package name (lowercase, hyphens to underscores,
// strip extras like [security]).
func normalizePyPIName(name string) string {
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "-", "_")
	return name
}

// PipfileLockParser handles Pipfile.lock files.
type PipfileLockParser struct{}

func (p *PipfileLockParser) Patterns() []string { return []string{"Pipfile.lock"} }
func (p *PipfileLockParser) Ecosystem() string  { return "python" }

func (p *PipfileLockParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}

	result := &ParseResult{
		LockfileUsed: true,
		ManifestPath: path,
	}

	for name, pkg := range lock.Default {
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    normalizePyPIName(name),
			Version: strings.TrimPrefix(pkg.Version, "=="),
			Vendor:  normalizePyPIName(name),
			Scope:   "runtime",
			Direct:  false,
		})
	}
	for name, pkg := range lock.Develop {
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    normalizePyPIName(name),
			Version: strings.TrimPrefix(pkg.Version, "=="),
			Vendor:  normalizePyPIName(name),
			Scope:   "dev",
			Direct:  false,
		})
	}

	return result, nil
}

// PoetryLockParser handles poetry.lock files.
type PoetryLockParser struct{}

func (p *PoetryLockParser) Patterns() []string { return []string{"poetry.lock"} }
func (p *PoetryLockParser) Ecosystem() string  { return "python" }

func (p *PoetryLockParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var lock struct {
		Package []struct {
			Name     string `toml:"name"`
			Version  string `toml:"version"`
			Category string `toml:"category"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse poetry.lock: %w", err)
	}

	result := &ParseResult{
		LockfileUsed: true,
		ManifestPath: path,
	}

	for _, pkg := range lock.Package {
		scope := "runtime"
		if pkg.Category == "dev" {
			scope = "dev"
		}
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    normalizePyPIName(pkg.Name),
			Version: pkg.Version,
			Vendor:  normalizePyPIName(pkg.Name),
			Scope:   scope,
			Direct:  false,
		})
	}

	return result, nil
}

// UvLockParser handles uv.lock files.
type UvLockParser struct{}

func (p *UvLockParser) Patterns() []string { return []string{"uv.lock"} }
func (p *UvLockParser) Ecosystem() string  { return "python" }

func (p *UvLockParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var lock struct {
		Package []struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse uv.lock: %w", err)
	}

	result := &ParseResult{
		LockfileUsed: true,
		ManifestPath: path,
	}

	for _, pkg := range lock.Package {
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    normalizePyPIName(pkg.Name),
			Version: pkg.Version,
			Vendor:  normalizePyPIName(pkg.Name),
			Scope:   "runtime",
			Direct:  false,
		})
	}

	return result, nil
}
