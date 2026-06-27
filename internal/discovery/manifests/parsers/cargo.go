package parsers

import (
	"context"
	"fmt"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// CargoTomlParser handles Cargo.toml files.
type CargoTomlParser struct{}

func (p *CargoTomlParser) Patterns() []string { return []string{"Cargo.toml"} }
func (p *CargoTomlParser) Ecosystem() string  { return "rust" }

func (p *CargoTomlParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var cargo struct {
		Dependencies      map[string]any `toml:"dependencies"`
		DevDependencies   map[string]any `toml:"dev-dependencies"`
		BuildDependencies map[string]any `toml:"build-dependencies"`
		Package           struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(content, &cargo); err != nil {
		return nil, fmt.Errorf("parse Cargo.toml: %w", err)
	}

	result := &ParseResult{
		ProjectName:    cargo.Package.Name,
		ProjectVersion: cargo.Package.Version,
		ManifestPath:   path,
	}

	addCargoDeps(result, cargo.Dependencies, "runtime")
	addCargoDeps(result, cargo.DevDependencies, "dev")
	addCargoDeps(result, cargo.BuildDependencies, "build")

	return result, nil
}

func addCargoDeps(result *ParseResult, deps map[string]any, scope string) {
	for name, val := range deps {
		version := extractCargoVersion(val)
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    name,
			Version: version,
			Vendor:  name,
			Scope:   scope,
			Direct:  true,
		})
	}
}

// extractCargoVersion handles both string ("1.0") and table ({version = "1.0"}) formats.
func extractCargoVersion(val any) string {
	switch v := val.(type) {
	case string:
		return cleanVersion(v)
	case map[string]any:
		if ver, ok := v["version"]; ok {
			if s, ok := ver.(string); ok {
				return cleanVersion(s)
			}
		}
	}
	return ""
}

// CargoLockParser handles Cargo.lock files.
type CargoLockParser struct{}

func (p *CargoLockParser) Patterns() []string { return []string{"Cargo.lock"} }
func (p *CargoLockParser) Ecosystem() string  { return "rust" }

func (p *CargoLockParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var lock struct {
		Package []struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
			Source  string `toml:"source"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse Cargo.lock: %w", err)
	}

	result := &ParseResult{
		LockfileUsed: true,
		ManifestPath: path,
	}

	for _, pkg := range lock.Package {
		// Skip the root package (no source)
		if pkg.Source == "" {
			if result.ProjectName == "" {
				result.ProjectName = pkg.Name
				result.ProjectVersion = pkg.Version
			}
			continue
		}
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    pkg.Name,
			Version: pkg.Version,
			Vendor:  pkg.Name,
			Scope:   "runtime",
			Direct:  false,
		})
	}

	// Strip registry prefix from source for cleaner output
	for i := range result.Dependencies {
		result.Dependencies[i].Version = strings.TrimSpace(result.Dependencies[i].Version)
	}

	return result, nil
}
