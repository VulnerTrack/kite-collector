package parsers

import (
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// PnpmLockParser handles pnpm-lock.yaml files (v6+ format).
type PnpmLockParser struct{}

func (p *PnpmLockParser) Patterns() []string { return []string{"pnpm-lock.yaml"} }
func (p *PnpmLockParser) Ecosystem() string  { return "node.js" }

func (p *PnpmLockParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `yaml:"version"`
			Dev     bool   `yaml:"dev"`
		} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse pnpm-lock.yaml: %w", err)
	}

	result := &ParseResult{
		LockfileUsed: true,
		ManifestPath: path,
	}

	for key, pkg := range lock.Packages {
		name, version := parsePnpmPackageKey(key)
		if name == "" {
			continue
		}
		// Prefer the version from the package entry if available.
		if pkg.Version != "" {
			version = pkg.Version
		}
		scope := "runtime"
		if pkg.Dev {
			scope = "dev"
		}
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    name,
			Version: version,
			Vendor:  nodeVendor(name),
			Scope:   scope,
			Direct:  false,
		})
	}

	return result, nil
}

// parsePnpmPackageKey extracts name and version from a pnpm packages key.
// "/express@4.18.2" → ("express", "4.18.2")
// "/@scope/pkg@1.0.0" → ("@scope/pkg", "1.0.0")
func parsePnpmPackageKey(key string) (string, string) {
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		return "", ""
	}

	// For scoped packages: @scope/name@version
	if strings.HasPrefix(key, "@") {
		slashIdx := strings.IndexByte(key, '/')
		if slashIdx < 0 {
			return key, ""
		}
		rest := key[slashIdx+1:]
		atIdx := strings.IndexByte(rest, '@')
		if atIdx < 0 {
			return key, ""
		}
		name := key[:slashIdx+1+atIdx]
		version := rest[atIdx+1:]
		return name, version
	}

	// Unscoped: name@version
	atIdx := strings.IndexByte(key, '@')
	if atIdx < 0 {
		return key, ""
	}
	return key[:atIdx], key[atIdx+1:]
}
