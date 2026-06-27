package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// NodeParser handles package.json files.
type NodeParser struct{}

func (p *NodeParser) Patterns() []string { return []string{"package.json"} }
func (p *NodeParser) Ecosystem() string  { return "node.js" }

func (p *NodeParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
		Name            string            `json:"name"`
		Version         string            `json:"version"`
	}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	result := &ParseResult{
		ProjectName:    pkg.Name,
		ProjectVersion: pkg.Version,
		ManifestPath:   path,
	}

	for name, version := range pkg.Dependencies {
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    name,
			Version: cleanVersion(version),
			Vendor:  nodeVendor(name),
			Scope:   "runtime",
			Direct:  true,
		})
	}
	for name, version := range pkg.DevDependencies {
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    name,
			Version: cleanVersion(version),
			Vendor:  nodeVendor(name),
			Scope:   "dev",
			Direct:  true,
		})
	}

	return result, nil
}

// NodeLockParser handles package-lock.json files (v1, v2, v3).
type NodeLockParser struct{}

func (p *NodeLockParser) Patterns() []string { return []string{"package-lock.json"} }
func (p *NodeLockParser) Ecosystem() string  { return "node.js" }

func (p *NodeLockParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var lock struct {
		// v2/v3 format
		Packages map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
		// v1 format
		Dependencies map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"dependencies"`
		Name            string `json:"name"`
		Version         string `json:"version"`
		LockfileVersion int    `json:"lockfileVersion"`
	}
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	result := &ParseResult{
		ProjectName:    lock.Name,
		ProjectVersion: lock.Version,
		LockfileUsed:   true,
		ManifestPath:   path,
	}

	if lock.LockfileVersion >= 2 && len(lock.Packages) > 0 {
		// v2/v3: packages keyed by path (e.g., "node_modules/express")
		for key, pkg := range lock.Packages {
			if key == "" {
				continue // root package
			}
			name := lockfilePackageName(key)
			scope := "runtime"
			if pkg.Dev {
				scope = "dev"
			}
			result.Dependencies = append(result.Dependencies, Dependency{
				Name:    name,
				Version: pkg.Version,
				Vendor:  nodeVendor(name),
				Scope:   scope,
				Direct:  false,
			})
		}
	} else {
		// v1: flat dependencies map
		for name, pkg := range lock.Dependencies {
			scope := "runtime"
			if pkg.Dev {
				scope = "dev"
			}
			result.Dependencies = append(result.Dependencies, Dependency{
				Name:    name,
				Version: pkg.Version,
				Vendor:  nodeVendor(name),
				Scope:   scope,
				Direct:  false,
			})
		}
	}

	return result, nil
}

// lockfilePackageName extracts the package name from a node_modules path.
// "node_modules/@scope/pkg" → "@scope/pkg"
// "node_modules/express" → "express"
func lockfilePackageName(key string) string {
	const prefix = "node_modules/"
	idx := strings.LastIndex(key, prefix)
	if idx < 0 {
		return key
	}
	return key[idx+len(prefix):]
}

// nodeVendor extracts the scope from a scoped npm package.
// "@angular/core" → "angular"; "express" → "express"
func nodeVendor(name string) string {
	if strings.HasPrefix(name, "@") {
		if i := strings.IndexByte(name, '/'); i > 0 {
			return name[1:i]
		}
	}
	return name
}

// cleanVersion strips common semver prefixes (^, ~, >=, etc.).
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "^~>=<! ")
	return v
}
