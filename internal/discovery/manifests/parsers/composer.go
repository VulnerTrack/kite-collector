package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ComposerParser handles composer.json files.
type ComposerParser struct{}

func (p *ComposerParser) Patterns() []string { return []string{"composer.json"} }
func (p *ComposerParser) Ecosystem() string  { return "php" }

func (p *ComposerParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var comp struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
		Name       string            `json:"name"`
		Version    string            `json:"version"`
	}
	if err := json.Unmarshal(content, &comp); err != nil {
		return nil, fmt.Errorf("parse composer.json: %w", err)
	}

	result := &ParseResult{
		ProjectName:    comp.Name,
		ProjectVersion: comp.Version,
		ManifestPath:   path,
	}

	for name, version := range comp.Require {
		if name == "php" || strings.HasPrefix(name, "ext-") {
			continue // skip PHP version and extension constraints
		}
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    name,
			Version: cleanVersion(version),
			Vendor:  composerVendor(name),
			Scope:   "runtime",
			Direct:  true,
		})
	}
	for name, version := range comp.RequireDev {
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    name,
			Version: cleanVersion(version),
			Vendor:  composerVendor(name),
			Scope:   "dev",
			Direct:  true,
		})
	}

	return result, nil
}

// ComposerLockParser handles composer.lock files.
type ComposerLockParser struct{}

func (p *ComposerLockParser) Patterns() []string { return []string{"composer.lock"} }
func (p *ComposerLockParser) Ecosystem() string  { return "php" }

func (p *ComposerLockParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var lock struct {
		Packages    []composerLockPkg `json:"packages"`
		PackagesDev []composerLockPkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}

	result := &ParseResult{
		LockfileUsed: true,
		ManifestPath: path,
	}

	for _, pkg := range lock.Packages {
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    pkg.Name,
			Version: strings.TrimPrefix(pkg.Version, "v"),
			Vendor:  composerVendor(pkg.Name),
			Scope:   "runtime",
			Direct:  false,
		})
	}
	for _, pkg := range lock.PackagesDev {
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    pkg.Name,
			Version: strings.TrimPrefix(pkg.Version, "v"),
			Vendor:  composerVendor(pkg.Name),
			Scope:   "dev",
			Direct:  false,
		})
	}

	return result, nil
}

type composerLockPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// composerVendor extracts the vendor from "vendor/package" format.
func composerVendor(name string) string {
	if i := strings.IndexByte(name, '/'); i > 0 {
		return name[:i]
	}
	return name
}
