package parsers

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
)

// CsprojParser handles *.csproj files (modern .NET SDK-style projects).
type CsprojParser struct{}

func (p *CsprojParser) Patterns() []string { return []string{"*.csproj"} }
func (p *CsprojParser) Ecosystem() string  { return "dotnet" }

func (p *CsprojParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var proj struct {
		ItemGroups []struct {
			PackageReferences []struct {
				Include string `xml:"Include,attr"`
				Version string `xml:"Version,attr"`
			} `xml:"PackageReference"`
		} `xml:"ItemGroup"`
	}
	if err := xml.Unmarshal(content, &proj); err != nil {
		return nil, fmt.Errorf("parse csproj: %w", err)
	}

	result := &ParseResult{ManifestPath: path}

	for _, group := range proj.ItemGroups {
		for _, ref := range group.PackageReferences {
			if ref.Include == "" {
				continue
			}
			result.Dependencies = append(result.Dependencies, Dependency{
				Name:    ref.Include,
				Version: ref.Version,
				Vendor:  dotnetVendor(ref.Include),
				Scope:   "runtime",
				Direct:  true,
			})
		}
	}

	return result, nil
}

// PackagesConfigParser handles packages.config files (legacy .NET).
type PackagesConfigParser struct{}

func (p *PackagesConfigParser) Patterns() []string { return []string{"packages.config"} }
func (p *PackagesConfigParser) Ecosystem() string  { return "dotnet" }

func (p *PackagesConfigParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var cfg struct {
		Packages []struct {
			ID      string `xml:"id,attr"`
			Version string `xml:"version,attr"`
		} `xml:"package"`
	}
	if err := xml.Unmarshal(content, &cfg); err != nil {
		return nil, fmt.Errorf("parse packages.config: %w", err)
	}

	result := &ParseResult{ManifestPath: path}

	for _, pkg := range cfg.Packages {
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    pkg.ID,
			Version: pkg.Version,
			Vendor:  dotnetVendor(pkg.ID),
			Scope:   "runtime",
			Direct:  true,
		})
	}

	return result, nil
}

func dotnetVendor(name string) string {
	if i := strings.IndexByte(name, '.'); i > 0 {
		return name[:i]
	}
	return name
}
