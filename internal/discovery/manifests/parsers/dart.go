package parsers

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v3"
)

// PubspecParser handles pubspec.yaml files (Dart/Flutter).
type PubspecParser struct{}

func (p *PubspecParser) Patterns() []string { return []string{"pubspec.yaml"} }
func (p *PubspecParser) Ecosystem() string  { return "dart" }

func (p *PubspecParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var spec struct {
		Dependencies    map[string]any `yaml:"dependencies"`
		DevDependencies map[string]any `yaml:"dev_dependencies"`
		Name            string         `yaml:"name"`
		Version         string         `yaml:"version"`
	}
	if err := yaml.Unmarshal(content, &spec); err != nil {
		return nil, fmt.Errorf("parse pubspec.yaml: %w", err)
	}

	result := &ParseResult{
		ProjectName:    spec.Name,
		ProjectVersion: spec.Version,
		ManifestPath:   path,
	}

	addPubDeps(result, spec.Dependencies, "runtime")
	addPubDeps(result, spec.DevDependencies, "dev")

	return result, nil
}

func addPubDeps(result *ParseResult, deps map[string]any, scope string) {
	for name, val := range deps {
		version := ""
		switch v := val.(type) {
		case string:
			version = cleanVersion(v)
		case map[string]any:
			if ver, ok := v["version"]; ok {
				if s, ok := ver.(string); ok {
					version = cleanVersion(s)
				}
			}
		}
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    name,
			Version: version,
			Vendor:  name,
			Scope:   scope,
			Direct:  true,
		})
	}
}
