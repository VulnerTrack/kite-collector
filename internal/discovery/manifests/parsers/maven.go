package parsers

import (
	"context"
	"encoding/xml"
	"fmt"
)

// MavenParser handles pom.xml files.
type MavenParser struct{}

func (p *MavenParser) Patterns() []string { return []string{"pom.xml"} }
func (p *MavenParser) Ecosystem() string  { return "java" }

func (p *MavenParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	var pom struct {
		GroupID      string              `xml:"groupId"`
		ArtifactID   string              `xml:"artifactId"`
		Version      string              `xml:"version"`
		Dependencies struct {
			Dependency []pomDependency `xml:"dependency"`
		} `xml:"dependencies"`
	}
	if err := xml.Unmarshal(content, &pom); err != nil {
		return nil, fmt.Errorf("parse pom.xml: %w", err)
	}

	result := &ParseResult{
		ProjectName:    pom.GroupID + ":" + pom.ArtifactID,
		ProjectVersion: pom.Version,
		ManifestPath:   path,
	}
	if pom.GroupID == "" {
		result.ProjectName = pom.ArtifactID
	}

	for _, dep := range pom.Dependencies.Dependency {
		// Skip dependencies with Maven property placeholders.
		if len(dep.Version) > 0 && dep.Version[0] == '$' {
			result.Errors = append(result.Errors,
				fmt.Sprintf("unresolved property in version for %s:%s", dep.GroupID, dep.ArtifactID))
			continue
		}
		scope := "runtime"
		switch dep.Scope {
		case "test":
			scope = "test"
		case "provided", "system":
			scope = "optional"
		}
		result.Dependencies = append(result.Dependencies, Dependency{
			Name:    dep.GroupID + ":" + dep.ArtifactID,
			Version: dep.Version,
			Vendor:  dep.GroupID,
			Scope:   scope,
			Direct:  true,
		})
	}

	return result, nil
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}
