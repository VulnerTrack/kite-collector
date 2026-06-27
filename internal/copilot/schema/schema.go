package schema

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/vulnertrack/kite-collector/internal/copilot/dag"
)

//go:embed schema.json
var defaultSchemaJSON []byte

// LoadDefault parses and validates the embedded default schema.
func LoadDefault() (*Schema, error) {
	return Parse(defaultSchemaJSON)
}

// Parse decodes JSON bytes into a Schema and validates structural integrity.
func Parse(data []byte) (*Schema, error) {
	var s Schema
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("schema: invalid JSON: %w", err)
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// BuildDAG constructs a DAG from the schema's node dependencies and returns
// both the graph and the topologically sorted node IDs. Returns an error if
// the dependency graph contains a cycle or references an undefined node.
func BuildDAG(s *Schema) (*dag.Graph, []string, error) {
	nodeIDs := make(map[string]bool)
	for _, n := range s.AllNodes() {
		nodeIDs[n.ID] = true
	}

	g := dag.New()
	for _, n := range s.AllNodes() {
		g.AddNode(n.ID)
		for _, dep := range n.DependsOn {
			if !nodeIDs[dep] {
				return nil, nil, fmt.Errorf("schema: node %q depends on undefined node %q", n.ID, dep)
			}
			g.AddEdge(n.ID, dep)
		}
	}

	sorted, err := g.TopologicalSort()
	if err != nil {
		return nil, nil, fmt.Errorf("schema: %w", err)
	}

	return g, sorted, nil
}

// validate checks the schema for structural correctness.
func (s *Schema) validate() error {
	if s.SchemaVersion == "" {
		return fmt.Errorf("schema: missing schema_version")
	}
	if len(s.Groups) == 0 {
		return fmt.Errorf("schema: no groups defined")
	}

	seen := make(map[string]bool)
	for _, g := range s.Groups {
		if g.ID == "" {
			return fmt.Errorf("schema: group has empty ID")
		}
		for _, n := range g.Nodes {
			if n.ID == "" {
				return fmt.Errorf("schema: node in group %q has empty ID", g.ID)
			}
			if seen[n.ID] {
				return fmt.Errorf("schema: duplicate node ID %q", n.ID)
			}
			seen[n.ID] = true

			if n.DefaultRule == "" {
				return fmt.Errorf("schema: node %q has empty default_rule", n.ID)
			}
		}
	}

	// Verify all depends_on references exist.
	for _, g := range s.Groups {
		for _, n := range g.Nodes {
			for _, dep := range n.DependsOn {
				if !seen[dep] {
					return fmt.Errorf("schema: node %q depends on undefined node %q", n.ID, dep)
				}
			}
		}
	}

	// Verify preset IDs are unique and skip_groups reference valid groups.
	groupIDs := make(map[string]bool)
	for _, g := range s.Groups {
		groupIDs[g.ID] = true
	}
	presetIDs := make(map[string]bool)
	for _, p := range s.Presets {
		if p.ID == "" {
			return fmt.Errorf("schema: preset has empty ID")
		}
		if presetIDs[p.ID] {
			return fmt.Errorf("schema: duplicate preset ID %q", p.ID)
		}
		presetIDs[p.ID] = true
		for _, sg := range p.SkipGroups {
			if !groupIDs[sg] {
				return fmt.Errorf("schema: preset %q references undefined skip_group %q", p.ID, sg)
			}
		}
	}

	return nil
}
