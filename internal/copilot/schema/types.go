// Package schema defines the data types and parser for the copilot wizard schema.
// The schema drives both the interactive wizard and headless --config validation.
package schema

// Schema is the top-level structure embedded as schema.json.
type Schema struct {
	SchemaVersion string   `json:"schema_version"`
	Groups        []Group  `json:"groups"`
	Presets       []Preset `json:"presets"`
}

// Group is a logical section of related configuration nodes.
type Group struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Nodes []Node `json:"nodes"`
}

// Node is a single configurable parameter in the wizard DAG.
// Fields ordered for optimal GC pointer scanning (strings before slices, bool last).
type Node struct {
	ID                string   `json:"id"`
	Type              string   `json:"type"` // "input", "select", "confirm", "multiselect", "password"
	Prompt            string   `json:"prompt"`
	DefaultRule       string   `json:"default_rule"`
	SkipWhen          string   `json:"skip_when,omitempty"`
	PreflightValidate string   `json:"preflight_validate,omitempty"`
	Options           []string `json:"options,omitempty"`
	DependsOn         []string `json:"depends_on"`
	Required          bool     `json:"required"`
}

// Preset is a goal-driven entry point that pre-fills context and skips groups.
type Preset struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Context     map[string]any `json:"context"`
	SkipGroups  []string       `json:"skip_groups"`
	PostActions []string       `json:"post_actions"`
	Primary     bool           `json:"primary"`
}

// AllNodes returns a flat list of all nodes across all groups.
func (s *Schema) AllNodes() []Node {
	var nodes []Node
	for _, g := range s.Groups {
		nodes = append(nodes, g.Nodes...)
	}
	return nodes
}

// NodeByID returns the node with the given ID, or nil if not found.
func (s *Schema) NodeByID(id string) *Node {
	for i := range s.Groups {
		for j := range s.Groups[i].Nodes {
			if s.Groups[i].Nodes[j].ID == id {
				return &s.Groups[i].Nodes[j]
			}
		}
	}
	return nil
}

// GroupForNode returns the group ID that contains the given node ID.
func (s *Schema) GroupForNode(nodeID string) string {
	for _, g := range s.Groups {
		for _, n := range g.Nodes {
			if n.ID == nodeID {
				return g.ID
			}
		}
	}
	return ""
}

// PresetByID returns the preset with the given ID, or nil if not found.
func (s *Schema) PresetByID(id string) *Preset {
	for i := range s.Presets {
		if s.Presets[i].ID == id {
			return &s.Presets[i]
		}
	}
	return nil
}

// PrimaryPresets returns only the presets marked as primary (shown by default).
func (s *Schema) PrimaryPresets() []Preset {
	var primary []Preset
	for _, p := range s.Presets {
		if p.Primary {
			primary = append(primary, p)
		}
	}
	return primary
}
