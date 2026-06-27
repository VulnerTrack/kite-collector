package schema

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDefault(t *testing.T) {
	s, err := LoadDefault()
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", s.SchemaVersion)
	assert.NotEmpty(t, s.Groups)
	assert.NotEmpty(t, s.Presets)
}

func TestLoadDefaultNodeCount(t *testing.T) {
	s, err := LoadDefault()
	require.NoError(t, err)
	nodes := s.AllNodes()
	assert.GreaterOrEqual(t, len(nodes), 30, "schema should define 30+ parameters")
}

func TestLoadDefaultPresetCount(t *testing.T) {
	s, err := LoadDefault()
	require.NoError(t, err)
	assert.Len(t, s.Presets, 10, "schema should define 10 presets")
}

func TestPrimaryPresets(t *testing.T) {
	s, err := LoadDefault()
	require.NoError(t, err)
	primary := s.PrimaryPresets()
	assert.Len(t, primary, 5, "5 presets should be primary")
}

func TestNodeByID(t *testing.T) {
	s, err := LoadDefault()
	require.NoError(t, err)

	node := s.NodeByID("log_level")
	require.NotNil(t, node)
	assert.Equal(t, "select", node.Type)
	assert.Equal(t, "'info'", node.DefaultRule)

	missing := s.NodeByID("nonexistent")
	assert.Nil(t, missing)
}

func TestPresetByID(t *testing.T) {
	s, err := LoadDefault()
	require.NoError(t, err)

	preset := s.PresetByID("quick_scan")
	require.NotNil(t, preset)
	assert.True(t, preset.Primary)
	assert.Contains(t, preset.SkipGroups, "endpoints")

	missing := s.PresetByID("nonexistent")
	assert.Nil(t, missing)
}

func TestGroupForNode(t *testing.T) {
	s, err := LoadDefault()
	require.NoError(t, err)

	assert.Equal(t, "environment", s.GroupForNode("log_level"))
	assert.Equal(t, "discovery", s.GroupForNode("discovery.agent.enabled"))
	assert.Equal(t, "", s.GroupForNode("nonexistent"))
}

func TestBuildDAG(t *testing.T) {
	s, err := LoadDefault()
	require.NoError(t, err)

	g, sorted, err := BuildDAG(s)
	require.NoError(t, err)
	assert.Equal(t, len(s.AllNodes()), g.NodeCount())
	assert.Equal(t, len(s.AllNodes()), len(sorted))

	// Verify dependency order: discovery.agent.collect_software depends on
	// discovery.agent.enabled, so enabled must come first.
	idxEnabled := indexOf(sorted, "discovery.agent.enabled")
	idxSoftware := indexOf(sorted, "discovery.agent.collect_software")
	assert.Less(t, idxEnabled, idxSoftware)
}

func TestBuildDAGDependencyOrdering(t *testing.T) {
	s, err := LoadDefault()
	require.NoError(t, err)

	_, sorted, err := BuildDAG(s)
	require.NoError(t, err)

	// For every node, verify all its dependencies appear earlier.
	posMap := make(map[string]int)
	for i, id := range sorted {
		posMap[id] = i
	}
	for _, n := range s.AllNodes() {
		for _, dep := range n.DependsOn {
			assert.Less(t, posMap[dep], posMap[n.ID],
				"dependency %q should appear before %q", dep, n.ID)
		}
	}
}

func TestParseInvalidJSON(t *testing.T) {
	_, err := Parse([]byte(`{invalid`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func TestParseMissingVersion(t *testing.T) {
	data, _ := json.Marshal(Schema{
		Groups: []Group{{ID: "g", Nodes: []Node{{
			ID: "n", DefaultRule: "'x'",
		}}}},
	})
	_, err := Parse(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing schema_version")
}

func TestParseNoGroups(t *testing.T) {
	data, _ := json.Marshal(Schema{SchemaVersion: "1.0.0"})
	_, err := Parse(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no groups defined")
}

func TestParseDuplicateNodeID(t *testing.T) {
	s := Schema{
		SchemaVersion: "1.0.0",
		Groups: []Group{{
			ID: "g",
			Nodes: []Node{
				{ID: "dup", DefaultRule: "'x'"},
				{ID: "dup", DefaultRule: "'y'"},
			},
		}},
	}
	data, _ := json.Marshal(s)
	_, err := Parse(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate node ID")
}

func TestParseEmptyDefaultRule(t *testing.T) {
	s := Schema{
		SchemaVersion: "1.0.0",
		Groups: []Group{{
			ID:    "g",
			Nodes: []Node{{ID: "n", DefaultRule: ""}},
		}},
	}
	data, _ := json.Marshal(s)
	_, err := Parse(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty default_rule")
}

func TestParseUndefinedDependency(t *testing.T) {
	s := Schema{
		SchemaVersion: "1.0.0",
		Groups: []Group{{
			ID: "g",
			Nodes: []Node{{
				ID:          "n",
				DefaultRule: "'x'",
				DependsOn:   []string{"ghost"},
			}},
		}},
	}
	data, _ := json.Marshal(s)
	_, err := Parse(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "undefined node")
}

func TestParseDuplicatePresetID(t *testing.T) {
	s := Schema{
		SchemaVersion: "1.0.0",
		Groups: []Group{{
			ID:    "g",
			Nodes: []Node{{ID: "n", DefaultRule: "'x'"}},
		}},
		Presets: []Preset{
			{ID: "p"},
			{ID: "p"},
		},
	}
	data, _ := json.Marshal(s)
	_, err := Parse(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate preset ID")
}

func TestParseInvalidSkipGroup(t *testing.T) {
	s := Schema{
		SchemaVersion: "1.0.0",
		Groups: []Group{{
			ID:    "g",
			Nodes: []Node{{ID: "n", DefaultRule: "'x'"}},
		}},
		Presets: []Preset{{
			ID:         "p",
			SkipGroups: []string{"nonexistent"},
		}},
	}
	data, _ := json.Marshal(s)
	_, err := Parse(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "undefined skip_group")
}

func TestBuildDAGCycleDetection(t *testing.T) {
	s := &Schema{
		SchemaVersion: "1.0.0",
		Groups: []Group{{
			ID: "g",
			Nodes: []Node{
				{ID: "a", DefaultRule: "'x'", DependsOn: []string{"b"}},
				{ID: "b", DefaultRule: "'y'", DependsOn: []string{"a"}},
			},
		}},
	}
	_, _, err := BuildDAG(s)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle detected")
}

func TestBuildDAGUndefinedDep(t *testing.T) {
	s := &Schema{
		SchemaVersion: "1.0.0",
		Groups: []Group{{
			ID: "g",
			Nodes: []Node{
				{ID: "a", DefaultRule: "'x'", DependsOn: []string{"ghost"}},
			},
		}},
	}
	_, _, err := BuildDAG(s)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "undefined node")
}

func indexOf(s []string, val string) int {
	for i, v := range s {
		if v == val {
			return i
		}
	}
	return -1
}
