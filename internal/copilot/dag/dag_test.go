package dag

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmptyGraph(t *testing.T) {
	g := New()
	sorted, err := g.TopologicalSort()
	require.NoError(t, err)
	assert.Empty(t, sorted)
	assert.Equal(t, 0, g.NodeCount())
}

func TestSingleNode(t *testing.T) {
	g := New()
	g.AddNode("a")
	sorted, err := g.TopologicalSort()
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, sorted)
}

func TestLinearChain(t *testing.T) {
	g := New()
	// a -> b -> c (b depends on a, c depends on b)
	g.AddEdge("b", "a")
	g.AddEdge("c", "b")
	sorted, err := g.TopologicalSort()
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, sorted)
}

func TestDiamond(t *testing.T) {
	g := New()
	// a -> b, a -> c, b -> d, c -> d
	g.AddEdge("b", "a")
	g.AddEdge("c", "a")
	g.AddEdge("d", "b")
	g.AddEdge("d", "c")
	sorted, err := g.TopologicalSort()
	require.NoError(t, err)
	// a must be first, d must be last, b and c in between
	assert.Equal(t, "a", sorted[0])
	assert.Equal(t, "d", sorted[3])
	// b and c are alphabetically sorted since they have same in-degree timing
	assert.Equal(t, "b", sorted[1])
	assert.Equal(t, "c", sorted[2])
}

func TestDisconnectedComponents(t *testing.T) {
	g := New()
	g.AddNode("x")
	g.AddNode("y")
	g.AddEdge("b", "a")
	sorted, err := g.TopologicalSort()
	require.NoError(t, err)
	assert.Len(t, sorted, 4)
	// All nodes present
	assert.Contains(t, sorted, "a")
	assert.Contains(t, sorted, "b")
	assert.Contains(t, sorted, "x")
	assert.Contains(t, sorted, "y")
}

func TestSimpleCycle(t *testing.T) {
	g := New()
	g.AddEdge("b", "a")
	g.AddEdge("a", "b")
	_, err := g.TopologicalSort()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle detected")
	assert.Contains(t, err.Error(), "a")
	assert.Contains(t, err.Error(), "b")
}

func TestSelfLoop(t *testing.T) {
	g := New()
	g.AddEdge("a", "a")
	_, err := g.TopologicalSort()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle detected")
}

func TestThreeNodeCycle(t *testing.T) {
	g := New()
	g.AddEdge("b", "a")
	g.AddEdge("c", "b")
	g.AddEdge("a", "c")
	_, err := g.TopologicalSort()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle detected")
}

func TestPartialCycle(t *testing.T) {
	// Some nodes form a cycle, others don't
	g := New()
	g.AddNode("x") // independent
	g.AddEdge("b", "a")
	g.AddEdge("a", "b") // cycle between a and b
	_, err := g.TopologicalSort()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle detected")
}

func TestDuplicateAddNode(t *testing.T) {
	g := New()
	g.AddNode("a")
	g.AddNode("a") // no-op
	assert.Equal(t, 1, g.NodeCount())
}

func TestDependencyOrder(t *testing.T) {
	g := New()
	// Complex dependency tree
	g.AddEdge("audit.profile", "audit.enabled")
	g.AddEdge("posture.enabled", "audit.enabled")
	g.AddNode("log_level")

	sorted, err := g.TopologicalSort()
	require.NoError(t, err)

	// audit.enabled must come before audit.profile and posture.enabled
	idxEnabled := indexOf(sorted, "audit.enabled")
	idxProfile := indexOf(sorted, "audit.profile")
	idxPosture := indexOf(sorted, "posture.enabled")
	assert.Less(t, idxEnabled, idxProfile)
	assert.Less(t, idxEnabled, idxPosture)
}

func TestTopologicalSortIsStable(t *testing.T) {
	// Run multiple times to verify deterministic output
	for range 10 {
		g := New()
		g.AddEdge("c", "a")
		g.AddEdge("d", "a")
		g.AddEdge("e", "b")
		g.AddNode("f")
		sorted, err := g.TopologicalSort()
		require.NoError(t, err)
		assert.Equal(t, sorted[0], "a")
		// Verify consistent ordering
		first := sorted
		g2 := New()
		g2.AddEdge("c", "a")
		g2.AddEdge("d", "a")
		g2.AddEdge("e", "b")
		g2.AddNode("f")
		second, err := g2.TopologicalSort()
		require.NoError(t, err)
		assert.Equal(t, first, second)
	}
}

func indexOf(s []string, val string) int {
	for i, v := range s {
		if v == val {
			return i
		}
	}
	return -1
}
