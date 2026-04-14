// Package dag implements a directed acyclic graph with topological sort
// and cycle detection. It is used to determine evaluation order for the
// copilot wizard's configuration parameters based on their dependencies.
package dag

import "fmt"

// Graph represents a directed acyclic graph of string-identified nodes.
type Graph struct {
	adjacency map[string][]string // node -> list of nodes that depend on it
	inDegree  map[string]int      // node -> number of dependencies
}

// New creates an empty graph.
func New() *Graph {
	return &Graph{
		adjacency: make(map[string][]string),
		inDegree:  make(map[string]int),
	}
}

// AddNode registers a node in the graph. Calling AddNode for an existing
// node is a no-op.
func (g *Graph) AddNode(id string) {
	if _, ok := g.inDegree[id]; !ok {
		g.inDegree[id] = 0
	}
	if _, ok := g.adjacency[id]; !ok {
		g.adjacency[id] = nil
	}
}

// AddEdge records that "node" depends on "dependsOn". In the topological
// ordering, dependsOn will appear before node.
func (g *Graph) AddEdge(node, dependsOn string) {
	g.AddNode(node)
	g.AddNode(dependsOn)
	g.adjacency[dependsOn] = append(g.adjacency[dependsOn], node)
	g.inDegree[node]++
}

// NodeCount returns the number of nodes in the graph.
func (g *Graph) NodeCount() int {
	return len(g.inDegree)
}

// TopologicalSort returns nodes in dependency order using Kahn's algorithm.
// If the graph contains a cycle, it returns an error listing the nodes
// involved in the cycle.
func (g *Graph) TopologicalSort() ([]string, error) {
	// Copy in-degree map so the original is not mutated.
	degree := make(map[string]int, len(g.inDegree))
	for k, v := range g.inDegree {
		degree[k] = v
	}

	// Seed the queue with all zero in-degree nodes.
	var queue []string
	for node, d := range degree {
		if d == 0 {
			queue = append(queue, node)
		}
	}

	// Stable iteration order isn't required for correctness, but we sort
	// the initial queue to make test output deterministic.
	sortStrings(queue)

	var sorted []string
	for len(queue) > 0 {
		// Pop front.
		current := queue[0]
		queue = queue[1:]
		sorted = append(sorted, current)

		// Build a mini-batch of newly freed neighbors so we can sort them
		// for deterministic output.
		var freed []string
		for _, neighbor := range g.adjacency[current] {
			degree[neighbor]--
			if degree[neighbor] == 0 {
				freed = append(freed, neighbor)
			}
		}
		sortStrings(freed)
		queue = append(queue, freed...)
	}

	if len(sorted) != len(degree) {
		cycle := cycleNodes(degree)
		return nil, fmt.Errorf("cycle detected involving nodes: %v", cycle)
	}

	return sorted, nil
}

// cycleNodes returns the IDs of nodes that still have a non-zero in-degree
// after Kahn's algorithm completes — these are the nodes involved in cycles.
func cycleNodes(degree map[string]int) []string {
	var nodes []string
	for id, d := range degree {
		if d > 0 {
			nodes = append(nodes, id)
		}
	}
	sortStrings(nodes)
	return nodes
}

// sortStrings performs an insertion sort on a small slice of strings.
// We avoid importing "sort" to keep the package dependency-free.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
