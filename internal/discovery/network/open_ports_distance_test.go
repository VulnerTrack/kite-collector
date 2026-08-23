package network

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parsePortForDistanceTest extracts the numeric port from a listener address.
// Named distinctively to avoid colliding with package helpers.
func parsePortForDistanceTest(t *testing.T, addr net.Addr) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr.String())
	require.NoError(t, err)
	p, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return p
}

// TestProbeIP_OpenPortsDistanceIsZero pins the scanner's accuracy: given a
// known set of open ports on loopback, probeIP must report EXACTLY those — no
// open port missed, no closed port reported open. The "distance" is the size
// of the symmetric difference between the detected set and the real set; the
// requirement is that it be 0.
func TestProbeIP_OpenPortsDistanceIsZero(t *testing.T) {
	ctx := context.Background()
	lc := &net.ListenConfig{}

	// Real open ports: held-open loopback listeners (closed at test end).
	realOpen := map[int]struct{}{}
	openList := make([]int, 0, 5)
	for i := 0; i < 5; i++ {
		ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		p := parsePortForDistanceTest(t, ln.Addr())
		realOpen[p] = struct{}{}
		openList = append(openList, p)
	}

	// Definitely-closed ports: bind then release so the number is free but
	// nothing is listening on it during the scan.
	closedList := make([]int, 0, 4)
	for i := 0; i < 4; i++ {
		ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		p := parsePortForDistanceTest(t, ln.Addr())
		require.NoError(t, ln.Close())
		closedList = append(closedList, p)
	}

	// Probe the union of open + closed ports.
	probe := append(append([]int{}, openList...), closedList...)
	detected, _ := New().probeIP(ctx, netip.MustParseAddr("127.0.0.1"), probe, 2*time.Second, false)

	detectedSet := make(map[int]struct{}, len(detected))
	for _, p := range detected {
		detectedSet[p] = struct{}{}
	}

	// distance = missed (real, undetected) + spurious (detected, not real).
	var missed, spurious []int
	for p := range realOpen {
		if _, ok := detectedSet[p]; !ok {
			missed = append(missed, p)
		}
	}
	for p := range detectedSet {
		if _, ok := realOpen[p]; !ok {
			spurious = append(spurious, p)
		}
	}
	distance := len(missed) + len(spurious)

	assert.Equalf(t, 0, distance,
		"open-port distance (current vs real) must be 0 — missed=%v spurious=%v detected=%v real=%v",
		missed, spurious, detected, openList)
	// Equivalent, more readable phrasing of the same guarantee.
	assert.ElementsMatch(t, openList, detected, "detected open ports must equal the real open ports")
}
