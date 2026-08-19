package vpn

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// fakeEnum is a scriptable enumerator for Source-level tests.
type fakeEnum struct {
	err   error
	typ   string
	peers []Peer
}

func (f fakeEnum) vpnType() string { return f.typ }
func (f fakeEnum) enumerate(context.Context, map[string]any) ([]Peer, error) {
	return f.peers, f.err
}

// newTestSource builds a Source with deterministic id/now and a fixed
// enumerator set.
func newTestSource(enums ...enumerator) *Source {
	var n int
	return &Source{
		now: func() time.Time { return fixedNow },
		newID: func() uuid.UUID {
			n++
			return uuid.MustParse(fmt.Sprintf("018f0000-0000-7000-8000-%012d", n))
		},
		enumerators: enums,
	}
}

func TestSource_Name(t *testing.T) {
	assert.Equal(t, "vpn", New().Name())
}

func TestSource_AggregatesAndTagsPerType(t *testing.T) {
	s := newTestSource(
		fakeEnum{typ: "tailscale", peers: []Peer{{VPNType: "tailscale", Hostname: "a", OS: "linux"}}},
		fakeEnum{typ: "wireguard", peers: []Peer{{Hostname: "b", PublicKey: "k"}}}, // VPNType empty → filled from enumerator
	)
	machines, err := s.Discover(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, machines, 2)

	a := findMachine(machines, "a")
	require.NotNil(t, a)
	assert.Equal(t, "vpn.tailscale", a.DiscoverySource)

	b := findMachine(machines, "b")
	require.NotNil(t, b)
	assert.Equal(t, "vpn.wireguard", b.DiscoverySource, "empty VPNType is backfilled from the enumerator")
}

func TestSource_DedupsWithinScan(t *testing.T) {
	dup := Peer{VPNType: "zerotier", PublicKey: "same"}
	s := newTestSource(fakeEnum{typ: "zerotier", peers: []Peer{dup, dup, {VPNType: "zerotier", PublicKey: "other"}}})
	machines, err := s.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, machines, 2, "identical dedup keys collapse to one machine")
}

func TestSource_IsolatesFailingEnumerator(t *testing.T) {
	s := newTestSource(
		fakeEnum{typ: "ipsec", err: errors.New("swanctl blew up")},
		fakeEnum{typ: "tailscale", peers: []Peer{{VPNType: "tailscale", Hostname: "survivor", OS: "linux"}}},
	)
	machines, err := s.Discover(context.Background(), nil)
	require.NoError(t, err, "one enumerator failing must not fail the source")
	require.Len(t, machines, 1)
	assert.Equal(t, "survivor", machines[0].Hostname)
}

func TestSource_DisabledViaConfig(t *testing.T) {
	s := newTestSource(fakeEnum{typ: "tailscale", peers: []Peer{{VPNType: "tailscale", Hostname: "x"}}})
	machines, err := s.Discover(context.Background(), map[string]any{"enabled": false})
	require.NoError(t, err)
	assert.Nil(t, machines, "explicit enabled:false skips the whole source")

	// Absent/nil config still runs — local discovery is on by default.
	machines, err = s.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, machines, 1)

	// Explicit enabled:true runs.
	machines, err = s.Discover(context.Background(), map[string]any{"enabled": true})
	require.NoError(t, err)
	assert.Len(t, machines, 1)
}

func TestSource_RespectsHostCap(t *testing.T) {
	peers := make([]Peer, MaxHosts+50)
	for i := range peers {
		peers[i] = Peer{VPNType: "wireguard", PublicKey: fmt.Sprintf("key-%d", i)}
	}
	s := newTestSource(fakeEnum{typ: "wireguard", peers: peers})
	machines, err := s.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, machines, MaxHosts, "output is capped at MaxHosts")
}

func TestSource_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := newTestSource(fakeEnum{typ: "tailscale", peers: []Peer{{VPNType: "tailscale", Hostname: "x"}}})
	_, err := s.Discover(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context cancelled")
}

func TestSource_EmptyWhenNothingFound(t *testing.T) {
	s := newTestSource(fakeEnum{typ: "tailscale"}, fakeEnum{typ: "wireguard"})
	machines, err := s.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, machines, "no fabrics present ⇒ no machines, no error")
}

func TestNew_WiresAllFabrics(t *testing.T) {
	s := New()
	types := map[string]bool{}
	for _, e := range s.enumerators {
		types[e.vpnType()] = true
	}
	for _, want := range []string{
		"tailscale", "wireguard", "zerotier", "netbird", "ipsec",
		"openvpn", "nebula", "cisco-anyconnect", "mullvad", "globalprotect",
	} {
		assert.Truef(t, types[want], "New() must wire the %q enumerator", want)
	}
}

// findMachine returns the first machine with the given hostname, or nil.
func findMachine(machines []model.Machine, hostname string) *model.Machine {
	for i := range machines {
		if machines[i].Hostname == hostname {
			return &machines[i]
		}
	}
	return nil
}
