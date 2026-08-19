package vpn

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// fixedID and fixedNow make Peer.toMachine fully deterministic in tests.
var (
	fixedID  = uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	fixedNow = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
)

func tagsOf(t *testing.T, m model.Machine) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(m.Tags), &out))
	return out
}

func TestToMachine_HappyPath(t *testing.T) {
	seen := time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC)
	p := Peer{
		VPNType:   "tailscale",
		Hostname:  "laptop-1",
		DNSName:   "laptop-1.tail1234.ts.net.",
		OS:        "macOS",
		OSVersion: "14.5",
		Owner:     "alice@example.com",
		Endpoint:  "203.0.113.5:41641",
		PublicKey: "nodekey:abc",
		Addresses: []string{"100.64.0.2", "fd7a::2"},
		Online:    true,
		LastSeen:  seen,
		Tags:      map[string]any{"tailnet": "example.com"},
	}
	m := p.toMachine(fixedID, fixedNow)

	assert.Equal(t, fixedID, m.ID)
	assert.Equal(t, "laptop-1", m.Hostname)
	assert.Equal(t, model.MachineTypeWorkstation, m.MachineType, "macOS is an endpoint")
	assert.Equal(t, "macos", m.OSFamily, "OS is normalised")
	assert.Equal(t, "14.5", m.OSVersion)
	assert.Equal(t, "alice@example.com", m.Owner)
	assert.Equal(t, "vpn.tailscale", m.DiscoverySource)
	assert.Equal(t, model.AuthorizationUnknown, m.IsAuthorized)
	assert.Equal(t, model.ManagedUnknown, m.IsManaged)
	assert.Equal(t, seen, m.LastSeenAt, "explicit LastSeen is preserved")

	tags := tagsOf(t, m)
	assert.Equal(t, "tailscale", tags["vpn_type"])
	assert.Equal(t, true, tags["online"])
	assert.Equal(t, "laptop-1.tail1234.ts.net", tags["dns_name"], "trailing dot trimmed")
	assert.Equal(t, "203.0.113.5:41641", tags["endpoint"])
	assert.Equal(t, "alice@example.com", tags["owner"])
	assert.Equal(t, "example.com", tags["tailnet"], "per-tech tag merged")
	assert.ElementsMatch(t, []any{"100.64.0.2", "fd7a::2"}, tags["overlay_addresses"])
}

func TestToMachine_ZeroLastSeenUsesNow(t *testing.T) {
	p := Peer{VPNType: "wireguard", PublicKey: "k", Addresses: []string{"10.0.0.9"}}
	m := p.toMachine(fixedID, fixedNow)
	assert.Equal(t, fixedNow, m.LastSeenAt, "zero LastSeen falls back to scan time")
}

func TestToMachine_HostnameFallbackChain(t *testing.T) {
	cases := []struct {
		name string
		peer Peer
		want string
	}{
		{"hostname wins", Peer{VPNType: "t", Hostname: "h", DNSName: "d.net", Addresses: []string{"1.2.3.4"}}, "h"},
		{"dns when no hostname", Peer{VPNType: "t", DNSName: "d.net.", Addresses: []string{"1.2.3.4"}}, "d.net"},
		{"address when no name", Peer{VPNType: "t", Addresses: []string{"1.2.3.4"}}, "1.2.3.4"},
		{"key label when only key", Peer{VPNType: "zerotier", PublicKey: "a1b2c3d4e5"}, "zerotier-a1b2c3d4e5"},
		{"long key truncated", Peer{VPNType: "wg", PublicKey: "0123456789abcdefXYZ"}, "wg-0123456789ab"},
		{"unknown last resort", Peer{VPNType: "nebula"}, "nebula-unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, c.peer.toMachine(fixedID, fixedNow).Hostname)
		})
	}
}

func TestToMachine_MachineTypeHintOverrides(t *testing.T) {
	p := Peer{VPNType: "cisco-anyconnect", Hostname: "vpn.corp.com", OS: "linux", MachineTypeHint: model.MachineTypeAppliance}
	m := p.toMachine(fixedID, fixedNow)
	assert.Equal(t, model.MachineTypeAppliance, m.MachineType, "hint beats OS-derived server")
}

func TestMachineTypeForOS(t *testing.T) {
	cases := map[string]model.MachineType{
		"macOS":   model.MachineTypeWorkstation,
		"darwin":  model.MachineTypeWorkstation,
		"iOS":     model.MachineTypeWorkstation,
		"android": model.MachineTypeWorkstation,
		"windows": model.MachineTypeWorkstation,
		"linux":   model.MachineTypeServer,
		"freebsd": model.MachineTypeServer,
		"":        model.MachineTypeWorkstation,
		"plan9":   model.MachineTypeWorkstation,
	}
	for in, want := range cases {
		assert.Equalf(t, want, machineTypeForOS(in), "os=%q", in)
	}
}

func TestNormalizeOS(t *testing.T) {
	assert.Equal(t, "macos", normalizeOS("Darwin"))
	assert.Equal(t, "macos", normalizeOS("macOS"))
	assert.Equal(t, "ios", normalizeOS("iPhone"))
	assert.Equal(t, "linux", normalizeOS("  Linux "))
	assert.Equal(t, "", normalizeOS(""))
}

func TestDedupKey_Precedence(t *testing.T) {
	// Public key is the strongest identity.
	assert.Equal(t, "tailscale|k:KEY",
		Peer{VPNType: "tailscale", PublicKey: "KEY", DNSName: "d", Addresses: []string{"1.2.3.4"}}.dedupKey())
	// Then DNS name (lower-cased, dot-trimmed).
	assert.Equal(t, "netbird|d:host.example.com",
		Peer{VPNType: "netbird", DNSName: "Host.Example.com."}.dedupKey())
	// Then first address.
	assert.Equal(t, "wireguard|a:10.0.0.2",
		Peer{VPNType: "wireguard", Addresses: []string{"10.0.0.2"}}.dedupKey())
	// Then hostname.
	assert.Equal(t, "ipsec|h:gw", Peer{VPNType: "ipsec", Hostname: "GW"}.dedupKey())
	// Same identity on different fabrics does NOT collide here.
	a := Peer{VPNType: "tailscale", PublicKey: "X"}.dedupKey()
	b := Peer{VPNType: "netbird", PublicKey: "X"}.dedupKey()
	assert.NotEqual(t, a, b)
}

func TestSortAddrs(t *testing.T) {
	got := sortAddrs([]string{"10.0.0.2", "", "  10.0.0.1  ", "10.0.0.2", "fd7a::1"})
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2", "fd7a::1"}, got,
		"trims, drops blanks, dedups, sorts")
	assert.Empty(t, sortAddrs(nil))
}

func TestToMachine_OwnerlessKeyFabric(t *testing.T) {
	// WireGuard has no user concept: Owner empty, key surfaced in tags.
	p := Peer{VPNType: "wireguard", PublicKey: "pk", Addresses: []string{"10.0.0.5"}}
	m := p.toMachine(fixedID, fixedNow)
	assert.Empty(t, m.Owner)
	tags := tagsOf(t, m)
	assert.Equal(t, "pk", tags["public_key"])
	_, hasOwner := tags["owner"]
	assert.False(t, hasOwner, "no owner tag when identity is absent")
}
