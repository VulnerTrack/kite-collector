//go:build e2e

package vpn

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// TestTailscaleHostDiscoveryE2E shells out to the real `tailscale` binary on
// the host running the test and enumerates live tailnet peers as machines.
// Behind the e2e build tag so `go test ./...` stays hermetic:
//
//	go test -tags=e2e ./internal/discovery/vpn/...
//
// It asserts only structural invariants — never a specific tailnet topology
// — so it is safe on any enrolled host and reveals nothing about a
// particular fleet in CI. Reads only; never mutates VPN state.
func TestTailscaleHostDiscoveryE2E(t *testing.T) {
	if _, err := exec.LookPath("tailscale"); err != nil {
		t.Skip("tailscale CLI not installed on this host")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Force the local CLI path regardless of any KITE_TAILSCALE_* env.
	e := newTailscaleEnumerator()
	peers, err := e.enumerateCLI(ctx)
	if err != nil {
		t.Fatalf("enumerateCLI: %v", err)
	}
	if len(peers) == 0 {
		t.Skip("tailscaled present but no peers (logged out / solo tailnet)")
	}

	owners := 0
	for _, p := range peers {
		if p.VPNType != "tailscale" {
			t.Fatalf("peer %q has vpn_type %q, want tailscale", p.Hostname, p.VPNType)
		}
		if p.displayHostname() == "" {
			t.Fatalf("peer has no derivable hostname: %+v", p)
		}
		if p.Owner != "" {
			owners++
		}
	}
	t.Logf("discovered %d tailnet peers, %d with a resolved owner", len(peers), owners)

	// Exercise the full Source pipeline (map + dedup) against real data.
	machines, err := New().Discover(ctx, nil)
	if err != nil {
		t.Fatalf("Source.Discover: %v", err)
	}
	tsMachines := 0
	for _, m := range machines {
		if m.DiscoverySource == "vpn.tailscale" {
			tsMachines++
			if m.Hostname == "" {
				t.Fatal("emitted machine has empty hostname")
			}
			if !m.MachineType.Valid() {
				t.Fatalf("machine %q has invalid machine_type %q", m.Hostname, m.MachineType)
			}
		}
	}
	t.Logf("Source.Discover emitted %d machines total, %d from tailscale", len(machines), tsMachines)
	if tsMachines == 0 {
		t.Fatal("live peers were enumerated but none survived mapping into machines")
	}
}
