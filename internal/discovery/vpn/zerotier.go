package vpn

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// zerotierEnumerator enumerates ZeroTier peers via `zerotier-cli -j
// listpeers`. Each LEAF peer is a member host, identified by its 10-hex
// node address. PLANET peers are ZeroTier's global public roots — shared
// infrastructure, not part of the operator's fleet — and are dropped;
// MOON peers (self-hosted roots) are kept.
//
// The local CLI exposes node addresses and transport paths but no
// hostname/OS/owner (those live in the ZeroTier Central API). The command
// reads the daemon authtoken and normally needs root; failure degrades to
// no peers, not a scan error.
type zerotierEnumerator struct {
	run      runner
	lookPath lookPather
	binary   string
	timeout  time.Duration
}

func newZeroTierEnumerator() *zerotierEnumerator {
	return &zerotierEnumerator{
		run:      defaultRunner,
		lookPath: defaultLookPath,
		binary:   "zerotier-cli",
		timeout:  5 * time.Second,
	}
}

func (e *zerotierEnumerator) vpnType() string { return "zerotier" }

func (e *zerotierEnumerator) enumerate(ctx context.Context, _ map[string]any) ([]Peer, error) {
	bin, err := e.lookPath(e.binary)
	if err != nil {
		return nil, nil // zerotier-one not installed
	}
	cctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	raw, err := e.run(cctx, bin, "-j", "listpeers")
	if err != nil || len(raw) == 0 {
		slog.Debug("vpn: zerotier listpeers failed",
			"code", string(LogCodeZeroTierCLIFailed), "error", err)
		return nil, nil
	}
	return peersFromZTListPeers(raw)
}

type ztPeer struct {
	Address string   `json:"address"`
	Role    string   `json:"role"`
	Version string   `json:"version"`
	Paths   []ztPath `json:"paths"`
	Latency int      `json:"latency"`
}

type ztPath struct {
	Address     string `json:"address"`
	LastReceive int64  `json:"lastReceive"` // ms since epoch
	Active      bool   `json:"active"`
}

// peersFromZTListPeers is the pure projection of the listpeers JSON.
func peersFromZTListPeers(raw []byte) ([]Peer, error) {
	var peers []ztPeer
	if err := json.Unmarshal(raw, &peers); err != nil {
		return nil, fmt.Errorf("zerotier: decode listpeers json: %w", err)
	}
	out := make([]Peer, 0, len(peers))
	for _, zp := range peers {
		if zp.Role == "PLANET" {
			continue // global public root — infrastructure, not a fleet host
		}
		p := Peer{
			VPNType:   "zerotier",
			PublicKey: zp.Address,
			Tags: map[string]any{
				"role":         zp.Role,
				"node_address": zp.Address,
			},
		}
		if zp.Version != "" && zp.Version != "-1.-1.-1" {
			p.OSVersion = zp.Version
			p.Tags["client_version"] = zp.Version
		}
		if zp.Latency >= 0 {
			p.Tags["latency_ms"] = zp.Latency
		}
		endpoint, lastSeen, active := bestZTPath(zp.Paths)
		p.Endpoint = endpoint
		p.Online = active
		p.LastSeen = lastSeen
		out = append(out, p)
	}
	return out, nil
}

// bestZTPath returns the transport endpoint, last-contact time, and
// liveness for a peer: it prefers an active path and the most recent
// lastReceive across all paths.
func bestZTPath(paths []ztPath) (endpoint string, lastSeen time.Time, active bool) {
	var newest int64
	for _, path := range paths {
		if path.Active {
			active = true
			if endpoint == "" {
				endpoint = path.Address
			}
		}
		if path.LastReceive > newest {
			newest = path.LastReceive
			if endpoint == "" || path.Active {
				endpoint = path.Address
			}
		}
	}
	if newest > 0 {
		lastSeen = time.UnixMilli(newest).UTC()
	}
	return endpoint, lastSeen, active
}
