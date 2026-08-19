// Package vpn implements a discovery.Source that performs HOST DISCOVERY
// across VPN fabrics: it enumerates the other machines — and, where the
// fabric exposes it, the users behind them — reachable from this collector
// over WireGuard, OpenVPN, IPSec/strongSwan, Tailscale, ZeroTier, Nebula,
// NetBird, and commercial clients (Cisco AnyConnect, Mullvad,
// GlobalProtect). Each discovered peer becomes a model.Machine tagged with
// its originating fabric (discovery_source = "vpn.<type>").
//
// This is the complement of internal/discovery/agent/vpn, which inventories
// THIS host's own VPN *profiles* for posture auditing. That package's
// Tailscale collector explicitly defers peer enumeration to "a future
// host_neighbors table, not host_vpn_profiles" — this package is that
// future.
//
// Every enumerator is strictly read-only: it queries a management daemon
// over its local control socket, reads a status/config file, or calls a
// vendor REST API with an operator-supplied token. It never brings a tunnel
// up or down, edits a config, or rotates a key. Enumerators that find their
// technology absent (binary missing, daemon down, config dir unreadable)
// return no peers and no error — a host without ZeroTier is not a failure.
package vpn

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// MaxHosts bounds the number of machines a single scan emits from this
// source. A mesh tailnet or a busy OpenVPN concentrator can list hundreds
// of peers; this ceiling protects the downstream persist path from a
// runaway fabric while staying far above any realistic small-org fleet.
const MaxHosts = 4096

// enumerator is the contract each per-technology backend satisfies. It is
// unexported: enumerators are an implementation detail of this source, not
// a public plugin surface.
type enumerator interface {
	// vpnType is the stable fabric identifier ("tailscale", "wireguard",
	// ...). It becomes the discovery_source suffix and the vpn_type tag.
	vpnType() string
	// enumerate returns the hosts this fabric can see. cfg is the
	// source-level configuration block (discovery.sources.vpn.*). A
	// technology that is not present MUST return (nil, nil).
	enumerate(ctx context.Context, cfg map[string]any) ([]Peer, error)
}

// Source is the VPN host-discovery source.
type Source struct {
	now         func() time.Time
	newID       func() uuid.UUID
	enumerators []enumerator
}

// New returns a Source wired with every built-in enumerator.
func New() *Source {
	return &Source{
		now:   func() time.Time { return time.Now().UTC() },
		newID: func() uuid.UUID { return uuid.Must(uuid.NewV7()) },
		enumerators: []enumerator{
			newTailscaleEnumerator(),
			newWireGuardEnumerator(),
			newZeroTierEnumerator(),
			newNetBirdEnumerator(),
			newIPSecEnumerator(),
			newOpenVPNEnumerator(),
			newNebulaEnumerator(),
			newAnyConnectEnumerator(),
			newMullvadEnumerator(),
			newGlobalProtectEnumerator(),
		},
	}
}

// Name returns the stable identifier used for per-source config lookup,
// heartbeats, and the circuit breaker. Individual machines carry a finer
// "vpn.<type>" discovery_source; this coarse name groups them.
func (s *Source) Name() string { return "vpn" }

// Discover runs every enumerator, aggregates their peers, deduplicates
// within the scan, and maps the survivors to machines. A single
// enumerator failing is logged at WARN and skipped: a broken swanctl parse
// must not drop the Tailscale inventory. The call only returns an error
// when the parent context is cancelled.
func (s *Source) Discover(ctx context.Context, cfg map[string]any) ([]model.Machine, error) {
	if !notDisabled(cfg) {
		slog.Debug("vpn: source disabled via config, skipping")
		return nil, nil
	}

	seen := make(map[string]struct{})
	var peers []Peer

	for _, e := range s.enumerators {
		if err := ctx.Err(); err != nil {
			return s.mapPeers(peers), fmt.Errorf("vpn: context cancelled mid-chain: %w", err)
		}

		got, err := e.enumerate(ctx, cfg)
		if err != nil {
			slog.Warn("vpn: enumerator failed",
				"code", string(LogCodeEnumeratorFailed),
				"vpn_type", e.vpnType(),
				"error", err)
			continue
		}

		for _, p := range got {
			if p.VPNType == "" {
				p.VPNType = e.vpnType()
			}
			key := p.dedupKey()
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			peers = append(peers, p)
			if len(peers) >= MaxHosts {
				slog.Warn("vpn: host cap reached, dropping later peers",
					"code", string(LogCodeHostCapReached),
					"cap", MaxHosts)
				return s.mapPeers(peers), nil
			}
		}
	}

	machines := s.mapPeers(peers)
	slog.Info("vpn: host discovery complete",
		"code", string(LogCodeDiscoveryComplete),
		"machines", len(machines))
	return machines, nil
}

// mapPeers projects the deduplicated peer set onto machines.
func (s *Source) mapPeers(peers []Peer) []model.Machine {
	if len(peers) == 0 {
		return nil
	}
	now := s.now()
	out := make([]model.Machine, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.toMachine(s.newID(), now))
	}
	return out
}
