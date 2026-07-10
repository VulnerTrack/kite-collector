package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

// tailscaleCollector queries the local tailscaled daemon via
// `tailscale status --json` (works without root over the local socket)
// and falls back to reading /var/lib/tailscale/tailscaled.state when the
// CLI is offline. Output projects to one Profile representing this
// node's tailnet membership — peer enumeration belongs in a future
// host_neighbors table, not host_vpn_profiles.
//
// Audit signals captured:
//   - is_full_tunnel ← an active ExitNode peer redirects all egress
//   - private_key_present ← daemon has a node key (HaveNodeKey)
//   - auto_connect ← Tailscale is daemon-managed; if BackendState is
//     "Running" the unattended host re-establishes on boot
//   - routed_subnets ← Self.PrimaryRoutes (subnet-router advertisements)
//   - endpoint ← currently-selected DERP relay or direct CurAddr
type tailscaleCollector struct {
	run        runner
	lookPath   func(string) (string, error)
	binary     string
	stateFiles []string
	timeout    time.Duration
}

// runner is the exec seam — mirrors the lldp package convention so
// tests can swap in a fixture without spawning processes.
type runner func(ctx context.Context, binary string, args ...string) ([]byte, error)

func defaultRunner(ctx context.Context, binary string, args ...string) ([]byte, error) {
	// binary is exec.LookPath-resolved (or an operator-supplied absolute
	// path) before reaching this seam; args are a fixed literal.
	cmd := exec.CommandContext(ctx, binary, args...) //#nosec G204 -- binary is LookPath-resolved; args are fixed literals
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("exec %s: %w", binary, err)
	}
	return out, nil
}

// NewTailscaleCollector returns a Tailscale collector backed by the
// local CLI/daemon.
func NewTailscaleCollector() Collector {
	return &tailscaleCollector{
		run:      defaultRunner,
		lookPath: exec.LookPath,
		binary:   "tailscale",
		timeout:  5 * time.Second,
		// State file fallback — the daemon writes node-key + login info
		// here. Linux paths only; the CLI route covers macOS/Windows.
		stateFiles: []string{
			"/var/lib/tailscale/tailscaled.state",
			"/var/db/tailscale/tailscaled.state",
		},
	}
}

func (c *tailscaleCollector) Name() string { return "tailscale-cli" }

// tsPeer is one peer node as reported under `Peer` in
// `tailscale status --json`. Only the fields we use are decoded.
//
// UserID identifies the tailnet member who owns this peer. When the
// peer's UserID differs from Self.UserID we treat it as a *shared
// server* — node sharing routed this peer into our user's view from
// another account. This is what powers the shared-peers risk signal.
type tsPeer struct {
	HostName string `json:"HostName"`
	DNSName  string `json:"DNSName"`
	UserID   int64  `json:"UserID"`
	ExitNode bool   `json:"ExitNode"`
}

// tsSelf is this node's own entry from the same JSON.
type tsSelf struct {
	HostName       string   `json:"HostName"`
	DNSName        string   `json:"DNSName"`
	OS             string   `json:"OS"`
	PublicKey      string   `json:"PublicKey"`
	Relay          string   `json:"Relay"`
	CurAddr        string   `json:"CurAddr"`
	TailscaleIPs   []string `json:"TailscaleIPs"`
	PrimaryRoutes  []string `json:"PrimaryRoutes"`
	AllowedIPs     []string `json:"AllowedIPs"`
	UserID         int64    `json:"UserID"`
	Online         bool     `json:"Online"`
	ExitNode       bool     `json:"ExitNode"`
	ExitNodeOption bool     `json:"ExitNodeOption"`
}

// tsTailnet holds the parent tailnet metadata (organisation name,
// MagicDNS suffix).
type tsTailnet struct {
	Name            string `json:"Name"`
	MagicDNSSuffix  string `json:"MagicDNSSuffix"`
	MagicDNSEnabled bool   `json:"MagicDNSEnabled"`
}

// tsStatus mirrors the fields we read from `tailscale status --json`.
// The upstream struct has many more fields; we deliberately decode a
// subset so an upstream addition cannot break our parser.
type tsStatus struct {
	Peer           map[string]tsPeer `json:"Peer"`
	Version        string            `json:"Version"`
	BackendState   string            `json:"BackendState"`
	CurrentTailnet tsTailnet         `json:"CurrentTailnet"`
	Self           tsSelf            `json:"Self"`
	HaveNodeKey    bool              `json:"HaveNodeKey"`
	TUN            bool              `json:"TUN"`
}

func (c *tailscaleCollector) Collect(ctx context.Context) ([]Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	st, source, ok := c.queryDaemon(ctx)
	if !ok {
		// Daemon path failed — try state-file fallback purely for the
		// "node key present + login known" signal. This still yields a
		// useful row even when the daemon is stopped.
		if p, ok2 := c.readStateFile(); ok2 {
			SortProfiles([]Profile{p})
			return []Profile{p}, nil
		}
		return []Profile{}, nil
	}

	p := profileFromStatus(st)
	p.ConfigPath = source
	if n := len(p.SharedPeers); n > 0 {
		// End-user devices are not expected to carry cross-account
		// routes — surface the risk so downstream alerting can pivot
		// on the log code without re-parsing the profile JSON.
		slog.Warn(
			"vpn: shared peers detected on tailnet member",
			"code", string(LogCodeTailscaleSharedPeersDetected),
			"profile", p.Name,
			"shared_peer_count", n,
			"shared_peers", p.SharedPeers,
		)
	}
	return []Profile{p}, nil
}

// queryDaemon runs `tailscale status --json` and decodes the response.
// Returns (status, configPath, true) on success; (_, _, false) when the
// binary is missing or the daemon is unreachable.
func (c *tailscaleCollector) queryDaemon(ctx context.Context) (tsStatus, string, bool) {
	bin, err := c.lookPath(c.binary)
	if err != nil {
		return tsStatus{}, "", false
	}
	cctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	raw, err := c.run(cctx, bin, "status", "--json")
	if err != nil || len(raw) == 0 {
		slog.Debug("vpn: tailscale CLI failed", "binary", bin, "error", err)
		return tsStatus{}, "", false
	}
	var st tsStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		slog.Debug("vpn: tailscale JSON decode failed", "error", err)
		return tsStatus{}, "", false
	}
	return st, bin, true
}

// readStateFile checks for /var/lib/tailscale/tailscaled.state and
// returns a minimal "configured but offline" profile when present. We
// do NOT parse the BoltDB-style state contents — presence alone tells
// us "node is enrolled in some tailnet".
func (c *tailscaleCollector) readStateFile() (Profile, bool) {
	for _, path := range c.stateFiles {
		if _, err := os.Stat(path); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				slog.Debug("vpn: tailscale state stat failed", "path", path, "error", err)
			}
			continue
		}
		return Profile{
			Type:              TypeTailscale,
			Name:              "tailscale",
			ConfigPath:        path,
			Protocol:          "wireguard",
			Enabled:           false, // daemon unreachable
			AutoConnect:       true,
			PrivateKeyPresent: true,
		}, true
	}
	return Profile{}, false
}

// profileFromStatus projects the tailscaled JSON view onto our
// cross-VPN Profile shape. Pure function — fully exercised by tests.
func profileFromStatus(st tsStatus) Profile {
	p := Profile{
		Type:              TypeTailscale,
		Protocol:          "wireguard", // Tailscale wraps WireGuard
		Enabled:           strings.EqualFold(st.BackendState, "Running") && st.Self.Online,
		AutoConnect:       true, // daemon-managed; survives reboot via systemd/launchd
		PrivateKeyPresent: st.HaveNodeKey,
	}

	// Name: prefer the MagicDNS short name, fall back to HostName, then
	// a synthetic "tailscale" so we never emit an empty Name.
	p.Name = strings.TrimSuffix(st.Self.DNSName, ".")
	if p.Name == "" {
		p.Name = st.Self.HostName
	}
	if p.Name == "" {
		p.Name = "tailscale"
	}

	// Endpoint: prefer the actual UDP peer when direct, else expose the
	// DERP region used for relayed traffic. This is the egress next-hop
	// the operator cares about for "where is my traffic going".
	switch {
	case st.Self.CurAddr != "":
		p.Endpoint = st.Self.CurAddr
	case st.Self.Relay != "":
		p.Endpoint = "derp:" + st.Self.Relay
	}

	// RoutedSubnets: PrimaryRoutes is the subnet-router advertisement
	// set. AllowedIPs is what *this* node accepts inbound — semantically
	// closer to interface addresses than to routed subnets, but we
	// include it when PrimaryRoutes is empty so dashboards see something.
	if len(st.Self.PrimaryRoutes) > 0 {
		p.RoutedSubnets = appendUniqueAll(nil, st.Self.PrimaryRoutes)
	} else {
		p.RoutedSubnets = appendUniqueAll(nil, st.Self.AllowedIPs)
	}

	// Full-tunnel: an exit node attached to this peer ⇒ all egress
	// flows through that node. We treat presence of any peer with
	// ExitNode=true (i.e. selected as the active exit) as the trigger.
	// IsFullTunnel via the standard 0.0.0.0/0 heuristic also fires when
	// an exit node is in use, but we don't have to rely on routes —
	// Tailscale models it as a peer flag, so check both.
	if hasActiveExitNode(st) {
		p.IsFullTunnel = true
		p.RoutedSubnets = appendUnique(p.RoutedSubnets, "0.0.0.0/0")
		p.RoutedSubnets = appendUnique(p.RoutedSubnets, "::/0")
	}
	if !p.IsFullTunnel {
		p.IsFullTunnel = HasFullTunnel(p.RoutedSubnets)
	}

	// DNSServers: tailscaled-managed resolver — we expose the MagicDNS
	// suffix as a marker. Real per-resolver state lives behind
	// `tailscale dns status`, which is shellable in a future iter.
	if st.CurrentTailnet.MagicDNSEnabled && st.CurrentTailnet.MagicDNSSuffix != "" {
		p.DNSServers = []string{"magicdns:" + st.CurrentTailnet.MagicDNSSuffix}
	}

	p.SharedPeers = sharedPeers(st)

	sortStrings(p.RoutedSubnets)
	sortStrings(p.DNSServers)
	sortStrings(p.SharedPeers)
	return p
}

// sharedPeers returns the DNS names of mesh peers owned by a different
// tailnet user than Self — i.e. nodes shared INTO this user's view.
// Empty when every peer belongs to the same user (Self.UserID == 0
// disables detection: we can't tell which side is the outsider).
func sharedPeers(st tsStatus) []string {
	if st.Self.UserID == 0 || len(st.Peer) == 0 {
		return nil
	}
	var out []string
	for _, peer := range st.Peer {
		if peer.UserID == 0 || peer.UserID == st.Self.UserID {
			continue
		}
		name := strings.TrimSuffix(peer.DNSName, ".")
		if name == "" {
			name = peer.HostName
		}
		if name != "" {
			out = appendUnique(out, name)
		}
	}
	return out
}

// hasActiveExitNode reports whether any peer is currently serving as
// this node's exit node.
func hasActiveExitNode(st tsStatus) bool {
	if st.Self.ExitNode {
		return true
	}
	for _, peer := range st.Peer {
		if peer.ExitNode {
			return true
		}
	}
	return false
}

// appendUniqueAll appends each element of src to dst if not already
// present; preserves the source order of first occurrences.
func appendUniqueAll(dst, src []string) []string {
	for _, v := range src {
		dst = appendUnique(dst, v)
	}
	return dst
}
