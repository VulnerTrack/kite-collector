package vpn

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Peer is the technology-neutral record every enumerator produces for one
// host reachable over a VPN. It is the intermediate shape between a
// vendor's native representation (a tailscale peer, a `wg` dump line, a
// swanctl SA) and the model.Machine we emit, so mapping logic lives in
// exactly one place and is unit-tested independently of any daemon.
//
// The prompt for this source is "enumerate the hosts — and the users
// behind them — on each VPN". Owner carries that user identity for the
// technologies that expose one (Tailscale tailnet user, NetBird setup-key
// owner). Key-only fabrics (WireGuard, plain IPSec) have no user concept,
// so Owner is empty there and the public key lands in Tags instead.
type Peer struct {
	// LastSeen is when the fabric last had contact with the host. Zero
	// means "unknown" — the mapper substitutes the scan time so a row is
	// never emitted with a zero LastSeenAt.
	LastSeen time.Time

	VPNType   string // "tailscale", "wireguard", ... — becomes the discovery_source suffix
	Hostname  string
	DNSName   string // FQDN inside the VPN (MagicDNS name, netbird domain, ...)
	OS        string // raw OS string as the vendor reports it
	OSVersion string
	Owner     string // login/email/identity of the user this host belongs to
	Endpoint  string // physical transport endpoint (ip:port), when known
	PublicKey string // node/peer key, for key-based fabrics

	Addresses []string // VPN-assigned overlay addresses

	// Tags carries per-technology context that does not map onto a
	// first-class Machine field. Merged under the base tag set.
	Tags map[string]any

	// MachineTypeHint overrides the OS-derived machine type. Used by the
	// gateway enumerators, where the discovered host is a VPN appliance
	// with no reported OS rather than an endpoint.
	MachineTypeHint model.MachineType

	Online     bool
	Expired    bool // key/certificate expired — host is enrolled but cannot connect
	IsExitNode bool // host offers/serves as an exit node (full-tunnel egress)
}

// dedupKey returns a stable identity for the peer within a single scan so
// the same host enumerated twice (e.g. a ZeroTier member on two networks,
// or a WireGuard peer present on two interfaces) collapses to one row. It
// prefers the strongest identifier available: public key, then FQDN, then
// the first overlay address, then the hostname. VPNType is included so an
// identically-named host on two different fabrics is NOT merged here — the
// global deduper handles cross-source identity by hostname.
func (p Peer) dedupKey() string {
	var id string
	switch {
	case p.PublicKey != "":
		id = "k:" + p.PublicKey
	case p.DNSName != "":
		id = "d:" + strings.ToLower(strings.TrimSuffix(p.DNSName, "."))
	case len(p.Addresses) > 0:
		id = "a:" + p.Addresses[0]
	default:
		id = "h:" + strings.ToLower(p.Hostname)
	}
	return p.VPNType + "|" + id
}

// displayHostname picks the most human-meaningful name for the host,
// degrading through DNS name and overlay address so a Machine is never
// emitted with an empty Hostname (the natural key depends on it).
func (p Peer) displayHostname() string {
	if h := strings.TrimSpace(p.Hostname); h != "" {
		return h
	}
	if d := strings.TrimSpace(strings.TrimSuffix(p.DNSName, ".")); d != "" {
		return d
	}
	if len(p.Addresses) > 0 && strings.TrimSpace(p.Addresses[0]) != "" {
		return p.Addresses[0]
	}
	if p.PublicKey != "" {
		// Short, stable label for a key-only peer with no name or address.
		key := p.PublicKey
		if len(key) > 12 {
			key = key[:12]
		}
		return p.VPNType + "-" + key
	}
	return p.VPNType + "-unknown"
}

// machineTypeForOS maps a VPN-reported OS string onto a MachineType. The
// fabrics never tell us "laptop vs. rack server", so this is a documented
// heuristic: desktop/mobile OSes are workstations, headless-typical OSes
// are servers, and anything unrecognised stays a workstation (the least
// alarming default for an unknown endpoint). The raw OS is always kept in
// Tags and OSFamily so a downstream consumer can reclassify.
func machineTypeForOS(os string) model.MachineType {
	switch normalizeOS(os) {
	case "windows", "macos", "ios", "ipados", "android", "tvos", "chromeos":
		return model.MachineTypeWorkstation
	case "linux", "freebsd", "openbsd", "netbsd", "illumos", "solaris":
		return model.MachineTypeServer
	default:
		return model.MachineTypeWorkstation
	}
}

// normalizeOS lower-cases and canonicalises the handful of OS spellings
// the supported fabrics emit ("macOS" vs "darwin", "iOS", ...).
func normalizeOS(os string) string {
	o := strings.ToLower(strings.TrimSpace(os))
	switch o {
	case "darwin":
		return "macos"
	case "iphone", "ipad":
		return "ios"
	default:
		return o
	}
}

// toMachine projects a Peer onto the model.Machine wire shape. Pure and
// deterministic apart from the UUID and the now fallback, both injected by
// the caller so tests stay reproducible.
func (p Peer) toMachine(id uuid.UUID, now time.Time) model.Machine {
	lastSeen := now
	if !p.LastSeen.IsZero() {
		lastSeen = p.LastSeen.UTC()
	}

	tags := map[string]any{
		"vpn_type": p.VPNType,
		"online":   p.Online,
	}
	if p.DNSName != "" {
		tags["dns_name"] = strings.TrimSuffix(p.DNSName, ".")
	}
	if len(p.Addresses) > 0 {
		tags["overlay_addresses"] = p.Addresses
	}
	if p.Endpoint != "" {
		tags["endpoint"] = p.Endpoint
	}
	if p.PublicKey != "" {
		tags["public_key"] = p.PublicKey
	}
	if p.Owner != "" {
		tags["owner"] = p.Owner
	}
	if p.Expired {
		tags["expired"] = true
	}
	if p.IsExitNode {
		tags["exit_node"] = true
	}
	// Per-technology extras win over nothing but never clobber the base
	// keys above — an enumerator that needs to override should set the
	// base field directly on the Peer.
	for k, v := range p.Tags {
		if _, taken := tags[k]; !taken {
			tags[k] = v
		}
	}
	tagsJSON, _ := json.Marshal(tags)

	machineType := machineTypeForOS(p.OS)
	if p.MachineTypeHint != "" {
		machineType = p.MachineTypeHint
	}

	return model.Machine{
		ID:              id,
		Hostname:        p.displayHostname(),
		MachineType:     machineType,
		OSFamily:        normalizeOS(p.OS),
		OSVersion:       p.OSVersion,
		Owner:           p.Owner,
		DiscoverySource: "vpn." + p.VPNType,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            string(tagsJSON),
		LastSeenAt:      lastSeen,
	}
}

// sortAddrs returns a sorted copy of addrs with blanks dropped and
// duplicates removed, so tag output and dedup keys are deterministic.
func sortAddrs(addrs []string) []string {
	seen := make(map[string]struct{}, len(addrs))
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}
