package vpn

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// wgHandshakeFreshness is how recently a peer must have completed a
// handshake to be reported Online. WireGuard has no session concept; an
// active peer rekeys roughly every two minutes, so a three-minute window
// distinguishes a live tunnel from a stale one.
const wgHandshakeFreshness = 3 * time.Minute

// wireguardEnumerator enumerates the PEERS of every WireGuard interface on
// this host via `wg show all dump` — each peer line is a distinct remote
// host, keyed by its public key. WireGuard is a key fabric with no user or
// hostname concept, so Owner is empty and the host is labelled by its
// overlay address.
//
// `wg show` reads kernel interface state and normally needs root; when it
// is unavailable (not installed, no interfaces, or insufficient privilege)
// the enumerator returns nothing rather than failing the scan.
type wireguardEnumerator struct {
	run      runner
	lookPath lookPather
	now      func() time.Time
	binary   string
	timeout  time.Duration
}

func newWireGuardEnumerator() *wireguardEnumerator {
	return &wireguardEnumerator{
		run:      defaultRunner,
		lookPath: defaultLookPath,
		now:      func() time.Time { return time.Now().UTC() },
		binary:   "wg",
		timeout:  5 * time.Second,
	}
}

func (e *wireguardEnumerator) vpnType() string { return "wireguard" }

func (e *wireguardEnumerator) enumerate(ctx context.Context, _ map[string]any) ([]Peer, error) {
	bin, err := e.lookPath(e.binary)
	if err != nil {
		return nil, nil // wireguard-tools not installed
	}
	cctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	raw, err := e.run(cctx, bin, "show", "all", "dump")
	if err != nil {
		// Typically EPERM when the collector runs unprivileged. Not fatal.
		slog.Debug("vpn: wireguard dump failed",
			"code", string(LogCodeWireGuardDumpFailed), "error", err)
		return nil, nil
	}
	return parseWGDump(string(raw), e.now()), nil
}

// parseWGDump turns `wg show all dump` output into peers. The dump format
// is tab-separated with the interface name prefixed on every line:
//
//	<iface>\t<privkey>\t<pubkey>\t<listen-port>\t<fwmark>            (interface: 5 cols)
//	<iface>\t<pubkey>\t<psk>\t<endpoint>\t<allowed-ips>\t<handshake>\t<rx>\t<tx>\t<keepalive>  (peer: 9 cols)
//
// Interface lines are skipped (that host is US); peer lines become Peers.
// now is injected so the Online freshness check is deterministic in tests.
func parseWGDump(raw string, now time.Time) []Peer {
	var out []Peer
	iface := ""
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		switch len(cols) {
		case 5:
			// Interface (self) line — remember the interface name for the
			// peer lines that follow.
			iface = cols[0]
			continue
		case 9:
			out = append(out, wgPeerFromCols(cols, iface, now))
		default:
			// Unknown arity — a format we do not model; skip defensively.
			continue
		}
	}
	return out
}

func wgPeerFromCols(cols []string, iface string, now time.Time) Peer {
	pubKey := cols[1]
	psk := cols[2]
	endpoint := cols[3]
	allowed := cols[4]
	handshake := cols[5]

	if iface == "" {
		iface = cols[0]
	}

	addrs := parseAllowedIPs(allowed)
	p := Peer{
		VPNType:   "wireguard",
		PublicKey: pubKey,
		Addresses: overlayIPs(addrs),
		Tags: map[string]any{
			"interface": iface,
		},
	}
	if len(addrs) > 0 {
		p.Tags["allowed_ips"] = addrs
	}
	// "(none)" is wg's sentinel for an unset endpoint (a roaming peer that
	// has not yet been contacted).
	if endpoint != "" && endpoint != "(none)" {
		p.Endpoint = endpoint
	}
	if psk != "" && psk != "(none)" {
		p.Tags["preshared_key"] = true
	}
	if hs, err := strconv.ParseInt(strings.TrimSpace(handshake), 10, 64); err == nil && hs > 0 {
		ts := time.Unix(hs, 0).UTC()
		p.LastSeen = ts
		p.Online = now.Sub(ts) <= wgHandshakeFreshness
	}
	return p
}

// parseAllowedIPs splits the allowed-ips field. wg joins multiple entries
// with commas in the dump format; we also tolerate whitespace separators.
func parseAllowedIPs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "(none)" {
		return nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// overlayIPs strips the CIDR mask from each allowed-ip so the values read
// as host addresses (10.0.0.2 rather than 10.0.0.2/32) for the hostname
// fallback and overlay_addresses tag.
func overlayIPs(cidrs []string) []string {
	out := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		if i := strings.IndexByte(c, '/'); i > 0 {
			out = append(out, c[:i])
		} else {
			out = append(out, c)
		}
	}
	return sortAddrs(out)
}
