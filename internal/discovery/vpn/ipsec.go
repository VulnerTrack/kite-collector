package vpn

import (
	"context"
	"log/slog"
	"strings"
	"time"
)

// ipsecEnumerator discovers the remote gateways of every established
// IPSec/strongSwan security association via `swanctl --list-sas`. Each IKE
// SA connects to one remote peer (a gateway or road-warrior), which becomes
// a discovered host. IPSec is a gateway fabric, not a mesh: the "host" is
// the far end of the tunnel, identified by its IKE identity and address.
//
// strongSwan exposes no stable machine-readable CLI, so this parses the
// human-readable `--list-sas` grammar. swanctl needs access to the VICI
// socket (root); failure degrades to no hosts.
type ipsecEnumerator struct {
	run      runner
	lookPath lookPather
	binary   string
	timeout  time.Duration
}

func newIPSecEnumerator() *ipsecEnumerator {
	return &ipsecEnumerator{
		run:      defaultRunner,
		lookPath: defaultLookPath,
		binary:   "swanctl",
		timeout:  5 * time.Second,
	}
}

func (e *ipsecEnumerator) vpnType() string { return "ipsec" }

func (e *ipsecEnumerator) enumerate(ctx context.Context, _ map[string]any) ([]Peer, error) {
	bin, err := e.lookPath(e.binary)
	if err != nil {
		return nil, nil // strongSwan/swanctl not installed
	}
	cctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	raw, err := e.run(cctx, bin, "--list-sas")
	if err != nil {
		slog.Debug("vpn: swanctl --list-sas failed",
			"code", string(LogCodeIPSecCLIFailed), "error", err)
		return nil, nil
	}
	return parseSwanctlSAs(string(raw)), nil
}

// parseSwanctlSAs parses `swanctl --list-sas`. The grammar per IKE SA is:
//
//	<conn>: #<n>, <STATE>, <IKEv2>, <spi>
//	  local  '<id>' @ <ip>[<port>]
//	  remote '<id>' @ <ip>[<port>]
//	  <proposal>
//	  established <n>s ago, ...
//	  child: <name>, INSTALLED, TUNNEL, ...
//	    local  <cidr> <cidr>
//	    remote <cidr> <cidr>
//
// A header line is unindented and contains ": #". The remote GATEWAY line
// carries " @ "; an indented "remote <cidr>" line without "@" is a child
// traffic selector. One Peer is emitted per IKE SA (the remote gateway).
func parseSwanctlSAs(raw string) []Peer {
	var out []Peer
	var cur *Peer
	var childSubnets []string

	flush := func() {
		if cur == nil {
			return
		}
		if len(childSubnets) > 0 {
			cur.Tags["remote_subnets"] = append([]string(nil), childSubnets...)
		}
		out = append(out, *cur)
		cur = nil
		childSubnets = nil
	}

	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		indented := line[0] == ' ' || line[0] == '\t'
		trimmed := strings.TrimSpace(line)

		// Header: unindented "conn: #n, STATE, VERSION, spi".
		if !indented && strings.Contains(trimmed, ": #") {
			flush()
			cur = ikeHeaderPeer(trimmed)
			continue
		}
		if cur == nil {
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "remote ") && strings.Contains(trimmed, "@"):
			id, addr, port := parseSAEndpoint(trimmed)
			if addr != "" {
				cur.Addresses = sortAddrs([]string{addr})
				cur.Hostname = ipsecHostname(id, addr)
				if port != "" {
					cur.Endpoint = addr + ":" + port
				} else {
					cur.Endpoint = addr
				}
			}
			if id != "" {
				cur.Tags["remote_id"] = id
			}
		case strings.HasPrefix(trimmed, "local ") && strings.Contains(trimmed, "@"):
			if id, _, _ := parseSAEndpoint(trimmed); id != "" {
				cur.Tags["local_id"] = id
			}
		case strings.HasPrefix(trimmed, "remote ") && !strings.Contains(trimmed, "@"):
			// Child traffic selector: "remote 10.2.0.0/16 10.3.0.0/16".
			childSubnets = append(childSubnets,
				strings.Fields(strings.TrimPrefix(trimmed, "remote "))...)
		}
	}
	flush()
	return out
}

func ikeHeaderPeer(header string) *Peer {
	name := header
	rest := ""
	if i := strings.Index(header, ": #"); i > 0 {
		name = strings.TrimSpace(header[:i])
		rest = header[i+2:] // keep from "#n, STATE, ..."
	}
	state, version := "", ""
	parts := strings.Split(rest, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) >= 2 {
		state = parts[1]
	}
	if len(parts) >= 3 {
		version = parts[2]
	}
	p := &Peer{
		VPNType: "ipsec",
		Online:  strings.EqualFold(state, "ESTABLISHED"),
		Tags: map[string]any{
			"connection": name,
		},
	}
	if state != "" {
		p.Tags["ike_state"] = state
	}
	if version != "" {
		p.Tags["ike_version"] = version
		p.OSVersion = version
	}
	return p
}

// parseSAEndpoint parses "remote '<id>' @ <ip>[<port>]" (or an unquoted
// id) into its identity, address, and port.
func parseSAEndpoint(line string) (id, addr, port string) {
	at := strings.Index(line, " @ ")
	if at < 0 {
		return "", "", ""
	}
	left := strings.TrimSpace(line[:at])    // "remote 'id'"
	right := strings.TrimSpace(line[at+3:]) // "ip[port] ..."
	left = strings.TrimPrefix(left, "remote ")
	left = strings.TrimPrefix(left, "local ")
	id = strings.Trim(strings.TrimSpace(left), "'\"")

	right = strings.Fields(right)[0] // first token only
	if i := strings.IndexByte(right, '['); i >= 0 {
		addr = right[:i]
		if j := strings.IndexByte(right[i:], ']'); j > 0 {
			port = right[i+1 : i+j]
		}
	} else {
		addr = right
	}
	return id, addr, port
}

// ipsecHostname prefers the IKE identity when it reads like a hostname
// (a bare FQDN, not a certificate DN or an IP), otherwise the address.
func ipsecHostname(id, addr string) string {
	id = strings.TrimSpace(id)
	switch {
	case id == "":
		return addr
	case strings.ContainsAny(id, "=,"): // certificate DN → not a hostname
		return addr
	case strings.Contains(id, " "):
		return addr
	default:
		return id
	}
}
