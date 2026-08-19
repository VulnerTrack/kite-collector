package vpn

import (
	"context"
	"regexp"
	"strings"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// The commercial clients here (Cisco AnyConnect, Mullvad, GlobalProtect)
// are client-to-GATEWAY VPNs, not peer meshes: this host connects to one or
// more concentrators/relays and sees no other members. "Host discovery" for
// them therefore means inventorying the GATEWAY the client targets — itself
// a real, security-relevant host (a corporate VPN headend or a relay).
//
// The reliable, version-independent signal is the configured gateway list,
// which an operator can declare per vendor via an env var; where a stable
// local config file exists (AnyConnect's preferences.xml) it is also parsed
// best-effort. Nothing is emitted when neither is present.
//
// gatewayEnumerator is the shared implementation; the three constructors
// below specialise it per vendor.
type gatewayEnumerator struct {
	readFile    fileReader
	getenv      func(string) string
	parseConfig func([]byte) []string
	vtype       string
	envVar      string
	configPaths []string
}

func (e *gatewayEnumerator) vpnType() string { return e.vtype }

func (e *gatewayEnumerator) enumerate(_ context.Context, _ map[string]any) ([]Peer, error) {
	seen := map[string]struct{}{}
	var hosts []string

	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" {
			return
		}
		key := strings.ToLower(h)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		hosts = append(hosts, h)
	}

	// Operator-declared gateways (comma-separated host[:port]).
	if e.envVar != "" {
		for _, h := range splitAndTrim(e.getenv(e.envVar), ',') {
			add(h)
		}
	}
	// Best-effort local config extraction.
	if e.parseConfig != nil {
		for _, path := range e.configPaths {
			data, err := e.readFile(path)
			if err != nil {
				continue
			}
			for _, h := range e.parseConfig(data) {
				add(h)
			}
		}
	}

	if len(hosts) == 0 {
		return nil, nil
	}
	out := make([]Peer, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, gatewayPeer(e.vtype, h))
	}
	return out, nil
}

// gatewayPeer builds a Peer for a VPN concentrator/relay. The host string
// may be "host" or "host:port"; the address portion becomes the hostname
// and the whole becomes the endpoint.
func gatewayPeer(vtype, host string) Peer {
	addr := host
	if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host, "]") {
		addr = host[:i]
	}
	return Peer{
		VPNType:         vtype,
		Hostname:        addr,
		Endpoint:        host,
		MachineTypeHint: model.MachineTypeAppliance,
		Tags: map[string]any{
			"role": "gateway",
		},
	}
}

func newAnyConnectEnumerator() *gatewayEnumerator {
	return &gatewayEnumerator{
		readFile:    osReadFile,
		getenv:      defaultGetenv,
		vtype:       "cisco-anyconnect",
		envVar:      "KITE_ANYCONNECT_GATEWAYS",
		parseConfig: anyConnectHostsFromXML,
		configPaths: []string{
			"/opt/cisco/anyconnect/profile/preferences.xml",
			"/opt/cisco/secureclient/profile/preferences.xml",
		},
	}
}

func newMullvadEnumerator() *gatewayEnumerator {
	return &gatewayEnumerator{
		getenv: defaultGetenv,
		vtype:  "mullvad",
		envVar: "KITE_MULLVAD_RELAYS",
	}
}

func newGlobalProtectEnumerator() *gatewayEnumerator {
	return &gatewayEnumerator{
		getenv: defaultGetenv,
		vtype:  "globalprotect",
		envVar: "KITE_GLOBALPROTECT_PORTALS",
	}
}

var anyConnectHostRe = regexp.MustCompile(`(?i)<(?:HostAddress|HostName)>([^<]+)</(?:HostAddress|HostName)>`)

// anyConnectHostsFromXML extracts <HostAddress>/<HostName> values from an
// AnyConnect/Secure Client preferences.xml. It uses a tolerant regex rather
// than a full XML decode so a partial or slightly malformed profile still
// yields the gateway host.
func anyConnectHostsFromXML(data []byte) []string {
	matches := anyConnectHostRe.FindAllSubmatch(data, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if h := strings.TrimSpace(string(m[1])); h != "" {
			out = append(out, h)
		}
	}
	return out
}
