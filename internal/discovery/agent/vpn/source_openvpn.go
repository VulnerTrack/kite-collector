package vpn

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// openvpnCollector parses OpenVPN client `.conf` files in the canonical
// /etc/openvpn/client/ and /etc/openvpn/ directories. Format is one
// keyword per line (not INI):
//
//	client
//	dev tun
//	proto udp
//	remote vpn.example.com 1194
//	resolv-retry infinite
//	nobind
//	persist-key
//	persist-tun
//	redirect-gateway def1 bypass-dhcp     # ← full-tunnel marker
//	dhcp-option DNS 1.1.1.1
//	route 10.0.0.0 255.0.0.0
//	ca ca.crt
//	cert client.crt
//	key client.key                         # ← private_key_present marker
//	tls-auth ta.key 1                      # ← preshared key marker
//
// Multiple `remote` lines mean failover candidates; we keep the first.
// `redirect-gateway` (with no def1/bypass-dhcp argument) is the OpenVPN
// equivalent of WireGuard's AllowedIPs=0.0.0.0/0, so we synthesise
// 0.0.0.0/0 into RoutedSubnets when seen.
type openvpnCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	confDirs []string
}

// NewOpenVPNCollector returns the default OpenVPN config-files collector.
func NewOpenVPNCollector() Collector {
	return &openvpnCollector{
		confDirs: []string{"/etc/openvpn/client", "/etc/openvpn"},
		readFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:  func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *openvpnCollector) Name() string { return "openvpn-files" }

func (c *openvpnCollector) Collect(ctx context.Context) ([]Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Profile
	for _, dir := range c.confDirs {
		entries, err := c.readDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".conf") && !strings.HasSuffix(name, ".ovpn") {
				continue
			}
			path := filepath.Join(dir, name)
			data, ferr := c.readFile(path)
			if ferr != nil {
				slog.Debug("vpn: openvpn read failed", "path", path, "error", ferr)
				continue
			}
			p, ok := parseOpenVPNConfig(string(data))
			if !ok {
				continue
			}
			p.Name = strings.TrimSuffix(strings.TrimSuffix(name, ".conf"), ".ovpn")
			p.ConfigPath = path
			p.Type = TypeOpenVPN
			out = append(out, p)
			if len(out) >= MaxProfiles {
				SortProfiles(out)
				return out, nil
			}
		}
	}
	SortProfiles(out)
	return out, nil
}

// parseOpenVPNConfig walks the keyword grammar and projects to a
// Profile. Returns (Profile{}, true) for any file containing a `client`
// or `tls-client` directive — both mark client-side configs (server
// configs are out of scope for this iteration).
//
// Inline blocks (<ca>…</ca>, <cert>…</cert>, <key>…</key>, <tls-auth>…
// </tls-auth>) are recognised as evidence of embedded credentials.
func parseOpenVPNConfig(raw string) (Profile, bool) {
	var p Profile
	var (
		isClient   bool
		routes     []string
		dns        []string
		fullTunnel bool
		inBlock    string // current inline block name (e.g. "key")
	)
	for _, rawLine := range strings.Split(raw, "\n") {
		line := stripComment(rawLine)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Inline block markers.
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			tag := line[1 : len(line)-1]
			closing := strings.HasPrefix(tag, "/")
			if closing {
				tag = tag[1:]
				if inBlock == tag {
					// On close, mark presence of the credential.
					recordInlineCredential(&p, tag)
					inBlock = ""
				}
			} else {
				inBlock = tag
			}
			continue
		}
		if inBlock != "" {
			// Skip the body of an inline block.
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "client", "tls-client":
			isClient = true
		case "proto":
			if len(fields) > 1 {
				p.Protocol = strings.ToLower(fields[1])
			}
		case "remote":
			// First `remote` line wins.
			if p.Endpoint == "" && len(fields) > 1 {
				p.Endpoint = fields[1]
				if len(fields) > 2 {
					if n, err := strconv.Atoi(fields[2]); err == nil {
						p.Port = n
						p.Endpoint = fields[1] + ":" + fields[2]
					}
				}
			}
		case "tun-mtu", "mtu":
			if len(fields) > 1 {
				if n, err := strconv.Atoi(fields[1]); err == nil {
					p.MTU = n
				}
			}
		case "key":
			// References to external key file.
			if len(fields) > 1 && fields[1] != "" {
				p.PrivateKeyPresent = true
			}
		case "tls-auth", "tls-crypt":
			// References to external TA / TLS-crypt key file.
			if len(fields) > 1 && fields[1] != "" {
				p.PresharedKeyPresent = true
			}
		case "redirect-gateway":
			fullTunnel = true
		case "route":
			// `route 10.0.0.0 255.0.0.0` → 10.0.0.0/8 (best-effort)
			if len(fields) >= 3 {
				routes = appendUnique(routes,
					fields[1]+"/"+maskToPrefix(fields[2]))
			} else if len(fields) == 2 {
				routes = appendUnique(routes, fields[1])
			}
		case "dhcp-option":
			// `dhcp-option DNS 1.1.1.1` is the conventional way to push DNS.
			if len(fields) >= 3 && strings.EqualFold(fields[1], "DNS") {
				dns = appendUnique(dns, fields[2])
			}
		case "auth-user-pass":
			// `auth-user-pass <file>` with a file → unattended.
			if len(fields) > 1 && fields[1] != "" {
				// Treat embedded user/pass file the same as a private key —
				// the credential lives on disk.
				p.PrivateKeyPresent = true
			}
		}
	}
	if !isClient {
		return Profile{}, false
	}
	if fullTunnel {
		routes = appendUnique(routes, "0.0.0.0/0")
	}
	sortStrings(routes)
	sortStrings(dns)
	p.RoutedSubnets = routes
	p.DNSServers = dns
	p.IsFullTunnel = HasFullTunnel(routes)
	return p, true
}

// recordInlineCredential flips the appropriate Profile flag when an
// inline credential block closes.
func recordInlineCredential(p *Profile, tag string) {
	switch tag {
	case "key":
		p.PrivateKeyPresent = true
	case "tls-auth", "tls-crypt":
		p.PresharedKeyPresent = true
	}
}

// maskToPrefix converts a dotted-quad netmask to a prefix-length string.
// Returns "" when the mask is malformed; callers append it to a CIDR so
// we want graceful degradation.
func maskToPrefix(mask string) string {
	parts := strings.Split(mask, ".")
	if len(parts) != 4 {
		return ""
	}
	bits := 0
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return ""
		}
		for i := 7; i >= 0; i-- {
			if (n>>i)&1 == 1 {
				bits++
			} else {
				return strconv.Itoa(bits)
			}
		}
	}
	return strconv.Itoa(bits)
}
