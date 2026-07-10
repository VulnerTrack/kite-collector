package vpn

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// wireguardCollector parses WireGuard `.conf` files in the canonical
// /etc/wireguard/ directory. The .conf grammar is a simplified INI:
//
//	[Interface]
//	PrivateKey = <base64>
//	Address    = 10.0.0.2/24
//	DNS        = 1.1.1.1, 1.0.0.1
//	MTU        = 1420
//
//	[Peer]
//	PublicKey           = <base64>
//	PresharedKey        = <base64>
//	AllowedIPs          = 0.0.0.0/0, ::/0
//	Endpoint            = vpn.example.com:51820
//	PersistentKeepalive = 25
//
// We capture the audit-relevant fields. Multiple [Peer] blocks per file
// collapse to one Profile (the AllowedIPs union; first peer's Endpoint).
type wireguardCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	confDir  string
}

// NewWireGuardCollector returns the default WireGuard config-files
// collector.
func NewWireGuardCollector() Collector {
	return &wireguardCollector{
		confDir:  "/etc/wireguard",
		readFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system path
		readDir:  func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *wireguardCollector) Name() string { return "wireguard-files" }

func (c *wireguardCollector) Collect(ctx context.Context) ([]Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	entries, err := c.readDir(c.confDir)
	if err != nil {
		return []Profile{}, nil //nolint:nilerr // missing /etc/wireguard = not installed, not an error
	}
	var out []Profile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		path := filepath.Join(c.confDir, name)
		data, ferr := c.readFile(path)
		if ferr != nil {
			slog.Debug("vpn: wireguard read failed", "path", path, "error", ferr)
			continue
		}
		p, ok := parseWireGuardConfig(string(data))
		if !ok {
			continue
		}
		// Interface name = filename without .conf — matches `wg show wg0`.
		p.Name = strings.TrimSuffix(name, ".conf")
		p.ConfigPath = path
		p.Type = TypeWireGuard
		out = append(out, p)
		if len(out) >= MaxProfiles {
			break
		}
	}
	SortProfiles(out)
	return out, nil
}

// parseWireGuardConfig returns the audit-relevant fields. Returns
// (Profile{}, false) only when the file has no [Interface] section.
//
// Lines are case-INsensitive for keys (WireGuard convention), comments
// (`#` or `;`) are stripped. Multiple [Peer] sections all contribute to
// the merged AllowedIPs union.
func parseWireGuardConfig(raw string) (Profile, bool) {
	var (
		p             Profile
		section       string
		sawInterface  bool
		firstEndpoint string
		firstPort     int
		mergedAllowed []string
		mergedDNS     []string
	)
	for _, rawLine := range strings.Split(raw, "\n") {
		line := stripComment(rawLine)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "interface" {
				sawInterface = true
			}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				if val != "" {
					p.PrivateKeyPresent = true
				}
			case "dns":
				for _, v := range splitCommaTrim(val) {
					mergedDNS = appendUnique(mergedDNS, v)
				}
			case "mtu":
				if n, err := strconv.Atoi(val); err == nil {
					p.MTU = n
				}
			case "listenport":
				if n, err := strconv.Atoi(val); err == nil {
					p.Port = n
				}
			}
		case "peer":
			switch key {
			case "presharedkey":
				if val != "" {
					p.PresharedKeyPresent = true
				}
			case "allowedips":
				for _, v := range splitCommaTrim(val) {
					mergedAllowed = appendUnique(mergedAllowed, v)
				}
			case "endpoint":
				if firstEndpoint == "" {
					firstEndpoint = val
					if host, port := splitHostPort(val); port > 0 {
						_ = host
						firstPort = port
					}
				}
			}
		}
	}
	if !sawInterface {
		return Profile{}, false
	}
	sortStrings(mergedAllowed)
	sortStrings(mergedDNS)
	p.RoutedSubnets = mergedAllowed
	p.DNSServers = mergedDNS
	p.Endpoint = firstEndpoint
	if firstPort > 0 && p.Port == 0 {
		p.Port = firstPort
	}
	p.Protocol = "udp" // WireGuard is UDP-only
	p.IsFullTunnel = HasFullTunnel(mergedAllowed)
	// WireGuard configs in /etc/wireguard/ are typically auto-started via
	// `systemctl enable wg-quick@<name>` — we can't know without querying
	// systemd, so we leave AutoConnect=false and Enabled=false here.
	// Future iter can cross-reference with the Services collector.
	return p, true
}

// stripComment removes `#` and `;` trailing comments from a line.
// WireGuard supports both styles.
func stripComment(line string) string {
	if i := strings.IndexAny(line, "#;"); i >= 0 {
		return line[:i]
	}
	return line
}

// splitCommaTrim splits on comma and trims each element. Empty strings
// are dropped.
func splitCommaTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// appendUnique appends v to s only if it's not already present.
func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// splitHostPort returns (host, port). Handles bare host (no port → 0),
// host:port, [v6]:port. Errors → ("", 0).
func splitHostPort(s string) (string, int) {
	// Bracketed IPv6 must come first.
	if strings.HasPrefix(s, "[") {
		if i := strings.LastIndex(s, "]:"); i > 0 {
			host := s[1:i]
			if n, err := strconv.Atoi(s[i+2:]); err == nil {
				return host, n
			}
		}
		return "", 0
	}
	if i := strings.LastIndexByte(s, ':'); i > 0 && !strings.Contains(s[:i], ":") {
		host := s[:i]
		if n, err := strconv.Atoi(s[i+1:]); err == nil {
			return host, n
		}
	}
	return "", 0
}

// sortStrings is a dep-free in-place insertion sort (private helper
// reused across this package; mirrors browserext/editorext).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j-1] > s[j] {
			s[j-1], s[j] = s[j], s[j-1]
			j--
		}
	}
}

// silence "imported but not used" if a future refactor drops fs.
var _ fs.DirEntry = os.DirEntry(nil)
