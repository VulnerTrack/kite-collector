package vpn

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// zerotierCollector reads ZeroTier network membership state from
// /var/lib/zerotier-one/networks.d/<network-id>.conf. Each joined
// network has one .conf file written by zerotier-one when the node
// successfully joined; the filename minus ".conf" is the 16-hex-char
// network ID. Format is INI-style "key=value" with no sections:
//
//	allowDNS=0
//	allowDefault=0          # ← full-tunnel marker (push default route)
//	allowGlobal=0           # accept routes for public-IP space?
//	allowManaged=1          # accept routes from the network controller
//
// Audit signals captured:
//   - is_full_tunnel ← allowDefault=1
//   - private_key_present ← /var/lib/zerotier-one/identity.secret on disk
//   - auto_connect ← zerotier-one is daemon-managed; if a network has
//     a persisted .conf file, the node will rejoin on boot
//   - endpoint ← network ID (ZeroTier has no per-network endpoint;
//     all traffic flows through the controller fleet)
//
// The collector never edits the conf files or invokes the CLI.
type zerotierCollector struct {
	readFile     func(string) ([]byte, error)
	readDir      func(string) ([]os.DirEntry, error)
	stat         func(string) (os.FileInfo, error)
	networksDir  string
	identityPath string
}

// NewZeroTierCollector returns the default ZeroTier collector.
func NewZeroTierCollector() Collector {
	return &zerotierCollector{
		networksDir:  "/var/lib/zerotier-one/networks.d",
		identityPath: "/var/lib/zerotier-one/identity.secret",
		readFile:     func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system path
		readDir:      func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
		stat:         func(p string) (os.FileInfo, error) { return os.Stat(p) },
	}
}

func (c *zerotierCollector) Name() string { return "zerotier-files" }

func (c *zerotierCollector) Collect(ctx context.Context) ([]Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	entries, err := c.readDir(c.networksDir)
	if err != nil {
		return []Profile{}, nil //nolint:nilerr // missing dir = not installed, not an error
	}
	// Identity check: presence of identity.secret means the daemon
	// has provisioned a node key on this host — fed into the
	// CWE-321 "unattended cred on disk" finding.
	hasIdentity := false
	if _, ierr := c.stat(c.identityPath); ierr == nil {
		hasIdentity = true
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
		path := filepath.Join(c.networksDir, name)
		data, ferr := c.readFile(path)
		if ferr != nil {
			slog.Debug("vpn: zerotier read failed", "path", path, "error", ferr)
			continue
		}
		p, ok := parseZeroTierConfig(string(data))
		if !ok {
			continue
		}
		networkID := strings.TrimSuffix(name, ".conf")
		p.Name = networkID
		p.ConfigPath = path
		p.Type = TypeZeroTier
		// ZeroTier doesn't expose a per-network UDP endpoint — peers
		// are reached via the global root/controller mesh. Use the
		// network ID as the endpoint slot so dashboards can filter.
		p.Endpoint = "zt:" + networkID
		p.Protocol = "udp" // ZeroTier-One uses UDP/9993 transport
		p.PrivateKeyPresent = hasIdentity
		p.AutoConnect = true // joined networks rejoin on boot
		out = append(out, p)
		if len(out) >= MaxProfiles {
			break
		}
	}
	SortProfiles(out)
	return out, nil
}

// parseZeroTierConfig walks the simple key=value grammar. Returns
// (Profile{}, true) for any file with at least one recognised key —
// ZeroTier writes empty .conf files for newly-joined networks before
// the controller has authorised them, so we always accept them.
func parseZeroTierConfig(raw string) (Profile, bool) {
	var p Profile
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(stripComment(rawLine))
		if line == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		switch key {
		case "allowdefault":
			if isTrueZT(val) {
				p.IsFullTunnel = true
				p.RoutedSubnets = appendUnique(p.RoutedSubnets, "0.0.0.0/0")
				p.RoutedSubnets = appendUnique(p.RoutedSubnets, "::/0")
			}
		case "allowdns":
			if isTrueZT(val) {
				// Mark that the network is allowed to push DNS — actual
				// resolver IPs come from the controller dynamically.
				p.DNSServers = appendUnique(p.DNSServers, "controller-pushed")
			}
		}
	}
	p.Enabled = true // presence of .conf == joined
	sortStrings(p.RoutedSubnets)
	sortStrings(p.DNSServers)
	return p, true
}

// isTrueZT reports whether a ZeroTier boolean is set. ZeroTier writes
// "1" / "0" but tolerates "true"/"false" if the operator edits the
// file by hand — match both.
func isTrueZT(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
