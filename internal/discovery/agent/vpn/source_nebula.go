package vpn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// nebulaCollector reads Slack's Nebula mesh-VPN config from
// /etc/nebula/config.yml. Nebula uses a single YAML document; we
// avoid a YAML dependency by parsing only the small set of top-level
// keys we care about with a line-oriented walker. Multi-line lists
// (`static_host_map:`, `lighthouse.hosts:`) are detected by
// indent-then-`-` pattern, which is enough to spot lighthouse
// endpoints and the `am_lighthouse` flag without committing to a
// full YAML implementation.
//
// Audit signals captured:
//   - private_key_present ← pki.key path is set and the referenced
//     file exists on disk
//   - endpoint ← first static_host_map entry (typically the
//     lighthouse address)
//   - auto_connect ← nebula is run as a service unit; a parseable
//     config implies the service will reconnect on boot
//   - is_full_tunnel ← Nebula is intentionally a *mesh* VPN; it
//     never tunnels the default route, so this stays false unless
//     the user explicitly added a punchy-relay catch-all (rare).
type nebulaCollector struct {
	readFile   func(string) ([]byte, error)
	stat       func(string) (os.FileInfo, error)
	configPath string
}

// NewNebulaCollector returns the default Nebula collector.
func NewNebulaCollector() Collector {
	return &nebulaCollector{
		configPath: "/etc/nebula/config.yml",
		readFile:   func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system path
		stat:       func(p string) (os.FileInfo, error) { return os.Stat(p) },
	}
}

func (c *nebulaCollector) Name() string { return "nebula-config" }

func (c *nebulaCollector) Collect(ctx context.Context) ([]Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	data, err := c.readFile(c.configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Profile{}, nil
		}
		return []Profile{}, nil //nolint:nilerr
	}
	p, ok := parseNebulaConfig(string(data))
	if !ok {
		return []Profile{}, nil
	}
	p.ConfigPath = c.configPath
	// Cross-check: pki.key path must exist for private_key_present
	// to be authoritative. parseNebulaConfig populates Name (the key
	// path); we set PrivateKeyPresent based on file presence here.
	if p.Name != "" {
		if _, statErr := c.stat(p.Name); statErr == nil {
			p.PrivateKeyPresent = true
		}
		// Reset Name back to a stable interface label; the path
		// goes into ConfigPath via the dedicated handler below.
	}
	p.Name = "nebula"
	return []Profile{p}, nil
}

// parseNebulaConfig is a minimal YAML reader scoped to Nebula's keys.
// It returns (Profile{}, false) for an empty document and (Profile, true)
// once any audit signal is captured.
func parseNebulaConfig(raw string) (Profile, bool) {
	var (
		p           Profile
		section     string // most-recent top-level key
		keyPath     string // pki.key
		hostMapSeen bool
		endpoint    string
	)
	p.Type = TypeNebula
	p.Protocol = "udp"
	p.Enabled = true
	p.AutoConnect = true

	for _, rawLine := range strings.Split(raw, "\n") {
		line := stripComment(rawLine)
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Top-level keys have no leading whitespace; nested keys
		// have at least one. We use this to track sections cheaply.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			if i := strings.IndexByte(line, ':'); i > 0 {
				section = strings.TrimSpace(line[:i])
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		switch section {
		case "pki":
			if k, v, ok := splitYAMLKV(trimmed); ok && k == "key" {
				keyPath = strings.Trim(v, `"'`)
			}
		case "static_host_map":
			// First "- ip:port" or "<vpn-ip>: [host:port]" line wins.
			if !hostMapSeen {
				if ep := extractEndpoint(trimmed); ep != "" {
					endpoint = ep
					hostMapSeen = true
				}
			}
		case "lighthouse":
			if k, v, ok := splitYAMLKV(trimmed); ok && k == "am_lighthouse" {
				if isTrueZT(strings.Trim(v, `"'`)) {
					// Lighthouse nodes act as rendezvous points.
					p.RoutedSubnets = appendUnique(p.RoutedSubnets, "lighthouse")
				}
			}
		case "tun":
			if k, v, ok := splitYAMLKV(trimmed); ok && k == "dev" {
				p.Name = strings.Trim(v, `"'`) // overridden by Collect afterwards
				_ = p.Name
			}
		}
	}
	p.Endpoint = endpoint
	// PrivateKeyPresent is finalised by Collect after stat()'ing the
	// pki.key path on disk. Stash the path in Name for that callee
	// (Collect resets Name to a stable label).
	if keyPath != "" {
		p.Name = keyPath
	}
	if endpoint == "" && keyPath == "" {
		return Profile{}, false
	}
	return p, true
}

// splitYAMLKV returns (key, value, true) for a "key: value" line and
// false for list items or malformed lines.
func splitYAMLKV(line string) (string, string, bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// extractEndpoint pulls "host:port" out of various static_host_map
// shapes that Nebula accepts:
//
//	'192.168.100.1': ['lighthouse1.example.com:4242']
//	192.168.100.1: ["10.0.0.1:4242"]
//	- 1.2.3.4:4242
//
// Returns "" when no host:port pattern is found.
func extractEndpoint(line string) string {
	// Strip the YAML-list dash so "- 1.2.3.4:4242" parses cleanly.
	line = strings.TrimPrefix(strings.TrimSpace(line), "- ")
	// If there's an inline list "[…]", take the first quoted element.
	if i := strings.IndexByte(line, '['); i >= 0 {
		rest := line[i+1:]
		if j := strings.IndexAny(rest, ",]"); j > 0 {
			rest = rest[:j]
		}
		return strings.Trim(strings.TrimSpace(rest), `"'`)
	}
	// Otherwise look for "key: value" where value is the endpoint.
	if _, v, ok := splitYAMLKV(line); ok {
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if strings.Contains(v, ":") && !strings.HasPrefix(v, "[") {
			return v
		}
	}
	return ""
}
