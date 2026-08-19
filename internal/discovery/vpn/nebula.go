package vpn

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"

	"gopkg.in/yaml.v3"
)

// nebulaEnumerator discovers Nebula overlay hosts from the local config.
// Nebula has no CLI that lists the live mesh (membership is learned
// dynamically from lighthouses at runtime), so this enumerates the hosts
// the config statically knows about: the lighthouses and any peers pinned
// in static_host_map. That is a lower bound on the mesh, not the whole
// fabric — documented honestly rather than implied to be complete.
//
// Nebula authenticates with certificates and exposes no user directory, so
// Owner is empty; hosts are identified by their overlay address.
type nebulaEnumerator struct {
	readFile fileReader
	getenv   func(string) string
	defaults []string
}

func newNebulaEnumerator() *nebulaEnumerator {
	return &nebulaEnumerator{
		readFile: osReadFile,
		getenv:   defaultGetenv,
		defaults: []string{
			"/etc/nebula/config.yml",
			"/etc/nebula/config.yaml",
		},
	}
}

func (e *nebulaEnumerator) vpnType() string { return "nebula" }

func (e *nebulaEnumerator) enumerate(_ context.Context, _ map[string]any) ([]Peer, error) {
	paths := e.defaults
	if override := strings.TrimSpace(e.getenv("KITE_NEBULA_CONFIG")); override != "" {
		paths = splitAndTrim(override, ',')
	}
	for _, path := range paths {
		data, err := e.readFile(path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				slog.Debug("vpn: nebula config read failed",
					"code", string(LogCodeNebulaConfigReadFailed),
					"path", path, "error", err)
			}
			continue
		}
		peers, perr := parseNebulaConfig(data)
		if perr != nil {
			slog.Debug("vpn: nebula config parse failed",
				"code", string(LogCodeNebulaConfigReadFailed),
				"path", path, "error", perr)
			continue
		}
		if len(peers) > 0 {
			return peers, nil // first readable config wins
		}
	}
	return nil, nil
}

type nebulaConfig struct {
	StaticHostMap map[string][]string `yaml:"static_host_map"`
	Lighthouse    struct {
		Hosts []string `yaml:"hosts"`
	} `yaml:"lighthouse"`
}

// parseNebulaConfig projects a Nebula config onto Peers: one per
// static_host_map entry, flagged when it is also a lighthouse.
func parseNebulaConfig(data []byte) ([]Peer, error) {
	var cfg nebulaConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("nebula: parse config yaml: %w", err)
	}
	lighthouses := make(map[string]struct{}, len(cfg.Lighthouse.Hosts))
	for _, h := range cfg.Lighthouse.Hosts {
		lighthouses[strings.TrimSpace(h)] = struct{}{}
	}

	out := make([]Peer, 0, len(cfg.StaticHostMap))
	for overlayIP, underlay := range cfg.StaticHostMap {
		overlayIP = strings.TrimSpace(overlayIP)
		if overlayIP == "" {
			continue
		}
		_, isLighthouse := lighthouses[overlayIP]
		p := Peer{
			VPNType:   "nebula",
			Addresses: sortAddrs([]string{overlayIP}),
			Tags: map[string]any{
				"is_lighthouse": isLighthouse,
			},
		}
		if eps := sortAddrs(underlay); len(eps) > 0 {
			p.Endpoint = eps[0]
			p.Tags["underlay_endpoints"] = eps
		}
		out = append(out, p)
	}
	return out, nil
}
