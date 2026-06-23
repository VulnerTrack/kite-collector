// Package lldp implements an LLDP (IEEE 802.1AB) neighbor-discovery source
// that reads neighbor state from the local `lldpd` daemon via `lldpctl -f
// json`. LLDP is what physically wired switches advertise; capturing it
// gives us the *relationship edge* — "this host is plugged into switch
// SW-01 port Gi0/3" — that mDNS / SSDP / WS-Discovery cannot.
//
// We deliberately read from the existing `lldpd` daemon rather than open a
// raw AF_PACKET socket. That keeps kite-collector non-privileged: the
// frame-capture work happens in the daemon that already needs CAP_NET_RAW,
// and we just consume its decoded view. When the daemon is absent the
// source no-ops with an INFO log; it never returns an error.
package lldp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	defaultBinary  = "lldpctl"
	defaultTimeout = 5 * time.Second
	maxNeighbors   = 1024
)

// runner is the seam we inject for tests. The default implementation shells
// out to `lldpctl -f json`; tests substitute a fixture.
type runner func(ctx context.Context, binary string, args ...string) ([]byte, error)

func defaultRunner(ctx context.Context, binary string, args ...string) ([]byte, error) {
	// binary is resolved via exec.LookPath (or operator-supplied absolute path
	// in cfg["binary"]) before reaching this seam — never operator-tainted
	// arbitrary input. Args is a fixed literal ([]string{"-f","json"}).
	cmd := exec.CommandContext(ctx, binary, args...) //#nosec G204 -- binary is LookPath-resolved or operator-configured absolute path; args are fixed literals
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("exec %s: %w", binary, err)
	}
	return out, nil
}

// lookPath is the seam for binary detection. Defaults to exec.LookPath.
type pathLookup func(string) (string, error)

// Source implements discovery.Source over `lldpctl`.
type Source struct {
	run      runner
	lookPath pathLookup
}

// New returns a new LLDP discovery source.
func New() *Source {
	return &Source{run: defaultRunner, lookPath: exec.LookPath}
}

// Name returns the stable identifier for this source.
func (s *Source) Name() string { return "lldp" }

// Config is the typed projection of operator YAML.
type Config struct {
	Binary  string
	Timeout time.Duration
}

func parseConfig(cfg map[string]any) Config {
	out := Config{Binary: defaultBinary, Timeout: defaultTimeout}
	if v, ok := cfg["binary"].(string); ok && v != "" {
		out.Binary = v
	}
	if v, ok := cfg["timeout"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			out.Timeout = d
		}
	}
	if out.Timeout <= 0 {
		out.Timeout = defaultTimeout
	}
	return out
}

// Discover invokes `lldpctl -f json` and emits one asset per LLDP neighbor.
// Supported config keys (all optional):
//
//	binary  string  override the lldpctl path (default: "lldpctl" on PATH)
//	timeout string  duration for the lldpctl invocation (default: 5s)
//
// If lldpctl is not installed the source returns (nil, nil) with an info
// log — never an error. This is the "graceful degradation when the daemon
// is absent" property documented in CONTRIBUTING.
func (s *Source) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	parsed := parseConfig(cfg)

	binPath, err := s.lookPath(parsed.Binary)
	if err != nil {
		slog.Info("lldp: lldpctl not on PATH; skipping (install lldpd to enable)",
			"binary", parsed.Binary)
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(ctx, parsed.Timeout)
	defer cancel()

	out, err := s.run(ctx, binPath, "-f", "json")
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			slog.Warn("lldp: lldpctl returned non-zero",
				"exit_code", exitErr.ExitCode(),
				"stderr", string(exitErr.Stderr),
			)
			return nil, nil
		}
		return nil, fmt.Errorf("lldp: invoke lldpctl: %w", err)
	}

	neighbors, err := parseLLDPCtl(out)
	if err != nil {
		return nil, fmt.Errorf("lldp: parse lldpctl output: %w", err)
	}
	if len(neighbors) > maxNeighbors {
		neighbors = neighbors[:maxNeighbors]
	}

	return assetsFromNeighbors(neighbors), nil
}

// neighbor is the projected shape of one LLDP neighbor — exactly what we
// need to build an asset and tag the switch-port edge.
type neighbor struct {
	LocalIface   string
	ChassisName  string
	ChassisID    string
	ChassisDescr string
	MgmtIP       string
	PortID       string
	PortDescr    string
	Capabilities []string
	VLANs        []string
}

// parseLLDPCtl decodes the JSON shape that `lldpctl -f json` emits. Two
// historical layouts are handled: `interface` as an array of single-key
// objects (the spec-friendly form when multiple neighbors are present) and
// `interface` as a single keyed object. Same for `chassis` and `port`.
func parseLLDPCtl(raw []byte) ([]neighbor, error) {
	var root struct {
		LLDP struct {
			Interface json.RawMessage `json:"interface"`
		} `json:"lldp"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("unmarshal lldpctl output: %w", err)
	}
	if len(root.LLDP.Interface) == 0 {
		return nil, nil
	}
	entries, err := flattenKeyedList(root.LLDP.Interface)
	if err != nil {
		return nil, fmt.Errorf("walk interfaces: %w", err)
	}

	var out []neighbor
	for _, e := range entries {
		n := neighbor{LocalIface: e.key}
		if err := absorbInterface(&n, e.value); err != nil {
			slog.Debug("lldp: skip malformed interface",
				"iface", e.key, "error", err)
			continue
		}
		if n.ChassisID == "" && n.ChassisName == "" {
			continue
		}
		out = append(out, n)
	}
	return out, nil
}

// keyedEntry is a tiny tuple used to unify the two JSON shapes lldpctl
// emits for collections — "object whose keys are names" vs "array of
// single-key objects".
type keyedEntry struct {
	key   string
	value json.RawMessage
}

func flattenKeyedList(raw json.RawMessage) ([]keyedEntry, error) {
	// Try array-of-single-key-object first.
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		var out []keyedEntry
		for _, m := range arr {
			for k, v := range m {
				out = append(out, keyedEntry{key: k, value: v})
			}
		}
		// Deterministic order.
		sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
		return out, nil
	}
	// Fall back to single keyed object.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		out := make([]keyedEntry, 0, len(obj))
		for k, v := range obj {
			out = append(out, keyedEntry{key: k, value: v})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
		return out, nil
	}
	return nil, errors.New("not a keyed object or list of objects")
}

// absorbInterface walks a single interface entry and fills the chassis/port
// fields on n.
func absorbInterface(n *neighbor, raw json.RawMessage) error {
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(raw, &meta); err != nil {
		return fmt.Errorf("unmarshal interface entry: %w", err)
	}
	if chassisRaw, ok := meta["chassis"]; ok {
		entries, err := flattenKeyedList(chassisRaw)
		if err == nil && len(entries) > 0 {
			n.ChassisName = entries[0].key
			absorbChassis(n, entries[0].value)
		} else {
			// Some lldpctl versions emit chassis as a flat object with no name key.
			absorbChassis(n, chassisRaw)
		}
	}
	if portRaw, ok := meta["port"]; ok {
		absorbPort(n, portRaw)
	}
	if vlanRaw, ok := meta["vlan"]; ok {
		n.VLANs = absorbVLANs(vlanRaw)
	}
	return nil
}

func absorbChassis(n *neighbor, raw json.RawMessage) {
	var c map[string]json.RawMessage
	if err := json.Unmarshal(raw, &c); err != nil {
		return
	}
	if idRaw, ok := c["id"]; ok {
		n.ChassisID = readIDValue(idRaw)
	}
	if d, ok := c["descr"]; ok {
		n.ChassisDescr = readString(d)
	}
	if m, ok := c["mgmt-ip"]; ok {
		n.MgmtIP = readFirstString(m)
	}
	if cap, ok := c["capability"]; ok {
		n.Capabilities = readCapabilities(cap)
	}
}

func absorbPort(n *neighbor, raw json.RawMessage) {
	var p map[string]json.RawMessage
	if err := json.Unmarshal(raw, &p); err != nil {
		return
	}
	if id, ok := p["id"]; ok {
		n.PortID = readIDValue(id)
	}
	if d, ok := p["descr"]; ok {
		n.PortDescr = readString(d)
	}
}

func absorbVLANs(raw json.RawMessage) []string {
	var asArr []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asArr); err == nil {
		var out []string
		for _, v := range asArr {
			if id, ok := v["vlan-id"]; ok {
				if s := readString(id); s != "" {
					out = append(out, s)
				}
			}
		}
		sort.Strings(out)
		return out
	}
	var single map[string]json.RawMessage
	if err := json.Unmarshal(raw, &single); err == nil {
		if id, ok := single["vlan-id"]; ok {
			if s := readString(id); s != "" {
				return []string{s}
			}
		}
	}
	return nil
}

// readIDValue normalises lldpctl's `{"type": "mac", "value": "aa:bb:..."}`
// shape into the bare value string. Falls back to interpreting raw as a
// plain string when the structured form is absent.
func readIDValue(raw json.RawMessage) string {
	var obj struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && obj.Value != "" {
		return obj.Value
	}
	return readString(raw)
}

// readString handles three shapes lldpctl uses for plain text: bare string,
// `{"value": "..."}`, or array of strings.
func readString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var obj struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return strings.TrimSpace(obj.Value)
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return strings.TrimSpace(arr[0])
	}
	return ""
}

func readFirstString(raw json.RawMessage) string {
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return arr[0]
	}
	return readString(raw)
}

// readCapabilities extracts enabled capability names from the
// `[{"type":"Bridge","enabled":true},...]` array.
func readCapabilities(raw json.RawMessage) []string {
	var arr []struct {
		Type    string `json:"type"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil
	}
	var out []string
	for _, c := range arr {
		if c.Enabled && c.Type != "" {
			out = append(out, c.Type)
		}
	}
	sort.Strings(out)
	return out
}

// assetsFromNeighbors collapses neighbors into a deterministic asset list.
// One asset per unique chassis identity — multiple uplinks to the same
// switch collapse to one asset whose tags name every observed local port.
func assetsFromNeighbors(ns []neighbor) []model.Asset {
	byChassis := map[string][]neighbor{}
	for _, n := range ns {
		key := n.ChassisID
		if key == "" {
			key = n.ChassisName
		}
		byChassis[key] = append(byChassis[key], n)
	}

	keys := make([]string, 0, len(byChassis))
	for k := range byChassis {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	now := time.Now().UTC()
	out := make([]model.Asset, 0, len(keys))
	for _, k := range keys {
		group := byChassis[k]
		first := group[0]
		hostname := first.ChassisName
		if hostname == "" {
			hostname = first.MgmtIP
		}
		if hostname == "" {
			hostname = first.ChassisID
		}
		a := model.Asset{
			AssetType:       classify(first.Capabilities, first.ChassisDescr),
			Hostname:        hostname,
			DiscoverySource: "lldp",
			FirstSeenAt:     now,
			LastSeenAt:      now,
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       model.ManagedUnknown,
			Tags:            buildTags(group),
		}
		a.ComputeNaturalKey()
		out = append(out, a)
	}
	return out
}

// classify maps LLDP system capabilities + sysDescr to an AssetType. LLDP
// neighbors are almost always switches/routers/APs, so the default is
// network_device.
func classify(caps []string, descr string) model.AssetType {
	for _, c := range caps {
		lc := strings.ToLower(c)
		switch lc {
		case "bridge", "router", "wlan", "wlan-access-point",
			"docsis-cable-device", "telephone":
			return model.AssetTypeNetworkDevice
		case "station-only":
			return model.AssetTypeServer
		}
	}
	d := strings.ToLower(descr)
	if strings.Contains(d, "linux") && !strings.Contains(d, "router") {
		return model.AssetTypeServer
	}
	return model.AssetTypeNetworkDevice
}

// buildTags emits a JSON blob recording every switch-port edge we saw to
// this chassis. Downstream consumers can use lldp_local_iface +
// lldp_port_id pairs to reconstruct the topology graph.
func buildTags(group []neighbor) string {
	type edge struct {
		LocalIface string `json:"local_iface"`
		PortID     string `json:"port_id"`
		PortDescr  string `json:"port_descr,omitempty"`
	}
	edges := make([]edge, 0, len(group))
	vlans := map[string]struct{}{}
	for _, n := range group {
		edges = append(edges, edge{
			LocalIface: n.LocalIface,
			PortID:     n.PortID,
			PortDescr:  n.PortDescr,
		})
		for _, v := range n.VLANs {
			vlans[v] = struct{}{}
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].LocalIface != edges[j].LocalIface {
			return edges[i].LocalIface < edges[j].LocalIface
		}
		return edges[i].PortID < edges[j].PortID
	})
	vlanList := make([]string, 0, len(vlans))
	for v := range vlans {
		vlanList = append(vlanList, v)
	}
	sort.Strings(vlanList)

	first := group[0]
	payload := struct {
		ChassisID    string   `json:"lldp_chassis_id"`
		ChassisDescr string   `json:"lldp_chassis_descr,omitempty"`
		MgmtIP       string   `json:"lldp_mgmt_ip,omitempty"`
		Capabilities []string `json:"lldp_capabilities,omitempty"`
		Edges        []edge   `json:"lldp_edges"`
		VLANs        []string `json:"lldp_vlans,omitempty"`
	}{
		ChassisID:    first.ChassisID,
		ChassisDescr: first.ChassisDescr,
		MgmtIP:       first.MgmtIP,
		Capabilities: first.Capabilities,
		Edges:        edges,
		VLANs:        vlanList,
	}
	b, _ := json.Marshal(payload)
	return string(b)
}
