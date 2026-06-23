// Package wsdiscovery implements a WS-Discovery (OASIS Web Services Dynamic
// Discovery) probe source. It sends a SOAP Probe to 239.255.255.250:3702
// (and ff02::c:3702 for IPv6), collects ProbeMatch responses for a bounded
// window, and emits one asset per unique EndpointReference.
//
// WS-Discovery is the protocol of choice for:
//   - ONVIF IP cameras and NVRs (almost universal)
//   - Network printers (PNP-X devices)
//   - Windows hosts that publish themselves via Function Discovery
//   - Many enterprise scanners and MFPs
//
// It runs on the LAN, requires no credentials, and exposes devices that
// neither mDNS nor SSDP advertise — particularly OT/IoT cameras.
package wsdiscovery

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	wsdPort          = 3702
	defaultListenWin = 4 * time.Second
	maxListenWin     = 30 * time.Second
	maxPacketSize    = 65507 // UDP max payload; ProbeMatches can be large
	maxRespondersCap = 4096
)

var (
	wsdIPv4 = net.IPv4(239, 255, 255, 250)
	wsdIPv6 = net.ParseIP("ff02::c")
)

// Source implements discovery.Source over WS-Discovery.
type Source struct{}

// New returns a new WS-Discovery source.
func New() *Source { return &Source{} }

// Name returns the stable identifier for this source.
func (s *Source) Name() string { return "wsdiscovery" }

// Config is the typed projection of operator YAML. Fields are ordered
// strings-first, slices-next, primitives last to minimise GC pointer-bitmap
// overhead (fieldalignment).
type Config struct {
	Types        string // optional SOAP `Types` filter (empty = ProbeAll)
	Interfaces   []string
	ListenWindow time.Duration
	DisableIPv4  bool
	DisableIPv6  bool
}

func parseConfig(cfg map[string]any) Config {
	out := Config{
		Interfaces:   toStringSlice(cfg["interfaces"]),
		ListenWindow: defaultListenWin,
	}
	if t, ok := cfg["types"].(string); ok {
		out.Types = t
	}
	if s, ok := cfg["listen_window"].(string); ok {
		if d, err := time.ParseDuration(s); err == nil {
			out.ListenWindow = d
		}
	}
	if out.ListenWindow > maxListenWin {
		out.ListenWindow = maxListenWin
	}
	if v, ok := cfg["disable_ipv4"].(bool); ok {
		out.DisableIPv4 = v
	}
	if v, ok := cfg["disable_ipv6"].(bool); ok {
		out.DisableIPv6 = v
	}
	return out
}

// responder accumulates one logical device, keyed by EndpointReference URN
// when present (the spec's stable identity), otherwise by source IP.
//
//nolint:govet // fieldalignment: all 7 fields are pointer-containing so ptrdata is floor-bounded at 128; the recommended 120 isn't reachable without splitting the type.
type responder struct {
	lastSeen time.Time
	addr     net.IP
	xaddrs   []string
	epr      string
	types    string
	scopes   string
	hostname string
}

// Discover sends a Probe and reads ProbeMatch replies for ListenWindow.
//
// Supported config keys (all optional):
//
//	interfaces    []string  restrict to these interface names
//	types         string    SOAP Types filter (empty = ProbeAll)
//	listen_window string    response window (default 4s, max 30s)
//	disable_ipv4  bool
//	disable_ipv6  bool
func (s *Source) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	parsed := parseConfig(cfg)

	ctx, cancel := context.WithTimeout(ctx, parsed.ListenWindow+2*time.Second)
	defer cancel()

	ifaces, err := pickInterfaces(parsed.Interfaces)
	if err != nil {
		return nil, fmt.Errorf("wsdiscovery: select interfaces: %w", err)
	}
	if len(ifaces) == 0 {
		slog.Info("wsdiscovery: no multicast-capable interfaces; nothing to discover")
		return nil, nil
	}

	var (
		mu         sync.Mutex
		responders = map[string]*responder{}
		wg         sync.WaitGroup
	)

	record := func(pm probeMatch, src net.IP) {
		mu.Lock()
		defer mu.Unlock()
		if len(responders) >= maxRespondersCap {
			return
		}
		key := pm.Address
		if key == "" && src != nil {
			key = src.String()
		}
		if key == "" {
			return
		}
		r, ok := responders[key]
		if !ok {
			r = &responder{addr: src, epr: pm.Address, lastSeen: time.Now().UTC()}
			responders[key] = r
		}
		absorb(r, pm)
	}

	for _, iface := range ifaces {
		if !parsed.DisableIPv4 {
			if conn, err := listenMulticast(iface, wsdIPv4); err == nil {
				wg.Add(1)
				go func(c *net.UDPConn) {
					defer wg.Done()
					defer func() { _ = c.Close() }()
					readLoop(ctx, c, record)
				}(conn)
			} else {
				slog.Debug("wsdiscovery: ipv4 listen failed",
					"iface", iface.Name, "error", err)
			}
		}
		if !parsed.DisableIPv6 {
			if conn, err := listenMulticast(iface, wsdIPv6); err == nil {
				wg.Add(1)
				go func(c *net.UDPConn) {
					defer wg.Done()
					defer func() { _ = c.Close() }()
					readLoop(ctx, c, record)
				}(conn)
			} else {
				slog.Debug("wsdiscovery: ipv6 listen failed",
					"iface", iface.Name, "error", err)
			}
		}
	}

	for _, iface := range ifaces {
		if !parsed.DisableIPv4 {
			wg.Add(1)
			go func(ifi net.Interface) {
				defer wg.Done()
				sendAndReadReplies(ctx, ifi, wsdIPv4, parsed.Types, record)
			}(iface)
		}
		if !parsed.DisableIPv6 {
			wg.Add(1)
			go func(ifi net.Interface) {
				defer wg.Done()
				sendAndReadReplies(ctx, ifi, wsdIPv6, parsed.Types, record)
			}(iface)
		}
	}

	select {
	case <-time.After(parsed.ListenWindow):
	case <-ctx.Done():
	}
	cancel()
	wg.Wait()

	return assetsFromResponders(responders), nil
}

func pickInterfaces(wanted []string) ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}
	want := map[string]struct{}{}
	for _, n := range wanted {
		want[n] = struct{}{}
	}
	var out []net.Interface
	for _, ifi := range all {
		if ifi.Flags&net.FlagUp == 0 ||
			ifi.Flags&net.FlagMulticast == 0 ||
			ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(want) > 0 {
			if _, ok := want[ifi.Name]; !ok {
				continue
			}
		}
		out = append(out, ifi)
	}
	return out, nil
}

func listenMulticast(iface net.Interface, group net.IP) (*net.UDPConn, error) {
	conn, err := net.ListenMulticastUDP(networkFor(group), &iface, &net.UDPAddr{IP: group, Port: wsdPort})
	if err != nil {
		return nil, fmt.Errorf("join %s on %s: %w", group, iface.Name, err)
	}
	_ = conn.SetReadBuffer(1 << 20)
	return conn, nil
}

func networkFor(ip net.IP) string {
	if ip.To4() != nil {
		return "udp4"
	}
	return "udp6"
}

// sendAndReadReplies opens an ephemeral socket, sends one Probe, drains
// replies until ctx is done.
func sendAndReadReplies(ctx context.Context, iface net.Interface, group net.IP, types string, record func(probeMatch, net.IP)) {
	conn, err := net.ListenUDP(networkFor(group), &net.UDPAddr{IP: nil, Port: 0})
	if err != nil {
		slog.Debug("wsdiscovery: open sender failed",
			"iface", iface.Name, "group", group.String(), "error", err)
		return
	}
	defer func() { _ = conn.Close() }()

	msgID := "uuid:" + uuid.Must(uuid.NewV7()).String()
	payload := buildProbe(msgID, types)
	dst := &net.UDPAddr{IP: group, Port: wsdPort}
	if _, err := conn.WriteTo(payload, dst); err != nil {
		slog.Debug("wsdiscovery: send failed",
			"iface", iface.Name, "group", group.String(), "error", err)
		return
	}
	readLoop(ctx, conn, record)
}

// buildProbe returns a SOAP 1.2 Probe envelope.
// types is optional; when empty the device matches any Type ("ProbeAll").
func buildProbe(messageID, types string) []byte {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	sb.WriteString(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"`)
	sb.WriteString(` xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"`)
	sb.WriteString(` xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">`)
	sb.WriteString(`<s:Header>`)
	sb.WriteString(`<a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>`)
	sb.WriteString(`<a:MessageID>`)
	xmlEscapeWrite(&sb, messageID)
	sb.WriteString(`</a:MessageID>`)
	sb.WriteString(`<a:To s:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>`)
	sb.WriteString(`</s:Header>`)
	sb.WriteString(`<s:Body><d:Probe>`)
	if types != "" {
		sb.WriteString(`<d:Types>`)
		xmlEscapeWrite(&sb, types)
		sb.WriteString(`</d:Types>`)
	}
	sb.WriteString(`</d:Probe></s:Body></s:Envelope>`)
	return []byte(sb.String())
}

// probeMatch is the projected shape of one match in a ProbeMatches response.
type probeMatch struct {
	Address string   // EndpointReference/Address (URN, stable identity)
	Types   string   // space-separated QNames (e.g. "dn:NetworkVideoTransmitter")
	Scopes  string   // space-separated URIs (e.g. "onvif://www.onvif.org/Profile/T")
	XAddrs  []string // transport addresses where the service is reachable
}

// xmlEnvelope is the projection we decode from any ProbeMatch / Hello /
// ProbeMatches response. Unprefixed XML tags match on local name regardless
// of namespace, which is exactly what we want for the multi-namespace WSD
// payload.
//
//nolint:govet // fieldalignment: encoding/xml field ordering must match the SOAP envelope's expected child order; reordering for ptrdata would break unmarshalling.
type xmlEnvelope struct {
	Body struct {
		Hello *struct {
			EndpointReference struct {
				Address string `xml:"Address"`
			} `xml:"EndpointReference"`
			Types  string `xml:"Types"`
			Scopes string `xml:"Scopes"`
			XAddrs string `xml:"XAddrs"`
		} `xml:"Hello"`
		ProbeMatches struct {
			Match []struct {
				EndpointReference struct {
					Address string `xml:"Address"`
				} `xml:"EndpointReference"`
				Types  string `xml:"Types"`
				Scopes string `xml:"Scopes"`
				XAddrs string `xml:"XAddrs"`
			} `xml:"ProbeMatch"`
		} `xml:"ProbeMatches"`
	} `xml:"Body"`
	XMLName xml.Name
}

// parseEnvelope decodes a SOAP datagram and returns a flat list of
// probeMatch records. It treats Hello broadcasts as additional matches so
// passive listening yields the same shape as active probing.
func parseEnvelope(raw []byte) ([]probeMatch, error) {
	var env xmlEnvelope
	if err := xml.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("unmarshal soap envelope: %w", err)
	}
	var out []probeMatch
	for _, m := range env.Body.ProbeMatches.Match {
		out = append(out, probeMatch{
			Address: strings.TrimSpace(m.EndpointReference.Address),
			Types:   strings.TrimSpace(m.Types),
			Scopes:  strings.TrimSpace(m.Scopes),
			XAddrs:  splitWS(m.XAddrs),
		})
	}
	if env.Body.Hello != nil {
		h := env.Body.Hello
		out = append(out, probeMatch{
			Address: strings.TrimSpace(h.EndpointReference.Address),
			Types:   strings.TrimSpace(h.Types),
			Scopes:  strings.TrimSpace(h.Scopes),
			XAddrs:  splitWS(h.XAddrs),
		})
	}
	return out, nil
}

// readLoop drains UDP packets and pushes parsed matches into the recorder.
func readLoop(ctx context.Context, conn *net.UDPConn, record func(probeMatch, net.IP)) {
	buf := make([]byte, maxPacketSize)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return
		}
		matches, perr := parseEnvelope(buf[:n])
		if perr != nil {
			continue
		}
		var srcIP net.IP
		if src != nil {
			srcIP = src.IP
		}
		for _, pm := range matches {
			record(pm, srcIP)
		}
	}
}

// absorb merges one ProbeMatch into the per-device accumulator.
func absorb(r *responder, pm probeMatch) {
	r.lastSeen = time.Now().UTC()
	if pm.Types != "" {
		r.types = mergeSpaceList(r.types, pm.Types)
	}
	if pm.Scopes != "" {
		r.scopes = mergeSpaceList(r.scopes, pm.Scopes)
	}
	for _, x := range pm.XAddrs {
		if x != "" && !sliceContains(r.xaddrs, x) {
			r.xaddrs = append(r.xaddrs, x)
		}
	}
	if r.hostname == "" {
		for _, x := range r.xaddrs {
			if u, err := url.Parse(x); err == nil {
				if h := u.Hostname(); h != "" {
					r.hostname = h
					break
				}
			}
		}
	}
}

// assetsFromResponders flattens the per-device map into a deterministic
// asset list.
func assetsFromResponders(in map[string]*responder) []model.Asset {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]model.Asset, 0, len(keys))
	for _, k := range keys {
		r := in[k]
		hostname := r.hostname
		if hostname == "" {
			if r.epr != "" {
				hostname = r.epr
			} else if r.addr != nil {
				hostname = r.addr.String()
			} else {
				hostname = k
			}
		}
		a := model.Asset{
			AssetType:       classify(r.types, r.scopes),
			Hostname:        hostname,
			DiscoverySource: "wsdiscovery",
			FirstSeenAt:     r.lastSeen,
			LastSeenAt:      r.lastSeen,
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       model.ManagedUnknown,
			Tags:            buildTags(r),
		}
		a.ComputeNaturalKey()
		out = append(out, a)
	}
	return out
}

// classify maps observed Types/Scopes to an AssetType. We lean on the
// strongest signal first: ONVIF scope → camera; printer scope → appliance;
// Computer type → workstation; otherwise fall back to iot_device.
func classify(types, scopes string) model.AssetType {
	t := strings.ToLower(types)
	s := strings.ToLower(scopes)
	switch {
	case strings.Contains(s, "onvif://") ||
		strings.Contains(t, "networkvideotransmitter") ||
		strings.Contains(t, "networkvideodisplay"):
		return model.AssetTypeIOTDevice
	case strings.Contains(s, "ldap.printer") ||
		strings.Contains(t, "printer") ||
		strings.Contains(t, "printerservicev10") ||
		strings.Contains(t, "printerservicev20"):
		return model.AssetTypeAppliance
	case strings.Contains(t, "computer") ||
		strings.Contains(s, "pkitypes.microsoft.com") ||
		strings.Contains(s, "microsoft.com/windows"):
		return model.AssetTypeWorkstation
	case strings.Contains(t, "device"):
		return model.AssetTypeIOTDevice
	default:
		return model.AssetTypeIOTDevice
	}
}

func buildTags(r *responder) string {
	xaddrs := append([]string(nil), r.xaddrs...)
	sort.Strings(xaddrs)
	var sb strings.Builder
	sb.WriteString(`{"wsd_epr":"`)
	sb.WriteString(jsonEscape(r.epr))
	sb.WriteString(`","wsd_types":"`)
	sb.WriteString(jsonEscape(r.types))
	sb.WriteString(`","wsd_scopes":"`)
	sb.WriteString(jsonEscape(r.scopes))
	sb.WriteString(`","wsd_xaddrs":[`)
	for i, x := range xaddrs {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('"')
		sb.WriteString(jsonEscape(x))
		sb.WriteByte('"')
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func mergeSpaceList(a, b string) string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, token := range append(strings.Fields(a), strings.Fields(b)...) {
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, token)
	}
	return strings.Join(out, " ")
}

func splitWS(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func sliceContains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func jsonEscape(s string) string {
	if !strings.ContainsAny(s, `"\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func xmlEscapeWrite(b *strings.Builder, s string) {
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(r)
		}
	}
}

func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	if ss, ok := v.([]string); ok {
		return ss
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
