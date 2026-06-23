// Package ssdp implements an SSDP / UPnP discovery source (RFC drafts;
// UPnP Device Architecture 2.0). It sends an HTTPU M-SEARCH to
// 239.255.255.250:1900 (and ff02::c:1900 for IPv6), then collects unicast
// responses and passive NOTIFY * announcements for a bounded window.
//
// SSDP is how smart TVs, IP cameras, routers, NAS boxes, printers, and most
// consumer IoT advertise themselves. It usually requires no credentials,
// runs on every modern home/office LAN, and surfaces firmware that a port
// sweep cannot fingerprint.
package ssdp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	ssdpPort         = 1900
	defaultMX        = 2 // M-SEARCH "MX" header in seconds (response delay budget)
	defaultListenWin = 4 * time.Second
	maxListenWin     = 30 * time.Second
	maxPacketSize    = 9000
	maxRespondersCap = 4096
	defaultSearchTgt = "ssdp:all"
)

var (
	ssdpIPv4 = net.IPv4(239, 255, 255, 250)
	ssdpIPv6 = net.ParseIP("ff02::c")
)

// Source implements discovery.Source over SSDP/UPnP.
type Source struct{}

// New returns a new SSDP discovery source.
func New() *Source { return &Source{} }

// Name returns the stable identifier for this source.
func (s *Source) Name() string { return "ssdp" }

// Config is the typed projection of operator YAML.
type Config struct {
	SearchTargets []string
	Interfaces    []string
	ListenWindow  time.Duration
	MX            int
	DisableIPv4   bool
	DisableIPv6   bool
}

func parseConfig(cfg map[string]any) Config {
	out := Config{
		SearchTargets: toStringSlice(cfg["search_targets"]),
		Interfaces:    toStringSlice(cfg["interfaces"]),
		ListenWindow:  defaultListenWin,
		MX:            defaultMX,
	}
	if len(out.SearchTargets) == 0 {
		out.SearchTargets = []string{defaultSearchTgt}
	}
	if s, ok := cfg["listen_window"].(string); ok {
		if d, err := time.ParseDuration(s); err == nil {
			out.ListenWindow = d
		}
	}
	if out.ListenWindow > maxListenWin {
		out.ListenWindow = maxListenWin
	}
	switch m := cfg["mx"].(type) {
	case int:
		out.MX = m
	case float64:
		out.MX = int(m)
	}
	if out.MX < 1 {
		out.MX = 1
	}
	if out.MX > 5 {
		out.MX = 5 // RFC recommends ≤5 to keep multicast chatter sane
	}
	if v, ok := cfg["disable_ipv4"].(bool); ok {
		out.DisableIPv4 = v
	}
	if v, ok := cfg["disable_ipv6"].(bool); ok {
		out.DisableIPv6 = v
	}
	return out
}

// responder accumulates everything seen from one SSDP endpoint, keyed by
// source IP. We merge multiple announcements (ST/USN pairs) into a single
// asset so a router advertising 8 service URNs is one asset, not 8.
type responder struct {
	addr      net.IP
	hostname  string
	server    string
	location  string
	usn       string
	sts       map[string]struct{}
	usns      map[string]struct{}
	lastSeen  time.Time
}

// Discover sends M-SEARCH, joins the multicast group to also pick up
// passive NOTIFY * announcements, and returns one asset per unique
// responder.
//
// Supported config keys (all optional):
//
//	search_targets []string  ST values to probe (default ["ssdp:all"])
//	interfaces     []string  restrict to these interface names
//	listen_window  string    response window (default 4s, max 30s)
//	mx             int       MX response budget (default 2, range 1..5)
//	disable_ipv4   bool      skip IPv4 multicast
//	disable_ipv6   bool      skip IPv6 multicast
func (s *Source) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	parsed := parseConfig(cfg)

	ctx, cancel := context.WithTimeout(ctx, parsed.ListenWindow+2*time.Second)
	defer cancel()

	ifaces, err := pickInterfaces(parsed.Interfaces)
	if err != nil {
		return nil, fmt.Errorf("ssdp: select interfaces: %w", err)
	}
	if len(ifaces) == 0 {
		slog.Info("ssdp: no multicast-capable interfaces; nothing to discover")
		return nil, nil
	}

	var (
		mu         sync.Mutex
		responders = map[string]*responder{}
		wg         sync.WaitGroup
	)

	record := func(msg ssdpMessage, src net.IP) {
		mu.Lock()
		defer mu.Unlock()
		if len(responders) >= maxRespondersCap {
			return
		}
		key := src.String()
		r, ok := responders[key]
		if !ok {
			r = &responder{
				addr:     src,
				sts:      map[string]struct{}{},
				usns:     map[string]struct{}{},
				lastSeen: time.Now().UTC(),
			}
			responders[key] = r
		}
		absorbMessage(r, msg)
	}

	// Passive listeners — join the multicast group so we also see NOTIFY *.
	for _, iface := range ifaces {
		if !parsed.DisableIPv4 {
			if conn, err := listenMulticast(iface, ssdpIPv4); err == nil {
				wg.Add(1)
				go func(c *net.UDPConn) {
					defer wg.Done()
					defer c.Close()
					readLoop(ctx, c, record)
				}(conn)
			} else {
				slog.Debug("ssdp: ipv4 listen failed",
					"iface", iface.Name, "error", err)
			}
		}
		if !parsed.DisableIPv6 {
			if conn, err := listenMulticast(iface, ssdpIPv6); err == nil {
				wg.Add(1)
				go func(c *net.UDPConn) {
					defer wg.Done()
					defer c.Close()
					readLoop(ctx, c, record)
				}(conn)
			} else {
				slog.Debug("ssdp: ipv6 listen failed",
					"iface", iface.Name, "error", err)
			}
		}
	}

	// Active M-SEARCH — one socket per (iface, family) so unicast replies
	// land on a known fd. We read each reply socket for parsed.ListenWindow.
	for _, iface := range ifaces {
		if !parsed.DisableIPv4 {
			for _, st := range parsed.SearchTargets {
				wg.Add(1)
				go func(ifi net.Interface, st string) {
					defer wg.Done()
					sendAndReadReplies(ctx, ifi, ssdpIPv4, st, parsed.MX, record)
				}(iface, st)
			}
		}
		if !parsed.DisableIPv6 {
			for _, st := range parsed.SearchTargets {
				wg.Add(1)
				go func(ifi net.Interface, st string) {
					defer wg.Done()
					sendAndReadReplies(ctx, ifi, ssdpIPv6, st, parsed.MX, record)
				}(iface, st)
			}
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

// pickInterfaces returns multicast-capable, up, non-loopback interfaces.
func pickInterfaces(wanted []string) ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	want := map[string]struct{}{}
	for _, n := range wanted {
		want[n] = struct{}{}
	}
	var out []net.Interface
	for _, ifi := range all {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		if ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		if ifi.Flags&net.FlagLoopback != 0 {
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

// listenMulticast joins the SSDP group on iface for passive NOTIFY capture.
func listenMulticast(iface net.Interface, group net.IP) (*net.UDPConn, error) {
	udpAddr := &net.UDPAddr{IP: group, Port: ssdpPort}
	conn, err := net.ListenMulticastUDP(networkFor(group), &iface, udpAddr)
	if err != nil {
		return nil, err
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

// sendAndReadReplies opens an ephemeral socket on iface, sends one
// M-SEARCH, then drains unicast replies until ctx is cancelled.
func sendAndReadReplies(ctx context.Context, iface net.Interface, group net.IP, st string, mx int, record func(ssdpMessage, net.IP)) {
	conn, err := net.ListenUDP(networkFor(group), &net.UDPAddr{IP: nil, Port: 0})
	if err != nil {
		slog.Debug("ssdp: open sender failed",
			"iface", iface.Name, "group", group.String(), "error", err)
		return
	}
	defer conn.Close()

	payload := buildMSearch(group, st, mx)
	dst := &net.UDPAddr{IP: group, Port: ssdpPort}
	if _, err := conn.WriteTo(payload, dst); err != nil {
		slog.Debug("ssdp: send failed",
			"iface", iface.Name, "group", group.String(), "error", err)
		return
	}
	readLoop(ctx, conn, record)
}

// buildMSearch returns an M-SEARCH datagram targeting the given search
// target with the supplied MX response budget.
func buildMSearch(group net.IP, st string, mx int) []byte {
	host := fmt.Sprintf("%s:%d", group.String(), ssdpPort)
	if group.To4() == nil {
		host = fmt.Sprintf("[%s]:%d", group.String(), ssdpPort)
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "M-SEARCH * HTTP/1.1\r\n")
	fmt.Fprintf(&b, "HOST: %s\r\n", host)
	fmt.Fprintf(&b, "MAN: \"ssdp:discover\"\r\n")
	fmt.Fprintf(&b, "MX: %d\r\n", mx)
	fmt.Fprintf(&b, "ST: %s\r\n", st)
	fmt.Fprintf(&b, "USER-AGENT: kite-collector/1.0 UPnP/2.0\r\n")
	fmt.Fprintf(&b, "\r\n")
	return b.Bytes()
}

// ssdpMessage is the parsed shape of either an M-SEARCH response or a
// NOTIFY * advertisement.
type ssdpMessage struct {
	Headers http.Header
	Method  string // "" for responses, "NOTIFY" for adverts
	NTS     string // for NOTIFY: ssdp:alive / ssdp:byebye / ssdp:update
}

// parseDatagram parses one UDP payload as an HTTPU message and returns the
// extracted headers + classification. Returns an error if the start line is
// malformed.
func parseDatagram(raw []byte) (ssdpMessage, error) {
	r := bufio.NewReader(bytes.NewReader(raw))
	startLine, err := r.ReadString('\n')
	if err != nil {
		return ssdpMessage{}, fmt.Errorf("read start line: %w", err)
	}
	startLine = strings.TrimRight(startLine, "\r\n")

	var msg ssdpMessage
	switch {
	case strings.HasPrefix(startLine, "HTTP/1."):
		// M-SEARCH response — already a response, no method.
	case strings.HasPrefix(startLine, "NOTIFY * HTTP/1."):
		msg.Method = "NOTIFY"
	case strings.HasPrefix(startLine, "M-SEARCH"):
		// somebody else's M-SEARCH — ignore.
		return ssdpMessage{}, errors.New("foreign m-search")
	default:
		return ssdpMessage{}, fmt.Errorf("unknown start line: %q", startLine)
	}

	headers := http.Header{}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// SSDP headers are case-insensitive; normalise to canonical.
		headers.Add(http.CanonicalHeaderKey(key), val)
	}
	msg.Headers = headers
	if msg.Method == "NOTIFY" {
		msg.NTS = headers.Get("Nts")
	}
	return msg, nil
}

// readLoop drains UDP packets, parses them, and pushes them to the recorder.
func readLoop(ctx context.Context, conn *net.UDPConn, record func(ssdpMessage, net.IP)) {
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
		msg, perr := parseDatagram(buf[:n])
		if perr != nil {
			continue
		}
		// Discard ssdp:byebye — useful for state, but at scan time we want
		// "what is alive now", not "what just went away".
		if msg.NTS == "ssdp:byebye" {
			continue
		}
		var srcIP net.IP
		if src != nil {
			srcIP = src.IP
		}
		record(msg, srcIP)
	}
}

// absorbMessage merges one parsed SSDP message into the per-responder
// accumulator.
func absorbMessage(r *responder, m ssdpMessage) {
	r.lastSeen = time.Now().UTC()
	if srv := m.Headers.Get("Server"); srv != "" && r.server == "" {
		r.server = srv
	}
	if loc := m.Headers.Get("Location"); loc != "" {
		if r.location == "" {
			r.location = loc
		}
		if r.hostname == "" {
			if u, err := url.Parse(loc); err == nil {
				if host := u.Hostname(); host != "" {
					r.hostname = host
				}
			}
		}
	}
	if usn := m.Headers.Get("Usn"); usn != "" {
		r.usns[usn] = struct{}{}
		if r.usn == "" {
			r.usn = usn
		}
	}
	// NOTIFY uses "Nt" (notification type); response uses "St" (search target).
	if st := m.Headers.Get("St"); st != "" {
		r.sts[st] = struct{}{}
	}
	if nt := m.Headers.Get("Nt"); nt != "" {
		r.sts[nt] = struct{}{}
	}
}

// assetsFromResponders collapses the per-source accumulator into a sorted
// list of model.Asset values.
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
			if r.usn != "" {
				hostname = r.usn
			} else {
				hostname = r.addr.String()
			}
		}
		a := model.Asset{
			AssetType:       classify(r.sts, r.server),
			Hostname:        hostname,
			DiscoverySource: "ssdp",
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

// classify maps observed Search Targets + Server header to an AssetType.
// The precedence ladder favours specific evidence (printer, router) over
// generic UPnP device URNs.
func classify(sts map[string]struct{}, server string) model.AssetType {
	contains := func(needle string) bool {
		for st := range sts {
			if strings.Contains(strings.ToLower(st), needle) {
				return true
			}
		}
		return false
	}
	srv := strings.ToLower(server)

	switch {
	case contains("internetgatewaydevice") || contains("wandevice") ||
		contains("wanconnectiondevice") || contains("wfawlanconfig"):
		return model.AssetTypeNetworkDevice
	case contains("printer") || strings.Contains(srv, "ipp"):
		return model.AssetTypeAppliance
	case contains("mediarenderer") || contains("mediaserver") ||
		contains("dial-multiscreen-org") || contains("googlecast") ||
		contains("avtransport"):
		return model.AssetTypeIOTDevice
	case contains("basic:1") && strings.Contains(srv, "linux"):
		return model.AssetTypeServer
	default:
		return model.AssetTypeIOTDevice
	}
}

// buildTags returns a small JSON object encoding everything we observed for
// downstream queries.
func buildTags(r *responder) string {
	sts := mapKeys(r.sts)
	usns := mapKeys(r.usns)
	sort.Strings(sts)
	sort.Strings(usns)
	var sb strings.Builder
	sb.WriteString(`{"ssdp_st":[`)
	for i, s := range sts {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('"')
		sb.WriteString(jsonEscape(s))
		sb.WriteByte('"')
	}
	sb.WriteString(`],"ssdp_usn":[`)
	for i, s := range usns {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('"')
		sb.WriteString(jsonEscape(s))
		sb.WriteByte('"')
	}
	sb.WriteString(`],"ssdp_server":"`)
	sb.WriteString(jsonEscape(r.server))
	sb.WriteString(`","ssdp_location":"`)
	sb.WriteString(jsonEscape(r.location))
	sb.WriteString(`"}`)
	return sb.String()
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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
