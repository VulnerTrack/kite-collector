// Package mdns implements a passive/active DNS-SD (RFC 6762/6763) discovery
// source. It issues PTR queries for a curated set of service types over
// link-local multicast (224.0.0.251:5353 / ff02::fb), listens for replies for
// a bounded window, and emits one asset per unique target.
//
// mDNS catches devices that *announce themselves* — printers, AirPlay/Cast
// targets, dev workstations, NAS, IP cameras — that a credentialed pull or a
// TCP port sweep typically misses. No credentials are required and no traffic
// leaves the local link.
package mdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	mdnsPort           = 5353
	defaultListenWin   = 3 * time.Second
	maxListenWin       = 30 * time.Second
	maxPacketSize      = 9000
	maxRespondersCap   = 4096 // hard ceiling so a hostile responder can't OOM us
	defaultQueryRepeat = 2
)

var (
	mdnsIPv4 = net.IPv4(224, 0, 0, 251)
	mdnsIPv6 = net.ParseIP("ff02::fb")
)

// DefaultServiceTypes is the curated list of DNS-SD service types we ask
// every responder to enumerate. The list is intentionally small to keep
// multicast chatter low — operators can override via config.
var DefaultServiceTypes = []string{
	"_services._dns-sd._udp.local.", // meta query: ask responders what they expose
	"_workstation._tcp.local.",      // Linux/macOS workstations (Avahi, mDNSResponder)
	"_ssh._tcp.local.",              // hosts advertising SSH
	"_http._tcp.local.",             // any web UI on the LAN
	"_smb._tcp.local.",              // SMB/CIFS shares (NAS, file servers)
	"_ipp._tcp.local.",              // IPP printers
	"_printer._tcp.local.",          // line-printer / legacy printers
	"_airplay._tcp.local.",          // AirPlay receivers (Apple TV, speakers)
	"_googlecast._tcp.local.",       // Chromecast, Google Home
	"_device-info._tcp.local.",      // generic device-info advertisement
	"_homekit._tcp.local.",          // HomeKit accessories
	"_hap._tcp.local.",              // HomeKit Accessory Protocol
}

// Source implements discovery.Source over mDNS / DNS-SD.
type Source struct{}

// New returns a new mDNS discovery source.
func New() *Source { return &Source{} }

// Name returns the stable identifier for this source.
func (s *Source) Name() string { return "mdns" }

// Config is the typed projection of the operator YAML.
type Config struct {
	ServiceTypes []string
	Interfaces   []string
	ListenWindow time.Duration
	QueryRepeat  int
	DisableIPv6  bool
	DisableIPv4  bool
}

func parseConfig(cfg map[string]any) Config {
	out := Config{
		ServiceTypes: toStringSlice(cfg["service_types"]),
		Interfaces:   toStringSlice(cfg["interfaces"]),
		ListenWindow: defaultListenWin,
		QueryRepeat:  defaultQueryRepeat,
	}
	if len(out.ServiceTypes) == 0 {
		out.ServiceTypes = DefaultServiceTypes
	}
	if s, ok := cfg["listen_window"].(string); ok {
		if d, err := time.ParseDuration(s); err == nil {
			out.ListenWindow = d
		}
	}
	if out.ListenWindow > maxListenWin {
		out.ListenWindow = maxListenWin
	}
	switch r := cfg["query_repeat"].(type) {
	case int:
		out.QueryRepeat = r
	case float64:
		out.QueryRepeat = int(r)
	}
	if out.QueryRepeat < 1 {
		out.QueryRepeat = 1
	}
	if v, ok := cfg["disable_ipv6"].(bool); ok {
		out.DisableIPv6 = v
	}
	if v, ok := cfg["disable_ipv4"].(bool); ok {
		out.DisableIPv4 = v
	}
	return out
}

// responder accumulates everything we observed about a single mDNS responder
// (one host, one network address) before we collapse it into a model.Asset.
type responder struct {
	lastSeen  time.Time
	services  map[string]struct{}
	instances map[string]struct{}
	hostname  string
	addr      net.IP
}

// Discover sends DNS-SD PTR queries on every usable multicast-capable
// interface, accumulates responses for cfg.listen_window, then returns one
// asset per unique responder.
//
// Supported config keys (all optional):
//
//	service_types  []string  override DefaultServiceTypes
//	interfaces     []string  restrict to these interface names
//	listen_window  string    duration to wait for responses (default 3s, max 30s)
//	query_repeat   int       how many times to re-send the query burst (default 2)
//	disable_ipv4   bool      skip IPv4 multicast
//	disable_ipv6   bool      skip IPv6 multicast
func (s *Source) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	parsed := parseConfig(cfg)

	ctx, cancel := context.WithTimeout(ctx, parsed.ListenWindow+2*time.Second)
	defer cancel()

	ifaces, err := pickInterfaces(parsed.Interfaces)
	if err != nil {
		return nil, fmt.Errorf("mdns: select interfaces: %w", err)
	}
	if len(ifaces) == 0 {
		slog.Info("mDNS no multicast-capable interfaces selected; discovery skipped",
			"code", string(LogCodeMDNSNoInterfaces))
		return nil, nil
	}

	var (
		mu         sync.Mutex
		responders = map[string]*responder{}
		wg         sync.WaitGroup
	)

	record := func(r dnsmessage.Resource, src net.IP) {
		mu.Lock()
		defer mu.Unlock()
		if len(responders) >= maxRespondersCap {
			return
		}
		key := src.String()
		resp, ok := responders[key]
		if !ok {
			resp = &responder{
				addr:      src,
				services:  map[string]struct{}{},
				instances: map[string]struct{}{},
				lastSeen:  time.Now().UTC(),
			}
			responders[key] = resp
		}
		resp.lastSeen = time.Now().UTC()
		absorbRecord(resp, r)
	}

	for _, iface := range ifaces {
		// IPv4 leg.
		if !parsed.DisableIPv4 {
			conn4, err := listenMulticast(iface, mdnsIPv4)
			if err != nil {
				slog.Debug("mDNS IPv4 multicast listen failed on interface; skipping leg",
					"code", string(LogCodeMDNSIPv4ListenFail),
					"iface", iface.Name,
					"error", err)
			} else {
				wg.Add(1)
				go func(c *net.UDPConn) {
					defer wg.Done()
					defer func() { _ = c.Close() }()
					readLoop(ctx, c, record)
				}(conn4)
			}
		}
		// IPv6 leg.
		if !parsed.DisableIPv6 {
			conn6, err := listenMulticast(iface, mdnsIPv6)
			if err != nil {
				slog.Debug("mDNS IPv6 multicast listen failed on interface; skipping leg",
					"code", string(LogCodeMDNSIPv6ListenFail),
					"iface", iface.Name,
					"error", err)
			} else {
				wg.Add(1)
				go func(c *net.UDPConn) {
					defer wg.Done()
					defer func() { _ = c.Close() }()
					readLoop(ctx, c, record)
				}(conn6)
			}
		}
	}

	// Send the query bursts on every interface we have.
	for i := 0; i < parsed.QueryRepeat; i++ {
		if ctx.Err() != nil {
			break
		}
		sendQueries(ifaces, parsed.ServiceTypes, parsed.DisableIPv4, parsed.DisableIPv6)
		// small back-off so a chatty network has time to reply before the
		// next burst.
		select {
		case <-time.After(250 * time.Millisecond):
		case <-ctx.Done():
		}
	}

	// Wait for the listen window to elapse, then cancel to wake readers.
	select {
	case <-time.After(parsed.ListenWindow):
	case <-ctx.Done():
	}
	cancel()
	wg.Wait()

	return assetsFromResponders(responders), nil
}

// pickInterfaces returns multicast-capable, up-and-running interfaces.
// If wanted is non-empty, only interfaces whose Name appears in wanted are
// returned.
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

// listenMulticast joins the mDNS multicast group on iface and returns a UDP
// connection ready for reading. The returned connection is also writable for
// directed responses.
func listenMulticast(iface net.Interface, group net.IP) (*net.UDPConn, error) {
	udpAddr := &net.UDPAddr{IP: group, Port: mdnsPort}
	conn, err := net.ListenMulticastUDP(networkFor(group), &iface, udpAddr)
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

// sendQueries fires a single PTR query for each service type on every
// interface. Failures are logged at debug and skipped — sending succeeds
// best-effort.
func sendQueries(ifaces []net.Interface, services []string, skipV4, skipV6 bool) {
	for _, ifi := range ifaces {
		if !skipV4 {
			sendQueryOn(ifi, mdnsIPv4, services)
		}
		if !skipV6 {
			sendQueryOn(ifi, mdnsIPv6, services)
		}
	}
}

func sendQueryOn(iface net.Interface, group net.IP, services []string) {
	conn, err := net.ListenUDP(networkFor(group), &net.UDPAddr{IP: nil, Port: 0})
	if err != nil {
		slog.Debug("mDNS sender socket open failed; skipping query burst on interface",
			"code", string(LogCodeMDNSOpenSenderFail),
			"iface", iface.Name,
			"error", err)
		return
	}
	defer func() { _ = conn.Close() }()

	payload, err := buildQuery(services)
	if err != nil {
		slog.Warn("mDNS DNS-message build for service-type query failed",
			"code", string(LogCodeMDNSBuildQueryFail),
			"error", err,
			"service_count", len(services))
		return
	}

	dst := &net.UDPAddr{IP: group, Port: mdnsPort}
	if _, err := conn.WriteTo(payload, dst); err != nil {
		slog.Debug("mDNS query write to multicast group failed",
			"code", string(LogCodeMDNSSendFail),
			"iface", iface.Name,
			"group", group.String(),
			"error", err)
	}
}

// buildQuery encodes a single DNS message containing one PTR question per
// service type. RFC 6762 §5.4 permits multiple questions in one mDNS query.
func buildQuery(services []string) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               0, // mDNS responses are unsolicited; ID is ignored
		Response:         false,
		RecursionDesired: false,
		Truncated:        false,
		Authoritative:    false,
		OpCode:           0,
		RCode:            dnsmessage.RCodeSuccess,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, fmt.Errorf("start questions: %w", err)
	}
	for _, svc := range services {
		name, err := dnsmessage.NewName(svc)
		if err != nil {
			return nil, fmt.Errorf("invalid service %q: %w", svc, err)
		}
		// QM (Question Multicast) — top bit of class left clear; RFC 6762 §5.2.
		// PTR query gets us instance names back.
		if err := b.Question(dnsmessage.Question{
			Name:  name,
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
		}); err != nil {
			return nil, fmt.Errorf("encode question %q: %w", svc, err)
		}
	}
	raw, err := b.Finish()
	if err != nil {
		return nil, fmt.Errorf("finish dns message: %w", err)
	}
	return raw, nil
}

// readLoop reads packets until ctx is done, parses them, and pushes records
// into the recorder. Unparseable packets are silently dropped.
func readLoop(ctx context.Context, conn *net.UDPConn, record func(dnsmessage.Resource, net.IP)) {
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
		var srcIP net.IP
		if src != nil {
			srcIP = src.IP
		}
		records, perr := parseMessage(buf[:n])
		if perr != nil {
			continue
		}
		for _, r := range records {
			record(r, srcIP)
		}
	}
}

// parseMessage decodes a single mDNS message and returns Answers + Additionals.
// Authorities are ignored. Returns an error if header parsing fails.
func parseMessage(raw []byte) ([]dnsmessage.Resource, error) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(raw); err != nil {
		return nil, fmt.Errorf("dns parser start: %w", err)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, fmt.Errorf("skip questions: %w", err)
	}
	var out []dnsmessage.Resource
	for {
		r, err := parser.Answer()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			// Partial parse — keep what we collected; the rest of the
			// section is malformed but earlier records are still valid
			// inventory signal. mDNS packets in the wild are messy.
			return out, nil //nolint:nilerr // intentional partial-parse
		}
		out = append(out, r)
	}
	_ = parser.SkipAllAuthorities()
	for {
		r, err := parser.Additional()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return out, nil //nolint:nilerr // intentional partial-parse
		}
		out = append(out, r)
	}
	return out, nil
}

// absorbRecord extracts the useful bits from one resource record into the
// per-responder accumulator.
func absorbRecord(r *responder, rr dnsmessage.Resource) {
	name := strings.TrimSuffix(rr.Header.Name.String(), ".")
	switch body := rr.Body.(type) {
	case *dnsmessage.PTRResource:
		target := strings.TrimSuffix(body.PTR.String(), ".")
		if isServiceMeta(name) {
			r.services[target] = struct{}{}
		} else {
			r.instances[target] = struct{}{}
			r.services[stripInstance(target)] = struct{}{}
		}
	case *dnsmessage.SRVResource:
		host := strings.TrimSuffix(body.Target.String(), ".")
		if host != "" && r.hostname == "" {
			r.hostname = host
		}
	case *dnsmessage.AResource:
		if r.addr == nil {
			r.addr = net.IP(body.A[:])
		}
	case *dnsmessage.AAAAResource:
		if r.addr == nil {
			r.addr = net.IP(body.AAAA[:])
		}
	default:
		_ = name
	}
}

// isServiceMeta reports whether name is the DNS-SD meta-query target
// "_services._dns-sd._udp.local"; entries pointing to this name are
// service-type announcements rather than concrete instances.
func isServiceMeta(name string) bool {
	return name == "_services._dns-sd._udp.local"
}

// stripInstance turns "Living Room._airplay._tcp.local" into
// "_airplay._tcp.local". Best-effort: returns the input unchanged when the
// name doesn't look like a DNS-SD instance.
func stripInstance(instance string) string {
	parts := strings.SplitN(instance, ".", 2)
	if len(parts) != 2 {
		return instance
	}
	rest := parts[1]
	if strings.HasPrefix(rest, "_") {
		return rest
	}
	return instance
}

// assetsFromResponders collapses the per-source accumulator map into a
// deterministic list of model.Asset values.
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
			hostname = r.addr.String()
		}
		atype := classify(r.services)
		a := model.Asset{
			AssetType:       atype,
			Hostname:        hostname,
			DiscoverySource: "mdns",
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

// classify maps observed service types to an AssetType using a simple
// precedence ladder. Printers and IoT win over generic web/SSH.
func classify(services map[string]struct{}) model.AssetType {
	has := func(s string) bool { _, ok := services[s]; return ok }
	switch {
	case has("_ipp._tcp.local") || has("_printer._tcp.local") ||
		has("_pdl-datastream._tcp.local"):
		return model.AssetTypeAppliance
	case has("_airplay._tcp.local") || has("_googlecast._tcp.local") ||
		has("_homekit._tcp.local") || has("_hap._tcp.local") ||
		has("_raop._tcp.local"):
		return model.AssetTypeIOTDevice
	case has("_workstation._tcp.local"):
		return model.AssetTypeWorkstation
	case has("_ssh._tcp.local") || has("_smb._tcp.local") ||
		has("_http._tcp.local"):
		return model.AssetTypeServer
	default:
		return model.AssetTypeIOTDevice
	}
}

// buildTags returns a small JSON object recording the observed services and
// instance names so downstream queries can answer "what is this device".
func buildTags(r *responder) string {
	svcs := mapKeys(r.services)
	inst := mapKeys(r.instances)
	sort.Strings(svcs)
	sort.Strings(inst)
	var sb strings.Builder
	sb.WriteString(`{"mdns_services":[`)
	for i, s := range svcs {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('"')
		sb.WriteString(jsonEscape(s))
		sb.WriteByte('"')
	}
	sb.WriteString(`],"mdns_instances":[`)
	for i, s := range inst {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('"')
		sb.WriteString(jsonEscape(s))
		sb.WriteByte('"')
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// jsonEscape escapes only the characters that would break a JSON string
// literal — sufficient for hostnames and DNS labels which never contain
// control characters in practice.
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
