// Package netbios implements a NetBIOS Name Service (RFC 1002) discovery
// source. It sends NBSTAT (Node Status Request) queries to the local IPv4
// broadcast address of each non-loopback interface — or to operator-supplied
// targets — and parses the responses for machine name, workgroup/domain,
// and the 16-byte service suffixes that identify the role each host plays
// (file server, browser master, domain controller, etc.).
//
// NetBIOS is a CWE-319 / CWE-200 surface in its own right: legacy Windows
// hosts and unconfigured Sambas leak identity over cleartext UDP without
// authentication. Surfacing what answers NBSTAT is therefore both an
// inventory signal and a security signal.
package netbios

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	nbnsPort         = 137
	defaultListenWin = 3 * time.Second
	maxListenWin     = 30 * time.Second
	maxPacketSize    = 1500
	maxRespondersCap = 4096

	qtypeNBSTAT = 0x0021
	qclassIN    = 0x0001
)

// Source implements discovery.Source over NetBIOS NBSTAT.
type Source struct{}

// New returns a new NetBIOS discovery source.
func New() *Source { return &Source{} }

// Name returns the stable identifier for this source.
func (s *Source) Name() string { return "netbios" }

// Config is the typed projection of operator YAML.
type Config struct {
	Targets      []string // optional explicit unicast targets (IPs)
	Interfaces   []string // restrict broadcast to these interfaces
	ListenWindow time.Duration
	NoBroadcast  bool // when true, only the explicit Targets list is probed
}

func parseConfig(cfg map[string]any) Config {
	out := Config{
		Targets:      toStringSlice(cfg["targets"]),
		Interfaces:   toStringSlice(cfg["interfaces"]),
		ListenWindow: defaultListenWin,
	}
	if s, ok := cfg["listen_window"].(string); ok {
		if d, err := time.ParseDuration(s); err == nil {
			out.ListenWindow = d
		}
	}
	if out.ListenWindow > maxListenWin {
		out.ListenWindow = maxListenWin
	}
	if v, ok := cfg["no_broadcast"].(bool); ok {
		out.NoBroadcast = v
	}
	return out
}

// responder accumulates one host. Multiple NBSTAT entries with the same
// machine name + different service suffixes collapse into one asset.
type responder struct {
	lastSeen  time.Time
	machine   string
	workgroup string
	mac       string
	addr      net.IP
	services  []string
}

// Discover sends NBSTAT to the broadcast address of each chosen interface
// (plus any explicit Targets) and emits one asset per responder.
//
// Supported config keys (all optional):
//
//	targets       []string  unicast IPs to probe in addition to broadcast
//	interfaces    []string  restrict broadcast to these iface names
//	listen_window string    response window (default 3s, max 30s)
//	no_broadcast  bool      probe only `targets`; never broadcast
func (s *Source) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	parsed := parseConfig(cfg)

	ctx, cancel := context.WithTimeout(ctx, parsed.ListenWindow+2*time.Second)
	defer cancel()

	dests, err := buildDestinations(parsed)
	if err != nil {
		return nil, fmt.Errorf("netbios: build destinations: %w", err)
	}
	if len(dests) == 0 {
		slog.Info("NetBIOS no broadcast/explicit targets resolved; discovery skipped",
			"code", string(LogCodeNetBIOSNoTargets))
		return nil, nil
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("netbios: open socket: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if err := enableBroadcast(conn); err != nil {
		// Non-fatal: unicast targets still work.
		slog.Debug("NetBIOS SO_BROADCAST sockopt failed; broadcast targets degraded but unicast still works",
			"code", string(LogCodeNetBIOSSOBroadcastFail),
			"error", err)
	}

	var (
		mu         sync.Mutex
		responders = map[string]*responder{}
		wg         sync.WaitGroup
	)

	record := func(r responder) {
		mu.Lock()
		defer mu.Unlock()
		if len(responders) >= maxRespondersCap {
			return
		}
		key := r.addr.String()
		responders[key] = &r
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		readLoop(ctx, conn, record)
	}()

	payload := buildNBSTATQuery(0x4242)
	for _, dst := range dests {
		if _, err := conn.WriteTo(payload, &net.UDPAddr{IP: dst, Port: nbnsPort}); err != nil {
			slog.Debug("NetBIOS NBSTAT query write to destination failed",
				"code", string(LogCodeNetBIOSSendFailed),
				"dst", dst.String(),
				"error", err)
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

// buildDestinations returns the list of IPs to send NBSTAT to: subnet
// broadcasts for every multicast/broadcast-capable IPv4 interface, plus
// any explicit Targets.
func buildDestinations(cfg Config) ([]net.IP, error) {
	var out []net.IP
	seen := map[string]struct{}{}
	add := func(ip net.IP) {
		key := ip.String()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, ip)
	}

	for _, t := range cfg.Targets {
		if ip := net.ParseIP(t); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				add(v4)
			}
		}
	}
	if cfg.NoBroadcast {
		return out, nil
	}

	want := map[string]struct{}{}
	for _, n := range cfg.Interfaces {
		want[n] = struct{}{}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return out, fmt.Errorf("enumerate interfaces: %w", err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 ||
			ifi.Flags&net.FlagBroadcast == 0 ||
			ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(want) > 0 {
			if _, ok := want[ifi.Name]; !ok {
				continue
			}
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipNet.IP.To4()
			if v4 == nil {
				continue
			}
			add(subnetBroadcast(v4, ipNet.Mask))
		}
	}
	return out, nil
}

// subnetBroadcast returns the broadcast address of a /N IPv4 subnet.
func subnetBroadcast(ip net.IP, mask net.IPMask) net.IP {
	v4 := ip.To4()
	if v4 == nil || len(mask) != net.IPv4len {
		return net.IPv4bcast
	}
	out := make(net.IP, net.IPv4len)
	for i := 0; i < net.IPv4len; i++ {
		out[i] = v4[i] | ^mask[i]
	}
	return out
}

// enableBroadcast sets SO_BROADCAST so writes to subnet broadcast addresses
// are not silently dropped by the kernel. The platform-specific syscall fd
// conversion lives in netbios_broadcast_{unix,windows}.go.
func enableBroadcast(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw conn: %w", err)
	}
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		sockErr = setBroadcastOpt(fd)
	})
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	if sockErr != nil {
		// setBroadcastOpt already wraps with its own context.
		return sockErr
	}
	return nil
}

// readLoop drains UDP, parses each datagram, pushes to the recorder.
func readLoop(ctx context.Context, conn *net.UDPConn, record func(responder)) {
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
		r, perr := parseNBSTAT(buf[:n], src.IP)
		if perr != nil {
			continue
		}
		record(r)
	}
}

// buildNBSTATQuery returns a 50-byte NBSTAT (Node Status Request) datagram.
//
// Header (12 bytes):
//
//	xid (2) | flags (2: query, opcode=0, no rec) | qd=1 (2) | an=0 (2) | ns=0 (2) | ar=0 (2)
//
// Question (38 bytes):
//
//	encoded "*" (34) | qtype NBSTAT (2) | qclass IN (2)
func buildNBSTATQuery(xid uint16) []byte {
	out := make([]byte, 0, 50)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:], xid)
	binary.BigEndian.PutUint16(hdr[2:], 0x0000) // query, opcode 0
	binary.BigEndian.PutUint16(hdr[4:], 1)      // qdcount
	binary.BigEndian.PutUint16(hdr[6:], 0)      // ancount
	binary.BigEndian.PutUint16(hdr[8:], 0)      // nscount
	binary.BigEndian.PutUint16(hdr[10:], 0)     // arcount
	out = append(out, hdr...)

	// Encode the wildcard "*" name padded to 16 bytes.
	var name [16]byte
	name[0] = '*'
	out = append(out, encodeNetBIOSName(name[:])...)

	// Question trailer: qtype (NBSTAT), qclass (IN).
	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:], qtypeNBSTAT)
	binary.BigEndian.PutUint16(tail[2:], qclassIN)
	out = append(out, tail...)
	return out
}

// encodeNetBIOSName performs the RFC 1001 level-1 encoding: each 16-byte
// raw NetBIOS name becomes 32 bytes where each nibble is mapped to an ASCII
// letter (0x4N where N is the nibble). The result is wrapped with a leading
// length byte (0x20 = 32) and a trailing 0x00 to terminate the label.
func encodeNetBIOSName(raw []byte) []byte {
	if len(raw) != 16 {
		// Pad or truncate to 16 — callers should already pass 16.
		fixed := make([]byte, 16)
		copy(fixed, raw)
		raw = fixed
	}
	out := make([]byte, 0, 34)
	out = append(out, 0x20)
	for _, b := range raw {
		out = append(out, 0x41+(b>>4))
		out = append(out, 0x41+(b&0x0F))
	}
	out = append(out, 0x00)
	return out
}

// decodeNetBIOSName reverses encodeNetBIOSName starting at offset off in
// raw. Returns the 16-byte raw name and the number of bytes consumed
// (including the leading length byte and trailing null).
func decodeNetBIOSName(raw []byte, off int) ([16]byte, int, error) {
	var out [16]byte
	if off+34 > len(raw) {
		return out, 0, errors.New("name truncated")
	}
	if raw[off] != 0x20 {
		return out, 0, fmt.Errorf("unexpected name length byte 0x%02x", raw[off])
	}
	body := raw[off+1 : off+33]
	for i := 0; i < 16; i++ {
		hi := body[2*i]
		lo := body[2*i+1]
		if hi < 0x41 || hi > 0x50 || lo < 0x41 || lo > 0x50 {
			return out, 0, fmt.Errorf("name contains non-encoded byte at %d", i)
		}
		out[i] = ((hi - 0x41) << 4) | (lo - 0x41)
	}
	if raw[off+33] != 0x00 {
		return out, 0, errors.New("missing name terminator")
	}
	return out, 34, nil
}

// parseNBSTAT walks an NBSTAT response and extracts the machine name,
// workgroup/domain, MAC address, and observed service suffixes.
func parseNBSTAT(raw []byte, src net.IP) (responder, error) {
	if len(raw) < 12 {
		return responder{}, errors.New("short header")
	}
	flags := binary.BigEndian.Uint16(raw[2:4])
	if flags&0x8000 == 0 {
		return responder{}, errors.New("not a response")
	}
	anCount := binary.BigEndian.Uint16(raw[6:8])
	if anCount == 0 {
		return responder{}, errors.New("no answer")
	}

	// Skip the question section if any (qdcount). NBSTAT responses sometimes
	// echo the question.
	off := 12
	qdCount := binary.BigEndian.Uint16(raw[4:6])
	for i := uint16(0); i < qdCount; i++ {
		_, n, err := decodeNetBIOSName(raw, off)
		if err != nil {
			return responder{}, err
		}
		off += n
		if off+4 > len(raw) {
			return responder{}, errors.New("short question trailer")
		}
		off += 4 // qtype + qclass
	}

	// Answer: name (34) | type (2) | class (2) | ttl (4) | rdlength (2) | rdata
	_, n, err := decodeNetBIOSName(raw, off)
	if err != nil {
		return responder{}, fmt.Errorf("answer name: %w", err)
	}
	off += n
	if off+10 > len(raw) {
		return responder{}, errors.New("short answer header")
	}
	rdLength := int(binary.BigEndian.Uint16(raw[off+8 : off+10]))
	off += 10
	if off+rdLength > len(raw) {
		return responder{}, errors.New("short rdata")
	}
	rdata := raw[off : off+rdLength]

	r := responder{addr: src, lastSeen: time.Now().UTC()}
	if err := parseNBSTATRData(&r, rdata); err != nil {
		return responder{}, err
	}
	return r, nil
}

// parseNBSTATRData walks the NBSTAT answer RDATA: one byte for num names,
// then N × (16-byte name + 2 bytes flags), then statistics starting with
// the 6-byte MAC.
func parseNBSTATRData(r *responder, rdata []byte) error {
	if len(rdata) < 1 {
		return errors.New("empty rdata")
	}
	numNames := int(rdata[0])
	off := 1
	need := numNames * 18
	if off+need+6 > len(rdata) {
		return errors.New("rdata truncated")
	}
	for i := 0; i < numNames; i++ {
		nameBytes := rdata[off : off+16]
		flags := binary.BigEndian.Uint16(rdata[off+16 : off+18])
		off += 18
		role := strings.TrimRight(string(nameBytes[:15]), " \x00")
		suffix := nameBytes[15]
		isGroup := flags&0x8000 != 0

		switch suffix {
		case 0x00:
			// Workstation/Redirector. The unique entry is the machine name;
			// the group entry is the workgroup/domain.
			if isGroup {
				r.workgroup = role
			} else if r.machine == "" {
				r.machine = role
			}
		case 0x1b:
			// Domain master browser (unique) — also reveals the domain.
			if r.workgroup == "" {
				r.workgroup = role
			}
		case 0x1c, 0x1d, 0x1e:
			// 0x1c domain group / 0x1d local master browser /
			// 0x1e browser election — all reveal the workgroup/domain.
			if isGroup && r.workgroup == "" {
				r.workgroup = role
			}
		case 0x20:
			// File server — useful service signal.
		}
		r.services = appendUnique(r.services, fmt.Sprintf("%s<%02x>", role, suffix))
	}

	// Stats begin at off — first 6 bytes are the MAC.
	mac := rdata[off : off+6]
	r.mac = formatMAC(mac)
	return nil
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func formatMAC(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02x", x)
	}
	return sb.String()
}

// assetsFromResponders flattens the per-host map into a deterministic
// asset list, classifying based on observed NetBIOS service suffixes.
func assetsFromResponders(in map[string]*responder) []model.Asset {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]model.Asset, 0, len(keys))
	for _, k := range keys {
		r := in[k]
		hostname := r.machine
		if hostname == "" {
			hostname = r.addr.String()
		}
		a := model.Asset{
			AssetType:       classify(r.services),
			Hostname:        hostname,
			DiscoverySource: "netbios",
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

// classify maps observed NetBIOS service suffixes to an AssetType.
// 0x1b/0x1c → domain controller-ish, treat as server; 0x20 → file server;
// otherwise the host is a workstation by default for NBNS.
func classify(services []string) model.AssetType {
	for _, s := range services {
		ls := strings.ToLower(s)
		switch {
		case strings.HasSuffix(ls, "<1b>") || strings.HasSuffix(ls, "<1c>"):
			return model.AssetTypeServer
		case strings.HasSuffix(ls, "<20>"):
			return model.AssetTypeServer
		}
	}
	return model.AssetTypeWorkstation
}

func buildTags(r *responder) string {
	services := append([]string(nil), r.services...)
	sort.Strings(services)
	var sb strings.Builder
	sb.WriteString(`{"nbns_machine":"`)
	sb.WriteString(jsonEscape(r.machine))
	sb.WriteString(`","nbns_workgroup":"`)
	sb.WriteString(jsonEscape(r.workgroup))
	sb.WriteString(`","nbns_mac":"`)
	sb.WriteString(jsonEscape(r.mac))
	sb.WriteString(`","nbns_services":[`)
	for i, s := range services {
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
