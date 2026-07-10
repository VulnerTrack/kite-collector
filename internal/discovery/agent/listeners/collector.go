package listeners

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	gopsnet "github.com/shirou/gopsutil/v4/net"
	gopsproc "github.com/shirou/gopsutil/v4/process"
)

// connSource is the test seam: gopsutil's `net.Connections(kind)` plus a
// per-process name lookup. Production wraps the real gopsutil calls.
type connSource interface {
	// Connections returns LISTEN-state TCP/UDP sockets.
	Connections(ctx context.Context, kind string) ([]Conn, error)
	// ProcessName returns the executable name + path + username for pid,
	// returning empty strings when the process can't be resolved (already
	// exited, EACCES, etc).
	ProcessName(ctx context.Context, pid int32) (name, exe, user string)
}

// Conn is the projected subset of gopsutil's ConnectionStat we consume.
// Decoupling lets tests construct fixtures without importing gopsutil.
type Conn struct {
	Status    string
	LocalIP   string
	Family    uint32
	Type      uint32
	PID       int32
	LocalPort uint16
}

type gopsutilCollector struct {
	src connSource
}

// NewCollector returns a production Collector backed by gopsutil/v4/net.
func NewCollector() Collector {
	return &gopsutilCollector{src: realSource{}}
}

func (gopsutilCollector) Name() string { return "gopsutil-net" }

// Collect enumerates LISTEN sockets across TCP and UDP (v4 + v6). For UDP
// we include every bound socket — UDP is connectionless so there is no
// formal LISTEN state, but a bound socket is exposed the same way.
func (c *gopsutilCollector) Collect(ctx context.Context) ([]Listener, error) {
	// "tcp" returns both v4 and v6; "udp" likewise. One call per protocol
	// family minimises syscall overhead vs four separate calls.
	conns, err := c.src.Connections(ctx, "tcp")
	if err != nil {
		return nil, fmt.Errorf("list tcp connections: %w", err)
	}
	udp, err := c.src.Connections(ctx, "udp")
	if err != nil {
		return nil, fmt.Errorf("list udp connections: %w", err)
	}
	conns = append(conns, udp...)

	out := make([]Listener, 0, len(conns))
	for _, k := range conns {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-collect: %w", err)
		}
		if !isListening(k) {
			continue
		}
		l := Listener{
			Protocol:    classifyProto(k.Family, k.Type),
			BindAddress: k.LocalIP,
			Port:        k.LocalPort,
			Exposure:    ClassifyExposure(k.LocalIP),
			PID:         k.PID,
		}
		if k.PID > 0 {
			l.ProcessName, l.Exe, l.Username = c.src.ProcessName(ctx, k.PID)
		}
		out = append(out, l)
		if len(out) >= MaxListeners {
			slog.Warn("listeners: capping inventory at MaxListeners",
				"code", string(LogCodeCollectorInventoryCapped), "observed_so_far", len(out), "cap", MaxListeners)
			break
		}
	}
	SortListeners(out)
	return out, nil
}

// isListening reports whether a Conn is a LISTEN-state TCP socket or a
// bound UDP socket. gopsutil uses "LISTEN" for tcp and reports udp
// sockets without a Status field (empty string) — both count.
func isListening(k Conn) bool {
	if k.LocalPort == 0 {
		return false
	}
	if isUDP(k.Type) {
		return true // bound UDP = exposed
	}
	return strings.EqualFold(k.Status, "LISTEN")
}

// classifyProto maps the syscall.AF_INET/AF_INET6 + SOCK_STREAM/SOCK_DGRAM
// pair to our normalised Protocol.
func classifyProto(family, sockType uint32) Protocol {
	const (
		AFInet     = 2
		AFInet6    = 10
		SOCKStream = 1
		SOCKDgram  = 2
	)
	v6 := family == AFInet6
	if sockType == SOCKDgram {
		if v6 {
			return ProtoUDP6
		}
		return ProtoUDP
	}
	// Default to TCP for SOCK_STREAM or anything else we don't recognise.
	if v6 {
		return ProtoTCP6
	}
	return ProtoTCP
}

func isUDP(sockType uint32) bool { return sockType == 2 } // SOCK_DGRAM

// realSource is the production adapter wrapping gopsutil's package-level
// API into the connSource interface.
type realSource struct{}

func (realSource) Connections(ctx context.Context, kind string) ([]Conn, error) {
	cs, err := gopsnet.ConnectionsWithContext(ctx, kind)
	if err != nil {
		return nil, fmt.Errorf("gopsutil connections(%q): %w", kind, err)
	}
	out := make([]Conn, 0, len(cs))
	for _, c := range cs {
		out = append(out, Conn{
			Family:    c.Family,
			Type:      c.Type,
			Status:    c.Status,
			LocalIP:   c.Laddr.IP,
			LocalPort: uint16(c.Laddr.Port), //#nosec G115 -- gopsutil returns int32; ports bounded to 0-65535 by kernel
			PID:       c.Pid,
		})
	}
	return out, nil
}

func (realSource) ProcessName(ctx context.Context, pid int32) (string, string, string) {
	p, err := gopsproc.NewProcessWithContext(ctx, pid)
	if err != nil {
		return "", "", ""
	}
	name, _ := p.NameWithContext(ctx)
	exe, _ := p.ExeWithContext(ctx)
	user, _ := p.UsernameWithContext(ctx)
	return name, exe, user
}
