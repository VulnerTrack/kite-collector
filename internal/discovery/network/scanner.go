package network

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	defaultTimeout     = 2 * time.Second
	defaultMaxConcurr  = 256
	defaultTCPPortsStr = "22,80,443"
)

// Scanner implements discovery.Source by performing TCP connect scans against
// configured CIDR ranges. It is pure-Go and requires no CGO or external
// binaries like nmap.
type Scanner struct{}

// New returns a new network Scanner.
func New() *Scanner {
	return &Scanner{}
}

// Name returns the stable identifier for this source.
func (s *Scanner) Name() string { return "network" }

// Discover scans the CIDR ranges specified in cfg["scope"] ([]any of strings)
// and probes each IP against tcp_ports. Assets are created for any IP that
// responds on at least one port.
//
// Supported config keys:
//
//	scope          – []any of CIDR strings (e.g. ["192.168.1.0/24"])
//	tcp_ports      – []any of float64 port numbers
//	timeout        – string duration for TCP dial (default "2s")
//	max_concurrent – float64 concurrency limit (default 256)
func (s *Scanner) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	cidrs := toStringSlice(cfg["scope"])
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("network scanner: scope is required")
	}

	ports := toIntSlice(cfg["tcp_ports"])
	if len(ports) == 0 {
		ports = []int{22, 80, 443}
	}

	timeout := defaultTimeout
	if ts, ok := cfg["timeout"].(string); ok {
		if d, err := time.ParseDuration(ts); err == nil {
			timeout = d
		}
	}

	maxConc := defaultMaxConcurr
	if mc, ok := cfg["max_concurrent"].(float64); ok && int(mc) > 0 {
		maxConc = int(mc)
	}

	// Collect all IPs from all CIDR ranges.
	var ips []netip.Addr
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			slog.Warn("network scanner: skipping invalid CIDR",
				"cidr", cidr, "error", err)
			continue
		}
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			// Skip network and broadcast addresses for IPv4 /31 and larger.
			if prefix.Bits() < 31 && (addr == prefix.Addr() || addr == broadcastAddr(prefix)) {
				continue
			}
			ips = append(ips, addr)
		}
	}

	if len(ips) == 0 {
		return nil, nil
	}

	slog.Info("network scanner: starting scan",
		"ips", len(ips),
		"ports", ports,
		"max_concurrent", maxConc,
	)

	// Semaphore to limit concurrency.
	sem := make(chan struct{}, maxConc)

	var (
		mu     sync.Mutex
		assets []model.Asset
	)

	var wg sync.WaitGroup

	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{} // acquire semaphore slot

		go func() {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore slot

			openPorts := s.probeIP(ctx, ip, ports, timeout)
			if len(openPorts) == 0 {
				return
			}

			ipStr := ip.String()
			now := time.Now().UTC()

			asset := model.Asset{
				AssetType:       model.AssetTypeServer,
				Hostname:        ipStr,
				DiscoverySource: "network_scan",
				FirstSeenAt:     now,
				LastSeenAt:      now,
				IsAuthorized:    model.AuthorizationUnknown,
				IsManaged:       model.ManagedUnknown,
			}

			mu.Lock()
			assets = append(assets, asset)
			mu.Unlock()
		}()
	}

	wg.Wait()

	return assets, nil
}

// probeIP attempts to TCP-connect to each port on the given IP. It returns
// the list of ports that responded successfully.
func (s *Scanner) probeIP(ctx context.Context, ip netip.Addr, ports []int, timeout time.Duration) []int {
	var open []int
	for _, port := range ports {
		if ctx.Err() != nil {
			return open
		}
		addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}
		_ = conn.Close()
		open = append(open, port)
	}
	return open
}

// broadcastAddr returns the broadcast address for the given IPv4 prefix.
func broadcastAddr(p netip.Prefix) netip.Addr {
	addr := p.Addr()
	if !addr.Is4() {
		return addr // broadcast concept doesn't apply to IPv6 the same way
	}
	a4 := addr.As4()
	bits := p.Bits()
	// Set all host bits to 1.
	for i := bits; i < 32; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		a4[byteIdx] |= 1 << uint(bitIdx)
	}
	return netip.AddrFrom4(a4)
}

// toStringSlice converts an any value (expected []any of strings) to []string.
func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	// Handle []string directly.
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

// toIntSlice converts an any value (expected []any of float64) to []int.
func toIntSlice(v any) []int {
	if v == nil {
		return nil
	}
	// Handle []int directly.
	if ii, ok := v.([]int); ok {
		return ii
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]int, 0, len(arr))
	for _, item := range arr {
		switch n := item.(type) {
		case float64:
			out = append(out, int(n))
		case int:
			out = append(out, n)
		}
	}
	return out
}

// ensure Scanner satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*Scanner)(nil)

// NewNetworkInterfaces creates NetworkInterface entries for a discovered IP.
// This is a helper for callers that need to persist interface data alongside
// the asset.
func NewNetworkInterfaces(assetID uuid.UUID, ipAddr string) []model.NetworkInterface {
	return []model.NetworkInterface{
		{
			ID:            uuid.Must(uuid.NewV7()),
			AssetID:       assetID,
			InterfaceName: "eth0",
			IPAddress:     ipAddr,
			IsPrimary:     true,
		},
	}
}
