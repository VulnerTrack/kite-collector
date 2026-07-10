package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

const (
	defaultTimeout      = 2 * time.Second
	defaultMaxConcurr   = 256
	defaultScanDeadline = 30 * time.Minute
)

// EventSink is the narrow contract through which the scanner persists
// scan-event and guard-event audit records. The store package implements
// this interface; tests can use a fake. The scanner deliberately does not
// import the store package to avoid a circular dependency and to keep the
// scanner unit-testable without SQLite.
type EventSink interface {
	WriteScanEvent(ctx context.Context, ev ScanEvent) error
	WriteOpenPorts(ctx context.Context, scanID string, ports []OpenPort) error
	WriteGuardEvent(ctx context.Context, ev safenet.GuardEvent) error
}

// ScanEvent is the durable record of a single Discover() invocation. It
// mirrors the SQLite network_scan_events row shape so the store layer can
// persist it without an extra translation step.
type ScanEvent struct {
	StartedAt        time.Time
	CompletedAt      *time.Time
	ScanID           string
	AgentID          string
	ScopeHash        string
	PortsProbedJSON  string
	Outcome          string
	IPsEnumerated    int
	IPsScanned       int
	IPsResponsive    int
	SafetyGuardCount int
}

// OpenPort is a single observation of an open TCP port emitted alongside a
// ScanEvent. ProbeAt is the wall-clock UTC time the connect succeeded.
type OpenPort struct {
	ProbeAt   time.Time
	IPAddress string
	Protocol  string
	Port      int
}

// Scanner implements discovery.Source by performing TCP connect scans
// against configured CIDR ranges. It is pure-Go and requires no CGO or
// external binaries like nmap.
type Scanner struct {
	sink    EventSink
	agentID string
}

// New returns a network Scanner with no audit sink. This is the constructor
// used by tooling and tests that do not exercise the full agent stack.
func New() *Scanner { return &Scanner{} }

// NewWithSink returns a Scanner that writes ScanEvent / OpenPort / GuardEvent
// records to sink. agentID is stamped into every ScanEvent for traceability;
// the empty string is acceptable for tooling but production callers should
// supply the agent's UUID.
func NewWithSink(sink EventSink, agentID string) *Scanner {
	return &Scanner{sink: sink, agentID: agentID}
}

// Name returns the stable identifier for this source.
func (s *Scanner) Name() string { return "network" }

// ScannerConfig is the typed projection of the operator-supplied YAML map.
// It exists so that all guard checks (R1, R2, R3, R4 from RFC-0124) run on a
// validated structure before any IP enumeration begins.
type ScannerConfig struct {
	Scope          []string
	TCPPorts       []int
	Timeout        time.Duration
	MaxConcurrent  int
	ScanTimeout    time.Duration
	AllowLinkLocal bool
}

// parseScannerConfig translates the loose YAML map into a ScannerConfig.
// It applies defaults but does not validate; that happens in Validate().
func parseScannerConfig(cfg map[string]any) ScannerConfig {
	out := ScannerConfig{
		Scope:         toStringSlice(cfg["scope"]),
		TCPPorts:      toIntSlice(cfg["tcp_ports"]),
		Timeout:       defaultTimeout,
		MaxConcurrent: defaultMaxConcurr,
		ScanTimeout:   defaultScanDeadline,
	}
	if len(out.TCPPorts) == 0 {
		out.TCPPorts = []int{22, 80, 443}
	}
	if ts, ok := cfg["timeout"].(string); ok {
		if d, err := time.ParseDuration(ts); err == nil {
			out.Timeout = d
		}
	}
	switch mc := cfg["max_concurrent"].(type) {
	case float64:
		out.MaxConcurrent = int(mc)
	case int:
		out.MaxConcurrent = mc
	}
	if sd, ok := cfg["scan_timeout"].(string); ok {
		if d, err := time.ParseDuration(sd); err == nil {
			out.ScanTimeout = d
		}
	}
	switch al := cfg["allow_link_local"].(type) {
	case bool:
		out.AllowLinkLocal = al
	case string:
		out.AllowLinkLocal = al == "true"
	}
	if !out.AllowLinkLocal && safenet.AllowLinkLocalFromEnv() {
		out.AllowLinkLocal = true
	}
	return out
}

// validateAndClamp enforces R1–R4. It returns the validated config and the
// total IP count (R1) on success. Guard events for clamping/rejection are
// emitted via sink when one is configured.
func (s *Scanner) validateAndClamp(ctx context.Context, c *ScannerConfig) (int, []safenet.GuardEvent, error) {
	var events []safenet.GuardEvent

	if err := safenet.ValidatePorts(c.TCPPorts, 0); err != nil {
		ev := safenet.NewGuardEvent(
			safenet.GuardPortRangeViolation,
			safenet.GuardActionRejected,
			"internal/discovery/network",
			fmt.Sprintf("ports=%v", c.TCPPorts),
			"{}",
		)
		events = append(events, ev)
		return 0, events, fmt.Errorf("validate ports: %w", err)
	}

	scopeGuard := &safenet.NetworkScopeGuard{
		MaxIPs:         safenet.MaxScanIPsFromEnv(),
		BlockLinkLocal: !c.AllowLinkLocal,
	}
	total, err := scopeGuard.Validate(c.Scope)
	if err != nil {
		gt := safenet.GuardIPCountCap
		summary := fmt.Sprintf("scope=%v cap=%d", c.Scope, scopeGuard.MaxIPs)
		if !c.AllowLinkLocal && strings.Contains(err.Error(), "link-local") {
			gt = safenet.GuardSSRFScopeBlock
		}
		ev := safenet.NewGuardEvent(
			gt,
			safenet.GuardActionRejected,
			"internal/discovery/network",
			summary,
			"{}",
		)
		events = append(events, ev)
		return total, events, fmt.Errorf("validate scope: %w", err)
	}

	clamped := safenet.ClampConcurrency(c.MaxConcurrent)
	if clamped != c.MaxConcurrent {
		ev := safenet.NewGuardEvent(
			safenet.GuardConcurrencyCap,
			safenet.GuardActionCapped,
			"internal/discovery/network",
			fmt.Sprintf("requested=%d effective=%d",
				c.MaxConcurrent, clamped),
			"{}",
		)
		events = append(events, ev)
		c.MaxConcurrent = clamped
	}

	return total, events, nil
}

// Discover scans the CIDR ranges specified in cfg["scope"] ([]any of strings)
// and probes each IP against tcp_ports. Assets are created for any IP that
// responds on at least one port.
//
// Supported config keys:
//
//	scope             – []any of CIDR strings (e.g. ["192.168.1.0/24"])
//	tcp_ports         – []any of float64 port numbers
//	timeout           – string duration for TCP dial (default "2s")
//	max_concurrent    – float64 concurrency limit (default 256, capped 512)
//	scan_timeout      – string duration overall deadline (default 30m)
//	allow_link_local  – bool; opt-in to scanning RFC-3927/loopback ranges
func (s *Scanner) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	scanID := uuid.Must(uuid.NewV7()).String()
	startedAt := time.Now().UTC()
	parsed := parseScannerConfig(cfg)

	totalIPs, guardEvents, err := s.validateAndClamp(ctx, &parsed)
	for _, ge := range guardEvents {
		s.recordGuardEvent(ctx, scanID, ge)
	}
	if err != nil {
		s.recordScanEvent(ctx, ScanEvent{
			ScanID:           scanID,
			AgentID:          s.agentID,
			ScopeHash:        scopeHash(parsed),
			StartedAt:        startedAt,
			CompletedAt:      ptrTime(time.Now().UTC()),
			IPsEnumerated:    0,
			Outcome:          outcomeForError(err),
			PortsProbedJSON:  portsJSON(parsed.TCPPorts),
			SafetyGuardCount: len(guardEvents),
		})
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, parsed.ScanTimeout)
	defer cancel()

	ips := enumerateIPs(parsed.Scope)
	if len(ips) == 0 {
		s.recordScanEvent(ctx, ScanEvent{
			ScanID:           scanID,
			AgentID:          s.agentID,
			ScopeHash:        scopeHash(parsed),
			StartedAt:        startedAt,
			CompletedAt:      ptrTime(time.Now().UTC()),
			IPsEnumerated:    totalIPs,
			Outcome:          "completed",
			PortsProbedJSON:  portsJSON(parsed.TCPPorts),
			SafetyGuardCount: len(guardEvents),
		})
		return nil, nil
	}

	slog.Info(
		"network scanner: starting scan",
		"code", string(LogCodeScannerStarting),
		"scan_id", scanID,
		"ips", len(ips),
		"ports", parsed.TCPPorts,
		"max_concurrent", parsed.MaxConcurrent,
	)

	sem := make(chan struct{}, parsed.MaxConcurrent)
	var (
		mu        sync.Mutex
		assets    []model.Asset
		openPorts []OpenPort
		probed    int
	)
	var wg sync.WaitGroup

	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			open := s.probeIP(ctx, ip, parsed.TCPPorts, parsed.Timeout)
			mu.Lock()
			probed++
			if len(open) > 0 {
				now := time.Now().UTC()
				ipStr := ip.String()
				assets = append(assets, model.Asset{
					AssetType:       model.AssetTypeServer,
					Hostname:        ipStr,
					DiscoverySource: "network_scan",
					FirstSeenAt:     now,
					LastSeenAt:      now,
					IsAuthorized:    model.AuthorizationUnknown,
					IsManaged:       model.ManagedUnknown,
				})
				for _, p := range open {
					openPorts = append(openPorts, OpenPort{
						IPAddress: ipStr,
						Port:      p,
						Protocol:  "tcp",
						ProbeAt:   now,
					})
				}
			}
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	completedAt := time.Now().UTC()
	outcome := "completed"
	if ctx.Err() != nil {
		outcome = "aborted"
	}
	scanEvent := ScanEvent{
		ScanID:           scanID,
		AgentID:          s.agentID,
		ScopeHash:        scopeHash(parsed),
		StartedAt:        startedAt,
		CompletedAt:      &completedAt,
		IPsEnumerated:    totalIPs,
		IPsScanned:       probed,
		IPsResponsive:    len(assets),
		PortsProbedJSON:  portsJSON(parsed.TCPPorts),
		Outcome:          outcome,
		SafetyGuardCount: len(guardEvents),
	}
	s.recordScanEvent(ctx, scanEvent)
	s.recordOpenPorts(ctx, scanID, openPorts)

	return assets, nil
}

// recordGuardEvent persists a guard event when a sink is wired. Failures to
// write are logged but never returned: the scanner's primary contract is to
// surface validation errors directly to the caller, not to depend on a
// healthy SQLite for correct rejection behavior.
func (s *Scanner) recordGuardEvent(ctx context.Context, scanID string, ge safenet.GuardEvent) {
	slog.Warn(
		"safety guard fired",
		"code", string(LogCodeScannerSafetyGuardFired),
		"guard_type", string(ge.GuardType),
		"action", string(ge.Action),
		"input_summary", ge.InputSummary,
		"scan_id", scanID,
	)
	if s.sink == nil {
		return
	}
	ge.ScanID = scanID
	if err := s.sink.WriteGuardEvent(ctx, ge); err != nil {
		slog.Error(
			"failed to persist guard event",
			"code", string(LogCodeScannerGuardEventPersistFail),
			"error", err.Error(),
			"guard_type", string(ge.GuardType),
		)
	}
}

func (s *Scanner) recordScanEvent(ctx context.Context, ev ScanEvent) {
	if s.sink == nil {
		return
	}
	if err := s.sink.WriteScanEvent(ctx, ev); err != nil {
		slog.Error(
			"failed to persist scan event",
			"code", string(LogCodeScannerScanEventPersistFail),
			"error", err.Error(),
			"scan_id", ev.ScanID,
		)
	}
}

func (s *Scanner) recordOpenPorts(ctx context.Context, scanID string, ports []OpenPort) {
	if s.sink == nil || len(ports) == 0 {
		return
	}
	if err := s.sink.WriteOpenPorts(ctx, scanID, ports); err != nil {
		slog.Error(
			"failed to persist open ports",
			"code", string(LogCodeScannerOpenPortsPersistFail),
			"error", err.Error(),
			"scan_id", scanID,
			"ports", len(ports),
		)
	}
}

func enumerateIPs(cidrs []string) []netip.Addr {
	var ips []netip.Addr
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			slog.Warn("network scanner: skipping invalid CIDR",
				"code", string(LogCodeScannerInvalidCIDRSkipped),
				"cidr", cidr, "error", err)
			continue
		}
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			if prefix.Bits() < 31 && (addr == prefix.Addr() || addr == broadcastAddr(prefix)) {
				continue
			}
			ips = append(ips, addr)
		}
	}
	return ips
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
		return addr
	}
	a4 := addr.As4()
	bits := p.Bits()
	for i := bits; i < 32; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		a4[byteIdx] |= 1 << uint(bitIdx)
	}
	return netip.AddrFrom4(a4)
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

func toIntSlice(v any) []int {
	if v == nil {
		return nil
	}
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

// scopeHash returns the SHA-256 hex of the canonical-JSON-encoded config.
// Sorted CIDRs and ports keep the hash stable regardless of YAML ordering.
func scopeHash(c ScannerConfig) string {
	cidrs := append([]string(nil), c.Scope...)
	ports := append([]int(nil), c.TCPPorts...)
	sort.Strings(cidrs)
	sort.Ints(ports)
	payload := struct {
		Scope          []string `json:"scope"`
		TCPPorts       []int    `json:"tcp_ports"`
		MaxConcurrent  int      `json:"max_concurrent"`
		ScanTimeoutMS  int64    `json:"scan_timeout_ms"`
		PerIPTimeoutMS int64    `json:"per_ip_timeout_ms"`
		AllowLinkLocal bool     `json:"allow_link_local"`
	}{
		Scope:          cidrs,
		TCPPorts:       ports,
		MaxConcurrent:  c.MaxConcurrent,
		ScanTimeoutMS:  c.ScanTimeout.Milliseconds(),
		PerIPTimeoutMS: c.Timeout.Milliseconds(),
		AllowLinkLocal: c.AllowLinkLocal,
	}
	b, _ := json.Marshal(&payload)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func portsJSON(ports []int) string {
	if len(ports) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(ports)
	return string(b)
}

func outcomeForError(err error) string {
	if err == nil {
		return "completed"
	}
	msg := err.Error()
	if strings.Contains(msg, "scope exceeds maximum") {
		return "capped_ips"
	}
	return "validation_error"
}

func ptrTime(t time.Time) *time.Time { return &t }

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
