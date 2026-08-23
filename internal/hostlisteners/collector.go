// Package hostlisteners wires the (previously unused) gopsutil listeners
// collector into persistence: it enumerates the local host's LISTEN sockets,
// fingerprints each open TCP port to name the service (fingerprintx -sV, on by
// default), and saves the set to host_listeners — replacing the machine's
// previous set so stale sockets don't linger.
//
// This is the zero-config path that makes service fingerprinting "just work"
// for the local host: it needs no scan scope, only the agent knowing its own
// ports.
package hostlisteners

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/listeners"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/servicefp"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// serviceFinger is the slice of servicefp.Fingerprinter the orchestrator needs,
// as an interface so tests can inject a deterministic fake. The concrete
// *servicefp.Fingerprinter satisfies it.
type serviceFinger interface {
	Identify(ctx context.Context, ip netip.Addr, port uint16) (servicefp.Result, bool)
}

// Collector enumerates, fingerprints, and persists the local host's listeners.
type Collector struct {
	store     store.Store
	listeners listeners.Collector
	sink      store.HostListenerStore
	fp        serviceFinger // nil disables fingerprinting
	logger    *slog.Logger
	hostname  string
	now       func() time.Time
}

// New builds a Collector when the store persists host listeners. A nil listener
// collector uses the production gopsutil one; a nil fingerprinter disables
// service fingerprinting (the default wiring passes a real one, so it is on by
// default). Returns (nil, false) for a store without HostListenerStore support.
func New(st store.Store, lc listeners.Collector, fp serviceFinger, logger *slog.Logger) (*Collector, bool) {
	sink, ok := st.(store.HostListenerStore)
	if !ok {
		return nil, false
	}
	if lc == nil {
		lc = listeners.NewCollector()
	}
	if logger == nil {
		logger = slog.Default()
	}
	host, _ := os.Hostname()
	return &Collector{
		store:     st,
		listeners: lc,
		sink:      sink,
		fp:        fp,
		logger:    logger,
		hostname:  strings.TrimSpace(host),
		now:       time.Now,
	}, true
}

// CollectAndStore enumerates the local listeners, fingerprints each open TCP
// port (when enabled), and replaces the machine's host_listeners set. It is a
// quiet no-op before the first scan has written the local machine.
func (c *Collector) CollectAndStore(ctx context.Context) error {
	machineID, ok := c.resolveLocalMachineID(ctx)
	if !ok {
		return nil
	}
	raw, err := c.listeners.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect listeners: %w", err)
	}

	out := make([]model.HostListener, 0, len(raw))
	for _, l := range raw {
		hl := model.HostListener{
			MachineID:   machineID,
			Protocol:    string(l.Protocol),
			BindAddress: l.BindAddress,
			Exposure:    string(l.Exposure),
			ProcessName: l.ProcessName,
			Exe:         l.Exe,
			Username:    l.Username,
			Port:        l.Port,
			PID:         l.PID,
			LastSeenAt:  c.now().UTC(),
			CollectedAt: c.now().UTC(),
		}
		if c.fp != nil && isTCP(l.Protocol) {
			if res, ok := c.fp.Identify(ctx, fingerprintTarget(l.BindAddress), l.Port); ok {
				hl.Service = res.Protocol
				hl.ServiceVersion = res.Version
			}
		}
		out = append(out, hl)
	}

	if err := c.sink.ReplaceHostListeners(ctx, machineID, out); err != nil {
		return fmt.Errorf("store host listeners: %w", err)
	}
	return nil
}

func isTCP(p listeners.Protocol) bool {
	return p == listeners.ProtoTCP || p == listeners.ProtoTCP6
}

// fingerprintTarget picks a connectable loopback address for a local listener.
// A wildcard (0.0.0.0 / ::) or an unparseable bind address is fingerprinted via
// loopback; a specific address is probed as-is.
func fingerprintTarget(bindAddress string) netip.Addr {
	addr, err := netip.ParseAddr(strings.TrimSpace(bindAddress))
	if err != nil {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	if addr.IsUnspecified() {
		if addr.Is6() {
			return netip.IPv6Loopback()
		}
		return netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	return addr
}

// resolveLocalMachineID finds this host's store row: exact hostname match
// first, then the row the local agent wrote for itself. Mirrors the memory
// sampler and dashboard resolution.
func (c *Collector) resolveLocalMachineID(ctx context.Context) (uuid.UUID, bool) {
	machines, err := c.store.ListMachines(ctx, store.MachineFilter{Limit: 5000})
	if err != nil {
		return uuid.Nil, false
	}
	var fallback *model.Machine
	for i := range machines {
		if c.hostname != "" && strings.EqualFold(strings.TrimSpace(machines[i].Hostname), c.hostname) {
			return machines[i].ID, true
		}
		src := strings.ToLower(strings.TrimSpace(machines[i].DiscoverySource))
		if fallback == nil && (src == "local_controller" || src == "agent") {
			fallback = &machines[i]
		}
	}
	if fallback != nil {
		return fallback.ID, true
	}
	return uuid.Nil, false
}
