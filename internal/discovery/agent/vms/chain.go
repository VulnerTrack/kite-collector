package vms

import (
	"context"
	"fmt"
	"log/slog"
)

// chainCollector runs every configured hypervisor collector and
// concatenates results. Per-hypervisor errors are logged at WARN and
// skipped — a host with both libvirt and VirtualBox installed still
// gets unified inventory even if one daemon is down.
type chainCollector struct {
	collectors []Collector
}

// NewChainCollector returns the default multi-hypervisor chain: libvirt
// + VirtualBox (real implementations) + Hyper-V/VMware/UTM/Parallels/
// Multipass (stubs). Add more by extending the slice.
func NewChainCollector() Collector {
	return &chainCollector{
		collectors: []Collector{
			NewLibvirtCollector(),
			NewVirtualBoxCollector(),
			NewHyperVCollector(),
			NewVMwareCollector(),
			NewUTMCollector(),
			NewParallelsCollector(),
			NewMultipassCollector(),
		},
	}
}

func (chainCollector) Name() string { return "hypervisors" }

// Collect runs every collector in the chain. Cap is applied across the
// total — first-come-first-served when the total exceeds MaxVMs.
func (c *chainCollector) Collect(ctx context.Context) ([]VM, error) {
	var out []VM
	for _, sub := range c.collectors {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-chain: %w", err)
		}
		got, err := sub.Collect(ctx)
		if err != nil {
			slog.Warn("vms: hypervisor collector failed",
				"hypervisor", sub.Name(), "error", err)
			continue
		}
		for _, v := range got {
			if len(out) >= MaxVMs {
				slog.Warn("vms: cap reached, dropping later hypervisors",
					"cap", MaxVMs)
				SortVMs(out)
				return out, nil
			}
			out = append(out, v)
		}
	}
	SortVMs(out)
	return out, nil
}
