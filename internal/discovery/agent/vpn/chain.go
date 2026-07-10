package vpn

import (
	"context"
	"fmt"
	"log/slog"
)

// chainCollector runs every configured source and concatenates results.
// Per-source errors are logged at WARN and skipped — WireGuard parsing
// failing for one file should not drop the OpenVPN inventory.
type chainCollector struct {
	collectors []Collector
}

// NewChainCollector returns the default multi-VPN chain.
func NewChainCollector() Collector {
	return &chainCollector{
		collectors: []Collector{
			NewWireGuardCollector(),
			NewOpenVPNCollector(),
			NewIPSecCollector(),
			NewTailscaleCollector(),
			NewZeroTierCollector(),
			NewNebulaCollector(),
			NewNetBirdCollector(),
			NewWindowsBuiltinCollector(),
			NewMacOSBuiltinCollector(),
			// Commercial / enterprise clients added in iter 14
			NewCiscoAnyConnectCollector(),
			NewMullvadCollector(),
			NewGlobalProtectCollector(),
			NewFortinetCollector(),
			NewCheckPointCollector(),
			NewDirectAccessCollector(),
			NewNordLayerCollector(),
			NewProtonVPNCollector(),
		},
	}
}

func (chainCollector) Name() string { return "vpn-profiles" }

func (c *chainCollector) Collect(ctx context.Context) ([]Profile, error) {
	var out []Profile
	for _, sub := range c.collectors {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-chain: %w", err)
		}
		got, err := sub.Collect(ctx)
		if err != nil {
			slog.Warn("vpn: source collector failed",
				"code", string(LogCodeChainSourceCollectorFailed), "source", sub.Name(), "error", err)
			continue
		}
		for _, p := range got {
			if len(out) >= MaxProfiles {
				slog.Warn("vpn: cap reached, dropping later sources",
					"code", string(LogCodeChainCapReached), "cap", MaxProfiles)
				SortProfiles(out)
				return out, nil
			}
			out = append(out, p)
		}
	}
	SortProfiles(out)
	return out, nil
}
