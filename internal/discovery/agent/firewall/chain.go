package firewall

import (
	"context"
	"fmt"
	"log/slog"
)

// chainCollector runs every configured engine collector and concatenates
// results. Per-engine errors are logged at WARN and skipped — a host
// with iptables-save installed but nft not yet doesn't lose iptables
// rules just because the nft probe failed.
type chainCollector struct {
	collectors []Collector
}

// NewChainCollector returns the default multi-engine chain.
func NewChainCollector() Collector {
	return &chainCollector{
		collectors: []Collector{
			NewIPTablesCollector(),
			NewNFTablesCollector(),
			NewPFCollector(),
			NewWindowsFirewallCollector(),
			NewUFWCollector(),
			NewFirewalldCollector(),
		},
	}
}

func (chainCollector) Name() string { return "firewall-engines" }

func (c *chainCollector) Collect(ctx context.Context) ([]Rule, error) {
	var out []Rule
	for _, sub := range c.collectors {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-chain: %w", err)
		}
		got, err := sub.Collect(ctx)
		if err != nil {
			slog.Warn("firewall: engine collector failed",
				"code", string(LogCodeChainEngineCollectorFailed), "engine", sub.Name(), "error", err)
			continue
		}
		for _, r := range got {
			if len(out) >= MaxRules {
				slog.Warn("firewall: cap reached, dropping later engines",
					"code", string(LogCodeChainCapReached), "cap", MaxRules)
				SortRules(out)
				return out, nil
			}
			out = append(out, r)
		}
	}
	SortRules(out)
	return out, nil
}
