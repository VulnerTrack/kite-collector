package browserext

import (
	"context"
	"fmt"
	"log/slog"
)

// chainCollector runs every configured source collector and concatenates
// results. Per-source errors are logged at WARN and skipped — a Firefox
// collector outage shouldn't drop the (real) Chromium-family inventory.
type chainCollector struct {
	collectors []Collector
}

// NewChainCollector returns the default multi-browser chain.
func NewChainCollector() Collector {
	return &chainCollector{
		collectors: []Collector{
			NewChromiumCollector(),
			NewFirefoxCollector(),
			NewSafariCollector(),
		},
	}
}

func (chainCollector) Name() string { return "browser-extensions" }

func (c *chainCollector) Collect(ctx context.Context) ([]Extension, error) {
	var out []Extension
	for _, sub := range c.collectors {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-chain: %w", err)
		}
		got, err := sub.Collect(ctx)
		if err != nil {
			slog.Warn("browserext: source collector failed",
				"source", sub.Name(), "error", err)
			continue
		}
		for _, e := range got {
			if len(out) >= MaxExtensions {
				slog.Warn("browserext: cap reached, dropping later sources",
					"cap", MaxExtensions)
				SortExtensions(out)
				return out, nil
			}
			out = append(out, e)
		}
	}
	SortExtensions(out)
	return out, nil
}
