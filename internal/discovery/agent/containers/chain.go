package containers

import (
	"context"
	"fmt"
	"log/slog"
)

// chainCollector runs every configured runtime collector and concatenates
// their results. Per-runtime errors are logged at WARN and skipped — the
// next runtime in the chain still runs. This lets a host with both Docker
// and containerd installed produce a unified inventory.
type chainCollector struct {
	collectors []Collector
}

// NewChainCollector returns the default multi-runtime chain: Docker
// (which also covers Podman via the shared Engine API) + containerd
// (stub). Add more runtimes here as their collectors land.
func NewChainCollector() Collector {
	return &chainCollector{
		collectors: []Collector{
			NewDockerCollector(),
			NewContainerdCollector(),
		},
	}
}

func (chainCollector) Name() string { return "container-runtimes" }

// Collect runs every collector in the chain. Cap is applied across the
// total — first-come-first-served when the total exceeds MaxContainers.
func (c *chainCollector) Collect(ctx context.Context) ([]Container, error) {
	var out []Container
	for _, sub := range c.collectors {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-chain: %w", err)
		}
		got, err := sub.Collect(ctx)
		if err != nil {
			slog.Warn("containers: runtime collector failed",
				"runtime", sub.Name(), "error", err)
			continue
		}
		for _, c := range got {
			if len(out) >= MaxContainers {
				slog.Warn("containers: cap reached, dropping later runtimes",
					"cap", MaxContainers)
				SortContainers(out)
				return out, nil
			}
			out = append(out, c)
		}
	}
	SortContainers(out)
	return out, nil
}
