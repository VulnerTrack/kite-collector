package scheduled

import (
	"context"
	"fmt"
	"log/slog"
)

// chainCollector runs every configured source collector and concatenates
// results. Per-source errors are logged at WARN and skipped — a host
// with cron entries but no systemd shouldn't fail just because
// systemctl is missing.
type chainCollector struct {
	collectors []Collector
}

// NewChainCollector returns the default multi-source chain.
func NewChainCollector() Collector {
	return &chainCollector{
		collectors: []Collector{
			NewCronCollector(),
			NewSystemdTimerCollector(),
			NewLaunchdCollector(),
			NewWindowsTaskSchedulerCollector(),
			NewAtCollector(),
		},
	}
}

func (chainCollector) Name() string { return "scheduled-sources" }

func (c *chainCollector) Collect(ctx context.Context) ([]Job, error) {
	var out []Job
	for _, sub := range c.collectors {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-chain: %w", err)
		}
		got, err := sub.Collect(ctx)
		if err != nil {
			slog.Warn("scheduled: source collector failed",
				"code", string(LogCodeChainSourceCollectorFailed), "source", sub.Name(), "error", err)
			continue
		}
		for _, j := range got {
			if len(out) >= MaxJobs {
				slog.Warn("scheduled: cap reached, dropping later sources",
					"code", string(LogCodeChainCapReached), "cap", MaxJobs)
				SortJobs(out)
				return out, nil
			}
			out = append(out, j)
		}
	}
	SortJobs(out)
	return out, nil
}
