package driver

import (
	"context"
	"log/slog"
	"sync"

	"golang.org/x/sync/errgroup"
)

// Registry runs every available driver collector in parallel and merges
// results into a single Result. Mirrors software.Registry.
type Registry struct {
	collectors []Collector
}

// NewRegistry returns a Registry pre-loaded with every cross-platform
// collector. Each collector's Available() is the runtime gate; collectors
// whose host conditions are not met are skipped on Collect.
func NewRegistry() *Registry {
	return &Registry{
		collectors: []Collector{
			NewProcModules(),
			NewSysfsBindings(),
			NewWMIDrivers(),
			NewPnPUtilDrivers(),
			NewKmutilShowloaded(),
			NewSystemExtensionsCtl(),
			NewKldstat(),
		},
	}
}

// Register adds an arbitrary collector. Useful for tests.
func (r *Registry) Register(c Collector) {
	r.collectors = append(r.collectors, c)
}

// Collect runs every Available() collector concurrently and aggregates their
// results. A failing collector logs and is recorded under Errs but never
// aborts the others.
func (r *Registry) Collect(ctx context.Context) *Result {
	merged := &Result{}

	var available []Collector
	for _, c := range r.collectors {
		if c.Available() {
			available = append(available, c)
			slog.Info("driver: collector available", "name", c.Name())
		} else {
			slog.Debug("driver: collector not available", "name", c.Name())
		}
	}

	if len(available) == 0 {
		return merged
	}

	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)

	for _, c := range available {
		g.Go(func() error {
			res, err := c.Collect(gctx)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				slog.Warn("driver: collector failed", "code", string(LogCodeRegistryCollectorFailed), "name", c.Name(), "error", err)
				merged.Errs = append(merged.Errs, CollectError{
					Collector: c.Name(),
					Err:       err,
				})
				return nil
			}

			if res == nil {
				return nil
			}
			merged.Merge(res)
			slog.Info(
				"driver: collector completed",
				"name", c.Name(),
				"drivers", len(res.Drivers),
				"bindings", len(res.Bindings),
				"errors", res.TotalErrors(),
			)
			return nil
		})
	}

	_ = g.Wait()
	return merged
}
