package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Registry manages discovery sources and runs them in parallel.
type Registry struct {
	sources []Source
}

// NewRegistry returns an empty Registry ready for source registration.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a discovery source to the registry. Sources are run in the
// order they were registered when DiscoverAll is called, but they execute
// concurrently.
func (r *Registry) Register(s Source) {
	r.sources = append(r.sources, s)
}

// DiscoverAll runs every registered source in parallel using errgroup.
// Per-source failures are logged as warnings but do not abort the overall
// discovery; partial results from successful sources are still returned.
// The function only returns an error when the parent context is cancelled.
func (r *Registry) DiscoverAll(ctx context.Context, configs map[string]map[string]any) ([]model.Asset, error) {
	if len(r.sources) == 0 {
		return nil, nil
	}

	var (
		mu     sync.Mutex
		assets []model.Asset
	)

	g, gctx := errgroup.WithContext(ctx)

	for _, src := range r.sources {
		g.Go(func() error {
			cfg := configs[src.Name()]

			slog.Info("discovery source starting", "source", src.Name())

			discovered, err := src.Discover(gctx, cfg)
			if err != nil {
				slog.Warn("discovery source failed",
					"source", src.Name(),
					"error", err,
				)
				// Return nil so other sources continue.
				return nil
			}

			slog.Info("discovery source completed",
				"source", src.Name(),
				"assets", len(discovered),
			)

			mu.Lock()
			assets = append(assets, discovered...)
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return assets, fmt.Errorf("discovery: %w", err)
	}

	return assets, nil
}
