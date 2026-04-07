package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safety"
)

// Registry manages discovery sources and runs them in parallel.
type Registry struct {
	sources         []Source
	panicsRecovered *prometheus.CounterVec
	circuitBreaker  *safety.CircuitBreaker
}

// SetPanicsRecovered sets the Prometheus counter used to track recovered
// panics. If nil, panics are still recovered and logged but not counted.
func (r *Registry) SetPanicsRecovered(c *prometheus.CounterVec) {
	r.panicsRecovered = c
}

// SetCircuitBreaker sets the circuit breaker used to skip sources that
// have repeatedly failed.
func (r *Registry) SetCircuitBreaker(cb *safety.CircuitBreaker) {
	r.circuitBreaker = cb
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
			defer safety.Recover("discovery."+src.Name(), r.panicsRecovered, nil)

			// Circuit breaker: skip sources with open circuits.
			if r.circuitBreaker != nil && r.circuitBreaker.ShouldSkip(src.Name()) {
				slog.Warn("discovery source skipped: circuit open",
					"source", src.Name())
				return nil
			}

			cfg := configs[src.Name()]

			slog.Info("discovery source starting", "source", src.Name())

			discovered, err := src.Discover(gctx, cfg)
			if err != nil {
				slog.Warn("discovery source failed",
					"source", src.Name(),
					"error", err,
				)
				if r.circuitBreaker != nil {
					r.circuitBreaker.RecordFailure(src.Name(), err.Error())
				}
				// Return nil so other sources continue.
				return nil
			}

			if r.circuitBreaker != nil {
				r.circuitBreaker.RecordSuccess(src.Name())
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
