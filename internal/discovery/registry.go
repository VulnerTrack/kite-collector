package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safety"
)

// HeartbeatRecorder receives one synthetic record per discovery source per
// scan. The Engine binds scan_id + signing identity + sink into a concrete
// recorder before calling DiscoverAll, so the Registry stays scan-agnostic.
// A nil recorder is allowed; sources still run, just without heartbeats.
type HeartbeatRecorder interface {
	Record(
		ctx context.Context,
		source string,
		status model.HeartbeatStatus,
		itemsEmitted int,
		duration time.Duration,
	) error
}

// Registry manages discovery sources and runs them in parallel.
type Registry struct {
	circuitBreaker    *safety.CircuitBreaker
	panicsRecovered   *prometheus.CounterVec
	heartbeatRecorder HeartbeatRecorder
	sources           []Source
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

// SetHeartbeatRecorder installs a recorder that DiscoverAll uses to emit
// one synthetic liveness record per source per scan. The Engine calls this
// before each scan with a scan-scoped recorder; passing nil disables
// heartbeat emission entirely (the existing tests rely on this).
func (r *Registry) SetHeartbeatRecorder(h HeartbeatRecorder) {
	r.heartbeatRecorder = h
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

// Get returns the registered source matching name, or nil if absent. It is
// used by post-discovery audit phases that need to pull source-specific
// state (e.g. the Entra auditor reaches into EntraID.Snapshot()).
func (r *Registry) Get(name string) Source {
	for _, src := range r.sources {
		if src.Name() == name {
			return src
		}
	}
	return nil
}

// DiscoverAll runs every registered source in parallel using errgroup.
// Per-source failures are logged as warnings but do not abort the overall
// discovery; partial results from successful sources are still returned.
// The function only returns an error when the parent context is cancelled.
func (r *Registry) DiscoverAll(ctx context.Context, configs map[string]map[string]any) ([]model.Asset, error) {
	if len(r.sources) == 0 {
		// No sources registered — the scan can find nothing. Explain the no-op
		// with the catalogued KITE-E009 remediation (enable at least one source
		// or use --auto) instead of returning silently.
		slog.LogAttrs(ctx, slog.LevelWarn, "no discovery sources registered; scan will find nothing",
			kiteerrors.Attrs(kiteerrors.FromCatalog(kiteerrors.CodeNoDiscoverySources, nil))...)
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

			// Circuit breaker: skip sources with open circuits. Emit a
			// 'circuit_open' heartbeat so the reconciler can tell a
			// quarantined collector apart from a missing one.
			if r.circuitBreaker != nil && r.circuitBreaker.ShouldSkip(src.Name()) {
				slog.Warn("discovery source skipped: circuit open",
					"code", string(LogCodeRegistrySourceCircuitOpen),
					"source", src.Name())
				r.emitHeartbeat(ctx, src.Name(), model.HeartbeatCircuitOpen, 0, 0)
				return nil
			}

			cfg := configs[src.Name()]
			slog.Info("discovery source starting", "source", src.Name())

			start := time.Now()
			discovered, err := src.Discover(gctx, cfg)
			elapsed := time.Since(start)

			if err != nil {
				// Emit the flat structured envelope (error_code/error_message/
				// hint/error_context) so a source returning a *kiteerrors.Error
				// surfaces its catalog code and remediation as top-level log
				// fields; plain errors degrade to error_message only. The stable
				// `code` pivot (LogCodeRegistrySourceFailed) is preserved.
				attrs := append([]slog.Attr{
					slog.String("code", string(LogCodeRegistrySourceFailed)),
					slog.String("source", src.Name()),
				}, kiteerrors.Attrs(err)...)
				slog.LogAttrs(gctx, slog.LevelWarn, "discovery source failed", attrs...)
				if r.circuitBreaker != nil {
					r.circuitBreaker.RecordFailure(src.Name(), err.Error())
				}
				// Distinguish deadline breaches from generic errors so the
				// reconciler can route 'timeout' heartbeats to a different
				// remediation channel than crash-grade failures.
				status := model.HeartbeatError
				if gctx.Err() == context.DeadlineExceeded {
					status = model.HeartbeatTimeout
				}
				r.emitHeartbeat(ctx, src.Name(), status, len(discovered), elapsed)
				// Return nil so other sources continue.
				return nil
			}

			if r.circuitBreaker != nil {
				r.circuitBreaker.RecordSuccess(src.Name())
			}

			slog.Info(
				"discovery source completed",
				"source", src.Name(),
				"assets", len(discovered),
			)

			mu.Lock()
			assets = append(assets, discovered...)
			mu.Unlock()

			r.emitHeartbeat(ctx, src.Name(), model.HeartbeatOK, len(discovered), elapsed)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return assets, fmt.Errorf("discovery: %w", err)
	}

	return assets, nil
}

// emitHeartbeat fires one synthetic liveness record for src. The recorder
// is allowed to be nil — registries used outside a scan context (tests,
// the introspection CLI) opt out. Errors here are logged but never
// propagated: a failed heartbeat must not cancel real discovery work.
func (r *Registry) emitHeartbeat(
	ctx context.Context,
	source string,
	status model.HeartbeatStatus,
	itemsEmitted int,
	duration time.Duration,
) {
	if r.heartbeatRecorder == nil {
		return
	}
	if err := r.heartbeatRecorder.Record(ctx, source, status, itemsEmitted, duration); err != nil {
		slog.Warn(
			"heartbeat record failed",
			"code", string(LogCodeHeartbeatRecordFailed),
			"source", source,
			"status", status,
			"error", err,
		)
	}
}
