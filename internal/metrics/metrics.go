package metrics

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus instruments used by kite-collector.
// Each instance carries its own registry so nothing touches the global default.
type Metrics struct {
	ScanDuration    *prometheus.HistogramVec
	AssetsTotal     *prometheus.GaugeVec
	EventsEmitted   *prometheus.CounterVec
	DiscoveryErrors *prometheus.CounterVec
	ScanCoverage    *prometheus.GaugeVec
	StaleAssets     prometheus.Gauge
	registry        *prometheus.Registry
}

// New creates a Metrics instance backed by a private registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	scanDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "kite_scan_duration_seconds",
		Help: "Duration of discovery scans in seconds.",
	}, []string{"source"})

	assetsTotal := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kite_assets_total",
		Help: "Current number of known assets by type, authorization and managed state.",
	}, []string{"type", "authorized", "managed"})

	eventsEmitted := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kite_events_emitted_total",
		Help: "Total number of asset events emitted.",
	}, []string{"event_type"})

	discoveryErrors := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kite_discovery_errors_total",
		Help: "Total number of errors encountered during discovery.",
	}, []string{"source"})

	scanCoverage := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kite_scan_coverage_ratio",
		Help: "Fraction of expected assets that were seen in the latest scan.",
	}, []string{"source"})

	staleAssets := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kite_stale_assets_total",
		Help: "Number of assets that have not been seen within the staleness threshold.",
	})

	reg.MustRegister(
		scanDuration,
		assetsTotal,
		eventsEmitted,
		discoveryErrors,
		scanCoverage,
		staleAssets,
	)

	return &Metrics{
		ScanDuration:    scanDuration,
		AssetsTotal:     assetsTotal,
		EventsEmitted:   eventsEmitted,
		DiscoveryErrors: discoveryErrors,
		ScanCoverage:    scanCoverage,
		StaleAssets:     staleAssets,
		registry:        reg,
	}
}

// Handler returns an http.Handler that serves Prometheus metrics from the
// private registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Serve starts an HTTP server in a background goroutine that exposes
// /metrics on the given address. It does not block the caller.
func (m *Metrics) Serve(addr string) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())

	slog.Info("starting metrics server", "addr", addr)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			slog.Error("metrics server exited", "error", err)
		}
	}()
}
