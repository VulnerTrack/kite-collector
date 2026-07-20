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
	ScanDuration         *prometheus.HistogramVec
	MachinesTotal        *prometheus.GaugeVec
	EventsEmitted        *prometheus.CounterVec
	DiscoveryErrors      *prometheus.CounterVec
	ScanCoverage         *prometheus.GaugeVec
	StaleMachines        prometheus.Gauge
	DedupSkipped         prometheus.Counter
	PanicsRecovered      *prometheus.CounterVec
	CircuitBreakerTrips  *prometheus.CounterVec
	SourceHealth         *prometheus.GaugeVec
	ResponseTruncations  prometheus.Counter
	ScanDeadlineExceeded prometheus.Counter
	// Code scanning metrics
	FindingsOpen    *prometheus.GaugeVec     // open findings by severity + auditor
	FindingsTotal   *prometheus.CounterVec   // cumulative findings ever emitted
	FindingAgeHours *prometheus.HistogramVec // age of open findings (MTTR proxy)
	// Safenet metrics (RFC-0124)
	SafetyGuardTotal         *prometheus.CounterVec // every guard fire by type + action
	PaginationTruncatedTotal *prometheus.CounterVec // pagination caps by connector + reason
	registry                 *prometheus.Registry
}

// New creates a Metrics instance backed by a private registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	scanDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "kite_scan_duration_seconds",
		Help: "Duration of discovery scans in seconds.",
	}, []string{"source"})

	machinesTotal := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kite_machines_total",
		Help: "Current number of known machines by type, authorization and managed state.",
	}, []string{"type", "authorized", "managed"})

	eventsEmitted := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kite_events_emitted_total",
		Help: "Total number of machine events emitted.",
	}, []string{"event_type"})

	discoveryErrors := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kite_discovery_errors_total",
		Help: "Total number of errors encountered during discovery.",
	}, []string{"source"})

	scanCoverage := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kite_scan_coverage_ratio",
		Help: "Fraction of expected machines that were seen in the latest scan.",
	}, []string{"source"})

	staleMachines := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kite_stale_machines_total",
		Help: "Number of machines that have not been seen within the staleness threshold.",
	})

	dedupSkipped := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kite_dedup_skipped_total",
		Help: "Total number of duplicate machines skipped during deduplication.",
	})

	panicsRecovered := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kite_panics_recovered_total",
		Help: "Total number of panics caught by recovery middleware.",
	}, []string{"component"})

	circuitBreakerTrips := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kite_circuit_breaker_trips_total",
		Help: "Total number of circuit breaker trips per discovery source.",
	}, []string{"source"})

	sourceHealth := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kite_source_health",
		Help: "Discovery source health: 0=open, 0.5=degraded, 1=healthy.",
	}, []string{"source"})

	responseTruncations := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kite_response_truncations_total",
		Help: "Total number of HTTP responses truncated due to size limits.",
	})

	scanDeadlineExceeded := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kite_scan_deadline_exceeded_total",
		Help: "Total number of scans that exceeded the deadline.",
	})

	findingsOpen := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kite_findings_open",
		Help: "Number of open findings from the most recent scan, by severity and auditor.",
	}, []string{"severity", "auditor"})

	findingsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kite_findings_total",
		Help: "Cumulative number of findings emitted, by severity and auditor.",
	}, []string{"severity", "auditor"})

	findingAgeHours := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "kite_finding_age_hours",
		Help:    "Age of open findings in hours (first_seen_at to now). Proxy for mean time to remediate.",
		Buckets: []float64{1, 6, 24, 72, 168, 336, 720, 2160}, // 1h … 90d
	}, []string{"severity", "auditor"})

	safetyGuardTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kite_safety_guard_total",
		Help: "Total RFC-0124 safety guard fires, labelled by guard_type and action_taken.",
	}, []string{"guard_type", "action_taken"})

	paginationTruncatedTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kite_pagination_truncated_total",
		Help: "Total pagination cap fires, labelled by connector and cap reason.",
	}, []string{"connector", "reason"})

	reg.MustRegister(
		scanDuration,
		machinesTotal,
		eventsEmitted,
		discoveryErrors,
		scanCoverage,
		staleMachines,
		dedupSkipped,
		panicsRecovered,
		circuitBreakerTrips,
		sourceHealth,
		responseTruncations,
		scanDeadlineExceeded,
		findingsOpen,
		findingsTotal,
		findingAgeHours,
		safetyGuardTotal,
		paginationTruncatedTotal,
	)

	return &Metrics{
		ScanDuration:             scanDuration,
		MachinesTotal:            machinesTotal,
		EventsEmitted:            eventsEmitted,
		DiscoveryErrors:          discoveryErrors,
		ScanCoverage:             scanCoverage,
		StaleMachines:            staleMachines,
		DedupSkipped:             dedupSkipped,
		PanicsRecovered:          panicsRecovered,
		CircuitBreakerTrips:      circuitBreakerTrips,
		SourceHealth:             sourceHealth,
		ResponseTruncations:      responseTruncations,
		ScanDeadlineExceeded:     scanDeadlineExceeded,
		FindingsOpen:             findingsOpen,
		FindingsTotal:            findingsTotal,
		FindingAgeHours:          findingAgeHours,
		SafetyGuardTotal:         safetyGuardTotal,
		PaginationTruncatedTotal: paginationTruncatedTotal,
		registry:                 reg,
	}
}

// Handler returns an http.Handler that serves Prometheus metrics from the
// private registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Serve starts an HTTP server in a background goroutine that exposes
// /metrics on the given address. The returned *http.Server can be used
// to shut the listener down gracefully.
func (m *Metrics) Serve(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())

	slog.Info("starting metrics server", "addr", addr)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server exited", "code", string(LogCodeServerExited), "error", err)
		}
	}()

	return srv
}
