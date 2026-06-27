package dashboard

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// onboardingProbeDurationHistogram returns a process-wide singleton
// histogram registered on the default Prometheus registry. The dashboard
// reuses the default registry (not the scanner's private one in
// internal/metrics) because the collector's `/metrics` handler already
// exposes the default registry on :9100 — adding a second registry would
// require routing surgery that is out of scope for RFC-0112.
//
// The singleton guards against re-registration panics when the dashboard
// Serve function is invoked more than once per process (notably in unit
// tests that spin up multiple servers).
func onboardingProbeDurationHistogram() *prometheus.HistogramVec {
	probeHistogramOnce.Do(func() {
		probeHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kite_dashboard_probe_duration_ms",
			Help:    "Latency of dashboard onboarding connection probes, in milliseconds.",
			Buckets: []float64{10, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
		}, []string{"probe", "result"})

		if err := prometheus.Register(probeHistogram); err != nil {
			// If Prometheus has already registered an identical collector
			// (possible in tests that don't share the binary), fall back to
			// that existing one so we do not panic.
			if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
				if existing, ok2 := are.ExistingCollector.(*prometheus.HistogramVec); ok2 {
					probeHistogram = existing
				}
			}
		}
	})
	return probeHistogram
}

var (
	probeHistogramOnce sync.Once
	probeHistogram     *prometheus.HistogramVec
)
