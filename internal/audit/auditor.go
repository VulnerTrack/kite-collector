// Package audit provides a pluggable configuration auditing framework.
// Each auditor inspects system configuration for known weaknesses and
// emits ConfigFinding results with CWE mappings.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safety"
)

// Auditor inspects system configuration and returns findings.
// Implementations must be safe for concurrent use and must never
// modify the system being audited (read-only discovery).
type Auditor interface {
	// Name returns a stable lowercase identifier (e.g. "ssh", "firewall").
	Name() string
	// Audit inspects the system and returns configuration findings.
	// It must gracefully handle permission denied errors and return
	// partial results rather than failing entirely.
	Audit(ctx context.Context, asset model.Asset) ([]model.ConfigFinding, error)
}

// Registry manages a set of auditors and orchestrates parallel execution.
type Registry struct {
	auditors        map[string]Auditor
	panicsRecovered *prometheus.CounterVec
	mu              sync.RWMutex
}

// SetPanicsRecovered sets the Prometheus counter used to track recovered
// panics. If nil, panics are still recovered and logged but not counted.
func (r *Registry) SetPanicsRecovered(c *prometheus.CounterVec) {
	r.panicsRecovered = c
}

// NewRegistry creates an empty auditor registry.
func NewRegistry() *Registry {
	return &Registry{
		auditors: make(map[string]Auditor),
	}
}

// Register adds an auditor to the registry. If an auditor with the same
// name already exists it is replaced.
func (r *Registry) Register(a Auditor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.auditors[a.Name()] = a
}

// AuditAll runs all registered auditors in parallel and collects their
// findings. Individual auditor failures are logged as warnings but do not
// prevent other auditors from completing (partial results).
func (r *Registry) AuditAll(ctx context.Context, asset model.Asset) ([]model.ConfigFinding, error) {
	r.mu.RLock()
	auditors := make([]Auditor, 0, len(r.auditors))
	for _, a := range r.auditors {
		auditors = append(auditors, a)
	}
	r.mu.RUnlock()

	type result struct {
		err      error
		name     string
		findings []model.ConfigFinding
	}

	ch := make(chan result, len(auditors))

	for _, a := range auditors {
		go func(aud Auditor) {
			var res result
			res.name = aud.Name()
			defer func() {
				if rv := recover(); rv != nil {
					stack := string(debug.Stack())
					safety.LogPanic("audit."+aud.Name(), rv, stack, r.panicsRecovered)
					res.err = fmt.Errorf("panic in audit.%s: %v", aud.Name(), rv)
				}
				ch <- res
			}()
			res.findings, res.err = aud.Audit(ctx, asset)
		}(a)
	}

	var allFindings []model.ConfigFinding
	for range auditors {
		res := <-ch
		if res.err != nil {
			slog.Warn("audit: auditor failed",
				"auditor", res.name, "error", res.err)
		}
		if len(res.findings) > 0 {
			allFindings = append(allFindings, res.findings...)
		}
	}

	return allFindings, nil
}
