// Package preflight implements parallel pre-flight validation checks that
// verify the wizard's resolved configuration against live infrastructure
// (Docker socket, CIDR parse, env vars, TLS endpoints, OTEL health).
package preflight

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// CheckResult holds the outcome of a single pre-flight check.
type CheckResult struct {
	NodeID  string `json:"node"`
	Check   string `json:"check"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	Passed  bool   `json:"passed"`
}

// Checker validates a single preflight check type.
type Checker interface {
	// Check runs the validation and returns a result.
	Check(ctx context.Context, nodeID string, value any, resolved map[string]any) CheckResult
}

// CheckSpec pairs a node ID and check type with the resolved value.
type CheckSpec struct {
	Resolved map[string]any
	Value    any
	NodeID   string
	CheckTag string
}

// Runner executes pre-flight checks in parallel with bounded concurrency.
type Runner struct {
	checkers    map[string]Checker
	logger      *slog.Logger
	concurrency int
}

// NewRunner creates a pre-flight runner with the given concurrency limit
// and registered checkers.
func NewRunner(concurrency int, logger *slog.Logger) *Runner {
	if concurrency <= 0 {
		concurrency = 8
	}
	r := &Runner{
		checkers:    make(map[string]Checker),
		concurrency: concurrency,
		logger:      logger,
	}
	r.registerDefaults()
	return r
}

// Register adds a checker for a given check tag (e.g., "docker:socket:probe").
func (r *Runner) Register(tag string, c Checker) {
	r.checkers[tag] = c
}

// Run executes all checks concurrently and returns all results.
func (r *Runner) Run(ctx context.Context, specs []CheckSpec) []CheckResult {
	results := make([]CheckResult, len(specs))
	sem := make(chan struct{}, r.concurrency)
	var wg sync.WaitGroup

	for i, spec := range specs {
		wg.Add(1)
		go func(idx int, s CheckSpec) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			checker, ok := r.checkers[s.CheckTag]
			if !ok {
				results[idx] = CheckResult{
					NodeID:  s.NodeID,
					Check:   s.CheckTag,
					Passed:  false,
					Message: fmt.Sprintf("no checker registered for %q", s.CheckTag),
				}
				return
			}
			results[idx] = checker.Check(ctx, s.NodeID, s.Value, s.Resolved)
			r.logger.Debug("preflight check",
				"node", s.NodeID,
				"check", s.CheckTag,
				"passed", results[idx].Passed,
			)
		}(i, spec)
	}

	wg.Wait()
	return results
}

// Summary returns counts of passed and failed checks.
func Summary(results []CheckResult) (passed, failed int) {
	for _, r := range results {
		if r.Passed {
			passed++
		} else {
			failed++
		}
	}
	return
}

// registerDefaults registers all built-in pre-flight checkers.
func (r *Runner) registerDefaults() {
	r.Register("docker:socket:probe", &DockerSocketChecker{})
	r.Register("network:cidr:parse", &CIDRChecker{})
	r.Register("vps:env:check", &VPSEnvChecker{})
	r.Register("mdm:env:check", &MDMEnvChecker{})
	r.Register("cmdb:env:check", &CMDBEnvChecker{})
	r.Register("file:exists", &FileExistsChecker{})
	r.Register("endpoint:tls:connect", &TLSConnectChecker{})
	r.Register("endpoint:enroll", &EnrollChecker{})
	r.Register("otel:health:check", &OTELHealthChecker{})
	r.Register("tunnel:binary:available", &TunnelBinaryChecker{})
	r.Register("tunnel:auth:valid", &TunnelAuthChecker{})
	r.Register("tunnel:port:free", &TunnelPortChecker{})
	r.Register("ldap:dc:connect", &LDAPDCConnectChecker{})
	r.Register("ldap:bind:env", &LDAPBindEnvChecker{})
	r.Register("ldap:base_dn:syntax", &LDAPBaseDNChecker{})
	r.Register("ldap:tls_mode:valid", &LDAPTLSModeChecker{})
}
