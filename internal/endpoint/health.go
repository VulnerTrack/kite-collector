package endpoint

import (
	"context"
	"math"
	"time"

	kitev1 "github.com/vulnertrack/kite-collector/api/grpc/proto/kite/v1"
)

const (
	failuresToDegrade    = 3
	failuresToUnreachable = 3 // 3 more after degraded
	successesToRecover   = 3
	successesToHealthy   = 3

	backoffBase    = 1 * time.Second
	backoffMax     = 5 * time.Minute
	backoffFactor  = 2.0
	backoffJitter  = 0.3
)

// healthLoop runs periodic health checks for a single endpoint.
func (m *Manager) healthLoop(ctx context.Context, ep *Endpoint) {
	interval := ep.Config.Health.HealthIntervalDuration()
	timeout := ep.Config.Health.HealthTimeoutDuration()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	attempt := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ok := m.checkHealth(ctx, ep, timeout)
			if ok {
				attempt = 0
				ticker.Reset(interval)
			} else {
				attempt++
				bo := backoff(attempt)
				ticker.Reset(bo)
			}
		}
	}
}

// checkHealth sends a heartbeat to the endpoint and updates its state.
func (m *Manager) checkHealth(ctx context.Context, ep *Endpoint, timeout time.Duration) bool {
	if ep.Client == nil {
		m.recordFailure(ep)
		return false
	}

	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	_, err := ep.Client.Heartbeat(hctx, &kitev1.HeartbeatRequest{
		AgentId: "health-check",
	})
	if err != nil {
		m.logger.Debug("endpoint health check failed",
			"name", ep.Config.Name,
			"error", err,
		)
		m.recordFailure(ep)
		return false
	}

	m.recordSuccess(ep)
	return true
}

func (m *Manager) recordFailure(ep *Endpoint) {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	ep.consecutiveSuccesses = 0
	ep.consecutiveFailures++

	switch ep.State {
	case StateHealthy:
		if ep.consecutiveFailures >= failuresToDegrade {
			ep.State = StateDegraded
			m.logger.Warn("endpoint degraded", "name", ep.Config.Name)
		}
	case StateDegraded:
		if ep.consecutiveFailures >= failuresToUnreachable {
			ep.State = StateUnreachable
			m.logger.Error("endpoint unreachable", "name", ep.Config.Name)
		}
	case StateUnreachable, StateUntrusted:
		// Already in terminal state; wait for success.
	}
}

func (m *Manager) recordSuccess(ep *Endpoint) {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	ep.consecutiveFailures = 0
	ep.consecutiveSuccesses++
	ep.LastSeen = time.Now()

	switch ep.State {
	case StateUnreachable:
		ep.State = StateDegraded
		ep.consecutiveSuccesses = 1
		m.logger.Info("endpoint recovering", "name", ep.Config.Name)
	case StateDegraded:
		if ep.consecutiveSuccesses >= successesToHealthy {
			ep.State = StateHealthy
			m.logger.Info("endpoint healthy", "name", ep.Config.Name)
		}
	case StateHealthy:
		// Already healthy.
	case StateUntrusted:
		// TOFU mismatch — stays untrusted until operator intervention.
	}
}

// backoff computes exponential backoff with jitter for the given attempt.
func backoff(attempt int) time.Duration {
	exp := math.Pow(backoffFactor, float64(attempt))
	d := float64(backoffBase) * exp
	maxF := float64(backoffMax)
	if d > maxF || math.IsInf(d, 0) || math.IsNaN(d) {
		d = maxF
	}
	// Add jitter: ±30%.
	jitter := d * backoffJitter
	d = d - jitter + 2*jitter*randFloat()
	return time.Duration(d)
}

// randFloat returns a pseudo-random float in [0,1) using time-based seeding.
// Intentionally avoids crypto/rand for a non-security-critical jitter value.
func randFloat() float64 {
	// Use nanosecond portion of current time as a simple source of jitter.
	return float64(time.Now().UnixNano()%1000) / 1000.0
}
