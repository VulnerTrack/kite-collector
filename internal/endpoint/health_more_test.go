package endpoint

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	kitev1 "github.com/vulnertrack/kite-collector/api/grpc/proto/kite/v1"
	"github.com/vulnertrack/kite-collector/internal/config"
)

// fakeCollectorClient stubs Heartbeat; every other CollectorService method
// panics via the embedded nil interface, which health checking never calls.
type fakeCollectorClient struct {
	kitev1.CollectorServiceClient

	mu      sync.Mutex
	hbErr   error
	calls   int
	lastReq *kitev1.HeartbeatRequest
}

func (f *fakeCollectorClient) Heartbeat(_ context.Context, in *kitev1.HeartbeatRequest, _ ...grpc.CallOption) (*kitev1.HeartbeatResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastReq = in
	if f.hbErr != nil {
		return nil, f.hbErr
	}
	return &kitev1.HeartbeatResponse{}, nil
}

func (f *fakeCollectorClient) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestCheckHealth_NilClientIsFailure(t *testing.T) {
	t.Parallel()

	m := &Manager{logger: testLogger()}
	ep := &Endpoint{Config: config.EndpointConfig{Name: "no-client"}, State: StateHealthy}

	ok := m.checkHealth(context.Background(), ep, time.Second)
	assert.False(t, ok)
	assert.Equal(t, 1, ep.consecutiveFailures, "a nil client must count as a failure")
	assert.Equal(t, 0, ep.consecutiveSuccesses)
}

func TestCheckHealth_HeartbeatErrorIsFailure(t *testing.T) {
	t.Parallel()

	client := &fakeCollectorClient{hbErr: errors.New("connection refused")}
	m := &Manager{logger: testLogger()}
	ep := &Endpoint{
		Config: config.EndpointConfig{Name: "down"},
		Client: client,
		State:  StateHealthy,
	}

	ok := m.checkHealth(context.Background(), ep, time.Second)
	assert.False(t, ok)
	assert.Equal(t, 1, ep.consecutiveFailures)
	assert.Equal(t, 1, client.callCount())
}

func TestCheckHealth_SuccessRecordsAndSendsAgentID(t *testing.T) {
	t.Parallel()

	client := &fakeCollectorClient{}
	m := &Manager{logger: testLogger()}
	ep := &Endpoint{
		Config: config.EndpointConfig{Name: "up"},
		Client: client,
		State:  StateHealthy,
	}

	before := time.Now()
	ok := m.checkHealth(context.Background(), ep, time.Second)
	assert.True(t, ok)
	assert.Equal(t, 1, ep.consecutiveSuccesses)
	assert.Equal(t, 0, ep.consecutiveFailures)
	assert.False(t, ep.LastSeen.Before(before), "a successful heartbeat must refresh LastSeen")

	require.NotNil(t, client.lastReq)
	assert.Equal(t, "health-check", client.lastReq.GetAgentId(),
		"health probes must identify themselves as health-check")
}

func TestRecordFailure_TerminalStatesHold(t *testing.T) {
	t.Parallel()

	m := &Manager{logger: testLogger()}

	unreachable := &Endpoint{Config: config.EndpointConfig{Name: "u"}, State: StateUnreachable}
	for i := 0; i < 10; i++ {
		m.recordFailure(unreachable)
	}
	assert.Equal(t, StateUnreachable, unreachable.State, "unreachable is terminal for failures")

	untrusted := &Endpoint{Config: config.EndpointConfig{Name: "t"}, State: StateUntrusted}
	m.recordFailure(untrusted)
	assert.Equal(t, StateUntrusted, untrusted.State)
}

func TestRecordFailure_BelowThresholdStaysHealthy(t *testing.T) {
	t.Parallel()

	m := &Manager{logger: testLogger()}
	ep := &Endpoint{Config: config.EndpointConfig{Name: "h"}, State: StateHealthy}

	for i := 0; i < failuresToDegrade-1; i++ {
		m.recordFailure(ep)
	}
	assert.Equal(t, StateHealthy, ep.State,
		"one failure short of the threshold must not degrade")
	assert.Equal(t, failuresToDegrade-1, ep.consecutiveFailures)
}

func TestRecordSuccess_UntrustedNeverAutoRecovers(t *testing.T) {
	t.Parallel()

	m := &Manager{logger: testLogger()}
	ep := &Endpoint{Config: config.EndpointConfig{Name: "t"}, State: StateUntrusted}

	for i := 0; i < 10; i++ {
		m.recordSuccess(ep)
	}
	assert.Equal(t, StateUntrusted, ep.State,
		"a TOFU mismatch must require operator intervention, not heartbeat luck")
}

func TestRecordSuccess_DegradedBelowThresholdHolds(t *testing.T) {
	t.Parallel()

	m := &Manager{logger: testLogger()}
	ep := &Endpoint{Config: config.EndpointConfig{Name: "d"}, State: StateDegraded}

	for i := 0; i < successesToHealthy-1; i++ {
		m.recordSuccess(ep)
	}
	assert.Equal(t, StateDegraded, ep.State)

	m.recordSuccess(ep)
	assert.Equal(t, StateHealthy, ep.State, "reaching the threshold must promote to healthy")
}

func TestRecordSuccess_HealthyStaysHealthy(t *testing.T) {
	t.Parallel()

	m := &Manager{logger: testLogger()}
	ep := &Endpoint{Config: config.EndpointConfig{Name: "h"}, State: StateHealthy}
	m.recordSuccess(ep)
	assert.Equal(t, StateHealthy, ep.State)
	assert.Equal(t, 1, ep.consecutiveSuccesses)
}

func TestHealthLoop_TicksSuccessesUntilCanceled(t *testing.T) {
	t.Parallel()

	client := &fakeCollectorClient{}
	m := &Manager{logger: testLogger()}
	ep := &Endpoint{
		Config: config.EndpointConfig{
			Name:   "fast",
			Health: config.HealthConfig{Interval: "10ms", Timeout: "100ms"},
		},
		Client: client,
		State:  StateHealthy,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.healthLoop(ctx, ep)
		close(done)
	}()

	require.Eventually(t, func() bool { return client.callCount() >= 3 },
		3*time.Second, 5*time.Millisecond, "the loop must keep ticking on success")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("healthLoop must exit promptly on context cancellation")
	}
}

func TestHealthLoop_FailureBacksOffAndExits(t *testing.T) {
	t.Parallel()

	client := &fakeCollectorClient{hbErr: errors.New("refused")}
	m := &Manager{logger: testLogger()}
	ep := &Endpoint{
		Config: config.EndpointConfig{
			Name:   "flaky",
			Health: config.HealthConfig{Interval: "10ms", Timeout: "100ms"},
		},
		Client: client,
		State:  StateHealthy,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.healthLoop(ctx, ep)
		close(done)
	}()

	// One failing tick is enough to prove the backoff path; waiting for more
	// would stall on the exponential backoff.
	require.Eventually(t, func() bool { return client.callCount() >= 1 },
		3*time.Second, 5*time.Millisecond)

	ep.mu.RLock()
	failures := ep.consecutiveFailures
	ep.mu.RUnlock()
	assert.GreaterOrEqual(t, failures, 1, "the failed probe must be recorded")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("healthLoop must exit promptly on context cancellation")
	}
}

func TestBackoff_GrowthAndJitterBounds(t *testing.T) {
	t.Parallel()

	// attempt=1: base 2s with ±30% jitter.
	d1 := backoff(1)
	assert.GreaterOrEqual(t, d1, 1400*time.Millisecond)
	assert.LessOrEqual(t, d1, 2600*time.Millisecond)

	// A float-overflowing attempt must clamp to the max, never go negative.
	dHuge := backoff(4096)
	assert.Greater(t, dHuge, time.Duration(0))
	assert.GreaterOrEqual(t, dHuge, time.Duration(float64(backoffMax)*(1-backoffJitter)))
	assert.LessOrEqual(t, dHuge, time.Duration(float64(backoffMax)*(1+backoffJitter)))
}
