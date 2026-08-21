package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// fakeAuditor is a scriptable Auditor with an invocation counter.
type fakeAuditor struct {
	name     string
	findings []model.ConfigFinding
	err      error
	panicVal any

	mu    sync.Mutex
	calls int
}

func (f *fakeAuditor) Name() string { return f.name }

func (f *fakeAuditor) Audit(_ context.Context, _ model.Machine) ([]model.ConfigFinding, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.panicVal != nil {
		panic(f.panicVal)
	}
	return f.findings, f.err
}

func finding(check string) model.ConfigFinding {
	return model.ConfigFinding{ID: uuid.New(), CheckID: check, Timestamp: time.Now().UTC()}
}

func TestRegistry_AuditAllMergesAllAuditors(t *testing.T) {
	r := NewRegistry()
	r.Register(&fakeAuditor{name: "a", findings: []model.ConfigFinding{finding("a-1"), finding("a-2")}})
	r.Register(&fakeAuditor{name: "b", findings: []model.ConfigFinding{finding("b-1")}})

	got, err := r.AuditAll(context.Background(), model.Machine{})
	require.NoError(t, err)
	require.Len(t, got, 3, "every auditor's findings must be merged")

	checks := make([]string, 0, len(got))
	for _, f := range got {
		checks = append(checks, f.CheckID)
	}
	assert.ElementsMatch(t, []string{"a-1", "a-2", "b-1"}, checks)
}

// Registering under an existing name REPLACES the auditor — running both
// would double-report every finding of that name.
func TestRegistry_RegisterReplacesSameName(t *testing.T) {
	r := NewRegistry()
	v1 := &fakeAuditor{name: "ssh", findings: []model.ConfigFinding{finding("v1")}}
	v2 := &fakeAuditor{name: "ssh", findings: []model.ConfigFinding{finding("v2")}}
	r.Register(v1)
	r.Register(v2)

	got, err := r.AuditAll(context.Background(), model.Machine{})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "v2", got[0].CheckID, "the later registration must win")
	assert.Equal(t, 0, v1.calls, "the replaced auditor must not run")
}

// One failing auditor must not suppress the others' findings, and
// AuditAll itself reports partial success (nil error).
func TestRegistry_AuditAllIsolatesFailures(t *testing.T) {
	r := NewRegistry()
	r.Register(&fakeAuditor{name: "broken", err: errors.New("permission denied")})
	r.Register(&fakeAuditor{name: "healthy", findings: []model.ConfigFinding{finding("ok-1")}})

	got, err := r.AuditAll(context.Background(), model.Machine{})
	require.NoError(t, err, "partial results, not a hard failure")
	require.Len(t, got, 1)
	assert.Equal(t, "ok-1", got[0].CheckID)
}

// A panicking auditor is recovered, counted when a counter is wired, and
// the rest of the fleet completes.
func TestRegistry_AuditAllRecoversPanicsAndCounts(t *testing.T) {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "test_panics_recovered_total"},
		[]string{"component"},
	)
	r := NewRegistry()
	r.SetPanicsRecovered(counter)
	r.Register(&fakeAuditor{name: "bomb", panicVal: "boom"})
	r.Register(&fakeAuditor{name: "healthy", findings: []model.ConfigFinding{finding("ok-1")}})

	got, err := r.AuditAll(context.Background(), model.Machine{})
	require.NoError(t, err)
	require.Len(t, got, 1, "healthy auditor must complete despite the sibling panic")
	assert.Equal(t, "ok-1", got[0].CheckID)
	assert.Equal(t, 1.0,
		testutil.ToFloat64(counter.WithLabelValues("audit.bomb")),
		"the recovered panic must be counted under audit.<name>")
}

// A nil panic counter is legal — panics are still recovered.
func TestRegistry_AuditAllRecoversPanicsWithoutCounter(t *testing.T) {
	r := NewRegistry()
	r.SetPanicsRecovered(nil)
	r.Register(&fakeAuditor{name: "bomb", panicVal: errors.New("kaboom")})

	got, err := r.AuditAll(context.Background(), model.Machine{})
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestRegistry_AuditAllEmptyRegistry(t *testing.T) {
	got, err := NewRegistry().AuditAll(context.Background(), model.Machine{})
	require.NoError(t, err)
	assert.Empty(t, got)
}

// Stress: many auditors, many concurrent AuditAll callers, registrations
// racing reads. The registry documents itself as safe for concurrent use —
// this is the test that keeps that claim honest under `go test -race`.
func TestRegistry_ConcurrentAuditAndRegisterStress(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 50; i++ {
		r.Register(&fakeAuditor{
			name:     fmt.Sprintf("aud-%02d", i),
			findings: []model.ConfigFinding{finding(fmt.Sprintf("c-%02d", i))},
		})
	}

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				got, err := r.AuditAll(context.Background(), model.Machine{})
				assert.NoError(t, err)
				assert.Len(t, got, 50)
				// Interleave a racing registration (same names — replacement).
				r.Register(&fakeAuditor{
					name:     fmt.Sprintf("aud-%02d", (w*10+i)%50),
					findings: []model.ConfigFinding{finding(fmt.Sprintf("c-%02d", (w*10+i)%50))},
				})
			}
		}(w)
	}
	wg.Wait()
}
