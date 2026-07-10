package safety

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
)

func TestRecover_CatchesPanic(t *testing.T) {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_panics_total",
	}, []string{"component"})

	var err error
	func() {
		defer Recover("test.source", counter, &err)
		panic("boom")
	}()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "panic in test.source: boom")

	// The recovered panic is now surfaced as the catalogued KITE-E011 error,
	// with the panic detail preserved as the cause.
	var ke *kiteerrors.Error
	require.True(t, errors.As(err, &ke), "recovered panic must be a *kiteerrors.Error")
	assert.Equal(t, kiteerrors.CodePanicRecovered, ke.Code)
	assert.NotEmpty(t, ke.Hint, "E011 remediation hint must be populated")

	val := testutil.ToFloat64(counter.With(prometheus.Labels{"component": "test.source"}))
	assert.Equal(t, float64(1), val)
}

func TestRecover_NoPanic(t *testing.T) {
	var err error
	func() {
		defer Recover("test.source", nil, &err)
	}()
	assert.NoError(t, err)
}

func TestRecover_NilRetErr(t *testing.T) {
	// Must not panic even when retErr is nil.
	func() {
		defer Recover("test.source", nil, nil)
		panic("boom")
	}()
}

func TestRecover_NilCounter(t *testing.T) {
	var err error
	func() {
		defer Recover("test.source", nil, &err)
		panic("boom")
	}()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestRecover_IncrementsCounterMultipleTimes(t *testing.T) {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_panics_multi",
	}, []string{"component"})

	for i := 0; i < 3; i++ {
		func() {
			defer Recover("multi.source", counter, nil)
			panic("repeated")
		}()
	}

	val := testutil.ToFloat64(counter.With(prometheus.Labels{"component": "multi.source"}))
	assert.Equal(t, float64(3), val)
}

func TestLogPanic(t *testing.T) {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_log_panic",
	}, []string{"component"})

	LogPanic("audit.ssh", "nil pointer", "fake stack", counter)

	val := testutil.ToFloat64(counter.With(prometheus.Labels{"component": "audit.ssh"}))
	assert.Equal(t, float64(1), val)
}

func TestLogPanic_NilCounter(t *testing.T) {
	// Must not panic with nil counter.
	LogPanic("audit.ssh", "nil pointer", "fake stack", nil)
}
