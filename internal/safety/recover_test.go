package safety

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
)

func TestRecover_CatchesPanic(t *testing.T) {
	var err error
	func() {
		defer Recover("test.source", &err)
		panic("boom")
	}()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "panic in test.source: boom")

	// The recovered panic is surfaced as the catalogued KITE-E011 error,
	// with the panic detail preserved as the cause.
	var ke *kiteerrors.Error
	require.True(t, errors.As(err, &ke), "recovered panic must be a *kiteerrors.Error")
	assert.Equal(t, kiteerrors.CodePanicRecovered, ke.Code)
	assert.NotEmpty(t, ke.Hint, "E011 remediation hint must be populated")
}

func TestRecover_NoPanic(t *testing.T) {
	var err error
	func() {
		defer Recover("test.source", &err)
	}()
	assert.NoError(t, err)
}

func TestRecover_NilRetErr(t *testing.T) {
	// Must not panic even when retErr is nil.
	func() {
		defer Recover("test.source", nil)
		panic("boom")
	}()
}

func TestRecover_RepeatedPanics(t *testing.T) {
	for i := 0; i < 3; i++ {
		var err error
		func() {
			defer Recover("multi.source", &err)
			panic("repeated")
		}()
		require.Error(t, err)
	}
}

func TestLogPanic(t *testing.T) {
	// Must not panic; the helper only logs.
	LogPanic("audit.ssh", "nil pointer", "fake stack")
}
