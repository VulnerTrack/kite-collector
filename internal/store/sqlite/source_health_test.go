package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/safety"
)

// TestCircuitBreakerSourceHealthWiring is the RFC-0135 R5 / Section 4.2.5
// acceptance test: it guards against a second "built but never wired" incident
// (Finding F2) by asserting both halves of the contract on real, wired
// components — (a) the breaker actually skips a source after 3 failures, and
// (b) the source_health table (created by RFC-0062, previously writer-less) has
// rows after those failures because the SQLite store is attached as the
// breaker's persister.
func TestCircuitBreakerSourceHealthWiring(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "kite.db")
	st, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	require.NoError(t, st.Migrate(context.Background()))

	cb := safety.NewCircuitBreaker(safety.CircuitBreakerConfig{
		FailureThreshold: 3,
		CooldownDuration: 5 * time.Minute,
		SuccessThreshold: 1,
	})
	// *SQLiteStore satisfies safety.HealthPersister via PersistSourceHealth.
	cb.SetPersister(st)

	// (a) The circuit opens (source is skipped) only after 3 failures.
	assert.False(t, cb.ShouldSkip("failing-source"), "healthy source must not be skipped")
	for range 3 {
		cb.RecordFailure("failing-source", "mock upstream 500")
	}
	assert.True(t, cb.ShouldSkip("failing-source"), "source must be skipped after 3 consecutive failures")

	// (b) The failure state was persisted — the regression guard: source_health
	// must have a row, not stay empty as it did before this RFC.
	var count, consecutiveFailures, totalTrips int
	var state string
	row := st.RawDB().QueryRowContext(context.Background(),
		`SELECT COUNT(*), MAX(state), MAX(consecutive_failures), MAX(total_trips)
		 FROM source_health WHERE source_name = ?`, "failing-source")
	require.NoError(t, row.Scan(&count, &state, &consecutiveFailures, &totalTrips))
	assert.Positive(t, count, "source_health must have a row after failures (F2 regression guard)")
	assert.Equal(t, "open", state)
	assert.GreaterOrEqual(t, consecutiveFailures, 3)
	assert.Positive(t, totalTrips, "a trip must have been recorded")

	// A subsequent success is persisted too, transitioning the row back healthy.
	cb.RecordSuccess("failing-source")
	var stateAfter string
	require.NoError(t, st.RawDB().QueryRowContext(context.Background(),
		`SELECT state FROM source_health WHERE source_name = ?`, "failing-source").Scan(&stateAfter))
	assert.Equal(t, "healthy", stateAfter)
}
