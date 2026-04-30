package safenet

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingObserver struct {
	events []GuardEvent
	mu     sync.Mutex
}

func (r *recordingObserver) ObserveGuardEvent(ev GuardEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingObserver) snapshot() []GuardEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]GuardEvent, len(r.events))
	copy(out, r.events)
	return out
}

func TestSetGuardObserver(t *testing.T) {
	t.Run("pagination cap fires emit guard event", func(t *testing.T) {
		obs := &recordingObserver{}
		SetGuardObserver(obs)
		t.Cleanup(func() { SetGuardObserver(nil) })

		g := NewPaginationGuardV2WithSource("heroku")
		g.MaxIterations = 1
		require.NoError(t, g.NextPage(0))
		require.Error(t, g.NextPage(0))

		events := obs.snapshot()
		require.Len(t, events, 1)
		assert.Equal(t, GuardEventType(PaginationCapIterations), events[0].GuardType)
		assert.Equal(t, GuardActionCapped, events[0].Action)
		assert.Equal(t, "heroku", events[0].SourceComponent)
	})

	t.Run("byte cap fires emit guard event with provider", func(t *testing.T) {
		obs := &recordingObserver{}
		SetGuardObserver(obs)
		t.Cleanup(func() { SetGuardObserver(nil) })

		g := &PaginationGuardV2{
			MaxIterations:   100,
			MaxBytesPerPage: 1024,
			MaxBytesTotal:   1024 * 1024,
			Source:          "wazuh",
		}
		require.Error(t, g.NextPage(2048))

		events := obs.snapshot()
		require.Len(t, events, 1)
		assert.Equal(t, GuardEventType(PaginationCapPageBytes), events[0].GuardType)
		assert.Equal(t, "wazuh", events[0].SourceComponent)
	})

	t.Run("cursor rejection emits event with provider source", func(t *testing.T) {
		obs := &recordingObserver{}
		SetGuardObserver(obs)
		t.Cleanup(func() { SetGuardObserver(nil) })

		_, err := SanitizeCursorWithSource("vultr", "bad cursor with space")
		require.Error(t, err)

		events := obs.snapshot()
		require.Len(t, events, 1)
		assert.Equal(t, GuardCursorSanitizationReject, events[0].GuardType)
		assert.Equal(t, GuardActionRejected, events[0].Action)
		assert.Equal(t, "vultr", events[0].SourceComponent)
	})

	t.Run("nil observer is a no-op", func(t *testing.T) {
		SetGuardObserver(nil)
		g := &PaginationGuardV2{MaxIterations: 1}
		require.NoError(t, g.NextPage(0))
		require.Error(t, g.NextPage(0))
	})

	t.Run("source defaults to pagination_guard when empty", func(t *testing.T) {
		obs := &recordingObserver{}
		SetGuardObserver(obs)
		t.Cleanup(func() { SetGuardObserver(nil) })

		g := &PaginationGuardV2{MaxIterations: 1}
		require.NoError(t, g.NextPage(0))
		require.Error(t, g.NextPage(0))

		events := obs.snapshot()
		require.Len(t, events, 1)
		assert.Equal(t, "pagination_guard", events[0].SourceComponent)
	})
}
