package safenet

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPaginationGuardV2_NextPage(t *testing.T) {
	t.Run("zero-value guard uses defaults", func(t *testing.T) {
		var g PaginationGuardV2
		require.NoError(t, g.NextPage(1024))
		assert.Equal(t, 1, g.Iterations())
		assert.Equal(t, int64(1024), g.BytesTotal())
	})

	t.Run("rejects iteration cap", func(t *testing.T) {
		g := &PaginationGuardV2{
			MaxIterations:   3,
			MaxBytesPerPage: DefaultMaxBytesPerPage,
			MaxBytesTotal:   DefaultMaxBytesTotal,
		}
		require.NoError(t, g.NextPage(0))
		require.NoError(t, g.NextPage(0))
		require.NoError(t, g.NextPage(0))
		err := g.NextPage(0)
		require.Error(t, err)
		var pe *PaginationGuardError
		require.True(t, errors.As(err, &pe))
		assert.Equal(t, PaginationCapIterations, pe.Reason)
	})

	t.Run("rejects per-page byte cap", func(t *testing.T) {
		g := &PaginationGuardV2{
			MaxIterations:   100,
			MaxBytesPerPage: 1024,
			MaxBytesTotal:   1024 * 1024,
		}
		err := g.NextPage(2048)
		require.Error(t, err)
		var pe *PaginationGuardError
		require.True(t, errors.As(err, &pe))
		assert.Equal(t, PaginationCapPageBytes, pe.Reason)
	})

	t.Run("rejects cumulative byte cap", func(t *testing.T) {
		g := &PaginationGuardV2{
			MaxIterations:   100,
			MaxBytesPerPage: 10_000,
			MaxBytesTotal:   15_000,
		}
		require.NoError(t, g.NextPage(8000))
		err := g.NextPage(8000)
		require.Error(t, err)
		var pe *PaginationGuardError
		require.True(t, errors.As(err, &pe))
		assert.Equal(t, PaginationCapTotalBytes, pe.Reason)
	})

	t.Run("rejects negative pageBytes", func(t *testing.T) {
		var g PaginationGuardV2
		err := g.NextPage(-1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "negative")
	})

	t.Run("Next is shim for NextPage(0)", func(t *testing.T) {
		g := &PaginationGuardV2{MaxIterations: 2}
		require.NoError(t, g.Next())
		require.NoError(t, g.Next())
		require.Error(t, g.Next())
		assert.Equal(t, int64(0), g.BytesTotal())
	})

	t.Run("NewPaginationGuardV2 honors env", func(t *testing.T) {
		t.Setenv("KITE_PAGINATION_MAX_BYTES_PER_PAGE", "1024")
		t.Setenv("KITE_PAGINATION_MAX_BYTES_TOTAL", "2048")
		g := NewPaginationGuardV2()
		assert.Equal(t, MaxPaginationIterations, g.MaxIterations)
		assert.Equal(t, int64(1024), g.MaxBytesPerPage)
		assert.Equal(t, int64(2048), g.MaxBytesTotal)
	})
}

func TestPaginationCapsFromEnv(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		t.Setenv("KITE_PAGINATION_MAX_BYTES_PER_PAGE", "")
		t.Setenv("KITE_PAGINATION_MAX_BYTES_TOTAL", "")
		perPage, total := PaginationCapsFromEnv()
		assert.Equal(t, DefaultMaxBytesPerPage, perPage)
		assert.Equal(t, DefaultMaxBytesTotal, total)
	})

	t.Run("override when set", func(t *testing.T) {
		t.Setenv("KITE_PAGINATION_MAX_BYTES_PER_PAGE", "5242880")
		t.Setenv("KITE_PAGINATION_MAX_BYTES_TOTAL", "52428800")
		perPage, total := PaginationCapsFromEnv()
		assert.Equal(t, int64(5242880), perPage)
		assert.Equal(t, int64(52428800), total)
	})
}
