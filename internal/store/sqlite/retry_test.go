package sqlite

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithTransientRetry_RetriesOnIOErr(t *testing.T) {
	calls := 0
	err := withTransientRetry(3, func() error {
		calls++
		if calls < 3 {
			// Mimic the modernc.org/sqlite extended-code error string
			// observed in the field for SQLITE_IOERR_DELETE_NOENT.
			return errors.New("upsert assets: commit tx: disk I/O error (5898)")
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 3, calls, "fn must be retried until it succeeds")
}

func TestWithTransientRetry_GivesUpAfterMaxAttempts(t *testing.T) {
	calls := 0
	err := withTransientRetry(3, func() error {
		calls++
		return errors.New("upsert assets: commit tx: disk I/O error (5898)")
	})
	require.Error(t, err)
	assert.Equal(t, 3, calls, "fn must be called exactly maxAttempts times")
	assert.True(t, errors.Is(err, ErrTransientStorageExhausted),
		"err must wrap ErrTransientStorageExhausted; got %v", err)
}

func TestWithTransientRetry_DoesNotRetryNonTransient(t *testing.T) {
	calls := 0
	err := withTransientRetry(3, func() error {
		calls++
		return errors.New("syntax error near 'FROM'")
	})
	require.Error(t, err)
	assert.Equal(t, 1, calls, "non-transient errors must not be retried")
	assert.False(t, errors.Is(err, ErrTransientStorageExhausted),
		"non-transient errors must not be wrapped as transient-exhausted")
}

func TestIsTransientSQLiteErr(t *testing.T) {
	cases := []struct {
		err  error
		name string
		want bool
	}{
		{nil, "nil", false},
		{errors.New("commit tx: disk I/O error (5898)"), "ioerr_delete_noent", true},
		{errors.New("disk I/O error (1546)"), "ioerr_fsync", true},
		{errors.New("disk I/O error"), "plain ioerr", true},
		{errors.New("database is locked"), "busy", true},
		{errors.New("database table is locked"), "locked", true},
		{errors.New("Disk I/O Error"), "case insensitive", true},
		{errors.New("constraint failed"), "not transient", false},
		{errors.New("syntax error"), "syntax", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isTransientSQLiteErr(tc.err))
		})
	}
}

func TestWithTransientRetry_HappyPathSingleCall(t *testing.T) {
	calls := 0
	err := withTransientRetry(3, func() error {
		calls++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
}
