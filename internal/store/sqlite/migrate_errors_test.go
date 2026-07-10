package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
)

// TestMigrate_WrapsFailureAsCatalogE010 pins that a migration failure is
// surfaced as the catalogued KITE-E010 error with its remediation hint, while
// the underlying cause stays reachable via errors.As. Closing the store's DB
// first makes the very first migration statement fail deterministically.
func TestMigrate_WrapsFailureAsCatalogE010(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "closed.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	err = s.Migrate(context.Background())
	require.Error(t, err)

	var ke *kiteerrors.Error
	require.True(t, errors.As(err, &ke), "migration failure must be a *kiteerrors.Error")
	assert.Equal(t, "KITE-E010", ke.Code)
	assert.NotEmpty(t, ke.Hint, "hint should be populated from the catalog")
}
