package identity

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
)

// TestFileErr_PermissionSurfacesCatalogE008 verifies the key-backend permission
// classification without a real chmod — which root silently bypasses, making a
// filesystem-based test flaky in CI containers. A synthetic os.ErrPermission
// wrapping error must surface KITE-E008 while staying detectable as a
// permission error with its operation context intact.
func TestFileErr_PermissionSurfacesCatalogE008(t *testing.T) {
	err := fileErr("write key file", fmt.Errorf("open /var/lib/kite/x.key: %w", os.ErrPermission))

	var ke *kiteerrors.Error
	require.True(t, errors.As(err, &ke), "permission failure must surface a *kiteerrors.Error")
	assert.Equal(t, "KITE-E008", ke.Code)
	assert.NotEmpty(t, ke.Hint)
	assert.True(t, errors.Is(err, os.ErrPermission), "must remain detectable as a permission error")
	assert.Contains(t, err.Error(), "write key file", "operation context must be preserved")
}

// TestFileErr_NonPermissionStaysGeneric guards precision: a non-permission
// filesystem error must not be mislabelled E008.
func TestFileErr_NonPermissionStaysGeneric(t *testing.T) {
	err := fileErr("read key file", errors.New("unexpected EOF"))

	var ke *kiteerrors.Error
	assert.False(t, errors.As(err, &ke), "non-permission errors must not be labelled E008")
	assert.Contains(t, err.Error(), "read key file")
}
