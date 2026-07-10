package dashboard

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
)

// TestFormatKiteOAuthTokenError_CatalogEnvelope pins the structured envelope
// that the OAuth token endpoint produces: a catalogued KITE-E016 code, a
// non-empty remediation hint sourced from the catalog, and the HTTP status
// plus provider detail carried in error_context. This guards the iteration-1
// migration to kiteerrors.FromCatalog against regressions.
func TestFormatKiteOAuthTokenError_CatalogEnvelope(t *testing.T) {
	body := []byte(`{"error_description":"authorization code expired"}`)

	err := formatKiteOAuthTokenError(400, body)

	var ke *kiteerrors.Error
	require.True(t, errors.As(err, &ke), "token error must be a *kiteerrors.Error")
	assert.Equal(t, "KITE-E016", ke.Code)
	assert.NotEmpty(t, ke.Hint, "hint should be populated from the catalog")
	assert.Equal(t, 400, ke.Context["http_status"])
	assert.Equal(t, "authorization code expired", ke.Context["provider_detail"])
}

// TestFormatKiteOAuthTokenError_UnparseableBody ensures a non-JSON provider
// body still yields a coded error with the status, just without provider
// detail — the envelope shape must be stable even on garbage responses.
func TestFormatKiteOAuthTokenError_UnparseableBody(t *testing.T) {
	err := formatKiteOAuthTokenError(502, []byte("<html>bad gateway</html>"))

	var ke *kiteerrors.Error
	require.True(t, errors.As(err, &ke))
	assert.Equal(t, "KITE-E016", ke.Code)
	assert.Equal(t, 502, ke.Context["http_status"])
	_, hasDetail := ke.Context["provider_detail"]
	assert.False(t, hasDetail, "no provider_detail expected when the body is not JSON")
}

// TestFormatKiteOAuthTokenError_AttrsEnvelopeShape locks the exact top-level
// keys the production log site emits via kiteerrors.Attrs, so a future change
// to the envelope shape trips this test rather than silently reshaping logs.
func TestFormatKiteOAuthTokenError_AttrsEnvelopeShape(t *testing.T) {
	err := formatKiteOAuthTokenError(400, []byte(`{"error":"invalid_grant"}`))

	got := make(map[string]bool)
	for _, a := range kiteerrors.Attrs(err) {
		got[a.Key] = true
	}
	for _, key := range []string{"error_code", "error_message", "hint", "error_context"} {
		assert.Truef(t, got[key], "envelope is missing top-level field %q", key)
	}
}
