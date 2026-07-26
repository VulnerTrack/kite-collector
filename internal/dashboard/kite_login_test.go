package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/enrollment"
	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

type fakeKitePKIEnroller struct {
	agentCode string
	token     string
}

func (f *fakeKitePKIEnroller) Enroll(_ context.Context, agentCode, token string) (*enrollment.Result, error) {
	f.agentCode = agentCode
	f.token = token
	return &enrollment.Result{
		Status:             "enrolled",
		CertificateID:      "cert-1",
		CACertificate:      []byte("test-ca"),
		ClientCertificate:  []byte("test-client-cert"),
		ClientKey:          []byte("test-client-key"),
		CertificateExpires: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}, nil
}

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

func TestEnrollKiteOAuthToken_EnrollsPKIAndStoresCertificates(t *testing.T) {
	st, err := sqlite.New(filepath.Join(t.TempDir(), "kite.db"))
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	certsDir := t.TempDir()
	pki := &fakeKitePKIEnroller{}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/callback", nil)
	err = enrollKiteOAuthToken(req, kiteOAuthEnrollmentOptions{
		Store:     st,
		WrapKey:   []byte("01234567890123456789012345678901"),
		CertsDir:  certsDir,
		PKIClient: pki,
	}, "oauth-access-token")
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(pki.agentCode, "kite-"))
	assert.Equal(t, "oauth-access-token", pki.token)
	for name, want := range map[string]string{
		"ca.pem":        "test-ca",
		"agent.pem":     "test-client-cert",
		"agent-key.pem": "test-client-key",
	} {
		got, readErr := os.ReadFile(filepath.Join(certsDir, name))
		require.NoError(t, readErr)
		assert.Equal(t, want, string(got))
	}
	identity, err := st.GetEnrolledIdentity(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, identity.ApiKeyFingerprint)
	assert.NotEmpty(t, identity.ApiKeyWrapped)
}
