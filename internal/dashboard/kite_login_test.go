package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	result    *enrollment.Result
	err       error
}

func (f *fakeKitePKIEnroller) Enroll(_ context.Context, agentCode, token string) (*enrollment.Result, error) {
	f.agentCode = agentCode
	f.token = token
	if f.err != nil {
		return nil, f.err
	}
	if f.result != nil {
		return f.result, nil
	}
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

func TestEnrollKiteOAuthToken_PKIFailureDoesNotPersistIdentity(t *testing.T) {
	st, err := sqlite.New(filepath.Join(t.TempDir(), "kite.db"))
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	pkiErr := errors.New("PKI unavailable")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/callback", nil)
	err = enrollKiteOAuthToken(req, kiteOAuthEnrollmentOptions{
		Store:     st,
		WrapKey:   []byte("01234567890123456789012345678901"),
		CertsDir:  t.TempDir(),
		PKIClient: &fakeKitePKIEnroller{err: pkiErr},
	}, "oauth-access-token")

	require.Error(t, err)
	assert.ErrorIs(t, err, pkiErr)
	_, identityErr := st.GetEnrolledIdentity(context.Background())
	require.Error(t, identityErr, "PKI failure must not leave the collector marked as enrolled")
}

func TestEnrollKiteOAuthToken_CertificateWriteFailureDoesNotPersistIdentity(t *testing.T) {
	st, err := sqlite.New(filepath.Join(t.TempDir(), "kite.db"))
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	notDirectory := filepath.Join(t.TempDir(), "certs-file")
	require.NoError(t, os.WriteFile(notDirectory, []byte("not a directory"), 0o600))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/callback", nil)
	err = enrollKiteOAuthToken(req, kiteOAuthEnrollmentOptions{
		Store:     st,
		WrapKey:   []byte("01234567890123456789012345678901"),
		CertsDir:  notDirectory,
		PKIClient: &fakeKitePKIEnroller{},
	}, "oauth-access-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "store PKI certificates")
	_, identityErr := st.GetEnrolledIdentity(context.Background())
	require.Error(t, identityErr, "certificate persistence failure must not mark enrollment complete")
}

func TestEnrollKiteOAuthToken_UnexpectedPKIStatusDoesNotPersistIdentity(t *testing.T) {
	st, err := sqlite.New(filepath.Join(t.TempDir(), "kite.db"))
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/callback", nil)
	err = enrollKiteOAuthToken(req, kiteOAuthEnrollmentOptions{
		Store:    st,
		WrapKey:  []byte("01234567890123456789012345678901"),
		CertsDir: t.TempDir(),
		PKIClient: &fakeKitePKIEnroller{result: &enrollment.Result{
			Status: "pending",
		}},
	}, "oauth-access-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), `unexpected status "pending"`)
	_, identityErr := st.GetEnrolledIdentity(context.Background())
	require.Error(t, identityErr, "non-enrolled PKI response must not mark enrollment complete")
}

// TestKiteOAuthEnrollment_EndToEnd exercises the complete local enrollment
// transaction behind the browser callback: state/PKCE validation, OAuth code
// exchange, PKI issuance, certificate persistence, encrypted identity
// persistence, cookie cleanup, and terminal wait notification.
func TestKiteOAuthEnrollment_EndToEnd(t *testing.T) {
	const (
		accessToken = "oauth-access-token-e2e"
		state       = "oauth-state-e2e"
		verifier    = "pkce-verifier-e2e"
		waitID      = "terminal-wait-e2e"
	)

	var tokenForm url.Values
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		tokenForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(kiteOAuthTokenResponse{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}))
	}))
	t.Cleanup(tokenServer.Close)

	st, err := sqlite.New(filepath.Join(t.TempDir(), "kite.db"))
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	wrapKey := []byte("01234567890123456789012345678901")
	certsDir := t.TempDir()
	pki := &fakeKitePKIEnroller{}
	oauth := OAuthOptions{
		AuthorizeURL: tokenServer.URL + "/authorize",
		ClientID:     "kite-e2e-client",
		Scope:        "openid email",
		RedirectPath: "/oauth/callback",
	}

	kiteOAuthWaitStates.Delete(state)
	kiteOAuthWaits.Delete(waitID)
	kiteOAuthInflight.Delete("authorization-code-e2e")
	t.Cleanup(func() {
		kiteOAuthWaitStates.Delete(state)
		kiteOAuthWaits.Delete(waitID)
		kiteOAuthInflight.Delete("authorization-code-e2e")
	})
	rememberKiteOAuthWait(state, waitID)

	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"http://127.0.0.1:9090/oauth/callback?code=authorization-code-e2e&state="+state,
		nil,
	)
	req.AddCookie(&http.Cookie{Name: kiteOAuthStateCookie, Value: state})
	req.AddCookie(&http.Cookie{Name: kiteOAuthVerifierCookie, Value: verifier})
	req.AddCookie(&http.Cookie{Name: kiteOAuthWaitCookie, Value: waitID})
	req.AddCookie(&http.Cookie{Name: kiteOAuthDashboardCookie, Value: "/machines"})
	rec := httptest.NewRecorder()

	serveKiteOAuthCallbackPage(rec, req, oauth, kiteOAuthEnrollmentOptions{
		PKIClient:        pki,
		Store:            st,
		PlatformEndpoint: "https://otel.example.test",
		CertsDir:         certsDir,
		WrapKey:          wrapKey,
	}, "test-version")

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Enrollment complete")
	assert.Equal(t, "authorization_code", tokenForm.Get("grant_type"))
	assert.Equal(t, "authorization-code-e2e", tokenForm.Get("code"))
	assert.Equal(t, verifier, tokenForm.Get("code_verifier"))
	assert.Equal(t, "kite-e2e-client", tokenForm.Get("client_id"))
	assert.Equal(t, "http://127.0.0.1:9090/oauth/callback", tokenForm.Get("redirect_uri"))
	assert.Empty(t, tokenForm.Get("client_secret"))

	assert.Equal(t, accessToken, pki.token)
	assert.True(t, strings.HasPrefix(pki.agentCode, "kite-"))
	for name, want := range map[string]string{
		"ca.pem":        "test-ca",
		"agent.pem":     "test-client-cert",
		"agent-key.pem": "test-client-key",
	} {
		got, readErr := os.ReadFile(filepath.Join(certsDir, name))
		require.NoError(t, readErr)
		assert.Equal(t, want, string(got))
	}

	stored, err := st.GetEnrolledIdentity(context.Background())
	require.NoError(t, err)
	assert.Equal(t, sqlite.APIKeyFingerprint(accessToken), stored.ApiKeyFingerprint)
	unwrapped, err := sqlite.AEADUnwrap(wrapKey, stored.ApiKeyWrapped)
	require.NoError(t, err)
	assert.Equal(t, accessToken, string(unwrapped))
	assert.False(t, stored.FirstEnrolledAt.IsZero())
	assert.False(t, stored.LastEnrolledAt.IsZero())
	assert.True(t, kiteOAuthWaitComplete(waitID))

	cleared := map[string]bool{}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.MaxAge < 0 {
			cleared[cookie.Name] = true
		}
	}
	for _, name := range []string{
		kiteOAuthStateCookie,
		kiteOAuthVerifierCookie,
		kiteOAuthDashboardCookie,
		kiteOAuthWaitCookie,
	} {
		assert.Truef(t, cleared[name], "OAuth cookie %s was not cleared", name)
	}
}

func TestKiteOAuthCallback_RejectsInvalidInputsBeforeEnrollment(t *testing.T) {
	tests := []struct {
		name       string
		rawURL     string
		cookies    []*http.Cookie
		wantStatus int
		wantBody   string
	}{
		{
			name:       "provider denial",
			rawURL:     "/oauth/callback?error=access_denied&error_description=operator+cancelled",
			wantStatus: http.StatusBadRequest,
			wantBody:   "operator cancelled",
		},
		{
			name:       "missing code",
			rawURL:     "/oauth/callback?state=s",
			wantStatus: http.StatusBadRequest,
			wantBody:   "missing code",
		},
		{
			name:       "state mismatch",
			rawURL:     "/oauth/callback?code=c&state=wrong",
			cookies:    []*http.Cookie{{Name: kiteOAuthStateCookie, Value: "expected"}},
			wantStatus: http.StatusBadRequest,
			wantBody:   "state mismatch",
		},
		{
			name:   "missing PKCE verifier",
			rawURL: "/oauth/callback?code=c&state=s",
			cookies: []*http.Cookie{
				{Name: kiteOAuthStateCookie, Value: "s"},
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   "PKCE verifier is missing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pki := &fakeKitePKIEnroller{}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.rawURL, nil)
			for _, cookie := range tc.cookies {
				req.AddCookie(cookie)
			}
			rec := httptest.NewRecorder()

			serveKiteOAuthCallbackPage(rec, req, OAuthOptions{}, kiteOAuthEnrollmentOptions{
				PKIClient: pki,
			}, "test")

			assert.Equal(t, tc.wantStatus, rec.Code)
			assert.Contains(t, rec.Body.String(), tc.wantBody)
			assert.Empty(t, pki.token, "invalid callback must not reach PKI enrollment")
		})
	}
}

func TestEnrollKiteOAuthToken_ReenrollmentRotatesCredentialsAndPreservesFirstEnrollment(t *testing.T) {
	st, err := sqlite.New(filepath.Join(t.TempDir(), "kite.db"))
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	wrapKey := []byte("01234567890123456789012345678901")
	certsDir := t.TempDir()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/callback", nil)

	firstPKI := &fakeKitePKIEnroller{result: &enrollment.Result{
		Status:            "enrolled",
		CACertificate:     []byte("ca-v1"),
		ClientCertificate: []byte("cert-v1"),
		ClientKey:         []byte("key-v1"),
	}}
	require.NoError(t, enrollKiteOAuthToken(req, kiteOAuthEnrollmentOptions{
		Store: st, WrapKey: wrapKey, CertsDir: certsDir, PKIClient: firstPKI,
	}, "token-v1"))
	first, err := st.GetEnrolledIdentity(context.Background())
	require.NoError(t, err)

	time.Sleep(time.Millisecond)
	secondPKI := &fakeKitePKIEnroller{result: &enrollment.Result{
		Status:            "enrolled",
		CACertificate:     []byte("ca-v2"),
		ClientCertificate: []byte("cert-v2"),
		ClientKey:         []byte("key-v2"),
	}}
	require.NoError(t, enrollKiteOAuthToken(req, kiteOAuthEnrollmentOptions{
		Store: st, WrapKey: wrapKey, CertsDir: certsDir, PKIClient: secondPKI,
	}, "token-v2"))
	second, err := st.GetEnrolledIdentity(context.Background())
	require.NoError(t, err)

	assert.Equal(t, first.FirstEnrolledAt, second.FirstEnrolledAt)
	assert.True(t, second.LastEnrolledAt.After(first.LastEnrolledAt))
	assert.Equal(t, sqlite.APIKeyFingerprint("token-v2"), second.ApiKeyFingerprint)
	unwrapped, err := sqlite.AEADUnwrap(wrapKey, second.ApiKeyWrapped)
	require.NoError(t, err)
	assert.Equal(t, "token-v2", string(unwrapped))
	for name, want := range map[string]string{
		"ca.pem":        "ca-v2",
		"agent.pem":     "cert-v2",
		"agent-key.pem": "key-v2",
	} {
		got, readErr := os.ReadFile(filepath.Join(certsDir, name))
		require.NoError(t, readErr)
		assert.Equal(t, want, string(got))
	}
}
