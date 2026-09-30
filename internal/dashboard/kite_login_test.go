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

func TestEnrollKiteOAuthToken_FleetLoginReusesExistingPKICredentials(t *testing.T) {
	st, err := sqlite.New(filepath.Join(t.TempDir(), "kite.db"))
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	certsDir := t.TempDir()
	for _, name := range []string{"ca.pem", "agent.pem", "agent-key.pem"} {
		require.NoError(t, os.WriteFile(filepath.Join(certsDir, name), []byte("existing"), 0o600))
	}
	pki := &fakeKitePKIEnroller{err: errors.New("PKI must not be called")}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth/callback", nil)
	req.AddCookie(&http.Cookie{Name: kiteOAuthDashboardCookie, Value: "/fleet"})
	err = enrollKiteOAuthToken(req, kiteOAuthEnrollmentOptions{
		Store: st, WrapKey: []byte("01234567890123456789012345678901"),
		CertsDir: certsDir, PKIClient: pki,
	}, "fleet-operator-token")
	require.NoError(t, err)
	assert.Empty(t, pki.token)
	identity, err := st.GetEnrolledIdentity(context.Background())
	require.NoError(t, err)
	unwrapped, err := sqlite.AEADUnwrap([]byte("01234567890123456789012345678901"), identity.ApiKeyWrapped)
	require.NoError(t, err)
	assert.Equal(t, "fleet-operator-token", string(unwrapped))
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
			wantBody:   "No se autorizó la conexión",
		},
		{
			name:       "missing code",
			rawURL:     "/oauth/callback?state=s",
			wantStatus: http.StatusBadRequest,
			wantBody:   "No se pudo completar la conexión",
		},
		{
			name:       "state mismatch",
			rawURL:     "/oauth/callback?code=c&state=wrong",
			cookies:    []*http.Cookie{{Name: kiteOAuthStateCookie, Value: "expected"}},
			wantStatus: http.StatusBadRequest,
			wantBody:   "La sesión de conexión venció",
		},
		{
			name:   "missing PKCE verifier",
			rawURL: "/oauth/callback?code=c&state=s",
			cookies: []*http.Cookie{
				{Name: kiteOAuthStateCookie, Value: "s"},
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   "No se pudo completar la conexión",
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
			assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Contains(t, rec.Body.String(), tc.wantBody)
			assert.Contains(t, rec.Body.String(), `href="/kite-login?retry=1"`)
			assert.NotContains(t, rec.Body.String(), "operator cancelled")
			assert.Empty(t, pki.token, "invalid callback must not reach PKI enrollment")
		})
	}
}

func TestKiteOAuthEnrollment_PermissionDeniedOffersFreshOrganizationSelection(t *testing.T) {
	const (
		state  = "role-denied-state"
		waitID = "role-denied-wait"
		code   = "role-denied-code"
	)
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"secret-access-token","token_type":"Bearer"}`))
	}))
	t.Cleanup(tokenServer.Close)

	st, err := sqlite.New(filepath.Join(t.TempDir(), "kite.db"))
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	oauth := OAuthOptions{AuthorizeURL: tokenServer.URL + "/authorize", ClientID: "kite-client"}
	pki := &fakeKitePKIEnroller{err: kiteerrors.FromCatalog(kiteerrors.CodeEnrollmentFailed,
		errors.New("PKI rejected enrollment")).With("http_status", http.StatusForbidden).
		With("pki_detail", "Kite enrollment is not enabled for this user")}
	rememberKiteOAuthWait(state, waitID)
	t.Cleanup(func() {
		kiteOAuthWaitStates.Delete(state)
		kiteOAuthWaits.Delete(waitID)
		kiteOAuthInflight.Delete(code)
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/oauth/callback?code="+code+"&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: kiteOAuthStateCookie, Value: state})
	req.AddCookie(&http.Cookie{Name: kiteOAuthVerifierCookie, Value: "verifier"})
	req.AddCookie(&http.Cookie{Name: kiteOAuthWaitCookie, Value: waitID})
	req.AddCookie(&http.Cookie{Name: kiteOAuthDashboardCookie, Value: "/machines"})
	rec := httptest.NewRecorder()
	serveKiteOAuthCallbackPage(rec, req, oauth, kiteOAuthEnrollmentOptions{
		PKIClient: pki, Store: st, CertsDir: t.TempDir(), WrapKey: []byte("01234567890123456789012345678901"),
	}, "test")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "Kite no está habilitado para tu usuario")
	assert.Contains(t, rec.Body.String(), "permiso de Kite en RR. HH.")
	assert.Contains(t, rec.Body.String(), "Volver a intentarlo")
	assert.NotContains(t, rec.Body.String(), "secret-access-token")
	assert.NotContains(t, rec.Body.String(), code)
	assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))
	assert.False(t, kiteOAuthWaitComplete(waitID))

	retry := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/kite-login?retry=1", nil)
	retry.AddCookie(&http.Cookie{Name: kiteOAuthWaitCookie, Value: waitID})
	retry.AddCookie(&http.Cookie{Name: kiteOAuthDashboardCookie, Value: "/machines"})
	retryRec := httptest.NewRecorder()
	serveKiteLoginPage(retryRec, retry, oauth, "test")
	assert.Equal(t, http.StatusSeeOther, retryRec.Code)
	location, err := url.Parse(retryRec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:9090/oauth/callback", location.Query().Get("redirect_uri"))
	assert.NotEqual(t, state, location.Query().Get("state"))
	assert.NotEmpty(t, location.Query().Get("code_challenge"))
	for _, cookie := range retryRec.Result().Cookies() {
		assert.NotEqual(t, kiteOAuthDashboardCookie, cookie.Name, "retry must preserve the original dashboard cookie")
	}
	newState := location.Query().Get("state")
	entry, ok := kiteOAuthWaitStates.Load(newState)
	require.True(t, ok)
	assert.Equal(t, waitID, entry.(kiteOAuthWaitState).WaitID)
	t.Cleanup(func() { kiteOAuthWaitStates.Delete(newState) })

	var newVerifier string
	for _, cookie := range retryRec.Result().Cookies() {
		if cookie.Name == kiteOAuthVerifierCookie {
			newVerifier = cookie.Value
		}
	}
	require.NotEmpty(t, newVerifier)
	pki.err = nil
	continued := httptest.NewRequest(http.MethodGet,
		"http://127.0.0.1:9090/oauth/callback?code=fresh-code&state="+newState, nil)
	continued.AddCookie(&http.Cookie{Name: kiteOAuthStateCookie, Value: newState})
	continued.AddCookie(&http.Cookie{Name: kiteOAuthVerifierCookie, Value: newVerifier})
	continued.AddCookie(&http.Cookie{Name: kiteOAuthWaitCookie, Value: waitID})
	continued.AddCookie(&http.Cookie{Name: kiteOAuthDashboardCookie, Value: "/machines"})
	continuedRec := httptest.NewRecorder()
	serveKiteOAuthCallbackPage(continuedRec, continued, oauth, kiteOAuthEnrollmentOptions{
		PKIClient: pki, Store: st, CertsDir: t.TempDir(), WrapKey: []byte("01234567890123456789012345678901"),
	}, "test")
	assert.Equal(t, http.StatusOK, continuedRec.Code)
	assert.Contains(t, continuedRec.Body.String(), "Enrollment complete")
	assert.Contains(t, continuedRec.Body.String(), "/machines?integration_prompt=1")
	assert.True(t, kiteOAuthWaitComplete(waitID))
	t.Cleanup(func() { kiteOAuthInflight.Delete("fresh-code") })
}

func TestKiteOAuthRetryLaunchURL_VisitsOrganizationSelector(t *testing.T) {
	authURL := "https://api.vulnertrack.com/auth/v1/oauth/authorize?state=new-state&code_challenge=new-challenge"
	bridgeURL := kiteOAuthRetryLaunchURL(authURL, "http://127.0.0.1:9090")
	parsed, err := url.Parse(bridgeURL)
	require.NoError(t, err)
	assert.Equal(t, "https://app.vulnertrack.com/kite/signin/oauth", parsed.Scheme+"://"+parsed.Host+parsed.Path)
	assert.Equal(t, "new-state", parsed.Query().Get("state"))
	assert.Equal(t, "new-challenge", parsed.Query().Get("code_challenge"))
	assert.Equal(t, "http://127.0.0.1:9090", parsed.Query().Get("collector"))
	assert.Empty(t, kiteOAuthRetryLaunchURL("https://untrusted.example/oauth/authorize", "http://127.0.0.1:9090"))
}

func TestKiteOAuthEnrollmentError_MissingMembership(t *testing.T) {
	err := kiteerrors.FromCatalog(kiteerrors.CodeEnrollmentFailed,
		errors.New("PKI rejected enrollment")).With("http_status", http.StatusForbidden).
		With("pki_detail", "User is not a member of this organization")
	view := kiteOAuthEnrollmentError(err, "test")
	assert.Equal(t, "No pertenecés a esta organización", view.Title)
	assert.Equal(t, "Elegir otra organización", view.ActionLabel)
}

func TestKiteOAuthRetry_UsesOrganizationBridgeBeforeAuthorize(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/kite-login?retry=1", nil)
	rec := httptest.NewRecorder()
	serveKiteLoginPage(rec, req, OAuthOptions{}, "test")
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "app.vulnertrack.com", location.Host)
	assert.Equal(t, "/kite/signin/oauth", location.Path)
	assert.NotEmpty(t, location.Query().Get("state"))
	assert.Equal(t, "http://127.0.0.1:9090", location.Query().Get("collector"))
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
