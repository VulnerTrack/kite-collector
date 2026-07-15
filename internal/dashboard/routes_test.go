package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// helper: build a Serve()-backed handler using the in-memory test store and
// no scan coordinator (read-only mode is fine — we never trigger a scan).
func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	st := testStore(t)
	rc := testContext()
	srv := Serve(":0", st, rc, nil, Options{})
	return srv.Handler
}

// TestRoute_GET_AssetsPlain_ReturnsFullShell — GET /assets without HX-Request
// MUST return the full HTML shell (so refresh / share-link / direct-load
// work) AND embed the Assets fragment so the page is usable on first paint.
// The Assets nav link MUST carry the `active` class; the others MUST NOT.
func TestRoute_GET_AssetsPlain_ReturnsFullShell(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/assets", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "<html", "plain GET should return full shell")
	assert.Contains(t, body, "<h2>Assets", "shell should embed initial assets fragment")
	// Assets link active.
	assert.True(t,
		strings.Contains(body, `href="/assets" hx-get="/assets" hx-target="#content" hx-push-url="true" class="active"`),
		"Assets link should have active class; got body=%s", body)
	// Other tabs MUST NOT be active.
	for _, other := range []string{"/software", "/findings", "/scans", "/tables"} {
		needle := `href="` + other + `" hx-get="` + other + `" hx-target="#content" hx-push-url="true" class="active"`
		assert.NotContains(t, body, needle, "%s link must not be active on /assets", other)
	}
}

// TestRoute_GET_AssetsHTMXOnly_ReturnsFragmentOnly — GET /assets with the
// HX-Request header MUST return only the fragment HTML (no <html>), so
// HTMX can swap it directly into #content without nesting a full doc.
func TestRoute_GET_AssetsHTMXOnly_ReturnsFragmentOnly(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/assets", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "<h2>Assets", "fragment must contain the assets header")
	assert.NotContains(t, body, "<html", "HX-Request must NOT include the full shell")
}

// TestRoute_GET_FindingsPlain_HasActiveOnFindingsLink — sanity-check that
// ActiveTab routes through cleanly: /findings plain marks Findings active
// and nothing else.
func TestRoute_GET_FindingsPlain_HasActiveOnFindingsLink(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/findings", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body,
		`href="/findings" hx-get="/findings" hx-target="#content" hx-push-url="true" class="active"`,
		"Findings link should be active")
	for _, other := range []string{"/assets", "/software", "/scans", "/tables"} {
		needle := `href="` + other + `" hx-get="` + other + `" hx-target="#content" hx-push-url="true" class="active"`
		assert.NotContains(t, body, needle, "%s link must not be active on /findings", other)
	}
}

// TestRoute_GET_Root_RedirectsToOnboardingWhenUnenrolled — GET / on a fresh
// host (no enrolled identity) lands on /onboarding so the operator sees the
// install + enroll flow immediately instead of an empty /assets page.
func TestRoute_GET_Root_RedirectsToOnboardingWhenUnenrolled(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code,
		"root should 307-redirect")
	assert.Equal(t, "/onboarding", rec.Header().Get("Location"),
		"fresh store with no enrolled identity should land on /onboarding")
}

// TestRoute_GET_Root_RedirectsToAssetsWhenEnrolled — once the identity slot
// is populated, the root redirect flips to /assets so reload / share-link /
// browser-back land on the steady-state home.
func TestRoute_GET_Root_RedirectsToAssetsWhenEnrolled(t *testing.T) {
	st := testStore(t)
	sqliteStore, ok := st.(*sqlite.SQLiteStore)
	require.True(t, ok, "test store must be a SQLite store")
	require.NoError(t, sqliteStore.UpsertEnrolledIdentity(context.Background(), sqlite.EnrolledIdentity{
		ApiKeyFingerprint: "enrolled-fingerprint",
		ApiKeyWrapped:     []byte("wrapped-blob"),
		LastEnrolledAt:    time.Now().UTC(),
	}))

	srv := Serve(":0", st, testContext(), nil, Options{})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)
	assert.Equal(t, "/assets", rec.Header().Get("Location"),
		"enrolled host should land on /assets, the steady-state home")
}

func TestRoute_GET_KiteLogin_RedirectsToAuthorize(t *testing.T) {
	st := testStore(t)
	rc := testContext()
	srv := Serve(":0", st, rc, nil, Options{
		OAuth: OAuthOptions{
			AuthorizeURL: "https://api.example.test/auth/v1/oauth/authorize",
			ClientID:     "kite-client-id",
			Scope:        "openid email",
			RedirectPath: "/oauth/callback",
		},
	})
	handler := srv.Handler
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/kite-login?collector=http%3A%2F%2F127.0.0.1%3A9090", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	authHref := rec.Header().Get("Location")
	require.NotEmpty(t, authHref)
	assert.True(t, strings.HasPrefix(authHref, "https://api.example.test/auth/v1/oauth/authorize?"))
	authURL, err := url.Parse(authHref)
	require.NoError(t, err)
	q := authURL.Query()
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, "kite-client-id", q.Get("client_id"))
	assert.Equal(t, "http://127.0.0.1:9090/oauth/callback", q.Get("redirect_uri"))
	assert.Equal(t, "openid email", q.Get("scope"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.NotEmpty(t, q.Get("state"))
	assert.NotEmpty(t, q.Get("code_challenge"))

	var stateCookie, verifierCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case kiteOAuthStateCookie:
			stateCookie = c
		case kiteOAuthVerifierCookie:
			verifierCookie = c
		}
	}
	require.NotNil(t, stateCookie)
	require.NotNil(t, verifierCookie)
	assert.Equal(t, q.Get("state"), stateCookie.Value)
	assert.Equal(t, q.Get("code_challenge"), codeChallengeS256(verifierCookie.Value))
	assert.True(t, stateCookie.HttpOnly)
	assert.True(t, verifierCookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, stateCookie.SameSite)
}

func TestRoute_GET_KiteSuccess_ReturnsAccessGrantedPage(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/kite-success", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `<body class="kite-success-page">`)
	assert.Contains(t, body, "Success!")
	assert.Contains(t, body, "You've granted Kite Collector access")
	assert.Contains(t, body, "Go to Dashboard")
	assert.Contains(t, body, `href="/assets"`)
}

func TestRoute_GET_RootWithOAuthParams_ReturnsAccessGrantedPage(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(tokenServer.Close)

	st := testStore(t)
	rc := testContext()
	srv := Serve(":0", st, rc, nil, Options{
		OAuth: OAuthOptions{
			AuthorizeURL: tokenServer.URL + "/authorize",
			ClientID:     "test-client",
			RedirectPath: "/oauth/callback",
		},
	})
	handler := srv.Handler

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/?state=abc&code=xyz", nil)
	req.AddCookie(&http.Cookie{Name: kiteOAuthStateCookie, Value: "abc"})
	req.AddCookie(&http.Cookie{Name: kiteOAuthVerifierCookie, Value: "verifier"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `<body class="kite-success-page">`)
	assert.Contains(t, body, "Go to Dashboard")
}

func TestRoute_GET_RootWithOAuthParams_RejectsStateMismatch(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/?state=abc&code=xyz", nil)
	req.AddCookie(&http.Cookie{Name: kiteOAuthStateCookie, Value: "different"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "state mismatch")
}

func hrefWithPrefix(t *testing.T, body, prefix string) string {
	t.Helper()
	idx := strings.Index(body, `href="`+prefix)
	require.NotEqual(t, -1, idx, "body should contain href prefix %q", prefix)
	start := idx + len(`href="`)
	end := strings.Index(body[start:], `"`)
	require.NotEqual(t, -1, end)
	return body[start : start+end]
}

// TestRoute_GET_TablesByName_Plain_ReturnsFullShellWithTableContent — a
// drill-in URL like /tables/scan_runs (a table the migration always creates)
// MUST also return the full shell with the Tables nav highlighted and the
// table-detail fragment embedded.
func TestRoute_GET_TablesByName_Plain_ReturnsFullShellWithTableContent(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tables/scan_runs", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "<html", "plain GET on /tables/{name} should return full shell")
	assert.Contains(t, body, "scan_runs", "shell should embed the table-detail fragment")
	// Tables nav link is active for any table-drill URL.
	assert.Contains(t, body,
		`href="/tables" hx-get="/tables" hx-target="#content" hx-push-url="true" class="active"`,
		"Tables nav link should be active when drilling into a table")
}

// TestRoute_GET_TablesByName_HTMX_ReturnsFragmentOnly — same URL with
// HX-Request returns only the table-detail fragment (no shell).
func TestRoute_GET_TablesByName_HTMX_ReturnsFragmentOnly(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tables/scan_runs", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "scan_runs")
	assert.NotContains(t, body, "<html", "HX-Request must NOT include the shell")
}

// TestRoute_GET_NavLinks_HavePushURLTrue — every primary nav link MUST set
// hx-push-url="true" (so HTMX history restores correctly on back/forward)
// AND have a matching href= for non-JS / right-click fallbacks.
func TestRoute_GET_NavLinks_HavePushURLTrue(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/assets", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	for _, tab := range []string{"/assets", "/software", "/findings", "/scans", "/tables"} {
		// Both the href fallback and the HTMX push must be set on the
		// same anchor — that is what makes browser back/forward and
		// JS-disabled clients both work.
		hxAttr := `hx-get="` + tab + `"`
		hrefAttr := `href="` + tab + `"`
		pushAttr := `hx-push-url="true"`
		assert.Contains(t, body, hxAttr, "nav link to %s should use canonical hx-get", tab)
		assert.Contains(t, body, hrefAttr, "nav link to %s should expose href fallback", tab)
		assert.Contains(t, body, pushAttr, "nav link to %s should push URL into history", tab)
	}
}
