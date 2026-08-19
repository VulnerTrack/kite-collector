package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
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

// TestRoute_GET_MachinesPlain_ReturnsFullShell — GET /machines without HX-Request
// MUST return the full HTML shell (so refresh / share-link / direct-load
// work) AND embed the Machines fragment so the page is usable on first paint.
// The Machines nav link MUST carry the `active` class; the others MUST NOT.
func TestRoute_GET_MachinesPlain_ReturnsFullShell(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/machines", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "<html", "plain GET should return full shell")
	assert.Contains(t, body, "<h2>Machines", "shell should embed initial machines fragment")
	// Machines link active.
	assert.True(t,
		strings.Contains(body, `href="/machines" hx-get="/machines" hx-target="#content" hx-push-url="true" class="active sidenav-resource"`),
		"Machines link should have active class; got body=%s", body)
	// Other tabs MUST NOT be active.
	for _, other := range []string{"/software", "/findings", "/scans", "/tables"} {
		needle := `href="` + other + `" hx-get="` + other + `" hx-target="#content" hx-push-url="true" class="active sidenav-resource"`
		assert.NotContains(t, body, needle, "%s link must not be active on /machines", other)
	}
}

// TestRoute_GET_MachinesHTMXOnly_ReturnsFragmentOnly — GET /machines with the
// HX-Request header MUST return only the fragment HTML (no <html>), so
// HTMX can swap it directly into #content without nesting a full doc.
func TestRoute_GET_MachinesHTMXOnly_ReturnsFragmentOnly(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/machines", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "<h2>Machines", "fragment must contain the machines header")
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
		`href="/findings" hx-get="/findings" hx-target="#content" hx-push-url="true" class="active sidenav-resource"`,
		"Findings link should be active")
	for _, other := range []string{"/machines", "/software", "/scans", "/tables"} {
		needle := `href="` + other + `" hx-get="` + other + `" hx-target="#content" hx-push-url="true" class="active sidenav-resource"`
		assert.NotContains(t, body, needle, "%s link must not be active on /findings", other)
	}
}

// TestRoute_GET_Root_RedirectsToOnboardingWhenUnenrolled — GET / on a fresh
// host (no enrolled identity) lands on /onboarding so the operator sees the
// install + enroll flow immediately instead of an empty /machines page.
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

// TestRoute_GET_Root_RedirectsToMachinesWhenEnrolled — once the identity slot
// is populated, the root redirect flips to /machines so reload / share-link /
// browser-back land on the steady-state home.
func TestRoute_GET_Root_RedirectsToMachinesWhenEnrolled(t *testing.T) {
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
	assert.Equal(t, "/machines", rec.Header().Get("Location"),
		"enrolled host should land on /machines, the steady-state home")
}

func TestRoute_GET_KiteLogin_RendersManualSignInByDefault(t *testing.T) {
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

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `<body class="kite-auth-page">`)
	assert.Contains(t, body, `>Sign In</a>`)
	assert.Contains(t, body, `href="https://api.example.test/auth/v1/oauth/authorize?`)
	assert.Empty(t, rec.Header().Get("Location"))

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
	assert.True(t, stateCookie.HttpOnly)
	assert.True(t, verifierCookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, stateCookie.SameSite)
}

func TestRoute_GET_KiteLogin_WithWaitIDRedirectsToAuthorize(t *testing.T) {
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
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/kite-login?collector=http%3A%2F%2F127.0.0.1%3A9090&wait_id=terminal-flow", nil)
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
	var waitCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case kiteOAuthStateCookie:
			stateCookie = c
		case kiteOAuthVerifierCookie:
			verifierCookie = c
		case kiteOAuthWaitCookie:
			waitCookie = c
		}
	}
	require.NotNil(t, stateCookie)
	require.NotNil(t, verifierCookie)
	require.NotNil(t, waitCookie)
	assert.Equal(t, q.Get("state"), stateCookie.Value)
	assert.Equal(t, q.Get("code_challenge"), codeChallengeS256(verifierCookie.Value))
	assert.Equal(t, "terminal-flow", waitCookie.Value)
	assert.True(t, stateCookie.HttpOnly)
	assert.True(t, verifierCookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, stateCookie.SameSite)
}

func TestOAuthWaitCompletesFromValidatedStateWithoutAuxiliaryCookie(t *testing.T) {
	const (
		state  = "validated-oauth-state"
		waitID = "terminal-flow-without-cookie"
	)
	kiteOAuthWaitStates.Delete(state)
	kiteOAuthWaits.Delete(waitID)
	t.Cleanup(func() {
		kiteOAuthWaitStates.Delete(state)
		kiteOAuthWaits.Delete(waitID)
	})

	rememberKiteOAuthWait(state, waitID)
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/callback?code=test-code&state="+state,
		nil,
	)
	req.AddCookie(&http.Cookie{
		Name:  kiteOAuthWaitCookie,
		Value: "stale-terminal-flow",
	})

	markKiteOAuthWaitComplete(req, state)

	assert.True(t, kiteOAuthWaitComplete(waitID))
	assert.False(t, kiteOAuthWaitComplete("stale-terminal-flow"))
}

func TestOAuthWaitDoesNotCompleteForUnknownState(t *testing.T) {
	const (
		state  = "expected-state"
		waitID = "terminal-flow-unknown-state"
	)
	kiteOAuthWaitStates.Delete(state)
	kiteOAuthWaits.Delete(waitID)
	t.Cleanup(func() {
		kiteOAuthWaitStates.Delete(state)
		kiteOAuthWaits.Delete(waitID)
	})
	rememberKiteOAuthWait(state, waitID)

	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth/callback?code=test-code&state=unknown",
		nil,
	)

	markKiteOAuthWaitComplete(req, "unknown")

	assert.False(t, kiteOAuthWaitComplete(waitID))
}

func TestRoute_GET_KiteSuccess_ReturnsWelcomePage(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/kite-success", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `<body class="kite-success-page">`)
	assert.Contains(t, body, "Welcome to Kite!")
	assert.Contains(t, body, "Enrollment complete.")
	assert.Contains(t, body, "Kite is ready.")
	assert.Contains(t, body, "Go to Dashboard")
	assert.Contains(t, body, `href="/machines"`)
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
		`href="/tables" hx-get="/tables" hx-target="#content" hx-push-url="true" class="active sidenav-resource"`,
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
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/machines", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	for _, tab := range []string{"/machines", "/software", "/findings", "/scans", "/tables"} {
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

// seedFacetMachines inserts machines with a known os_family split (2 linux,
// 1 windows, 1 empty) so facet tests can assert exact bucket counts.
func seedFacetMachines(t *testing.T, st store.Store) {
	t.Helper()
	now := time.Now().UTC()
	machines := []model.Machine{
		{Hostname: "facet-linux-a", OSFamily: "linux"},
		{Hostname: "facet-linux-b", OSFamily: "linux"},
		{Hostname: "facet-windows", OSFamily: "windows"},
		{Hostname: "facet-blank", OSFamily: ""},
	}
	for i := range machines {
		machines[i].ID = uuid.Must(uuid.NewV7())
		machines[i].MachineType = model.MachineTypeServer
		machines[i].DiscoverySource = "test"
		machines[i].IsAuthorized = model.AuthorizationUnknown
		machines[i].IsManaged = model.ManagedUnknown
		machines[i].FirstSeenAt = now
		machines[i].LastSeenAt = now
	}
	_, _, err := st.UpsertMachines(context.Background(), machines)
	require.NoError(t, err)
}

// TestRoute_GET_TablesByName_RendersFacetsAndSQLStrip — the table grid must
// carry the facet rail (low-cardinality columns with value counts) and the
// copyable SQL strip showing the query behind the grid.
func TestRoute_GET_TablesByName_RendersFacetsAndSQLStrip(t *testing.T) {
	st := testStore(t)
	seedFacetMachines(t, st)
	handler := Serve(":0", st, testContext(), nil, Options{}).Handler

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tables/machines", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `class="sql-strip"`, "grid must show its SQL")
	assert.Contains(t, body, "SELECT * FROM machines", "SQL strip carries the query text")
	assert.Contains(t, body, `class="facet-rail"`, "facet rail must render")
	assert.Contains(t, body, "os_family", "os_family is low-cardinality and must be faceted")
	assert.Contains(t, body, "fcol=os_family", "facet values link to the filtered grid")
}

// TestRoute_GET_TablesByName_FacetFilterAppliesWhere — selecting a facet
// value filters the grid: the row count reflects matches only, the active
// filter chip renders, and the SQL strip shows the WHERE clause.
func TestRoute_GET_TablesByName_FacetFilterAppliesWhere(t *testing.T) {
	st := testStore(t)
	seedFacetMachines(t, st)
	handler := Serve(":0", st, testContext(), nil, Options{}).Handler

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/tables/machines?fcol=os_family&fval=linux", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "(2 rows matching)", "filtered total counts matches only")
	assert.Contains(t, body, `class="facet-active-chip"`, "active filter chip renders")
	assert.Contains(t, body, "WHERE os_family = &#39;linux&#39;", "SQL strip shows the WHERE clause")

	// The empty value selects the NULL-or-'' bucket.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/tables/machines?fcol=os_family&fval=", nil)
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "(1 rows matching)")
}

// seedMachineResource inserts one machine with a finding and a software row
// and returns its id, for machine-page tests.
func seedMachineResource(t *testing.T, st store.Store) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	id := uuid.Must(uuid.NewV7())
	_, _, err := st.UpsertMachines(ctx, []model.Machine{{
		ID:              id,
		Hostname:        "resource-host",
		MachineType:     model.MachineTypeWorkstation,
		OSFamily:        "linux",
		OSVersion:       "arch",
		DiscoverySource: "test",
		IsAuthorized:    model.AuthorizationAuthorized,
		IsManaged:       model.ManagedManaged,
		FirstSeenAt:     now,
		LastSeenAt:      now,
	}})
	require.NoError(t, err)

	require.NoError(t, st.UpsertSoftware(ctx, id, []model.InstalledSoftware{{
		SoftwareName: "openssh", Version: "9.8p1",
	}}))

	runID := uuid.Must(uuid.NewV7())
	require.NoError(t, st.CreateScanRun(ctx, model.ScanRun{
		ID: runID, StartedAt: now, Status: model.ScanStatusCompleted,
	}))
	require.NoError(t, st.InsertFindings(ctx, []model.ConfigFinding{{
		ID: uuid.Must(uuid.NewV7()), MachineID: id, ScanRunID: runID,
		Auditor: "test-auditor", CheckID: "KITE-TEST-001",
		Title: "SSH root login permitted", Severity: model.SeverityCritical,
		Timestamp: now,
	}}))
	return id
}

// TestRoute_GET_MachineByID_OverviewRendersIdentityAndPreviews — the machine
// page shows breadcrumb, identity header with badges, counted tabs, and the
// overview previews for findings and software.
func TestRoute_GET_MachineByID_OverviewRendersIdentityAndPreviews(t *testing.T) {
	st := testStore(t)
	id := seedMachineResource(t, st)
	handler := Serve(":0", st, testContext(), nil, Options{}).Handler

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/machines/"+id.String(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "<html", "plain GET returns the full shell")
	assert.Contains(t, body, "resource-host")
	assert.Contains(t, body, `class="machine-breadcrumb"`)
	assert.Contains(t, body, "SSH root login permitted", "overview shows the findings preview")
	assert.Contains(t, body, "openssh", "overview shows the software preview")
	assert.Contains(t, body, `?tab=findings`, "tabs link to related resources")
	// Machines nav link stays active for the drill-in page.
	assert.Contains(t, body,
		`href="/machines" hx-get="/machines" hx-target="#content" hx-push-url="true" class="active sidenav-resource"`)
}

// TestRoute_GET_MachineByID_SoftwareTab — ?tab=software renders the full
// software grid for the machine.
func TestRoute_GET_MachineByID_SoftwareTab(t *testing.T) {
	st := testStore(t)
	id := seedMachineResource(t, st)
	handler := Serve(":0", st, testContext(), nil, Options{}).Handler

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/machines/"+id.String()+"?tab=software", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "openssh")
	assert.Contains(t, body, "9.8p1")
	assert.NotContains(t, body, "<html", "HX-Request returns the fragment only")
}

// TestRoute_GET_MachineByID_UnknownIDReturns404 — a well-formed but unknown
// id 404s; a malformed id 404s without hitting the store.
func TestRoute_GET_MachineByID_UnknownIDReturns404(t *testing.T) {
	st := testStore(t)
	handler := Serve(":0", st, testContext(), nil, Options{}).Handler

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/machines/"+uuid.Must(uuid.NewV7()).String(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/machines/not-a-uuid", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestRoute_GET_ViewBySlug_BuiltinLeftJoinRendersSQLAndRows — the built-in
// "Machine findings coverage" view renders its description, the join SQL,
// and — because it is a LEFT JOIN — keeps machines that have no findings.
func TestRoute_GET_ViewBySlug_BuiltinLeftJoinRendersSQLAndRows(t *testing.T) {
	st := testStore(t)
	seedMachineResource(t, st) // resource-host: one finding
	// A machine with no findings must still appear in the left join.
	_, _, err := st.UpsertMachines(context.Background(), []model.Machine{{
		ID: uuid.Must(uuid.NewV7()), Hostname: "clean-host",
		MachineType: model.MachineTypeServer, DiscoverySource: "test",
		IsAuthorized: model.AuthorizationUnknown, IsManaged: model.ManagedUnknown,
		FirstSeenAt: time.Now().UTC(), LastSeenAt: time.Now().UTC(),
	}})
	require.NoError(t, err)
	handler := Serve(":0", st, testContext(), nil, Options{}).Handler

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/views/machine-findings-coverage", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Machine findings coverage")
	assert.Contains(t, body, "LEFT JOIN config_findings", "the SQL behind the view stays visible")
	assert.Contains(t, body, "resource-host")
	assert.Contains(t, body, "SSH root login permitted")
	assert.Contains(t, body, "clean-host", "left join keeps machines with no findings")

	// Unknown slugs 404.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/views/nope", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestRoute_ViewBuilder_PreviewAndSave — the builder renders with FK-derived
// defaults, previews the join, and Save persists a view that then renders at
// its own URL and appears in the sidebar tree.
func TestRoute_ViewBuilder_PreviewAndSave(t *testing.T) {
	st := testStore(t)
	seedMachineResource(t, st)
	handler := Serve(":0", st, testContext(), nil, Options{}).Handler

	// Builder page with defaults.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/views/new", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `id="view-builder"`)
	assert.Contains(t, body, "Left &mdash; keep all", "join type is a plain-language toggle")

	// Save a view.
	form := url.Values{
		"base":     {"machines"},
		"join":     {"config_findings"},
		"jointype": {"left"},
		"onbase":   {"id"},
		"onjoin":   {"machine_id"},
		"cols":     {"machines.hostname", "config_findings.title"},
		"name":     {"Findings per host"},
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/views", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "/views/findings-per-host", rec.Header().Get("HX-Redirect"))

	// The saved view renders at its slug.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/views/findings-per-host", nil)
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "resource-host")

	// And appears in the counted sidebar tree.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/fragments/sidebar-tree", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Findings per host")

	// A validation problem re-renders the builder with the error inline.
	form.Set("name", "")
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/views", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "name this view before saving")
}

// fakeTableSource is an extra read-only table backend for transparency
// tests: the dashboard must render its tables exactly like store tables.
type fakeTableSource struct {
	tables  []store.TableSchema
	rows    map[string][]store.Row
	listErr error
}

func (f *fakeTableSource) ListContentTables(context.Context) ([]store.TableSchema, error) {
	return f.tables, f.listErr
}

func (f *fakeTableSource) DescribeTable(_ context.Context, table string) (*store.TableSchema, error) {
	for i := range f.tables {
		if f.tables[i].Name == table {
			return &f.tables[i], nil
		}
	}
	return nil, store.ErrUnknownTable
}

func (f *fakeTableSource) ListRows(_ context.Context, filter store.RowsFilter) ([]store.Row, int64, error) {
	if _, err := f.DescribeTable(context.Background(), filter.Table); err != nil {
		return nil, 0, err
	}
	rows := f.rows[filter.Table]
	return rows, int64(len(rows)), nil
}

func (f *fakeTableSource) FacetTable(_ context.Context, table string, _, _ int) ([]store.ColumnFacet, error) {
	if _, err := f.DescribeTable(context.Background(), table); err != nil {
		return nil, err
	}
	return []store.ColumnFacet{{Column: "state", Distinct: 2, Values: []store.FacetValue{
		{Value: "running", Count: 3}, {Value: "sleeping", Count: 1},
	}}}, nil
}

func osqueryLikeSource() *fakeTableSource {
	return &fakeTableSource{
		tables: []store.TableSchema{{
			Name:        "processes",
			Description: "All running processes on the host system.",
			RowCount:    -1,
			Columns: []store.ColumnSchema{
				{Name: "pid", Type: "bigint", Position: 1, Description: "Process (or thread) ID"},
				{Name: "name", Type: "text", Position: 2, Description: "The process path or shorthand argv[0]"},
				{Name: "state", Type: "text", Position: 3},
			},
		}},
		rows: map[string][]store.Row{
			"processes": {{
				PrimaryKey: map[string]string{},
				Columns: []store.ColumnValue{
					{Name: "pid", Value: "780266"}, {Name: "name", Value: "kite-collector"}, {Name: "state", Value: "running"},
				},
			}},
		},
	}
}

// TestRoute_TableSources_RenderTransparently — a table from an extra source
// renders through the exact same catalog, sidebar, grid, facets, and SQL
// strip as a kite.db table; the UI carries no source marker at all.
func TestRoute_TableSources_RenderTransparently(t *testing.T) {
	st := testStore(t)
	handler := Serve(":0", st, testContext(), nil, Options{
		TableSources: []store.TableSource{osqueryLikeSource()},
	}).Handler

	// Catalog lists it next to the durable tables.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tables", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "/tables/processes")
	assert.Contains(t, body, "/tables/machines")
	assert.NotContains(t, body, "osquery", "the UI must not know the source")

	// Sidebar tree carries it in All tables.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fragments/sidebar-tree", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "/tables/processes")

	// The generic grid renders it: description, documented headers, rows,
	// SQL strip, facets — and no row drawer, since these rows have no PK.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tables/processes", nil)
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	body = rec.Body.String()
	assert.Contains(t, body, "All running processes on the host system.")
	assert.Contains(t, body, `title="Process (or thread) ID"`, "column docs surface as header tooltips")
	assert.Contains(t, body, "kite-collector")
	assert.Contains(t, body, `class="sql-strip"`)
	assert.Contains(t, body, `class="facet-rail"`)
	assert.NotContains(t, body, "row-click", "PK-less rows must not offer the row drawer")
}

// TestRoute_TableSources_StoreWinsCollision — a secondary source can never
// shadow a durable table of the same name.
func TestRoute_TableSources_StoreWinsCollision(t *testing.T) {
	st := testStore(t)
	src := osqueryLikeSource()
	src.tables[0].Name = "machines"
	src.tables[0].Description = "SHADOW MARKER: must never render"
	handler := Serve(":0", st, testContext(), nil, Options{
		TableSources: []store.TableSource{src},
	}).Handler

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tables/machines", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "SHADOW MARKER")
}

// TestRoute_TableSources_DeadSecondaryDegrades — a failing extra backend
// drops out of the catalog instead of breaking the page.
func TestRoute_TableSources_DeadSecondaryDegrades(t *testing.T) {
	st := testStore(t)
	src := osqueryLikeSource()
	src.listErr = context.DeadlineExceeded
	handler := Serve(":0", st, testContext(), nil, Options{
		TableSources: []store.TableSource{src},
	}).Handler

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tables", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "/tables/machines")
}
