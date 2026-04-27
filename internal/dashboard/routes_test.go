package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

// TestRoute_GET_Root_RedirectsToAssets — GET / must redirect to /assets so
// the URL bar always reflects an addressable tab. 307 keeps the request
// method intact (defensive — every real request here is a GET).
func TestRoute_GET_Root_RedirectsToAssets(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code,
		"root should 307-redirect to /assets")
	assert.Equal(t, "/assets", rec.Header().Get("Location"))
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
