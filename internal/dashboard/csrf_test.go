package dashboard

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// recordingInstaller fails the test if a request ever reaches the real
// install path. The whole point of the guard is that a cross-site POST never
// gets this far.
type recordingInstaller struct{ installs, uninstalls int }

func (i *recordingInstaller) Install(context.Context, installer.Options) error {
	i.installs++
	return nil
}

func (i *recordingInstaller) Uninstall(context.Context, installer.Options) error {
	i.uninstalls++
	return nil
}

// TestGuardCrossSite_BlocksCrossSiteInstall is the regression this file
// exists for: a page on another site submitting a form at the loopback
// dashboard used to run a real install, because a form post is a "simple"
// request and nothing about it is preflighted.
func TestGuardCrossSite_BlocksCrossSiteInstall(t *testing.T) {
	inst := &recordingInstaller{}
	handler := newGuardedTestHandler(t, Options{Installer: inst})

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodPost, "http://127.0.0.1:9090/api/v1/agent/install",
		strings.NewReader("confirm=true"))
	req.Host = "127.0.0.1:9090"
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Zero(t, inst.installs, "cross-site POST must never reach the installer")
}

// TestGuardCrossSite_BlocksDNSRebinding covers the bypass that makes a naive
// Origin check useless: when evil.example resolves to 127.0.0.1, the browser
// sends an Origin that *matches* the Host, so only the Host allowlist can
// tell the request apart from a genuine local one.
func TestGuardCrossSite_BlocksDNSRebinding(t *testing.T) {
	inst := &recordingInstaller{}
	handler := newGuardedTestHandler(t, Options{Installer: inst})

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodPost, "http://evil.example:9090/api/v1/agent/install", nil)
	req.Host = "evil.example:9090"
	req.Header.Set("Origin", "http://evil.example:9090")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "DNS rebinding")
	assert.Zero(t, inst.installs)
}

// TestGuardCrossSite_AllowsDashboardsOwnRequests pins that the fix does not
// break the UI: the dashboard's own HTMX buttons are same-origin posts from
// a loopback host and must pass through untouched.
func TestGuardCrossSite_AllowsDashboardsOwnRequests(t *testing.T) {
	handler := newGuardedTestHandler(t, Options{})

	for _, host := range []string{"127.0.0.1:9090", "localhost:9090", "[::1]:9090"} {
		t.Run(host, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(),
				http.MethodPost, "/api/v1/agent/install", nil)
			req.Host = host
			req.Header.Set("Origin", "http://"+host)
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("HX-Request", "true")

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			// No Installer is wired, so the endpoint answers 503 with a CLI
			// hint. What matters is that the guard did not answer 403.
			assert.NotEqual(t, http.StatusForbidden, rec.Code)
		})
	}
}

// TestGuardCrossSite_AllowsScriptedClients keeps the documented curl path
// working. A tool sends neither Origin nor Sec-Fetch-*, and for those the
// loopback bind remains the gate — tightening past that would break the
// scripted flows the handlers explicitly support.
func TestGuardCrossSite_AllowsScriptedClients(t *testing.T) {
	handler := newGuardedTestHandler(t, Options{})

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodPost, "/api/v1/agent/install", nil)
	req.Host = "example.com" // a tool can send anything; no browser headers
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusForbidden, rec.Code)
}

// TestGuardCrossSite_LeavesReadsAlone documents the scope of the change: the
// guard covers state changes only. Cross-site *reads* are already stopped by
// the same-origin policy at the browser (the attacker cannot see the
// response), and guarding GET would break plain links into the dashboard.
func TestGuardCrossSite_LeavesReadsAlone(t *testing.T) {
	handler := newGuardedTestHandler(t, Options{})

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, "/machines", nil)
	req.Host = "evil.example"
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusForbidden, rec.Code)
}

func TestCrossSiteRejection(t *testing.T) {
	guard := newHostGuard("127.0.0.1:9090", nil)

	cases := []struct {
		name    string
		method  string
		host    string
		headers map[string]string
		blocked bool
	}{
		{
			name: "safe method is never guarded", method: http.MethodGet, host: "evil.example",
			headers: map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
		},
		{
			name: "cross-site fetch metadata", method: http.MethodPost, host: "127.0.0.1:9090",
			headers: map[string]string{"Sec-Fetch-Site": "cross-site"}, blocked: true,
		},
		{
			name: "origin from another host", method: http.MethodPost, host: "127.0.0.1:9090",
			headers: map[string]string{"Origin": "http://127.0.0.1:8080"}, blocked: true,
		},
		{
			name: "opaque null origin", method: http.MethodPost, host: "127.0.0.1:9090",
			headers: map[string]string{"Origin": "null"}, blocked: true,
		},
		{
			name: "rebound hostname", method: http.MethodPost, host: "evil.example",
			headers: map[string]string{"Origin": "http://evil.example", "Sec-Fetch-Site": "same-origin"},
			blocked: true,
		},
		{
			name: "same origin on loopback", method: http.MethodPost, host: "127.0.0.1:9090",
			headers: map[string]string{"Origin": "http://127.0.0.1:9090", "Sec-Fetch-Site": "same-origin"},
		},
		{
			name: "tool with no browser headers", method: http.MethodPost, host: "anything.example",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), tc.method, "/api/v1/scan", nil)
			req.Host = tc.host
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			assert.Equal(t, tc.blocked, crossSiteRejection(req, guard) != "")
		})
	}
}

func TestHostGuardPermits(t *testing.T) {
	guard := newHostGuard("0.0.0.0:9090", []string{"Kite.Corp.Local"})

	allowed := []string{
		"127.0.0.1:9090", "127.0.0.1", "192.168.1.10:9090", "[::1]:9090", "::1",
		"localhost", "localhost:9090", "kite.localhost:9090", "kite.corp.local:9090",
	}
	for _, host := range allowed {
		assert.True(t, guard.permits(host), "%q must be permitted", host)
	}

	for _, host := range []string{"", "evil.example", "evil.example:9090", "attacker.localhost.evil.com"} {
		assert.False(t, guard.permits(host), "%q must be refused", host)
	}

	// A dashboard bound to a name is reachable at that name; a wildcard bind
	// names nothing, which is why 0.0.0.0 above added no entry.
	named := newHostGuard("kite.internal:9090", nil)
	assert.True(t, named.permits("kite.internal:9090"))
	assert.False(t, named.permits("kite.external:9090"))
}

func TestCrossSiteFormPost(t *testing.T) {
	newReq := func(method, contentType string, hx bool) *http.Request {
		req := httptest.NewRequestWithContext(context.Background(), method, "/api/v1/agent/install", nil)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if hx {
			req.Header.Set("HX-Request", "true")
		}
		return req
	}

	assert.True(t, crossSiteFormPost(newReq(http.MethodPost, "application/x-www-form-urlencoded", false)))
	assert.True(t, crossSiteFormPost(newReq(http.MethodPost, "multipart/form-data; boundary=x", false)))
	assert.True(t, crossSiteFormPost(newReq(http.MethodPost, "text/plain", false)))

	// The dashboard's own HTMX posts are form-encoded too — the HX-Request
	// header is what a cross-site form cannot add without a preflight.
	assert.False(t, crossSiteFormPost(newReq(http.MethodPost, "application/x-www-form-urlencoded", true)))
	// curl with no body sends no content type at all.
	assert.False(t, crossSiteFormPost(newReq(http.MethodPost, "", false)))
	assert.False(t, crossSiteFormPost(newReq(http.MethodPost, "application/json", false)))
	assert.False(t, crossSiteFormPost(newReq(http.MethodGet, "text/plain", false)))
}

// TestHandleAgentInstall_RefusesFormEncodedPost checks the second lock
// directly: even reaching the handler, a form-shaped install is refused.
func TestHandleAgentInstall_RefusesFormEncodedPost(t *testing.T) {
	inst := &recordingInstaller{}
	deps := onboardingDeps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Installer: inst}

	for _, path := range []string{"/api/v1/agent/install", "/api/v1/agent/install/uninstall?confirm=true"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(),
				http.MethodPost, path, strings.NewReader("user_mode=true"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			if strings.Contains(path, "uninstall") {
				handleAgentUninstall(rec, req, deps)
			} else {
				handleAgentInstall(rec, req, deps)
			}

			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Contains(t, rec.Body.String(), "not accepted")
		})
	}

	assert.Zero(t, inst.installs)
	assert.Zero(t, inst.uninstalls)
}

func newGuardedTestHandler(t *testing.T, opts Options) http.Handler {
	t.Helper()
	st := testStore(t)
	srv := Serve("127.0.0.1:9090", st, testContext(), nil, opts)
	require.NotNil(t, srv.Handler)
	return srv.Handler
}
