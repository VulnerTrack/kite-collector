package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// resourceTagRe matches the URL a page auto-loads: a <link ... href="…"> or a
// <script ... src="…">. It deliberately does NOT match <a href> (clickable
// links) or form actions — those may legitimately point at a loopback URL or
// an external site the operator chooses to open; they are not fetched to
// render the page.
var resourceTagRe = regexp.MustCompile(`(?i)<(?:link\b[^>]*?\bhref|script\b[^>]*?\bsrc)="([^"]+)"`)

// localResource reports whether an auto-loaded resource URL stays on the host:
// a relative path, a data:/blob: URI, or an absolute URL whose host is
// loopback. Anything else is the internet.
func localResource(raw string) bool {
	if raw == "" {
		return true
	}
	if strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "blob:") {
		return true
	}
	if !strings.Contains(raw, "://") {
		return true // relative path like /static/style.css
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.Trim(u.Hostname(), "[]")
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// TestDashboardServesNoExternalResources pins the "a loopback security
// dashboard never reaches the internet to render" guarantee at the unit level,
// cheaply and without a browser: it renders the real pages through Serve and
// asserts every auto-loaded <link>/<script> resource stays on the host.
//
// The one allowed exception is Cloudflare Turnstile, which the sign-in flow
// lazy-loads from JavaScript (`s.src = 'https://…'`) only when a .cf-turnstile
// widget is present — a runtime assignment, never a static <script src="https…">
// tag, so it is invisible to the resource-tag regex while any statically
// embedded external resource is still caught.
func TestDashboardServesNoExternalResources(t *testing.T) {
	st := testStore(t)
	handler := Serve(":0", st, testContext(), nil, Options{}).Handler

	pages := []string{"/machines", "/software", "/scans", "/kite-login", "/kite-success"}

	for _, path := range pages {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
			req.Host = "127.0.0.1:9090"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			// A page that redirects (e.g. onboarding gating) has no body to
			// check; only assert on a rendered HTML body.
			if rec.Code != http.StatusOK {
				t.Skipf("%s returned %d, not an HTML render", path, rec.Code)
			}
			body := rec.Body.String()

			for _, m := range resourceTagRe.FindAllStringSubmatch(body, -1) {
				res := m[1]
				assert.Truef(t, localResource(res),
					"%s auto-loads a non-local resource (must be self-contained): %s", path, res)
			}
			// Belt and suspenders: the known external hosts must never appear
			// as a loaded resource, even if the regex above ever misses a shape.
			for _, host := range []string{"fonts.googleapis.com", "fonts.gstatic.com"} {
				assert.NotContainsf(t, body, `href="https://`+host, "%s loads %s", path, host)
			}
		})
	}
}
