package cloud

// intercept_test.go: test-only HTTP interception for the cloud sources whose
// endpoints are hardcoded package constants (EC2/STS SigV4 endpoints, the ARM
// and Microsoft identity endpoints, the Compute Engine API, the GCE metadata
// server, and the Google OAuth2 token endpoint). Those code paths issue
// requests through clients with a nil Transport, which resolve
// http.DefaultTransport at call time — so swapping the package-level default
// transport for a host-routing fake redirects them to in-process handlers.
// Every host without an explicit route is refused, guaranteeing the tests can
// never touch the real network.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// hostRoutes maps a request host (e.g. "ec2.us-east-1.amazonaws.com") to the
// in-process handler that serves it during a test.
type hostRoutes map[string]http.Handler

// hostRoundTripper serves intercepted requests via httptest.ResponseRecorder,
// with no listener or real connection involved.
type hostRoundTripper struct {
	routes hostRoutes
}

func (h *hostRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	handler, ok := h.routes[req.URL.Host]
	if !ok {
		return nil, fmt.Errorf("test transport: blocked request to unrouted host %q", req.URL.Host)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

// interceptHosts swaps http.DefaultTransport for a host-routing fake for the
// duration of the test. Tests in this package run sequentially (none call
// t.Parallel), so the process-global swap is safe; t.Cleanup restores the
// original transport.
func interceptHosts(t *testing.T, routes hostRoutes) {
	t.Helper()
	orig := http.DefaultTransport
	http.DefaultTransport = &hostRoundTripper{routes: routes}
	t.Cleanup(func() { http.DefaultTransport = orig })
}
