package main

import "net/http"

var version = "dev"

// userAgent names this build on the wire instead of net/http's
// "Go-http-client/1.1" default, with the same product token as the main
// collector (internal/useragent, which this go1.17 module cannot import).
func userAgent() string { return "Kite-collector-http-client/" + version }

// uaTransport stamps userAgent on requests that do not set one. A nil base
// means http.DefaultTransport.
type uaTransport struct{ base http.RoundTripper }

func (t uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, set := req.Header["User-Agent"]; !set {
		req = req.Clone(req.Context())
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set("User-Agent", userAgent())
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
