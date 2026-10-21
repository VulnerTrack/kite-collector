// Package useragent names the collector on the wire. Every outbound HTTP
// client routes through Wrap so requests carry
// "Kite-collector-http-client/<version>" instead of net/http's anonymous
// "Go-http-client/1.1" / "Go-http-client/2.0" default, which lets platform
// logs, WAFs and rate limiters attribute traffic to a collector build.
//
// A request that already sets User-Agent keeps it: the network fingerprint
// probes and the storage analyzer pick their own on purpose, and an explicit
// empty value is how a caller opts out of sending one at all.
//
// net/http has no hook for its default User-Agent, and swapping
// http.DefaultTransport for a wrapper would break the
// http.DefaultTransport.(*http.Transport).Clone() idiom, so each client wraps
// its own transport.
package useragent

import (
	"net/http"
	"sync/atomic"
)

// Product is the User-Agent product token; the version follows the slash.
const Product = "Kite-collector-http-client"

var current atomic.Pointer[string]

func init() { SetVersion("dev") }

// SetVersion records the running build's version. main calls it once at
// startup with the ldflags-injected value; until then the token reads "dev".
func SetVersion(v string) {
	if v == "" {
		v = "dev"
	}
	s := Product + "/" + v
	current.Store(&s)
}

// String returns the User-Agent header value, e.g.
// "Kite-collector-http-client/1.4.0".
func String() string { return *current.Load() }

// Wrap returns a RoundTripper that sets User-Agent on requests that lack the
// header and passes everything else to base untouched. A nil base means
// http.DefaultTransport, looked up per request so tests that swap it still
// take effect.
func Wrap(base http.RoundTripper) http.RoundTripper {
	if t, ok := base.(*transport); ok {
		return t
	}
	return &transport{base: base}
}

type transport struct {
	base http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, set := req.Header["User-Agent"]; !set {
		// RoundTrippers must not mutate the caller's request.
		req = req.Clone(req.Context())
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set("User-Agent", String())
	}
	return t.next().RoundTrip(req) //nolint:wrapcheck // transparent RoundTripper: callers match on the base transport's errors.
}

// CloseIdleConnections forwards to base so http.Client.CloseIdleConnections
// keeps working through the wrapper.
func (t *transport) CloseIdleConnections() {
	if c, ok := t.next().(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func (t *transport) next() http.RoundTripper {
	if t.base != nil {
		return t.base
	}
	return http.DefaultTransport
}
