// Package middleware provides HTTP middleware for the kite-collector REST API.
// It is designed to wrap http.Handler chains using the standard library.
package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// apiKeyHeader is the HTTP header name checked by APIKeyAuth.
const apiKeyHeader = "X-API-Key" //#nosec G101 -- this is a header name, not a credential

// errorBody is the JSON body returned on authentication failure.
type errorBody struct {
	Error string `json:"error"`
}

// writeJSONError writes a JSON-encoded error response with the given status
// code. It mirrors the pattern used in the rest package.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: msg})
}

// APIKeyAuth returns middleware that validates the X-API-Key request header
// against apiKey. Requests with a missing or incorrect key receive a 401
// Unauthorized JSON response; valid requests are forwarded to next.
func APIKeyAuth(next http.Handler, apiKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get(apiKeyHeader)
		if provided == "" {
			writeJSONError(w, http.StatusUnauthorized, "missing API key")
			return
		}
		if provided != apiKey {
			writeJSONError(w, http.StatusUnauthorized, "invalid API key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// MTLSAuth returns middleware that will enforce mutual TLS client certificate
// validation in Phase 3. Currently it logs a warning and passes the request
// through without verification.
func MTLSAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			slog.Warn("mTLS auth not yet enforced — passing request through", //#nosec G706 -- method and path are safe to log for audit purposes
				"method", r.Method,
				"path", r.URL.Path,
			)
		}
		next.ServeHTTP(w, r)
	})
}
