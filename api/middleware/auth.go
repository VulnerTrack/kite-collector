// Package middleware provides HTTP middleware for the kite-collector REST API.
// It is designed to wrap http.Handler chains using the standard library.
package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
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

// MTLSAuth returns middleware that enforces mutual TLS client certificate
// authentication. Requests without a valid, non-expired client certificate
// receive a 401 Unauthorized JSON response.
func MTLSAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeJSONError(w, http.StatusUnauthorized, "mTLS required: no client certificate provided")
			return
		}

		// Extract client certificate subject for logging.
		clientCert := r.TLS.PeerCertificates[0]
		slog.Debug("mTLS: client authenticated", //#nosec G706 -- cert fields from TLS handshake, not user input
			"subject", clientCert.Subject.CommonName,
			"issuer", clientCert.Issuer.CommonName,
			"serial", clientCert.SerialNumber.String(),
			"not_after", clientCert.NotAfter.Format(time.RFC3339),
		)

		// Check certificate expiry.
		if time.Now().After(clientCert.NotAfter) {
			writeJSONError(w, http.StatusUnauthorized, "mTLS: client certificate has expired")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// MTLSOrAPIKey returns middleware that accepts either a valid mTLS client
// certificate or a matching X-API-Key header. If neither authentication
// method succeeds, the request receives a 401 Unauthorized JSON response.
func MTLSOrAPIKey(next http.Handler, apiKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If mTLS client cert is present and not expired, use that.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientCert := r.TLS.PeerCertificates[0]
			if time.Now().Before(clientCert.NotAfter) {
				slog.Debug("mTLS+APIKey: authenticated via client certificate", //#nosec G706 -- cert fields from TLS handshake, not user input
					"subject", clientCert.Subject.CommonName,
				)
				next.ServeHTTP(w, r)
				return
			}
		}

		// Fall back to API key.
		if apiKey != "" {
			provided := r.Header.Get(apiKeyHeader)
			if provided == apiKey {
				slog.Debug("mTLS+APIKey: authenticated via API key")
				next.ServeHTTP(w, r)
				return
			}
		}

		writeJSONError(w, http.StatusUnauthorized, "authentication required: provide client certificate or API key")
	})
}
