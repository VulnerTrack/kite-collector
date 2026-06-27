// Package middleware provides HTTP middleware for the kite-collector REST API.
// It is designed to wrap http.Handler chains using the standard library.
package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"time"
)

// controlCharRe matches control characters that could cause log injection (CWE-117).
var controlCharRe = regexp.MustCompile(`[\x00-\x1f\x7f]`)

// sanitizeLog replaces control characters in tainted values such as
// certificate fields to prevent log injection.
func sanitizeLog(s string) string {
	return controlCharRe.ReplaceAllString(s, "_")
}

// apiKeyHeader is the HTTP header name checked by APIKeyAuth.
const apiKeyHeader = "X-API-Key" //#nosec G101 -- this is a header name, not a credential

// contextKey is a private type for context keys in this package.
type contextKey string

const (
	// tenantIDCtxKey stores the tenant UUID extracted from the mTLS certificate
	// Organization field (RFC-0063 §5.1).
	tenantIDCtxKey contextKey = "tenant_id"
	// agentIDCtxKey stores the agent UUID extracted from the mTLS certificate
	// Common Name field (RFC-0063 §5.1).
	agentIDCtxKey contextKey = "agent_id"
)

// TenantIDFromContext returns the tenant_id injected by the auth middleware,
// or an empty string if no mTLS certificate was presented.
func TenantIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(tenantIDCtxKey).(string)
	return v
}

// AgentIDFromContext returns the agent_id (certificate CN) injected by the
// auth middleware, or an empty string if no mTLS certificate was presented.
func AgentIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(agentIDCtxKey).(string)
	return v
}

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
// authentication. It extracts agent_id from the certificate CN and tenant_id
// from the Organization field, injecting both into the request context.
func MTLSAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeJSONError(w, http.StatusUnauthorized, "mTLS required: no client certificate provided")
			return
		}

		clientCert := r.TLS.PeerCertificates[0]
		slog.LogAttrs(r.Context(), slog.LevelDebug, "mTLS: client authenticated",
			slog.String("subject", sanitizeLog(clientCert.Subject.CommonName)),
			slog.String("issuer", sanitizeLog(clientCert.Issuer.CommonName)),
			slog.String("serial", sanitizeLog(clientCert.SerialNumber.String())),
			slog.String("not_after", clientCert.NotAfter.Format(time.RFC3339)),
		)

		if time.Now().After(clientCert.NotAfter) {
			writeJSONError(w, http.StatusUnauthorized, "mTLS: client certificate has expired")
			return
		}

		// Inject agent_id (CN) and tenant_id (Organization) into context.
		ctx := r.Context()
		ctx = context.WithValue(ctx, agentIDCtxKey, clientCert.Subject.CommonName)
		if len(clientCert.Subject.Organization) > 0 {
			ctx = context.WithValue(ctx, tenantIDCtxKey, clientCert.Subject.Organization[0])
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MTLSOrAPIKey returns middleware that accepts either a valid mTLS client
// certificate or a matching X-API-Key header. When mTLS is used, agent_id
// and tenant_id are extracted from the certificate and injected into context.
func MTLSOrAPIKey(next http.Handler, apiKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If mTLS client cert is present and not expired, use that.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientCert := r.TLS.PeerCertificates[0]
			if time.Now().Before(clientCert.NotAfter) {
				slog.LogAttrs(r.Context(), slog.LevelDebug, "mTLS+APIKey: authenticated via client certificate",
					slog.String("subject", sanitizeLog(clientCert.Subject.CommonName)),
				)

				// Inject agent_id (CN) and tenant_id (Organization) into context.
				ctx := r.Context()
				ctx = context.WithValue(ctx, agentIDCtxKey, clientCert.Subject.CommonName)
				if len(clientCert.Subject.Organization) > 0 {
					ctx = context.WithValue(ctx, tenantIDCtxKey, clientCert.Subject.Organization[0])
				}

				next.ServeHTTP(w, r.WithContext(ctx))
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
