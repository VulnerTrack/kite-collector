package dashboard

import (
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Cross-site request guard.
//
// The dashboard is an unauthenticated loopback surface: whoever reaches
// 127.0.0.1:9090 drives it, and for a local operator that is the intended
// contract. A browser breaks it. Any page the operator has open can submit a
// form at http://127.0.0.1:9090/api/v1/agent/install — a "simple" request, so
// no CORS preflight stands in the way — and the collector installs a system
// service on their behalf. Binding to loopback authenticates nobody once a
// browser is in the loop.
//
// So every state-changing request has to prove it came from the dashboard's
// own origin. Two checks, because either one alone is bypassable:
//
//   - Origin / Sec-Fetch-Site rejects the plain cross-site form post.
//   - Host rejects DNS rebinding, where evil.example resolves to 127.0.0.1 and
//     the browser therefore sends a *matching* Origin/Host pair that sails
//     through the first check. Rebinding needs a hostname; an IP literal and
//     localhost cannot be rebound, so restricting Host to those is the entire
//     defense.
//
// Non-browser clients (curl, the CLI, scripted deploys) send neither Origin
// nor Sec-Fetch-*, so the Host check does not apply to them and the loopback
// bind stays their only gate — the documented curl flows keep working.

// safeHTTPMethod reports whether the method only reads state (RFC 9110 §9.2.1)
// and therefore needs no guard. Everything else can change the machine.
func safeHTTPMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// browserOriginated reports whether the request carries headers a browser
// attaches to every fetch it makes. Page script can neither remove nor forge
// them, which makes their presence a reliable "a page sent this" and their
// absence a reliable "a tool sent this".
func browserOriginated(r *http.Request) bool {
	return r.Header.Get("Origin") != "" ||
		r.Header.Get("Sec-Fetch-Site") != "" ||
		r.Header.Get("Sec-Fetch-Mode") != ""
}

// sameOriginRequest reports whether the request claims to come from the
// dashboard itself. An absent Origin is allowed: non-browser clients omit it,
// and browsers always send it on the state-changing requests we care about.
func sameOriginRequest(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		// Opaque origins ("null" — sandboxed iframes, some redirect chains)
		// land here. They can never be the dashboard, so they are refused.
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

// hostGuard decides whether the Host header of a browser-issued request names
// an address this dashboard can legitimately be reached at.
type hostGuard struct {
	extra []string
}

// newHostGuard builds the allowlist: loopback-ish literals always, plus the
// host the dashboard was told to bind (an operator who runs
// --addr kite.corp.local:9090 is reachable at that name by definition) and
// anything the embedder listed in Options.AllowedHosts.
func newHostGuard(addr string, allowed []string) hostGuard {
	extra := make([]string, 0, len(allowed)+1)
	for _, host := range allowed {
		if host = strings.ToLower(strings.TrimSpace(host)); host != "" {
			extra = append(extra, host)
		}
	}
	switch host := strings.ToLower(hostHeaderName(addr)); host {
	case "", "0.0.0.0", "::", "[::]":
		// Wildcard binds name no reachable host of their own.
	default:
		extra = append(extra, host)
	}
	return hostGuard{extra: extra}
}

// permits reports whether hostHeader is an address a browser could reach this
// dashboard at without DNS rebinding being involved.
func (g hostGuard) permits(hostHeader string) bool {
	host := strings.ToLower(strings.Trim(hostHeaderName(hostHeader), "[]"))
	if host == "" {
		return false
	}
	// A literal cannot be rebound — rebinding works by changing what a *name*
	// resolves to, and there is no name here.
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	for _, allowed := range g.extra {
		if host == allowed {
			return true
		}
	}
	return false
}

// hostHeaderName strips the optional :port from a Host header or listen
// address. Values with no port come back unchanged.
func hostHeaderName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return host
	}
	return value
}

// crossSiteRejection returns the reason a request must be refused, or "" when
// it may proceed.
func crossSiteRejection(r *http.Request, guard hostGuard) string {
	if safeHTTPMethod(r.Method) {
		return ""
	}
	if !sameOriginRequest(r) {
		return "request originated on another site"
	}
	if browserOriginated(r) && !guard.permits(r.Host) {
		return "Host header is not a local dashboard address (possible DNS rebinding)"
	}
	return ""
}

// guardCrossSite wraps the whole mux rather than individual routes, so a POST
// route added next month is covered the day it is written instead of the day
// someone remembers to guard it.
func guardCrossSite(next http.Handler, guard hostGuard, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reason := crossSiteRejection(r, guard)
		if reason == "" {
			next.ServeHTTP(w, r)
			return
		}
		logger.Warn("dashboard: blocked cross-site request",
			"code", string(LogCodeServeCrossSiteBlocked),
			"reason", reason,
			"method", r.Method,
			"request_path", r.URL.Path,
			"request_host", r.Host,
			"origin", r.Header.Get("Origin"),
			"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"))
		http.Error(w, "cross-site request blocked: "+reason, http.StatusForbidden)
	})
}

// crossSiteFormPost reports whether a request has the exact shape of a
// cross-site <form> submission: a content type a form can produce without a
// preflight, and none of the markers the dashboard's own HTMX calls carry.
//
// The mux-level guard already rejects these. This is the second lock, kept on
// the two endpoints that install and remove a system service, so those stay
// closed even if the guard is ever misconfigured or bypassed by a header the
// next browser generation stops sending. A bodyless curl (no Content-Type at
// all) is not a form post and keeps working.
func crossSiteFormPost(r *http.Request) bool {
	if safeHTTPMethod(r.Method) || isHXRequest(r) {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return false
	}
	switch strings.ToLower(mediaType) {
	case "application/x-www-form-urlencoded", "multipart/form-data", "text/plain":
		return true
	}
	return false
}
