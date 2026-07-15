package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

type kiteLoginView struct {
	CollectorURL          string
	OAuthAuthorizationURL string
	OAuthError            string
}

type kiteSuccessView struct {
	DashboardURL string
}

type kiteOAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
}

type kiteOAuthTokenError struct {
	Error            string `json:"error"`
	ErrorCode        string `json:"error_code"`
	ErrorDescription string `json:"error_description"`
	Message          string `json:"msg"`
}

type kiteOAuthEnrollmentOptions struct {
	Store            *sqlite.SQLiteStore
	Logger           *slog.Logger
	PlatformEndpoint string
	WrapKey          []byte
}

// OAuthOptions configures the first-party OAuth client used by Kite.
type OAuthOptions struct {
	SupabaseURL      string
	SupabaseAnonKey  string
	TurnstileSiteKey string
	AuthorizeURL     string
	ClientID         string
	Scope            string
	RedirectPath     string
}

const (
	defaultKiteOAuthSupabaseURL  = "https://wjurmocfraqhdqarnytz.supabase.co"
	defaultKiteOAuthAuthorizeURL = "https://api.vulnertrack.com/auth/v1/oauth/authorize"
	defaultKiteOAuthClientID     = "d9be121a-a430-4c3a-9837-5cf67f9edfa3"
	defaultKiteOAuthScope        = "openid email"
	defaultKiteOAuthRedirectPath = "/oauth/callback"
	kiteOAuthCookieTTL           = 10 * time.Minute
	kiteOAuthStateCookie         = "kite_oauth_state"
	kiteOAuthVerifierCookie      = "kite_oauth_code_verifier"
	kiteOAuthDashboardCookie     = "kite_oauth_dashboard"
	kiteOAuthWaitCookie          = "kite_oauth_wait_id"
	kiteOAuthTokenMaxBody        = 1 << 20
)

const kiteLoginTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Link Kite Collector - Vulnertrack</title>
<link rel="stylesheet" href="/static/style.css?v=1.0.1">
<style>
  body.kite-auth-page {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    margin: 0;
    padding: 24px;
    box-sizing: border-box;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: radial-gradient(circle at 50% 50%, #fdfdfd 0%, #f4f5f7 100%);
    color: #1C252E;
  }
  .kite-auth-card {
    background: #ffffff;
    border: 1px solid rgba(145, 158, 171, 0.16);
    border-radius: 16px;
    box-shadow: 0 12px 40px -4px rgba(145, 158, 171, 0.12), 0 2px 10px -2px rgba(145, 158, 171, 0.08);
    width: 100%;
    max-width: 420px;
    padding: 40px 32px;
    box-sizing: border-box;
    text-align: center;
  }
  .kite-auth-logo-container {
    display: flex;
    justify-content: center;
    margin-bottom: 24px;
  }
  .kite-auth-logo {
    width: 64px;
    height: 64px;
    object-fit: contain;
  }
  .kite-auth-title {
    font-size: 1.5rem;
    font-weight: 800;
    margin: 0 0 12px 0;
    color: #1C252E;
    letter-spacing: -0.5px;
  }
  .kite-auth-desc {
    font-size: 0.925rem;
    line-height: 1.5;
    color: #637381;
    margin: 0 0 32px 0;
  }
  .kite-auth-btn-stack {
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin-bottom: 28px;
  }
  .kite-auth-btn-primary {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 48px;
    border-radius: 24px;
    background: #FF3131;
    color: #ffffff;
    font-size: 0.95rem;
    font-weight: 700;
    text-decoration: none;
    transition: all 0.2s ease-in-out;
    box-shadow: 0 4px 12px rgba(255, 49, 49, 0.2);
  }
  .kite-auth-btn-primary:hover {
    background: #e02828;
    transform: translateY(-1px);
    box-shadow: 0 6px 16px rgba(255, 49, 49, 0.3);
  }
  .kite-auth-btn-secondary {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 48px;
    border-radius: 24px;
    background: transparent;
    border: 1px solid rgba(145, 158, 171, 0.32);
    color: #1C252E;
    font-size: 0.95rem;
    font-weight: 700;
    text-decoration: none;
    transition: all 0.2s ease-in-out;
  }
  .kite-auth-btn-secondary:hover {
    background: rgba(145, 158, 171, 0.08);
    border-color: #1C252E;
  }
  .kite-auth-divider {
    height: 1px;
    background: rgba(145, 158, 171, 0.12);
    margin: 0 0 24px 0;
  }
  .kite-auth-status-container {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    margin-bottom: 8px;
  }
  .kite-auth-status-dot {
    width: 8px;
    height: 8px;
    background-color: #22C55E;
    border-radius: 50%;
    position: relative;
  }
  .kite-auth-status-dot::after {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: #22C55E;
    border-radius: 50%;
    animation: pulse 1.8s infinite ease-in-out;
  }
  @keyframes pulse {
    0% { transform: scale(1); opacity: 0.8; }
    100% { transform: scale(2.6); opacity: 0; }
  }
  .kite-auth-status-text {
    font-size: 0.8rem;
    font-weight: 600;
    color: #22C55E;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .kite-auth-panel-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    height: 40px;
    padding: 0 20px;
    border-radius: 20px;
    background: transparent;
    border: 1px solid rgba(145, 158, 171, 0.32);
    color: #637381;
    font-size: 0.85rem;
    font-weight: 500;
    text-decoration: none;
    transition: all 0.2s ease-in-out;
    cursor: pointer;
    margin-top: 4px;
  }
  .kite-auth-panel-btn:hover {
    background: rgba(145, 158, 171, 0.08);
    border-color: #1C252E;
    color: #1C252E;
  }
  .kite-auth-panel-btn code {
    font-family: monospace;
    background: #f4f6f8;
    padding: 2px 8px;
    border-radius: 4px;
    color: #1C252E;
    font-weight: 600;
    font-size: 0.82rem;
  }
  .kite-auth-panel-btn:hover code {
    background: rgba(145, 158, 171, 0.16);
  }
  .kite-auth-error {
    color: #B71D18;
    background: rgba(255, 86, 48, 0.08);
    border: 1px solid rgba(255, 86, 48, 0.22);
    border-radius: 12px;
    padding: 12px 14px;
    font-size: 0.875rem;
    line-height: 1.45;
    margin: 0 0 24px 0;
  }
</style>
</head>
<body class="kite-auth-page">
<div class="kite-auth-card">
  <div class="kite-auth-logo-container">
    <img class="kite-auth-logo" src="/static/img/logo.png" alt="Vulnertrack Logo">
  </div>
  <h1 class="kite-auth-title">Link Kite Collector</h1>
  <p class="kite-auth-desc">Connect this collector to your account to view assets, software, and findings in your dashboard.</p>
  
  {{if .OAuthError}}
  <p class="kite-auth-error">{{.OAuthError}}</p>
  {{else}}
  <div class="kite-auth-btn-stack">
    <a class="kite-auth-btn-primary" href="{{.OAuthAuthorizationURL}}">Sign In</a>
  </div>
  {{end}}

  <div class="kite-auth-divider"></div>

  <div class="kite-auth-status-container">
    <div class="kite-auth-status-dot"></div>
    <span class="kite-auth-status-text">Collector installed</span>
  </div>
  {{if .CollectorURL}}
  <a class="kite-auth-panel-btn" href="{{.CollectorURL}}">
    Open local panel: <code>{{.CollectorURL}}</code>
  </a>
  {{end}}
</div>
</body>
</html>`

var kiteLoginTmpl = template.Must(template.New("kiteLogin").Parse(kiteLoginTemplate))

const kiteSuccessTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Granted - Kite Collector</title>
<link rel="stylesheet" href="/static/style.css?v=1.0.1">
<style>
  body.kite-success-page {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    margin: 0;
    padding: 24px;
    box-sizing: border-box;
    background: radial-gradient(circle at 50% 50%, #fdfdfd 0%, #f4f5f7 100%);
    color: #1C252E;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  }
  .kite-success-card {
    background: #ffffff;
    border: 1px solid rgba(145, 158, 171, 0.16);
    border-radius: 16px;
    box-shadow: 0 12px 40px -4px rgba(145, 158, 171, 0.12), 0 2px 10px -2px rgba(145, 158, 171, 0.08);
    width: 100%;
    max-width: 420px;
    padding: 40px 32px;
    box-sizing: border-box;
    text-align: center;
  }
  .kite-success-logo {
    display: block;
    width: 148px;
    height: auto;
    margin: 0 auto 32px auto;
  }
  .kite-success-heading {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 12px;
    margin: 0 0 18px 0;
    font-size: 1.6rem;
    font-weight: 700;
    color: #1C252E;
  }
  .kite-success-check {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: 50%;
    background: #22C55E;
    color: #ffffff;
    font-size: 1.1rem;
    font-weight: 800;
    line-height: 1;
    box-shadow: 0 4px 10px rgba(34, 197, 94, 0.2);
  }
  .kite-success-copy {
    margin: 0 0 16px 0;
    color: #637381;
    font-size: 0.95rem;
    line-height: 1.5;
  }
  .kite-success-actions {
    margin-top: 28px;
  }
  .kite-success-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 48px;
    width: 100%;
    border-radius: 24px;
    background: #FF3131;
    color: #ffffff;
    font-size: 0.95rem;
    font-weight: 700;
    text-decoration: none;
    box-shadow: 0 4px 12px rgba(255, 49, 49, 0.2);
    transition: background 0.2s ease-in-out, box-shadow 0.2s ease-in-out, transform 0.2s ease-in-out;
  }
  .kite-success-btn:hover {
    background: #e02828;
    box-shadow: 0 6px 16px rgba(255, 49, 49, 0.3);
    transform: translateY(-1px);
  }
</style>
</head>
<body class="kite-success-page">
<main class="kite-success-card" aria-labelledby="kite-success-title">
  <img class="kite-success-logo" src="/static/img/vulnertrack_banner_dark.png" alt="Vulnertrack">
  <h1 class="kite-success-heading" id="kite-success-title">
    <span>Success!</span>
    <span class="kite-success-check" aria-hidden="true">✓</span>
  </h1>
  <p class="kite-success-copy">You've granted Kite Collector access to your Vulnertrack account.</p>
  <p class="kite-success-copy">To continue, return to the dashboard and finish reviewing your collector status.</p>
  <div class="kite-success-actions">
    <a class="kite-success-btn" href="{{.DashboardURL}}">Go to Dashboard</a>
  </div>
</main>
</body>
</html>`

var kiteSuccessTmpl = template.Must(template.New("kiteSuccess").Parse(kiteSuccessTemplate))

var kiteOAuthWaits sync.Map // wait_id -> time.Time

func serveKiteLoginPage(w http.ResponseWriter, r *http.Request, oauth OAuthOptions) {
	collectorURL := collectorBaseURL(r, r.URL.Query().Get("collector"))
	authURL, verifier, state, authErr := buildKiteOAuthAuthorizationURL(oauth, collectorURL)

	// Diagnostic: log the authorize-step redirect_uri so it can be compared
	// with the callback-step redirect_uri in the token exchange logs.
	if authErr == nil {
		if redirectURI, err := buildKiteOAuthRedirectURI(collectorURL, oauth.RedirectPath); err == nil {
			slog.Info( //#nosec G706 -- structured slog: message is a constant literal; r-derived attributes are emitted as escaped JSON values, not concatenated into the message
				"OAuth authorize step",
				"collector_url", collectorURL,
				"redirect_uri", redirectURI,
				"r_host", r.Host,
				"authorize_url_len", len(authURL),
				"verifier_len", len(verifier),
				"state_len", len(state),
			)
		}
	}

	if authErr == nil {
		setKiteOAuthCookie(w, r, kiteOAuthVerifierCookie, verifier)
		setKiteOAuthCookie(w, r, kiteOAuthStateCookie, state)
		if dbg := r.URL.Query().Get("dashboard"); dbg != "" {
			setKiteOAuthCookie(w, r, kiteOAuthDashboardCookie, dbg)
		}
		if waitID := strings.TrimSpace(r.URL.Query().Get("wait_id")); waitID != "" {
			setKiteOAuthCookie(w, r, kiteOAuthWaitCookie, waitID)
		}
		http.Redirect(w, r, resolveKiteOAuthLaunchURL(r.Context(), authURL), http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	view := kiteLoginView{
		CollectorURL:          collectorURL,
		OAuthAuthorizationURL: authURL,
	}
	if authErr != nil {
		view.OAuthError = authErr.Error()
	}
	if err := kiteLoginTmpl.Execute(w, view); err != nil {
		http.Error(w, fmt.Sprintf("render kite login: %v", err), http.StatusInternalServerError)
	}
}
func serveKiteSuccessPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	dashboardURL := r.URL.Query().Get("dashboard")
	if dashboardURL == "" {
		if cookie, err := r.Cookie(kiteOAuthDashboardCookie); err == nil && cookie.Value != "" {
			dashboardURL = cookie.Value
		}
	}
	if dashboardURL == "" {
		dashboardURL = "/assets"
	}
	view := kiteSuccessView{
		DashboardURL: dashboardURL,
	}
	if err := kiteSuccessTmpl.Execute(w, view); err != nil {
		http.Error(w, fmt.Sprintf("render kite success: %v", err), http.StatusInternalServerError)
	}
}

// kiteOAuthInflight deduplicates concurrent callback requests for the same
// authorization code. The consent page may fire multiple rapid navigations
// to /oauth/callback (e.g. replace + retry), each of which creates a new
// HTTP request with the same single-use code. Without deduplication, the
// first request's context gets canceled by the browser navigation, but the
// token endpoint may have already consumed the code — causing later
// requests to fail with "Invalid authorization code".
var kiteOAuthInflight sync.Map // code → chan *kiteOAuthInflightResult

type kiteOAuthInflightResult struct {
	Token *kiteOAuthTokenResponse
	Err   error
}

func serveKiteOAuthCallbackPage(w http.ResponseWriter, r *http.Request, oauth OAuthOptions, enrollment kiteOAuthEnrollmentOptions) {
	logger := enrollment.Logger
	if logger == nil {
		logger = slog.Default()
	}

	logger.Info("OAuth callback hit",
		"request_path", r.URL.Path,
		"request_url", r.URL.String(),
		"r_host", r.Host,
		"code_len", len(r.URL.Query().Get("code")),
		"has_state", r.URL.Query().Get("state") != "",
	)

	if oauthErr := r.URL.Query().Get("error"); oauthErr != "" {
		description := r.URL.Query().Get("error_description")
		if description == "" {
			description = oauthErr
		}
		http.Error(w, "Kite OAuth authorization failed: "+description, http.StatusBadRequest)
		return
	}

	code, state := kiteOAuthCallbackCodeAndState(r)
	if code == "" {
		http.Error(w, "Kite OAuth callback is missing code.", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie(kiteOAuthStateCookie)
	if err != nil || cookie.Value == "" || state == "" || cookie.Value != state {
		logger.Warn("OAuth state mismatch",
			"cookie_err", err,
			"cookie_empty", cookie == nil || cookie.Value == "",
			"state_empty", state == "",
			"match", cookie != nil && cookie.Value == state,
		)
		http.Error(w, "Kite OAuth state mismatch. Restart the authorization flow.", http.StatusBadRequest)
		return
	}

	verifierCookie, err := r.Cookie(kiteOAuthVerifierCookie)
	if err != nil || verifierCookie.Value == "" {
		http.Error(w, "Kite OAuth PKCE verifier is missing. Restart the authorization flow.", http.StatusBadRequest)
		return
	}

	collectorURL := collectorBaseURL(r, "")
	redirectURI, err := buildKiteOAuthRedirectURI(collectorURL, oauth.RedirectPath)
	if err != nil {
		http.Error(w, "Kite OAuth callback has an invalid redirect URI.", http.StatusBadRequest)
		return
	}

	logger.Info("OAuth token exchange attempt",
		"collector_url", collectorURL,
		"redirect_uri", redirectURI,
		"code_prefix", code[:min(len(code), 12)]+"...",
		"verifier_len", len(verifierCookie.Value),
		"oauth_redirect_path", oauth.RedirectPath,
	)

	// Deduplicate concurrent requests for the same authorization code.
	// The consent page may trigger multiple rapid navigations; only the
	// first one actually hits the token endpoint.
	resultCh := make(chan *kiteOAuthInflightResult, 1)
	if existing, loaded := kiteOAuthInflight.LoadOrStore(code, resultCh); loaded {
		// Another goroutine is already exchanging this code — wait for it.
		logger.Info("OAuth token exchange dedup — waiting for in-flight request",
			"code_prefix", code[:min(len(code), 12)]+"...",
		)
		ch := existing.(chan *kiteOAuthInflightResult)
		result := <-ch
		ch <- result // put it back for other waiters
		if result.Err != nil {
			http.Error(w, "Kite OAuth token exchange failed: "+result.Err.Error(), http.StatusBadGateway)
			return
		}
		if err := enrollKiteOAuthToken(r, enrollment, result.Token.AccessToken); err != nil {
			http.Error(w, "Kite OAuth enrollment failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		clearKiteOAuthCookie(w, kiteOAuthStateCookie)
		clearKiteOAuthCookie(w, kiteOAuthVerifierCookie)
		clearKiteOAuthCookie(w, kiteOAuthDashboardCookie)
		markKiteOAuthWaitComplete(r)
		clearKiteOAuthCookie(w, kiteOAuthWaitCookie)
		serveKiteSuccessPage(w, r)
		return
	}

	// We are the first request for this code. Use a detached context so
	// browser-initiated cancellation (from rapid re-navigation) does not
	// kill the HTTP round-trip to the Supabase token endpoint.
	detachedCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	detachedReq := r.Clone(detachedCtx)

	token, exchangeErr := exchangeKiteOAuthCode(detachedReq, oauth, code, verifierCookie.Value, redirectURI)

	// Publish the result and clean up the in-flight map.
	result := &kiteOAuthInflightResult{Token: token, Err: exchangeErr}
	resultCh <- result
	// Clean up after a short delay so late-arriving duplicates still find it.
	go func() {
		time.Sleep(5 * time.Second)
		kiteOAuthInflight.Delete(code)
	}()

	if exchangeErr != nil {
		attrs := append(kiteerrors.Attrs(exchangeErr),
			slog.String("redirect_uri", redirectURI),
			slog.String("collector_url", collectorURL),
		)
		logger.LogAttrs(r.Context(), slog.LevelError, "OAuth token exchange FAILED", attrs...)
		http.Error(w, "Kite OAuth token exchange failed: "+exchangeErr.Error(), http.StatusBadGateway)
		return
	}

	if err := enrollKiteOAuthToken(r, enrollment, token.AccessToken); err != nil {
		http.Error(w, "Kite OAuth enrollment failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	clearKiteOAuthCookie(w, kiteOAuthStateCookie)
	clearKiteOAuthCookie(w, kiteOAuthVerifierCookie)
	clearKiteOAuthCookie(w, kiteOAuthDashboardCookie)
	markKiteOAuthWaitComplete(r)
	clearKiteOAuthCookie(w, kiteOAuthWaitCookie)
	serveKiteSuccessPage(w, r)
}

func markKiteOAuthWaitComplete(r *http.Request) {
	cookie, err := r.Cookie(kiteOAuthWaitCookie)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return
	}
	kiteOAuthWaits.Store(cookie.Value, time.Now().UTC())
}

func kiteOAuthWaitComplete(waitID string) bool {
	if strings.TrimSpace(waitID) == "" {
		return false
	}
	_, ok := kiteOAuthWaits.Load(waitID)
	return ok
}

func resolveKiteOAuthLaunchURL(ctx context.Context, authURL string) string {
	endpoint, err := url.Parse(authURL)
	if err != nil || endpoint.Host != "api.vulnertrack.com" {
		return authURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return authURL
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return authURL
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return authURL
	}
	location := strings.TrimSpace(resp.Header.Get("Location"))
	if location == "" {
		return authURL
	}
	launchURL, err := endpoint.Parse(location)
	if err != nil {
		return authURL
	}
	if launchURL.Host == "app.vulnertrack.com" && strings.HasPrefix(launchURL.Path, "/kite/signin/oauth/") {
		return launchURL.String()
	}
	return authURL
}

func kiteOAuthCallbackCodeAndState(r *http.Request) (string, string) {
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	if state != "" {
		return code, state
	}

	// DevTools shows JSON response values with \u0026 for '&'. If an operator
	// manually pastes that escaped value into the browser, net/url treats the
	// entire suffix as part of code. Recover the intended state for that
	// manual fallback path.
	for _, marker := range []string{`\\u0026state=`, `\u0026state=`, `%5Cu0026state=`} {
		if idx := strings.Index(code, marker); idx >= 0 {
			return code[:idx], code[idx+len(marker):]
		}
	}

	return code, state
}

func enrollKiteOAuthToken(r *http.Request, enrollment kiteOAuthEnrollmentOptions, accessToken string) error {
	if enrollment.Store == nil {
		return fmt.Errorf("local enrollment store is unavailable")
	}
	if len(enrollment.WrapKey) != 32 {
		return fmt.Errorf("local enrollment wrap key is unavailable")
	}

	fingerprint := sqlite.APIKeyFingerprint(accessToken)
	wrapped, wrapErr := sqlite.AEADWrap(enrollment.WrapKey, []byte(accessToken))
	if wrapErr != nil {
		if enrollment.Logger != nil {
			enrollment.Logger.Error("AEAD wrap of OAuth access token failed",
				"code", string(LogCodeEnrollAEADWrap),
				"fingerprint", shortFingerprint(fingerprint),
				"error", wrapErr,
				"request_path", r.URL.Path,
				"endpoint", enrollment.PlatformEndpoint)
		}
		return fmt.Errorf("failed to wrap OAuth token")
	}

	now := time.Now().UTC()
	if upsertErr := enrollment.Store.UpsertEnrolledIdentity(r.Context(), sqlite.EnrolledIdentity{
		ApiKeyFingerprint: fingerprint,
		ApiKeyWrapped:     wrapped,
		LastEnrolledAt:    now,
	}); upsertErr != nil {
		if enrollment.Logger != nil {
			enrollment.Logger.Error("OAuth enrolled-identity upsert failed",
				"code", string(LogCodeEnrollUpsert),
				"fingerprint", shortFingerprint(fingerprint),
				"error", upsertErr,
				"endpoint", enrollment.PlatformEndpoint,
				"request_path", r.URL.Path)
		}
		return fmt.Errorf("failed to persist local enrollment")
	}

	if enrollment.Logger != nil {
		enrollment.Logger.Info("platform identity enrolled via OAuth",
			"code", string(LogCodeEnrollSuccess),
			"endpoint", enrollment.PlatformEndpoint,
			"fingerprint", shortFingerprint(fingerprint),
			"remote_addr", r.RemoteAddr)
	}
	return nil
}

func buildKiteOAuthAuthorizationURL(oauth OAuthOptions, collectorURL string) (string, string, string, error) {
	redirectURI, err := buildKiteOAuthRedirectURI(collectorURL, oauth.RedirectPath)
	if err != nil {
		return "", "", "", err
	}

	verifier, err := randomBase64URL(32)
	if err != nil {
		return "", "", "", fmt.Errorf("generate PKCE verifier: %w", err)
	}
	state, err := randomBase64URL(32)
	if err != nil {
		return "", "", "", fmt.Errorf("generate OAuth state: %w", err)
	}
	challenge := codeChallengeS256(verifier)

	scope := strings.TrimSpace(oauth.Scope)
	if scope == "" {
		scope = defaultKiteOAuthScope
	}

	clientID := strings.TrimSpace(oauth.ClientID)
	if clientID == "" {
		clientID = defaultKiteOAuthClientID
	}
	if clientID == "" {
		return "", "", "", fmt.Errorf("kite OAuth is not configured; set KITE_OAUTH_CLIENT_ID and reload this page")
	}

	endpoint, err := url.Parse(resolveKiteOAuthAuthorizeURL(oauth))
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return "", "", "", fmt.Errorf("invalid Kite OAuth authorize URL")
	}

	q := endpoint.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	endpoint.RawQuery = q.Encode()

	return endpoint.String(), verifier, state, nil
}

func resolveKiteOAuthAuthorizeURL(oauth OAuthOptions) string {
	if strings.TrimSpace(oauth.AuthorizeURL) != "" {
		return strings.TrimSpace(oauth.AuthorizeURL)
	}
	return defaultKiteOAuthAuthorizeURL
}

func resolveKiteOAuthTokenURL(oauth OAuthOptions) (string, error) {
	authorizeURL := resolveKiteOAuthAuthorizeURL(oauth)
	endpoint, err := url.Parse(authorizeURL)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return "", fmt.Errorf("invalid Kite OAuth authorize URL")
	}
	path := strings.TrimRight(endpoint.Path, "/")
	if !strings.HasSuffix(path, "/authorize") {
		return "", fmt.Errorf("kite OAuth authorize URL must end in /authorize")
	}
	endpoint.Path = strings.TrimSuffix(path, "/authorize") + "/token"
	endpoint.RawQuery = ""
	endpoint.Fragment = ""
	return endpoint.String(), nil
}

func exchangeKiteOAuthCode(r *http.Request, oauth OAuthOptions, code, verifier, redirectURI string) (*kiteOAuthTokenResponse, error) {
	clientID := strings.TrimSpace(oauth.ClientID)
	if clientID == "" {
		clientID = defaultKiteOAuthClientID
	}
	if clientID == "" {
		return nil, fmt.Errorf("missing OAuth client ID")
	}

	tokenURL, err := resolveKiteOAuthTokenURL(oauth)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, kiteerrors.FromCatalog(kiteerrors.CodeOAuthTokenExchange, err).With("stage", "build_request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, kiteerrors.FromCatalog(kiteerrors.CodeOAuthTokenExchange, err).With("stage", "network")
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, kiteOAuthTokenMaxBody))
	if err != nil {
		return nil, kiteerrors.FromCatalog(kiteerrors.CodeOAuthTokenExchange, err).With("stage", "read_response")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, formatKiteOAuthTokenError(resp.StatusCode, body)
	}

	var token kiteOAuthTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, kiteerrors.FromCatalog(kiteerrors.CodeOAuthTokenExchange, err).With("stage", "decode_response")
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return nil, kiteerrors.FromCatalog(kiteerrors.CodeOAuthTokenExchange, nil).With("stage", "missing_access_token")
	}
	return &token, nil
}

func formatKiteOAuthTokenError(status int, body []byte) error {
	err := kiteerrors.FromCatalog(kiteerrors.CodeOAuthTokenExchange, nil).
		With("http_status", status)

	var payload kiteOAuthTokenError
	if jsonErr := json.Unmarshal(body, &payload); jsonErr == nil {
		switch {
		case payload.ErrorDescription != "":
			err = err.With("provider_detail", payload.ErrorDescription)
		case payload.Message != "":
			err = err.With("provider_detail", payload.Message)
		case payload.ErrorCode != "":
			err = err.With("provider_error_code", payload.ErrorCode)
		case payload.Error != "":
			err = err.With("provider_error", payload.Error)
		}
	}
	return err
}

func buildKiteOAuthRedirectURI(collectorURL, redirectPath string) (string, error) {
	base, err := url.Parse(collectorURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("invalid collector URL")
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return "", fmt.Errorf("collector URL must use http or https")
	}
	path := strings.TrimSpace(redirectPath)
	if path == "" {
		path = defaultKiteOAuthRedirectPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	base.RawQuery = ""
	base.Fragment = ""
	base.Path = strings.TrimRight(base.Path, "/") + path
	return base.String(), nil
}

func collectorBaseURL(r *http.Request, raw string) string {
	if u, err := url.Parse(strings.TrimSpace(raw)); err == nil && u.Scheme != "" && u.Host != "" {
		if u.Scheme == "http" || u.Scheme == "https" {
			u.RawQuery = ""
			u.Fragment = ""
			return strings.TrimRight(u.String(), "/")
		}
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func randomBase64URL(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func setKiteOAuthCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	http.SetCookie(w, &http.Cookie{ //#nosec G124 -- Secure is set conditionally on r.TLS; the collector is commonly reached at http://localhost during setup, so unconditional Secure would break the flow
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(kiteOAuthCookieTTL.Seconds()),
		Expires:  time.Now().Add(kiteOAuthCookieTTL),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearKiteOAuthCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{ //#nosec G124 -- clearing cookie: empty value + MaxAge=-1; matches setKiteOAuthCookie which is conditionally Secure for localhost setup flows
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
