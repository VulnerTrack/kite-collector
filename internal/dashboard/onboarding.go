package dashboard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/scan"
	"github.com/vulnertrack/kite-collector/internal/secretstore"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// onboardingDeps bundles everything the onboarding handlers need.
// The sqlite store is taken directly (not via the store.Store interface)
// because identity + probe_result persistence is onboarding-specific and
// does not belong on the generic Store contract.
type onboardingDeps struct {
	StreamCtrl       StreamController
	Installer        Installer
	Store            *sqlite.SQLiteStore
	Logger           *slog.Logger
	ProbeClient      *http.Client
	ProbeDuration    *prometheus.HistogramVec
	PKIReader        pkiCertificateReader
	PKIOperatorToken func(context.Context) (string, error)
	AppVersion       string
	Commit           string
	BuildDate        string
	ConfigFile       string
	DBPath           string
	PlatformEndpoint string
	PKIEndpoint      string
	CertsDir         string
	WrapKey          []byte
	OAuth            OAuthOptions
	TLSConfig        config.TLSConfig
	Coordinator      *scan.Coordinator
	BaseConfig       *config.Config
	SecretStore      secretstore.Store
	// ScanEnabled tells the post-completion launcher panel whether to surface
	// the "Run your first scan" CTA. True when the dashboard was wired with
	// both a scan.Coordinator and a config.Config (the same condition the
	// existing /api/v1/scan handler uses to gate real scan starts vs the
	// read-only placeholder). Kept last so the pointerless bool falls outside
	// the struct's GC pointer-scan region (govet fieldalignment).
	ScanEnabled bool
}

// registerOnboardingRoutes mounts every RFC-0112 dashboard route onto mux.
// Keeping the registration in one function makes the rollback described in
// §6.3 a one-line commentout.
func registerOnboardingRoutes(mux *http.ServeMux, deps onboardingDeps) {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	hydrateIntegrationSecrets(deps)
	mux.HandleFunc("GET /onboarding", serveOnboardingPage)
	mux.HandleFunc("GET /fragments/enroll-form", func(w http.ResponseWriter, r *http.Request) {
		renderOnboardingFragment(w, deps.Logger, "enroll-form", func(buf io.Writer) error {
			return renderEnrollFragment(buf, r.Context(), deps)
		})
	})
	mux.HandleFunc("GET /fragments/active-directory-setup", func(w http.ResponseWriter, r *http.Request) {
		renderOnboardingFragment(w, deps.Logger, "active-directory-setup", func(buf io.Writer) error {
			return renderActiveDirectorySetup(buf, deps, "", "")
		})
	})
	mux.HandleFunc("GET /fragments/services-setup", func(w http.ResponseWriter, r *http.Request) {
		renderOnboardingFragment(w, deps.Logger, "services-setup", func(buf io.Writer) error {
			return renderDiscoveredServicesSetup(buf, r.Context(), deps)
		})
	})
	mux.HandleFunc("GET /api/v1/integrations", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, deps.Logger, http.StatusOK, discoveredIntegrationsAPI(r.Context(), deps))
	})
	mux.HandleFunc("POST /api/v1/onboarding/active-directory", func(w http.ResponseWriter, r *http.Request) {
		handleActiveDirectorySetup(w, r, deps)
	})
	mux.HandleFunc("POST /api/v1/identity/enroll", func(w http.ResponseWriter, r *http.Request) {
		handleEnroll(w, r, deps)
	})
	mux.HandleFunc("GET /api/v1/connection/check", func(w http.ResponseWriter, r *http.Request) {
		handleConnectionCheckJSON(w, r, deps)
	})
	mux.HandleFunc("GET /fragments/connection-check", func(w http.ResponseWriter, r *http.Request) {
		renderOnboardingFragment(w, deps.Logger, "connection-check", func(buf io.Writer) error {
			return renderConnectionCheckFragment(buf, r, deps, false)
		})
	})
	mux.HandleFunc("POST /api/v1/connection/check", func(w http.ResponseWriter, r *http.Request) {
		renderOnboardingFragment(w, deps.Logger, "connection-check", func(buf io.Writer) error {
			return renderConnectionCheckFragment(buf, r, deps, true)
		})
	})
	mux.HandleFunc("POST /api/v1/stream/start", func(w http.ResponseWriter, r *http.Request) {
		handleStreamStart(w, r, deps)
	})
	mux.HandleFunc("POST /api/v1/stream/stop", func(w http.ResponseWriter, r *http.Request) {
		handleStreamStop(w, r, deps)
	})
	mux.HandleFunc("GET /fragments/onboarding-steps", func(w http.ResponseWriter, r *http.Request) {
		renderOnboardingFragment(w, deps.Logger, "onboarding-steps", func(buf io.Writer) error {
			return renderOnboardingStepsFragment(buf, r.Context(), deps)
		})
	})
	mux.HandleFunc("GET /fragments/stream-status", func(w http.ResponseWriter, r *http.Request) {
		renderOnboardingFragment(w, deps.Logger, "stream-status", func(buf io.Writer) error {
			return renderStreamStatusFragment(buf, deps)
		})
	})
	mux.HandleFunc("GET /api/v1/support-bundle", func(w http.ResponseWriter, r *http.Request) {
		handleSupportBundle(w, r, deps)
	})

	// Install / state APIs (smart-default OS-aware onboarding). Lives in
	// onboarding_install.go to keep the install surface area isolated from
	// the enroll/check/stream code paths.
	registerAgentInstallRoutes(mux, deps)

	// Local observability surface — healthchecks + probe metrics + scan
	// stats. Pulls from the same store the onboarding flow uses, so all
	// the data shown is computed on this host (no external scrapers).
	registerObservabilityRoutes(mux, deps)
	registerCertificatesRoutes(mux, deps)
}

// onboardingBody is the /onboarding shell content: an intro line and the
// server-rendered onboarding flow (#onboarding-steps), which re-renders on
// every refresh-agent-state trigger. It is composed inside the shared
// dashboard shell (renderIndexPage) so /onboarding gets the same sidebar +
// grid chrome as the rest of the dashboard. Step visibility is decided
// entirely server-side (onboarding_steps.go); the only page script left is
// the HTMX error-toast pipeline.
const onboardingBody = `<div id="onboarding-toasts" class="toasts" aria-live="polite" aria-atomic="false" role="status"></div>

<div class="onboarding-layout">
  <h2>Collector onboarding</h2>
  <p class="muted onb-intro">Guided setup. Kite detects what&rsquo;s already done and only shows service configuration when an integration is available. No agent data leaves this host until streaming starts.</p>

  <div id="onboarding-steps"
       hx-get="/fragments/onboarding-steps"
       hx-trigger="load, refresh-agent-state from:body"
       hx-swap="innerHTML">
    <div class="htmx-indicator">Detecting agent state&hellip;</div>
  </div>
</div>

<script>
  // HTMX error toast pipeline — closes the only place in the onboarding
  // flow where the operator can be left without feedback after an action.
  // Without this, htmx:sendError (network/connect refused: usually the
  // dashboard process died) and htmx:responseError (5xx) are silent — the
  // button re-enables, spinner stops, nothing appears. Operators wonder if
  // they're doing something wrong instead of seeing the actual root cause.
  (function() {
    var toasts = document.getElementById('onboarding-toasts');
    if (!toasts) return;
    function show(message) {
      var t = document.createElement('div');
      t.className = 'toast toast-error';
      t.textContent = message;
      t.addEventListener('click', function() { t.remove(); });
      toasts.appendChild(t);
      // Auto-dismiss after 7s — long enough to read, short enough not to
      // accumulate on repeated failures.
      setTimeout(function() { t.remove(); }, 7000);
    }
    document.body.addEventListener('htmx:sendError', function() {
      show('Lost connection to dashboard — check the terminal or restart with: kite-collector dashboard');
    });
    document.body.addEventListener('htmx:responseError', function(e) {
      var status = (e && e.detail && e.detail.xhr && e.detail.xhr.status) || '?';
      show('Dashboard returned HTTP ' + status + ' — check the terminal for the full error trace.');
    });
  })();

  // copyFromBtn reads data-copy off the clicked button and writes it to
  // the system clipboard, with a brief ✓ confirmation so operators know
  // the copy actually happened. Used by the fingerprint + CLI hint copy
  // buttons. Fails gracefully (button shows × Failed) if the Clipboard
  // API is unavailable (HTTP-only origin without a secure context, or
  // browsers that gate writeText behind permissions).
  window.copyFromBtn = function(btn) {
    var text = btn.getAttribute('data-copy') || '';
    if (!text || !navigator.clipboard) {
      btn.textContent = '× failed';
      setTimeout(function(){ btn.textContent = 'copy'; }, 1500);
      return;
    }
    navigator.clipboard.writeText(text).then(function() {
      var original = btn.textContent;
      btn.textContent = '✓ copied';
      btn.disabled = true;
      setTimeout(function() {
        btn.textContent = original;
        btn.disabled = false;
      }, 1500);
    }).catch(function() {
      btn.textContent = '× failed';
      setTimeout(function(){ btn.textContent = 'copy'; }, 1500);
    });
  };
</script>`

// serveOnboardingPage writes the onboarding view inside the dashboard
// shell. Plain GET returns the full shell with onboardingBody embedded;
// HX-Request: true returns the fragment only so the navigation swap from
// any other page lands without a full reload.
//
// ?step=<install|enroll|check|stream> adds a visual focus accent on the
// matching card. The query param is validated against an allow-list so
// the step name cannot inject HTML / CSS via concatenation — only the
// four canonical card IDs are honoured. Used for teamwork URLs ("look
// at the check card") shared in chats / tickets.
func serveOnboardingPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	focusStep := validatedFocusStep(r.URL.Query().Get("step"))
	if r.Header.Get("HX-Request") == "true" {
		writeFocusStepStyle(w, focusStep)
		_, _ = io.WriteString(w, onboardingBody)
		return
	}
	var buf bytes.Buffer
	if err := renderIndexPage(&buf, "onboarding", func(fragBuf io.Writer) error {
		writeFocusStepStyle(fragBuf, focusStep)
		if _, err := io.WriteString(fragBuf, onboardingBody); err != nil {
			return fmt.Errorf("write onboarding body: %w", err)
		}
		return nil
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(buf.Bytes())
}

// validatedFocusStep maps the ?step= query value to a canonical onboarding
// card ID, or "" when the value is missing or unrecognised. Pinned to an
// allow-list so the value can be safely substituted into a CSS selector
// without escaping concerns — there is no path for operator-supplied text
// to reach the response body unsanitized.
func validatedFocusStep(raw string) string {
	switch raw {
	case "install", "enroll", "check", "stream":
		return raw
	}
	return ""
}

// writeFocusStepStyle emits a tiny inline <style> tag adding the
// .focused-step accent to the card matching the ?step= query, so a teamwork
// URL like /onboarding?step=check arrives with the check card visually
// highlighted instead of the operator having to hunt for it after the
// browser auto-scroll lands. No-ops when step is empty (the normal case).
func writeFocusStepStyle(w io.Writer, step string) {
	if step == "" {
		return
	}
	// Hard-coded class + selector — step is from a fixed allow-list so
	// Fprintf into a CSS selector is safe by construction. Write error is
	// ignored consistently with the other io.WriteString calls in this
	// package — the response writer is best-effort here.
	// The check step folded into the stream card; "enroll" keeps its
	// historical card id.
	card := step + "-card"
	switch step {
	case "check", "stream":
		card = "stream-card"
	case "enroll":
		card = "enroll-card"
	case "install":
		card = "install-card"
	}
	_, _ = fmt.Fprintf(w, `<style>#%s{box-shadow:0 0 0 3px var(--palette-primary-main,#ff3131);transition:box-shadow .25s ease-in-out;border-radius:10px;}</style>`+"\n", card)
}

// renderOnboardingFragment is a buffered renderer that mirrors the
// existing scan-status fragment: template errors never produce a half-
// written response with a 200 status.
func renderOnboardingFragment(w http.ResponseWriter, logger *slog.Logger, name string, render func(io.Writer) error) {
	var buf bytes.Buffer
	if err := render(&buf); err != nil {
		logger.Error("dashboard: onboarding render "+name,
			"code", string(LogCodeOnboardingFragmentRender),
			"error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// ===========================================================================
// Enroll
// ===========================================================================

type enrollView struct {
	Endpoint              string
	FingerprintShort      string
	FingerprintFull       string
	FirstEnrolledAt       string // RFC3339 — preserved for the hover tooltip / machine-readable use
	LastEnrolledAt        string
	FirstEnrolledRelative string // "2h ago" — primary display for human-glance reading
	LastEnrolledRelative  string
	Error                 string
	TurnstileSiteKey      string
	ReadOnly              bool
	Enrolled              bool
}

var enrollFragmentTmpl = template.Must(template.New("enroll").Parse(`
{{- if .Enrolled}}
<div class="enroll-status">
  <p>
    <span class="badge badge-green">enrolled</span>
    &mdash; fingerprint <code title="{{.FingerprintFull}}">{{.FingerprintShort}}</code>
    <button type="button" class="btn-copy" data-copy="{{.FingerprintFull}}" onclick="copyFromBtn(this)" title="Copy the full SHA-256 fingerprint to clipboard" aria-label="Copy full SHA-256 fingerprint to clipboard">copy</button>
  </p>
  <p class="muted small">
    first enrolled <span title="{{.FirstEnrolledAt}}">{{.FirstEnrolledRelative}}</span>
    &middot; last refreshed <span title="{{.LastEnrolledAt}}">{{.LastEnrolledRelative}}</span>
  </p>
</div>
{{- end}}
<p>Platform endpoint: <code>{{.Endpoint}}</code> <span class="muted small">(from collector config)</span></p>
<div class="enroll-action-container" style="margin-top: 1.5rem;">
  {{- if .ReadOnly}}
    <p class="muted small">Read-only inspector mode &mdash; enroll disabled.</p>
  {{- else}}
    {{- if .Error}}<p id="enroll-error-msg" class="enroll-error badge-red" role="alert" style="margin: 0 0 0.85rem 0; padding: 6px 10px; font-size: var(--text-sm); border-radius: 8px;">{{.Error}}</p>{{end}}
    <div style="padding: 1.25rem; border: 1px dashed var(--palette-divider, #e5e7eb); border-radius: 12px; background: rgba(145, 158, 171, 0.02);">
      <h3 style="margin: 0 0 0.4rem 0; font-size: var(--text-md); font-weight: 600; color: var(--palette-text-primary, #1c252e);">Link via browser</h3>
      <p class="muted small" style="margin-bottom: 0.85rem; line-height: 1.4;">Sign in securely from your browser and connect this collector to your VulnerTrack account.</p>
      <a class="btn btn-primary" href="/kite-login?dashboard=/onboarding#check-card" style="width: 100%; text-align: center; justify-content: center; box-shadow: none;">
        {{if .Enrolled}}Re-link collector{{else}}Link collector / Sign in &rarr;{{end}}
      </a>
    </div>
  {{- end}}
</div>
`))

func renderEnrollFragment(w io.Writer, ctx context.Context, deps onboardingDeps) error {
	view := enrollView{ReadOnly: deps.Store == nil, Endpoint: deps.PlatformEndpoint, TurnstileSiteKey: deps.OAuth.TurnstileSiteKey}
	if deps.Store != nil {
		id, err := deps.Store.GetEnrolledIdentity(ctx)
		if err != nil && !errors.Is(err, sqlite.ErrNoIdentity) {
			return fmt.Errorf("load identity: %w", err)
		}
		if err == nil {
			view.Enrolled = true
			view.FingerprintFull = id.ApiKeyFingerprint
			view.FingerprintShort = shortFingerprint(id.ApiKeyFingerprint)
			view.FirstEnrolledAt = id.FirstEnrolledAt.Format(time.RFC3339)
			view.LastEnrolledAt = id.LastEnrolledAt.Format(time.RFC3339)
			view.FirstEnrolledRelative = humanizeRelativeTime(time.Since(id.FirstEnrolledAt))
			view.LastEnrolledRelative = humanizeRelativeTime(time.Since(id.LastEnrolledAt))
		}
	}
	if execErr := enrollFragmentTmpl.Execute(w, view); execErr != nil {
		return fmt.Errorf("render enroll fragment: %w", execErr)
	}
	return nil
}

// shortFingerprint returns the first eight hex characters of a full
// sha256-hex fingerprint. When the input is already short it is returned
// as-is. This is the canonical "sha256[:8]" rendering from R4.
func shortFingerprint(fp string) string {
	if len(fp) < 8 {
		return fp
	}
	return fp[:8]
}

func handleEnroll(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	ctx := r.Context()
	view := enrollView{Endpoint: deps.PlatformEndpoint, TurnstileSiteKey: deps.OAuth.TurnstileSiteKey}

	if deps.Store == nil {
		view.ReadOnly = true
		view.Error = "enrollment disabled in read-only dashboard mode"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}
	if len(deps.WrapKey) != 32 {
		deps.Logger.Error("enroll cannot proceed without AEAD wrap key",
			"code", string(LogCodeEnrollMissingWrapKey),
			"wrap_key_len", len(deps.WrapKey),
			"want_wrap_key_len", 32,
			"request_path", r.URL.Path,
			"remote_addr", r.RemoteAddr)
		view.Error = "server misconfigured: no wrap key"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}

	if err := r.ParseForm(); err != nil {
		view.Error = "invalid form submission"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}

	email := r.PostFormValue("email")
	password := r.PostFormValue("password")
	var apiKey string

	if email != "" && password != "" {
		if strings.TrimSpace(deps.OAuth.TurnstileSiteKey) == "" {
			view.Error = "Direct sign-in requires captcha configuration. Set KITE_OAUTH_TURNSTILE_SITE_KEY or use browser linking."
			writeEnrollFragment(w, deps.Logger, view)
			return
		}
		captchaToken := r.PostFormValue("cf-turnstile-response")
		if strings.TrimSpace(captchaToken) == "" {
			view.Error = "Complete the captcha challenge before signing in"
			writeEnrollFragment(w, deps.Logger, view)
			return
		}
		token, err := loginToSupabase(ctx, deps.OAuth.SupabaseURL, deps.OAuth.SupabaseAnonKey, email, password, captchaToken)
		if err != nil {
			deps.Logger.Error("Direct login to Supabase failed", "error", err, "email", email)
			view.Error = "Login failed: " + err.Error()
			writeEnrollFragment(w, deps.Logger, view)
			return
		}
		apiKey = token
	} else {
		apiKey = r.PostFormValue("api_key")
	}

	if strings.TrimSpace(apiKey) == "" {
		view.Error = "Email and password are required"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}

	fingerprint := sqlite.APIKeyFingerprint(apiKey)
	wrapped, wrapErr := sqlite.AEADWrap(deps.WrapKey, []byte(apiKey))
	if wrapErr != nil {
		deps.Logger.Error("AEAD wrap of API key failed",
			"code", string(LogCodeEnrollAEADWrap),
			"fingerprint", shortFingerprint(fingerprint),
			"error", wrapErr,
			"request_path", r.URL.Path,
			"endpoint", deps.PlatformEndpoint)
		view.Error = "internal error wrapping API key"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}

	now := time.Now().UTC()
	if upsertErr := deps.Store.UpsertEnrolledIdentity(ctx, sqlite.EnrolledIdentity{
		ApiKeyFingerprint: fingerprint,
		ApiKeyWrapped:     wrapped,
		LastEnrolledAt:    now,
	}); upsertErr != nil {
		deps.Logger.Error("enrolled-identity upsert failed",
			"code", string(LogCodeEnrollUpsert),
			"fingerprint", shortFingerprint(fingerprint),
			"error", upsertErr,
			"endpoint", deps.PlatformEndpoint,
			"request_path", r.URL.Path)
		view.Error = "failed to persist enrollment"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}

	deps.Logger.Info(
		"platform identity enrolled",
		"code", string(LogCodeEnrollSuccess),
		"endpoint", deps.PlatformEndpoint,
		"fingerprint", shortFingerprint(fingerprint),
		"remote_addr", r.RemoteAddr,
	)
	startBaseOnboardingScan(ctx, deps.Coordinator, deps.BaseConfig, deps.Logger)

	id, err := deps.Store.GetEnrolledIdentity(ctx)
	if err != nil {
		view.Error = "enrollment saved but reload failed"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}
	view = enrollView{
		Enrolled:              true,
		Endpoint:              deps.PlatformEndpoint,
		FingerprintFull:       id.ApiKeyFingerprint,
		FingerprintShort:      shortFingerprint(id.ApiKeyFingerprint),
		FirstEnrolledAt:       id.FirstEnrolledAt.Format(time.RFC3339),
		LastEnrolledAt:        id.LastEnrolledAt.Format(time.RFC3339),
		FirstEnrolledRelative: humanizeRelativeTime(time.Since(id.FirstEnrolledAt)),
		LastEnrolledRelative:  humanizeRelativeTime(time.Since(id.LastEnrolledAt)),
	}

	// Auto-run the connection check after a successful enrollment, OOB-swapping
	// the #check-fragment so the operator sees six fresh probe outcomes without
	// a second click. The HX-Trigger header tells the onboarding-header
	// fragment to re-render immediately so the stepper advances enroll →
	// check on the next HTMX cycle without waiting for the 10s heartbeat.
	w.Header().Set("HX-Trigger", "refresh-agent-state")
	// After-Settle fires the smooth-scroll to the check card after the new
	// enroll fragment + OOB-swapped check fragment have both landed.
	// Operator sees the auto-run probe results without scrolling manually.
	w.Header().Set("HX-Trigger-After-Settle", `{"scroll-to-step":{"target":"#stream-card"}}`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	if err := enrollFragmentTmpl.Execute(&buf, view); err != nil {
		deps.Logger.Error("enroll fragment template render failed",
			"code", string(LogCodeEnrollRender),
			"error", err,
			"fingerprint", view.FingerprintShort,
			"request_path", r.URL.Path)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Out-of-band probe render.
	buf.WriteString(`<div id="check-fragment" hx-swap-oob="innerHTML">`)
	if renderErr := renderConnectionCheckFragment(&buf, r, deps, true); renderErr != nil {
		deps.Logger.Warn("auto-run connection check after enroll failed",
			"code", string(LogCodeEnrollAutoCheck),
			"error", renderErr,
			"fingerprint", view.FingerprintShort,
			"endpoint", deps.PlatformEndpoint)
	}
	buf.WriteString(`</div>`)
	_, _ = w.Write(buf.Bytes())
}

func loginToSupabase(ctx context.Context, supabaseURL, anonKey, email, password, captchaToken string) (string, error) {
	if supabaseURL == "" {
		return "", errors.New("supabase url is not configured")
	}
	if anonKey == "" {
		return "", errors.New("supabase anon key is not configured")
	}

	loginURL := fmt.Sprintf("%s/auth/v1/token?grant_type=password", strings.TrimRight(supabaseURL, "/"))

	type securityMeta struct {
		CaptchaToken string `json:"captcha_token"`
	}
	type loginPayload struct {
		GoTrueMetaSecurity *securityMeta `json:"gotrue_meta_security,omitempty"`
		Email              string        `json:"email"`
		Password           string        `json:"password"`
	}

	payload := loginPayload{
		Email:    email,
		Password: password,
	}
	if captchaToken != "" {
		payload.GoTrueMetaSecurity = &securityMeta{
			CaptchaToken: captchaToken,
		}
	}

	bodyBytes, err := json.Marshal(payload) //#nosec G117 -- Password field is the credential we intentionally send to the Supabase password-grant endpoint
	if err != nil {
		return "", fmt.Errorf("failed to encode credentials: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("apikey", anonKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("network error authenticating with Supabase: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errPayload struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
			Message          string `json:"msg"`
		}
		if jsonErr := json.Unmarshal(respBody, &errPayload); jsonErr == nil {
			if errPayload.ErrorDescription != "" {
				return "", errors.New(errPayload.ErrorDescription)
			}
			if errPayload.Message != "" {
				return "", errors.New(errPayload.Message)
			}
			if errPayload.Error != "" {
				return "", errors.New(errPayload.Error)
			}
		}
		return "", fmt.Errorf("auth server returned status %d", resp.StatusCode)
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(respBody, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if strings.TrimSpace(tokenResponse.AccessToken) == "" {
		return "", errors.New("empty access token returned from auth server")
	}

	return tokenResponse.AccessToken, nil
}

func writeEnrollFragment(w http.ResponseWriter, logger *slog.Logger, view enrollView) {
	renderOnboardingFragment(w, logger, "enroll-form", func(buf io.Writer) error {
		if err := enrollFragmentTmpl.Execute(buf, view); err != nil {
			return fmt.Errorf("render enroll fragment: %w", err)
		}
		return nil
	})
}

// ===========================================================================
// Connection check
// ===========================================================================

// probeName is the canonical identifier for connection probes.
type probeName string

const (
	probeDNS   probeName = "dns"
	probeTLS   probeName = "tls"
	probeReach probeName = "reach"
	probeAuth  probeName = "auth"
	probeClock probeName = "clock"
	probeOTLP  probeName = "otlp"
)

// probeAction is the optional typed recovery button surfaced beside a
// failed probe's remediation text. URL can be a relative anchor (Target
// empty → scroll-and-focus in the current frame) or an external URL
// (Target="_blank" → opens in a new tab). Kept as a pointer on
// probeResult so it serializes out of the JSON wire only when present.
type probeAction struct {
	URL    string `json:"url"`
	Label  string `json:"label"`
	Target string `json:"target,omitempty"`
}

// probeResult is the wire shape returned by GET /api/v1/connection/check and
// also the per-row view model consumed by the HTMX fragment.
type probeResult struct {
	Action      *probeAction `json:"action,omitempty"`
	Name        probeName    `json:"name"`
	Result      string       `json:"result"`
	Diagnostic  string       `json:"diagnostic,omitempty"`
	Remediation string       `json:"remediation,omitempty"`
	LatencyMS   int64        `json:"latency_ms"`
}

type connectionCheckResponse struct {
	CheckedAt string        `json:"checked_at"`
	Probes    []probeResult `json:"probes"`
	AllPass   bool          `json:"all_pass"`
}

func onboardingTLSConfig(deps onboardingDeps) (config.TLSConfig, bool) {
	cfg := deps.TLSConfig
	certsDir := strings.TrimSpace(deps.CertsDir)
	if certsDir != "" {
		certFile := filepath.Join(certsDir, "agent.pem")
		keyFile := filepath.Join(certsDir, "agent-key.pem")
		caFile := filepath.Join(certsDir, "ca.pem")
		_, certErr := os.Stat(certFile)
		_, keyErr := os.Stat(keyFile)
		_, caErr := os.Stat(caFile)
		if certErr == nil && keyErr == nil && caErr == nil {
			cfg.Enabled = true
			cfg.CertFile = certFile
			cfg.KeyFile = keyFile
			cfg.CAFile = caFile
		}
	}

	havePKI := cfg.Enabled && cfg.CertFile != "" && cfg.KeyFile != ""
	if havePKI {
		_, certErr := os.Stat(cfg.CertFile)
		_, keyErr := os.Stat(cfg.KeyFile)
		havePKI = certErr == nil && keyErr == nil
	}
	return cfg, havePKI
}

func onboardingProbeClient(deps onboardingDeps, tlsSettings config.TLSConfig) (*http.Client, error) {
	if deps.ProbeClient != nil {
		return deps.ProbeClient, nil
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if tlsSettings.Enabled {
		tlsCfg, err := buildTLSConfig(tlsSettings)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsCfg
	}
	return &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
	}, nil
}

// runAllProbes executes the five probes against the enrolled identity. Four
// of the five (DNS, TLS, reach, OTLP) are independent and run in
// parallel; clock waits on reach so it can parse the Date header from the
// reach response (the same HTTP round-trip provides the skew baseline).
//
// Wall-time reduction is the point: sequentially the worst-case is the sum
// of every probe timeout (~30-48s); in parallel it collapses to the slowest
// single probe (~5-8s). The connection-check fragment becomes responsive
// enough that operators no longer wonder if the dashboard hung.
//
// When no identity is present probes 3–5 return SKIP with "no identity
// enrolled" per RFC §4.3. When deps.Store is nil (read-only dashboard) the
// same SKIP applies.
func runAllProbes(ctx context.Context, deps onboardingDeps) []probeResult {
	// Fixed-index slice keeps the canonical DNS→TLS→reach→clock→OTLP
	// order in the UI even though goroutines complete out of order. Each
	// position is written by exactly one goroutine — no mutex needed.
	results := make([]probeResult, 5)

	var (
		endpoint    = deps.PlatformEndpoint
		apiKey      string
		haveID      bool
		readOnly    = deps.Store == nil
		enrolledURL *url.URL
	)
	tlsSettings, havePKI := onboardingTLSConfig(deps)
	probeClient, probeClientErr := onboardingProbeClient(deps, tlsSettings)
	if endpoint != "" {
		enrolledURL, _ = url.Parse(endpoint)
	}
	if !readOnly {
		id, err := deps.Store.GetEnrolledIdentity(ctx)
		if err == nil {
			haveID = havePKI
			if !havePKI && len(deps.WrapKey) == 32 {
				if pt, unwrapErr := sqlite.AEADUnwrap(deps.WrapKey, id.ApiKeyWrapped); unwrapErr == nil {
					apiKey = string(pt)
					haveID = true
				} else {
					deps.Logger.Warn("identity AEAD unwrap failed",
						"code", string(LogCodeIdentityUnwrap),
						"error", unwrapErr,
						"fingerprint", shortFingerprint(id.ApiKeyFingerprint),
						"wrapped_len", len(id.ApiKeyWrapped))
				}
			}
		}
	}

	if os.Getenv("KITE_ONBOARDING_SKIP_CHECKS") == "true" {
		names := []probeName{probeDNS, probeTLS, probeReach, probeClock, probeOTLP}
		for i, name := range names {
			results[i] = probeResult{
				Name:       name,
				Result:     "pass",
				Diagnostic: "skipped (mocked success)",
				LatencyMS:  1,
			}
		}
		if deps.Store != nil {
			now := time.Now().UTC()
			for _, r := range results {
				_ = deps.Store.InsertProbeResult(ctx, sqlite.ProbeResultRecord{
					ProbeName:  string(r.Name),
					Result:     r.Result,
					LatencyMS:  r.LatencyMS,
					Diagnostic: r.Diagnostic,
					CheckedAt:  now,
				})
			}
			if haveID {
				_ = deps.Store.UpdateIdentityCheckStamp(ctx, &now, nil)
			}
		}
		return results
	}

	var tlsCfg *tls.Config
	if probeClientErr == nil && tlsSettings.Enabled {
		tlsCfg, _ = buildTLSConfig(tlsSettings)
	}

	// reachDone is closed when the reach probe finishes; the clock goroutine
	// blocks on this channel so it can consume reachDateHeader without a
	// data race (channel close happens-before the read after receive).
	reachDone := make(chan struct{})
	var reachDateHeader string

	var wg sync.WaitGroup
	wg.Add(5)

	go func() {
		defer wg.Done()
		results[0] = timeProbe(deps, probeDNS, func() probeResult {
			if enrolledURL == nil || enrolledURL.Hostname() == "" {
				return probeResult{Result: "skip", Diagnostic: "no identity enrolled"}
			}
			return runDNSProbe(ctx, enrolledURL.Hostname())
		})
	}()

	go func() {
		defer wg.Done()
		results[1] = timeProbe(deps, probeTLS, func() probeResult {
			if enrolledURL == nil {
				return probeResult{Result: "skip", Diagnostic: "no identity enrolled"}
			}
			if enrolledURL.Scheme != "https" {
				return probeResult{Result: "skip", Diagnostic: "endpoint is plain http"}
			}
			if probeClientErr != nil {
				return probeResult{Result: "fail", Diagnostic: "PKI credentials: " + probeClientErr.Error()}
			}
			return runTLSProbe(ctx, enrolledURL, tlsCfg)
		})
	}()

	go func() {
		defer wg.Done()
		defer close(reachDone)
		results[2] = timeProbe(deps, probeReach, func() probeResult {
			if readOnly {
				return probeResult{Result: "skip", Diagnostic: "read-only inspector mode"}
			}
			if !haveID {
				return probeResult{Result: "skip", Diagnostic: "no identity enrolled"}
			}
			if probeClientErr != nil {
				return probeResult{Result: "fail", Diagnostic: "PKI credentials: " + probeClientErr.Error()}
			}
			res, dateHdr := runReachProbe(ctx, probeClient, endpoint)
			reachDateHeader = dateHdr
			return res
		})
	}()

	go func() {
		defer wg.Done()
		// Clock depends on reach for the Date header. Block on reachDone so
		// reachDateHeader is safe to read; ctx cancellation unblocks early.
		select {
		case <-reachDone:
		case <-ctx.Done():
		}
		results[3] = timeProbe(deps, probeClock, func() probeResult {
			if readOnly {
				return probeResult{Result: "skip", Diagnostic: "read-only inspector mode"}
			}
			if !haveID {
				return probeResult{Result: "skip", Diagnostic: "no identity enrolled"}
			}
			if reachDateHeader == "" {
				return probeResult{Result: "skip", Diagnostic: "no Date header on reach response"}
			}
			return runClockProbe(reachDateHeader)
		})
	}()

	go func() {
		defer wg.Done()
		results[4] = timeProbe(deps, probeOTLP, func() probeResult {
			if readOnly {
				return probeResult{Result: "skip", Diagnostic: "read-only inspector mode"}
			}
			if !haveID {
				return probeResult{Result: "skip", Diagnostic: "no identity enrolled"}
			}
			if probeClientErr != nil {
				return probeResult{Result: "fail", Diagnostic: "PKI credentials: " + probeClientErr.Error()}
			}
			return runOTLPProbe(ctx, probeClient, endpoint, apiKey)
		})
	}()

	wg.Wait()

	// Persist probe_result rows and stamp the identity.
	if deps.Store != nil {
		now := time.Now().UTC()
		anyFail := false
		for _, r := range results {
			_ = deps.Store.InsertProbeResult(ctx, sqlite.ProbeResultRecord{
				ProbeName:  string(r.Name),
				Result:     r.Result,
				LatencyMS:  r.LatencyMS,
				Diagnostic: r.Diagnostic,
				CheckedAt:  now,
			})
			if r.Result == "fail" {
				anyFail = true
			}
		}
		if haveID {
			if anyFail {
				_ = deps.Store.UpdateIdentityCheckStamp(ctx, nil, &now)
			} else {
				_ = deps.Store.UpdateIdentityCheckStamp(ctx, &now, nil)
			}
		}
	}

	// Attach remediation hints + typed recovery actions for any fail.
	// Action is optional — only probes whose recovery is unambiguously a
	// jump to another panel (auth → enroll) or an out-of-band check (reach
	// → open endpoint URL) get one. Other probes rely on the existing
	// primary "Run check" button so we don't dilute the UI with redundant
	// per-row "retry" buttons.
	for i := range results {
		if results[i].Result == "fail" {
			results[i].Remediation = remediationFor(results[i])
			results[i].Action = actionFor(results[i].Name, endpoint)
		}
	}

	return results
}

// actionFor returns the typed recovery action for a failed probe, or nil
// when re-running the check is the only sensible next step.
//
//   - probeAuth → "Re-enroll" anchor that scrolls to the enroll card and
//     focuses the API key input via a tiny inline onclick. Recovery here
//     is unambiguous (the key is bad / revoked) and lives in a different
//     panel, so a typed button removes the "scroll, find input, click,
//     paste" sequence.
//   - probeReach → "Open endpoint" external link that lets the operator
//     eyeball the URL in a new tab without copy/pasting it out of the
//     diagnostic.
//
// New probe-action mappings belong here so the taxonomy stays auditable.
func actionFor(name probeName, endpoint string) *probeAction {
	switch name {
	case probeAuth:
		return &probeAction{
			URL:   "#enroll-card",
			Label: "Re-enroll",
		}
	case probeReach:
		if endpoint != "" {
			return &probeAction{
				URL:    strings.TrimRight(endpoint, "/") + "/healthz",
				Label:  "Open endpoint",
				Target: "_blank",
			}
		}
	case probeDNS, probeTLS, probeClock, probeOTLP:
		// Re-running the check covers these. No per-row action.
	}
	return nil
}

// timeProbe wraps probe execution with an elapsed-ms measurement and
// a Prometheus histogram observation. It also ensures Name is set on the
// returned result so callers do not need to remember to fill it.
func timeProbe(deps onboardingDeps, name probeName, fn func() probeResult) probeResult {
	start := time.Now()
	r := fn()
	r.Name = name
	r.LatencyMS = time.Since(start).Milliseconds()
	if deps.ProbeDuration != nil {
		deps.ProbeDuration.WithLabelValues(string(name), r.Result).Observe(float64(r.LatencyMS))
	}
	return r
}

// remediationFor returns a one-line remediation hint per probe. The strings
// are stable so operator runbooks can grep for them. It inspects the result's
// diagnostic where the same probe can fail for materially different reasons —
// e.g. an auth 404 (the endpoint has no /v1/auth/echo route: the mTLS handshake
// succeeded, so it is NOT a certificate problem) must not send the operator to
// re-enroll, which cannot add a missing route.
func remediationFor(r probeResult) string {
	switch r.Name {
	case probeDNS:
		return "verify the platform endpoint hostname resolves from this host (check /etc/resolv.conf)"
	case probeTLS:
		return "TLS handshake failed — check cert pinning and system CA bundle"
	case probeReach:
		return "endpoint unreachable — check egress firewall and that the platform is up"
	case probeAuth:
		if strings.Contains(r.Diagnostic, "404") {
			return "endpoint has no /v1/auth/echo route: the mTLS handshake succeeded, " +
				"so the certificate is fine — point the platform endpoint at the API " +
				"that implements it (not the OTLP receiver). Re-enrolling will not help."
		}
		return "mTLS authentication failed — re-enroll with PKI and verify the client certificate"
	case probeClock:
		return "local clock differs from platform by more than 60s — sync with NTP"
	case probeOTLP:
		return "OTLP handshake failed — confirm the endpoint exposes /v1/logs"
	}
	return ""
}

// runDNSProbe performs a 5-second A/AAAA lookup.
func runDNSProbe(ctx context.Context, host string) probeResult {
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var r net.Resolver
	addrs, err := r.LookupHost(lookupCtx, host)
	if err != nil {
		return probeResult{Result: "fail", Diagnostic: "DNS lookup: " + err.Error()}
	}
	if len(addrs) == 0 {
		return probeResult{Result: "fail", Diagnostic: "no addresses returned"}
	}
	return probeResult{Result: "pass", Diagnostic: fmt.Sprintf("resolved %d addrs", len(addrs))}
}

// runTLSProbe dials the endpoint host:port and completes a TLS handshake,
// failing on any cert validation error.
func runTLSProbe(ctx context.Context, u *url.URL, tlsCfg *tls.Config) probeResult {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d := tls.Dialer{
		Config: tlsCfg,
	}
	conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return probeResult{Result: "fail", Diagnostic: "TLS dial: " + err.Error()}
	}
	_ = conn.Close()
	return probeResult{Result: "pass", Diagnostic: "handshake ok"}
}

// runReachProbe issues GET /healthz and considers any 2xx–4xx as reachable.
// It returns the Date response header (empty on any error) so the clock probe
// can derive skew from the same HTTP round-trip without a second request.
func runReachProbe(ctx context.Context, client *http.Client, endpoint string) (probeResult, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/healthz", nil)
	if err != nil {
		return probeResult{Result: "fail", Diagnostic: "build reach request: " + err.Error()}, ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return probeResult{Result: "fail", Diagnostic: "reach: " + err.Error()}, ""
	}
	// Drain and close the body so connection is reusable.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	dateHdr := resp.Header.Get("Date")
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return probeResult{
			Result:     "pass",
			Diagnostic: fmt.Sprintf("HTTP %d", resp.StatusCode),
		}, dateHdr
	}
	return probeResult{
		Result:     "fail",
		Diagnostic: fmt.Sprintf("HTTP %d from /healthz", resp.StatusCode),
	}, dateHdr
}

// runClockProbe parses the Date header captured from the reach response and
// flags any skew greater than 60 seconds.
func runClockProbe(dateHdr string) probeResult {
	if dateHdr == "" {
		return probeResult{Result: "skip", Diagnostic: "no Date header on reach response"}
	}
	serverTime, err := http.ParseTime(dateHdr)
	if err != nil {
		return probeResult{Result: "fail", Diagnostic: "cannot parse Date header: " + err.Error()}
	}
	skew := time.Since(serverTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > 60*time.Second {
		return probeResult{Result: "fail", Diagnostic: fmt.Sprintf("clock skew %s > 60s", skew.Round(time.Second))}
	}
	return probeResult{Result: "pass", Diagnostic: fmt.Sprintf("skew %s", skew.Round(100*time.Millisecond))}
}

// runOTLPProbe posts a minimal OTLP log record to <endpoint>/v1/logs.
// The platform's accepted responses are 200 and 202; everything else is fail.
func runOTLPProbe(ctx context.Context, client *http.Client, endpoint, apiKey string) probeResult {
	body := []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"kite-collector probe"}}]}]}]}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/v1/logs", bytes.NewReader(body))
	if err != nil {
		return probeResult{Result: "fail", Diagnostic: "build otlp request: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return probeResult{Result: "fail", Diagnostic: "otlp: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
		return probeResult{Result: "pass", Diagnostic: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	return probeResult{Result: "fail", Diagnostic: fmt.Sprintf("HTTP %d from /v1/logs", resp.StatusCode)}
}

// handleConnectionCheckJSON is the machine-readable wire: it returns the
// same probe array as the fragment renders but as JSON.
func handleConnectionCheckJSON(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	results := runAllProbes(r.Context(), deps)
	allPass := true
	for _, p := range results {
		if p.Result != "pass" {
			allPass = false
		}
	}
	resp := connectionCheckResponse{
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Probes:    results,
		AllPass:   allPass,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		deps.Logger.Error("connection-check JSON response encode failed",
			"code", string(LogCodeCheckJSONEncode),
			"error", err,
			"request_path", r.URL.Path,
			"probe_count", len(resp.Probes),
			"all_pass", resp.AllPass)
	}
}

type probeFragmentView struct {
	CheckedAt  string
	Probes     []probeResult
	RecentRuns []recentRun // chronological (oldest → newest, left-to-right)
	HasRun     bool
}

// recentRun is one historical check run distilled to a single boolean +
// timestamp pair so the sparkline can render it as one colored dot. The
// dashboard turns the trail of probe_result rows into a glanceable health
// story without surfacing every per-probe diagnostic.
type recentRun struct {
	CheckedAt    time.Time
	RelativeTime string // pre-formatted "2h ago" for the title tooltip
	AllPass      bool
	AnyFail      bool
}

// summarizeProbeHistory walks the probe_result rows (which the store
// returns newest → oldest) and groups them by CheckedAt into per-run
// summaries. Returns runs ordered oldest → newest so the sparkline reads
// left-to-right chronologically (matching how operators read history).
// Caps at limit so the sparkline stays scannable.
func summarizeProbeHistory(rows []sqlite.ProbeResultRecord, limit int) []recentRun {
	if len(rows) == 0 {
		return nil
	}
	// Group rows by CheckedAt. Rows are dense (6 per run) so a small map is
	// cheap. We preserve first-seen order to reconstruct chronology after.
	type bucket struct {
		ts      time.Time
		anyFail bool
		count   int
	}
	order := make([]time.Time, 0, len(rows)/6+1)
	buckets := make(map[time.Time]*bucket, len(rows)/6+1)
	for _, r := range rows {
		b, ok := buckets[r.CheckedAt]
		if !ok {
			b = &bucket{ts: r.CheckedAt}
			buckets[r.CheckedAt] = b
			order = append(order, r.CheckedAt)
		}
		b.count++
		if r.Result == "fail" {
			b.anyFail = true
		}
	}
	// order is currently newest → oldest (store returns newest first).
	// Reverse so the sparkline renders chronologically left-to-right.
	out := make([]recentRun, 0, len(order))
	for i := len(order) - 1; i >= 0; i-- {
		b := buckets[order[i]]
		out = append(out, recentRun{
			CheckedAt:    b.ts,
			AllPass:      !b.anyFail,
			AnyFail:      b.anyFail,
			RelativeTime: humanizeRelativeTime(time.Since(b.ts)),
		})
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// humanizeRelativeTime renders a duration as "2h ago" / "1d ago" / "just now"
// for the sparkline title tooltip. Coarse on purpose — exact seconds aren't
// useful when scanning a health trail.
func humanizeRelativeTime(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

var connectionCheckTmpl = template.Must(template.New("check").Funcs(template.FuncMap{
	"probeBadge": func(result string) string {
		switch result {
		case "pass":
			return "badge-green"
		case "fail":
			return "badge-red"
		case "skip":
			return "badge-gray"
		}
		return "badge-gray"
	},
	"upper": strings.ToUpper,
}).Parse(`
<form hx-post="/api/v1/connection/check"
      hx-target="#check-fragment"
      hx-swap="innerHTML"
      hx-disabled-elt="find button"
      hx-indicator="#check-indicator">
  <button class="btn" type="submit">Run check</button>
  <span id="check-indicator" class="htmx-indicator muted small">
    &nbsp;running 6 probes in parallel &middot; usually under 10&nbsp;seconds&hellip;
  </span>
  {{if .HasRun}}<span class="muted small">last run {{.CheckedAt}}</span>{{end}}
</form>
{{if .RecentRuns}}
<div class="probe-sparkline" title="Recent check runs · oldest left, newest right">
  <span class="muted small">Recent:&nbsp;</span>
  {{range .RecentRuns}}
    {{if .AllPass}}
      <span class="spark-dot spark-pass" title="all 6 probes passed · {{.RelativeTime}}">●</span>
    {{else}}
      <span class="spark-dot spark-fail" title="one or more probes failed · {{.RelativeTime}}">●</span>
    {{end}}
  {{end}}
</div>
{{end}}
{{if .HasRun}}
<table>
  <thead><tr><th>Probe</th><th>Result</th><th>Latency</th><th>Diagnostic</th><th>Remediation</th></tr></thead>
  <tbody>
  {{range .Probes}}
    <tr>
      <td><code>{{.Name}}</code></td>
      <td><span class="badge {{probeBadge .Result}}">{{upper .Result}}</span></td>
      <td>{{.LatencyMS}} ms</td>
      <td>{{.Diagnostic}}</td>
      <td class="muted small">
        {{.Remediation}}
        {{if .Action}}
          <br>
          <a href="{{.Action.URL}}"
             class="btn btn-sm btn-outline"
             {{if eq .Action.Target "_blank"}}target="_blank" rel="noopener noreferrer"
             {{else}}onclick="setTimeout(function(){var i=document.getElementById('api_key');if(i){i.focus();}},50);"{{end}}>
            {{.Action.Label}} &rarr;
          </a>
        {{end}}
      </td>
    </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p class="muted">No probe run yet. Enroll first, then click &ldquo;Run check&rdquo;.</p>
{{end}}
`))

func renderConnectionCheckFragment(w io.Writer, r *http.Request, deps onboardingDeps, run bool) error {
	view := probeFragmentView{}
	if run {
		view.Probes = runAllProbes(r.Context(), deps)
		view.HasRun = true
		view.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	} else if deps.Store != nil {
		// Load the last probe batch (one full run = 6 rows) and render it.
		history, listErr := deps.Store.ListProbeResults(r.Context(), 6)
		if listErr != nil {
			return fmt.Errorf("list probe history: %w", listErr)
		}
		if len(history) > 0 {
			view.HasRun = true
			view.CheckedAt = history[0].CheckedAt.Format(time.RFC3339)
			for _, h := range history {
				pr := probeResult{
					Name:       probeName(h.ProbeName),
					Result:     h.Result,
					LatencyMS:  h.LatencyMS,
					Diagnostic: h.Diagnostic,
				}
				if pr.Result == "fail" {
					pr.Remediation = remediationFor(pr)
				}
				view.Probes = append(view.Probes, pr)
			}
		}
	}
	// Sparkline of the last few runs — converts the snapshot view into a
	// glanceable health trail without any new endpoints. Capped at 10 runs
	// (60 rows) so the dot row stays scannable on narrow screens.
	if deps.Store != nil {
		if rows, err := deps.Store.ListProbeResults(r.Context(), 60); err == nil {
			view.RecentRuns = summarizeProbeHistory(rows, 10)
		}
	}
	if err := connectionCheckTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render connection-check fragment: %w", err)
	}
	return nil
}

// ===========================================================================
// Streaming toggle
// ===========================================================================

type streamView struct {
	State         string
	LastEventAt   string
	LastErrorText string
	BacklogDepth  int
	TotalSent     int64
	Available     bool
	Running       bool
}

var streamTmpl = template.Must(template.New("stream").Funcs(template.FuncMap{
	"streamBadge": func(state string) string {
		switch state {
		case "running":
			return "badge-green"
		case "degraded":
			return "badge-orange"
		case "stopped":
			return "badge-gray"
		case "idle":
			return "badge-blue"
		}
		return "badge-gray"
	},
	"upper": strings.ToUpper,
}).Parse(`
<div class="stream-row">
  <span class="badge {{streamBadge .State}}">{{upper .State}}</span>
  <span class="muted small">
    last event {{if .LastEventAt}}{{.LastEventAt}}{{else}}never{{end}} &middot;
    backlog {{.BacklogDepth}} &middot;
    sent {{.TotalSent}}
  </span>
  {{if .LastErrorText}}<div class="badge badge-red">{{.LastErrorText}}</div>{{end}}
</div>
<form hx-post="/api/v1/stream/start" hx-target="#stream-fragment" hx-swap="innerHTML" style="display:inline">
  <button class="btn" type="submit" {{if not .Available}}disabled{{end}} {{if .Running}}disabled{{end}}>Start streaming</button>
</form>
<form hx-post="/api/v1/stream/stop" hx-target="#stream-fragment" hx-swap="innerHTML" style="display:inline">
  <button class="btn btn-outline" type="submit" {{if not .Available}}disabled{{end}} {{if not .Running}}disabled{{end}}>Stop streaming</button>
</form>
{{if not .Available}}
<p class="muted small">Streaming controller not wired in this mode.</p>
{{end}}
`))

func renderStreamStatusFragment(w io.Writer, deps onboardingDeps) error {
	view := streamView{Available: deps.StreamCtrl != nil, State: "idle"}
	if deps.StreamCtrl != nil {
		s := deps.StreamCtrl.Status()
		view.State = s.NormalizeState()
		view.BacklogDepth = s.BacklogDepth
		view.TotalSent = s.TotalSent
		view.LastErrorText = s.LastErrorText
		view.Running = view.State == "running" || view.State == "degraded"
		if !s.LastEventAt.IsZero() {
			view.LastEventAt = s.LastEventAt.Format(time.RFC3339)
		}
	}
	if err := streamTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render stream-status fragment: %w", err)
	}
	return nil
}

func handleStreamStart(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	if deps.StreamCtrl == nil {
		renderOnboardingFragment(w, deps.Logger, "stream-status", func(buf io.Writer) error {
			return renderStreamStatusFragment(buf, deps)
		})
		return
	}
	if err := deps.StreamCtrl.Start(r.Context()); err != nil {
		deps.Logger.Warn("StreamController.Start returned error",
			"code", string(LogCodeStreamStart),
			"error", err,
			"endpoint", deps.PlatformEndpoint,
			"request_path", r.URL.Path)
	}
	// The steps flow re-renders on this trigger so the stream step collapses
	// to its receipt once streaming is up.
	w.Header().Set("HX-Trigger", "refresh-agent-state")
	renderOnboardingFragment(w, deps.Logger, "stream-status", func(buf io.Writer) error {
		return renderStreamStatusFragment(buf, deps)
	})
}

func handleStreamStop(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	if deps.StreamCtrl == nil {
		renderOnboardingFragment(w, deps.Logger, "stream-status", func(buf io.Writer) error {
			return renderStreamStatusFragment(buf, deps)
		})
		return
	}
	if err := deps.StreamCtrl.Stop(r.Context()); err != nil {
		deps.Logger.Warn("StreamController.Stop returned error",
			"code", string(LogCodeStreamStop),
			"error", err,
			"endpoint", deps.PlatformEndpoint,
			"request_path", r.URL.Path)
	}
	w.Header().Set("HX-Trigger", "refresh-agent-state")
	renderOnboardingFragment(w, deps.Logger, "stream-status", func(buf io.Writer) error {
		return renderStreamStatusFragment(buf, deps)
	})
}

// ===========================================================================
// Support bundle
// ===========================================================================

type supportManifest struct {
	GeneratedAt   string              `json:"generated_at"`
	AppVersion    string              `json:"app_version"`
	Commit        string              `json:"commit"`
	GoVersion     string              `json:"go_version"`
	GOOS          string              `json:"goos"`
	GOARCH        string              `json:"goarch"`
	Endpoint      string              `json:"enrolled_endpoint,omitempty"`
	KeyFinger8    string              `json:"api_key_fingerprint_short,omitempty"`
	LastPassed    string              `json:"last_check_passed_at,omitempty"`
	LastFailed    string              `json:"last_check_failed_at,omitempty"`
	ProbeSnapshot []probeResult       `json:"probe_snapshot,omitempty"`
	ProbeHistory  []probeHistoryEntry `json:"probe_history,omitempty"`
}

type probeHistoryEntry struct {
	CheckedAt  string `json:"checked_at"`
	Name       string `json:"name"`
	Result     string `json:"result"`
	Diagnostic string `json:"diagnostic,omitempty"`
	LatencyMS  int64  `json:"latency_ms"`
}

func handleSupportBundle(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	m := supportManifest{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		AppVersion:  deps.AppVersion,
		Commit:      deps.Commit,
		GoVersion:   runtime.Version(),
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
		Endpoint:    deps.PlatformEndpoint,
	}
	if deps.Store != nil {
		if id, err := deps.Store.GetEnrolledIdentity(r.Context()); err == nil {
			m.KeyFinger8 = shortFingerprint(id.ApiKeyFingerprint)
			if id.LastCheckPassedAt != nil {
				m.LastPassed = id.LastCheckPassedAt.Format(time.RFC3339)
			}
			if id.LastCheckFailedAt != nil {
				m.LastFailed = id.LastCheckFailedAt.Format(time.RFC3339)
			}
		}
		if history, err := deps.Store.ListProbeResults(r.Context(), 20); err == nil {
			for _, h := range history {
				m.ProbeHistory = append(m.ProbeHistory, probeHistoryEntry{
					CheckedAt:  h.CheckedAt.Format(time.RFC3339),
					Name:       h.ProbeName,
					Result:     h.Result,
					Diagnostic: h.Diagnostic,
					LatencyMS:  h.LatencyMS,
				})
			}
		}
	}

	manifestBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		http.Error(w, "manifest encode: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="kite-collector-support.tar.gz"`)

	gz := gzip.NewWriter(w)
	defer func() { _ = gz.Close() }()
	tw := tar.NewWriter(gz)
	defer func() { _ = tw.Close() }()

	if err := writeTarFile(tw, "manifest.json", manifestBytes); err != nil {
		deps.Logger.Error("support-bundle manifest write failed",
			"code", string(LogCodeSupportBundleManifest),
			"error", err,
			"manifest_size", len(manifestBytes))
		return
	}

	// Randomised nonce in the bundle name to make regex scanners easy to test.
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	_ = writeTarFile(tw, "bundle-id", []byte(hex.EncodeToString(nonce)))
}

func writeTarFile(tw *tar.Writer, name string, body []byte) error {
	h := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}
	if err := tw.WriteHeader(h); err != nil {
		return fmt.Errorf("write tar header %s: %w", name, err)
	}
	if _, err := tw.Write(body); err != nil {
		return fmt.Errorf("write tar body %s: %w", name, err)
	}
	return nil
}

// ===========================================================================
// misc helpers
// ===========================================================================

// newOnboardingWrapKey generates a 32-byte AEAD key. Used by tests and as a
// last-resort default when the host has no identity backend. The key is
// kept in memory; rotating it invalidates the persisted wrapped blob which
// the enroll page surfaces as "fingerprint mismatch" so operators know to
// re-enroll.
func newOnboardingWrapKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("generate wrap key: %w", err)
	}
	return k, nil
}

// ensure uuid import is retained — registerOnboardingRoutes indirectly uses
// uuid via sqlite.ProbeResultRecord.
var _ = uuid.Nil

// buildTLSConfig constructs a *tls.Config for onboarding connection checks using config.TLSConfig.
func buildTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	// Build trusted pool: system roots extended with our private CA.
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		caPEM, readErr := os.ReadFile(cfg.CAFile)
		if readErr != nil {
			return nil, fmt.Errorf("read CA file %q: %w", cfg.CAFile, readErr)
		}
		pool.AppendCertsFromPEM(caPEM)
	}

	tlsCfg := &tls.Config{
		RootCAs:            pool,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: os.Getenv("KITE_INSECURE_SKIP_VERIFY") == "true", //#nosec G402 -- opt-in via KITE_INSECURE_SKIP_VERIFY env var for debug against self-signed dev backends
		VerifyConnection: func(cs tls.ConnectionState) error {
			if os.Getenv("KITE_INSECURE_SKIP_VERIFY") == "true" {
				return nil
			}
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("server presented no certificate")
			}
			intermediates := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			// Pass 1: full verification — hostname + CA chain (public certs).
			if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				DNSName:       cs.ServerName,
				Roots:         pool,
				Intermediates: intermediates,
			}); err == nil {
				return nil
			}
			// Pass 2: CA-chain only — private PKI cert issued for internal name.
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         pool,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			if err != nil {
				return fmt.Errorf("verify peer certificate: %w", err)
			}
			return nil
		},
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}
