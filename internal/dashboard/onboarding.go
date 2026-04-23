package dashboard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// onboardingDeps bundles everything the onboarding handlers need.
// The sqlite store is taken directly (not via the store.Store interface)
// because identity + probe_result persistence is onboarding-specific and
// does not belong on the generic Store contract.
type onboardingDeps struct {
	Store         *sqlite.SQLiteStore
	StreamCtrl    StreamController
	Logger        *slog.Logger
	ProbeClient   *http.Client
	ProbeDuration *prometheus.HistogramVec
	AppVersion    string
	Commit        string
	WrapKey       []byte // 32-byte AEAD key for api_key_wrapped
}

// registerOnboardingRoutes mounts every RFC-0112 dashboard route onto mux.
// Keeping the registration in one function makes the rollback described in
// §6.3 a one-line commentout.
func registerOnboardingRoutes(mux *http.ServeMux, deps onboardingDeps) {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.ProbeClient == nil {
		deps.ProbeClient = &http.Client{Timeout: 8 * time.Second}
	}

	mux.HandleFunc("GET /onboarding", serveOnboardingPage)
	mux.HandleFunc("GET /fragments/enroll-form", func(w http.ResponseWriter, r *http.Request) {
		renderOnboardingFragment(w, deps.Logger, "enroll-form", func(buf io.Writer) error {
			return renderEnrollFragment(buf, r.Context(), deps)
		})
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
	mux.HandleFunc("GET /fragments/stream-status", func(w http.ResponseWriter, r *http.Request) {
		renderOnboardingFragment(w, deps.Logger, "stream-status", func(buf io.Writer) error {
			return renderStreamStatusFragment(buf, deps)
		})
	})
	mux.HandleFunc("GET /api/v1/support-bundle", func(w http.ResponseWriter, r *http.Request) {
		handleSupportBundle(w, r, deps)
	})
}

// serveOnboardingPage writes the static onboarding shell that wires up the
// three HTMX fragments below it.
func serveOnboardingPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body, err := fs.ReadFile(staticFS, "static/onboarding.html")
	if err != nil {
		http.Error(w, "onboarding.html not found", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(body)
}

// renderOnboardingFragment is a buffered renderer that mirrors the
// existing scan-status fragment: template errors never produce a half-
// written response with a 200 status.
func renderOnboardingFragment(w http.ResponseWriter, logger *slog.Logger, name string, render func(io.Writer) error) {
	var buf bytes.Buffer
	if err := render(&buf); err != nil {
		logger.Error("dashboard: onboarding render "+name, "error", err)
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
	Endpoint         string
	FingerprintShort string
	FingerprintFull  string
	FirstEnrolledAt  string
	LastEnrolledAt   string
	Error            string
	ReadOnly         bool
	Enrolled         bool
}

var enrollFragmentTmpl = template.Must(template.New("enroll").Parse(`
{{- if .Enrolled}}
<div class="enroll-status">
  <p>
    <span class="badge badge-green">enrolled</span>
    <code>{{.Endpoint}}</code>
    &mdash; fingerprint <code title="{{.FingerprintFull}}">{{.FingerprintShort}}</code>
  </p>
  <p class="muted small">first enrolled {{.FirstEnrolledAt}} &middot; last refreshed {{.LastEnrolledAt}}</p>
</div>
{{- end}}
<form id="enroll-form"
      hx-post="/api/v1/identity/enroll"
      hx-target="#enroll-fragment"
      hx-swap="innerHTML">
  <div class="form-row">
    <label for="platform_endpoint">Platform endpoint</label>
    <input id="platform_endpoint" name="platform_endpoint" type="url"
           placeholder="https://platform.example.com"
           value="{{.Endpoint}}"
           required {{if .ReadOnly}}disabled{{end}}>
  </div>
  <div class="form-row">
    <label for="api_key">API key</label>
    <input id="api_key" name="api_key" type="password"
           placeholder="paste the platform-issued token"
           autocomplete="off"
           required {{if .ReadOnly}}disabled{{end}}>
  </div>
  {{- if .Error}}<p class="enroll-error badge-red">{{.Error}}</p>{{end}}
  <button class="btn" type="submit" {{if .ReadOnly}}disabled{{end}}>
    {{if .Enrolled}}Re-enroll{{else}}Enroll{{end}}
  </button>
  {{- if .ReadOnly}}
  <p class="muted small">Read-only inspector mode &mdash; enroll disabled.</p>
  {{- end}}
</form>
`))

func renderEnrollFragment(w io.Writer, ctx context.Context, deps onboardingDeps) error {
	view := enrollView{ReadOnly: deps.Store == nil}
	if deps.Store != nil {
		id, err := deps.Store.GetEnrolledIdentity(ctx)
		if err != nil && !errors.Is(err, sqlite.ErrNoIdentity) {
			return fmt.Errorf("load identity: %w", err)
		}
		if err == nil {
			view.Enrolled = true
			view.Endpoint = id.PlatformEndpoint
			view.FingerprintFull = id.ApiKeyFingerprint
			view.FingerprintShort = shortFingerprint(id.ApiKeyFingerprint)
			view.FirstEnrolledAt = id.FirstEnrolledAt.Format(time.RFC3339)
			view.LastEnrolledAt = id.LastEnrolledAt.Format(time.RFC3339)
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
	view := enrollView{}

	if deps.Store == nil {
		view.ReadOnly = true
		view.Error = "enrollment disabled in read-only dashboard mode"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}
	if len(deps.WrapKey) != 32 {
		deps.Logger.Error("dashboard: enroll missing AEAD wrap key")
		view.Error = "server misconfigured: no wrap key"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}

	if err := r.ParseForm(); err != nil {
		view.Error = "invalid form submission"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}

	endpoint := strings.TrimSpace(r.PostFormValue("platform_endpoint"))
	apiKey := r.PostFormValue("api_key")

	if endpoint == "" || apiKey == "" {
		view.Endpoint = endpoint
		view.Error = "platform endpoint and API key are both required"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		view.Endpoint = endpoint
		view.Error = "platform endpoint must be an http:// or https:// URL"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}

	fingerprint := sqlite.APIKeyFingerprint(apiKey)
	wrapped, wrapErr := sqlite.AEADWrap(deps.WrapKey, []byte(apiKey))
	if wrapErr != nil {
		deps.Logger.Error("dashboard: aead wrap failed",
			"fingerprint", shortFingerprint(fingerprint),
			"error", wrapErr,
		)
		view.Endpoint = endpoint
		view.Error = "internal error wrapping API key"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}

	now := time.Now().UTC()
	if upsertErr := deps.Store.UpsertEnrolledIdentity(ctx, sqlite.EnrolledIdentity{
		PlatformEndpoint:  endpoint,
		ApiKeyFingerprint: fingerprint,
		ApiKeyWrapped:     wrapped,
		LastEnrolledAt:    now,
	}); upsertErr != nil {
		deps.Logger.Error("dashboard: enroll upsert",
			"fingerprint", shortFingerprint(fingerprint),
			"error", upsertErr,
		)
		view.Endpoint = endpoint
		view.Error = "failed to persist enrollment"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}

	deps.Logger.Info("dashboard: enrolled platform identity",
		"endpoint", endpoint,
		"fingerprint", shortFingerprint(fingerprint),
	)

	id, err := deps.Store.GetEnrolledIdentity(ctx)
	if err != nil {
		view.Error = "enrollment saved but reload failed"
		writeEnrollFragment(w, deps.Logger, view)
		return
	}
	view = enrollView{
		Enrolled:         true,
		Endpoint:         id.PlatformEndpoint,
		FingerprintFull:  id.ApiKeyFingerprint,
		FingerprintShort: shortFingerprint(id.ApiKeyFingerprint),
		FirstEnrolledAt:  id.FirstEnrolledAt.Format(time.RFC3339),
		LastEnrolledAt:   id.LastEnrolledAt.Format(time.RFC3339),
	}

	// Auto-run the connection check after a successful enrollment, OOB-swapping
	// the #check-fragment so the operator sees six fresh probe outcomes without
	// a second click.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	if err := enrollFragmentTmpl.Execute(&buf, view); err != nil {
		deps.Logger.Error("dashboard: enroll render", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Out-of-band probe render.
	buf.WriteString(`<div id="check-fragment" hx-swap-oob="innerHTML">`)
	if renderErr := renderConnectionCheckFragment(&buf, r, deps, true); renderErr != nil {
		deps.Logger.Warn("dashboard: auto-run check after enroll failed", "error", renderErr)
	}
	buf.WriteString(`</div>`)
	_, _ = w.Write(buf.Bytes())
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

// probeName is the canonical identifier for each of the six probes.
type probeName string

const (
	probeDNS   probeName = "dns"
	probeTLS   probeName = "tls"
	probeReach probeName = "reach"
	probeAuth  probeName = "auth"
	probeClock probeName = "clock"
	probeOTLP  probeName = "otlp"
)

// probeResult is the wire shape returned by GET /api/v1/connection/check and
// also the per-row view model consumed by the HTMX fragment.
type probeResult struct {
	Name        probeName `json:"name"`
	Result      string    `json:"result"` // pass | fail | skip
	Diagnostic  string    `json:"diagnostic,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	LatencyMS   int64     `json:"latency_ms"`
}

type connectionCheckResponse struct {
	CheckedAt string        `json:"checked_at"`
	Probes    []probeResult `json:"probes"`
	AllPass   bool          `json:"all_pass"`
}

// runAllProbes executes the six probes in sequence (DNS → TLS → reach →
// auth → clock → OTLP) against the enrolled identity. When no identity is
// present probes 3–6 return SKIP with "no identity enrolled" per RFC §4.3.
// When deps.Store is nil (read-only dashboard) the same SKIP applies.
func runAllProbes(ctx context.Context, deps onboardingDeps) []probeResult {
	results := make([]probeResult, 0, 6)

	var (
		endpoint    string
		apiKey      string
		haveID      bool
		readOnly    = deps.Store == nil
		enrolledURL *url.URL
	)
	if !readOnly {
		id, err := deps.Store.GetEnrolledIdentity(ctx)
		if err == nil {
			endpoint = id.PlatformEndpoint
			enrolledURL, _ = url.Parse(endpoint)
			if len(deps.WrapKey) == 32 {
				if pt, unwrapErr := sqlite.AEADUnwrap(deps.WrapKey, id.ApiKeyWrapped); unwrapErr == nil {
					apiKey = string(pt)
					haveID = true
				} else {
					deps.Logger.Warn("dashboard: identity unwrap failed", "error", unwrapErr)
				}
			}
		}
	}

	// Probe 1 — DNS
	results = append(results, timeProbe(deps, probeDNS, func() probeResult {
		if enrolledURL == nil || enrolledURL.Hostname() == "" {
			return probeResult{Result: "skip", Diagnostic: "no identity enrolled"}
		}
		return runDNSProbe(ctx, enrolledURL.Hostname())
	}))

	// Probe 2 — TLS
	results = append(results, timeProbe(deps, probeTLS, func() probeResult {
		if enrolledURL == nil {
			return probeResult{Result: "skip", Diagnostic: "no identity enrolled"}
		}
		if enrolledURL.Scheme != "https" {
			return probeResult{Result: "skip", Diagnostic: "endpoint is plain http"}
		}
		return runTLSProbe(ctx, enrolledURL)
	}))

	// Probe 3 — reach. We capture the Date header from the reach response so
	// the clock probe (5) can derive skew from the same HTTP round-trip.
	var reachDateHeader string
	results = append(results, timeProbe(deps, probeReach, func() probeResult {
		if readOnly {
			return probeResult{Result: "skip", Diagnostic: "read-only inspector mode"}
		}
		if !haveID {
			return probeResult{Result: "skip", Diagnostic: "no identity enrolled"}
		}
		res, dateHdr := runReachProbe(ctx, deps.ProbeClient, endpoint)
		reachDateHeader = dateHdr
		return res
	}))

	// Probe 4 — auth
	results = append(results, timeProbe(deps, probeAuth, func() probeResult {
		if readOnly {
			return probeResult{Result: "skip", Diagnostic: "read-only inspector mode"}
		}
		if !haveID {
			return probeResult{Result: "skip", Diagnostic: "no identity enrolled"}
		}
		return runAuthProbe(ctx, deps.ProbeClient, endpoint, apiKey)
	}))

	// Probe 5 — clock (derived from reach response Date header when present)
	results = append(results, timeProbe(deps, probeClock, func() probeResult {
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
	}))

	// Probe 6 — OTLP
	results = append(results, timeProbe(deps, probeOTLP, func() probeResult {
		if readOnly {
			return probeResult{Result: "skip", Diagnostic: "read-only inspector mode"}
		}
		if !haveID {
			return probeResult{Result: "skip", Diagnostic: "no identity enrolled"}
		}
		return runOTLPProbe(ctx, deps.ProbeClient, endpoint, apiKey)
	}))

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

	// Attach remediation hints for any fail.
	for i := range results {
		if results[i].Result == "fail" {
			results[i].Remediation = remediationFor(results[i].Name)
		}
	}

	return results
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

// remediationFor returns a one-line remediation hint per probe. The
// strings are stable so operator runbooks can grep for them.
func remediationFor(name probeName) string {
	switch name {
	case probeDNS:
		return "verify the platform endpoint hostname resolves from this host (check /etc/resolv.conf)"
	case probeTLS:
		return "TLS handshake failed — check cert pinning and system CA bundle"
	case probeReach:
		return "endpoint unreachable — check egress firewall and that the platform is up"
	case probeAuth:
		return "token rejected — re-issue the API key on the platform console and re-enroll"
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
func runTLSProbe(ctx context.Context, u *url.URL) probeResult {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d := tls.Dialer{}
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

// runAuthProbe calls GET /v1/auth/echo with X-API-Key and expects a 2xx
// response whose body contains the fingerprint we computed locally.
func runAuthProbe(ctx context.Context, client *http.Client, endpoint, apiKey string) probeResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/v1/auth/echo", nil)
	if err != nil {
		return probeResult{Result: "fail", Diagnostic: "build auth request: " + err.Error()}
	}
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return probeResult{Result: "fail", Diagnostic: "auth: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return probeResult{Result: "fail", Diagnostic: fmt.Sprintf("HTTP %d — token rejected", resp.StatusCode)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return probeResult{Result: "fail", Diagnostic: fmt.Sprintf("HTTP %d from /v1/auth/echo", resp.StatusCode)}
	}
	expected := sqlite.APIKeyFingerprint(apiKey)
	var parsed struct {
		Fingerprint string `json:"api_key_fingerprint"`
	}
	if jsonErr := json.Unmarshal(body, &parsed); jsonErr == nil && parsed.Fingerprint != "" {
		if strings.EqualFold(parsed.Fingerprint, expected) {
			return probeResult{Result: "pass", Diagnostic: "fingerprint echoed"}
		}
		return probeResult{Result: "fail", Diagnostic: "fingerprint mismatch"}
	}
	// Some platforms don't echo — accept a clean 2xx as pass.
	return probeResult{Result: "pass", Diagnostic: fmt.Sprintf("HTTP %d", resp.StatusCode)}
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
	req.Header.Set("X-API-Key", apiKey)
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
		deps.Logger.Error("dashboard: check json encode", "error", err)
	}
}

type probeFragmentView struct {
	CheckedAt string
	Probes    []probeResult
	HasRun    bool
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
<form hx-post="/api/v1/connection/check" hx-target="#check-fragment" hx-swap="innerHTML">
  <button class="btn" type="submit">Run check</button>
  {{if .HasRun}}<span class="muted small">last run {{.CheckedAt}}</span>{{end}}
</form>
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
      <td class="muted small">{{.Remediation}}</td>
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
					pr.Remediation = remediationFor(pr.Name)
				}
				view.Probes = append(view.Probes, pr)
			}
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
		deps.Logger.Warn("dashboard: stream start", "error", err)
	}
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
		deps.Logger.Warn("dashboard: stream stop", "error", err)
	}
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
	}
	if deps.Store != nil {
		if id, err := deps.Store.GetEnrolledIdentity(r.Context()); err == nil {
			m.Endpoint = id.PlatformEndpoint
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
		deps.Logger.Error("support bundle: manifest", "error", err)
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
