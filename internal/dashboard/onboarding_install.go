package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/installer"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// Installer is the dashboard-side install interface. The default production
// wiring (cmd/kite-collector/main.go) supplies a concrete implementation that
// calls installer.InstallBinary + service.Install; tests inject a fake that
// records calls. A nil Installer puts the dashboard in "advisory-only" mode:
// state + defaults are still served, but POST /api/v1/agent/install returns
// 503 with a CLI command operators can copy-paste.
//
// Uninstall is the destructive counterpart — it best-effort stops the
// service and removes the OS registration. By design it leaves the binary
// and certificate store in place so re-install is reversible without
// re-enrolling. Surfacing it from the dashboard closes the symmetry gap:
// install/uninstall both live in the UI, not just install.
type Installer interface {
	Install(ctx context.Context, opts installer.Options) error
	Uninstall(ctx context.Context, opts installer.Options) error
}

// agentInstallView is the JSON wire shape for the install/defaults/state APIs.
// The three response variants (defaults | state | install result) all share
// this struct so dashboard consumers can decode once and read whichever
// fields are populated.
type agentInstallView struct {
	Defaults      *installer.Defaults  `json:"defaults,omitempty"`
	State         *installer.State     `json:"state,omitempty"`
	CLIHint       string               `json:"cli_hint,omitempty"`
	Error         string               `json:"error,omitempty"`
	ErrorCategory installErrorCategory `json:"error_category,omitempty"`
	// InstallEnabled tells the UI whether to enable the "Install now" button
	// or fall back to surfacing the CLI hint.
	InstallEnabled bool `json:"install_enabled"`
}

// agentStateView is the comprehensive "after state" the dashboard surfaces
// once the agent is up and running. It composes install state, identity
// state, last-check stamps, and (optionally) streaming health into a single
// JSON object so the UI does not need to chain multiple requests.
type agentStateView struct {
	Identity      *identityStateView `json:"identity,omitempty"`
	Stream        *streamStateView   `json:"stream,omitempty"`
	GeneratedAt   string             `json:"generated_at"`
	NextAction    string             `json:"next_action"`
	OverallStatus string             `json:"overall_status"`
	Install       installer.State    `json:"install"`
}

type identityStateView struct {
	FingerprintShort  string `json:"fingerprint_short,omitempty"`
	FirstEnrolledAt   string `json:"first_enrolled_at,omitempty"`
	LastEnrolledAt    string `json:"last_enrolled_at,omitempty"`
	LastCheckPassedAt string `json:"last_check_passed_at,omitempty"`
	LastCheckFailedAt string `json:"last_check_failed_at,omitempty"`
	Enrolled          bool   `json:"enrolled"`
}

type streamStateView struct {
	State        string `json:"state"`
	LastEventAt  string `json:"last_event_at,omitempty"`
	Error        string `json:"error,omitempty"`
	TotalSent    int64  `json:"total_sent"`
	BacklogDepth int    `json:"backlog_depth"`
}

// registerAgentInstallRoutes wires the install / state / defaults endpoints
// onto mux. Called from registerOnboardingRoutes so the install API ships
// behind the same RFC-0112 feature flag as the rest of onboarding.
func registerAgentInstallRoutes(mux *http.ServeMux, deps onboardingDeps) {
	mux.HandleFunc("GET /api/v1/agent/install/defaults", func(w http.ResponseWriter, _ *http.Request) {
		handleAgentInstallDefaults(w, deps)
	})
	mux.HandleFunc("GET /api/v1/agent/install/state", func(w http.ResponseWriter, _ *http.Request) {
		handleAgentInstallState(w, deps)
	})
	mux.HandleFunc("POST /api/v1/agent/install", func(w http.ResponseWriter, r *http.Request) {
		handleAgentInstall(w, r, deps)
	})
	mux.HandleFunc("POST /api/v1/agent/install/uninstall", func(w http.ResponseWriter, r *http.Request) {
		handleAgentUninstall(w, r, deps)
	})
	mux.HandleFunc("GET /api/v1/agent/state", func(w http.ResponseWriter, r *http.Request) {
		handleAgentState(w, r, deps)
	})
	mux.HandleFunc("GET /fragments/install-status", func(w http.ResponseWriter, _ *http.Request) {
		renderOnboardingFragment(w, deps.Logger, "install-status", func(buf io.Writer) error {
			return renderInstallStatusFragment(buf, deps)
		})
	})
	mux.HandleFunc("GET /fragments/onboarding-header", func(w http.ResponseWriter, r *http.Request) {
		renderOnboardingFragment(w, deps.Logger, "onboarding-header", func(buf io.Writer) error {
			return renderOnboardingHeaderFragment(buf, r.Context(), deps)
		})
	})
	mux.HandleFunc("GET /fragments/onboarding-status-badge", func(w http.ResponseWriter, r *http.Request) {
		renderOnboardingFragment(w, deps.Logger, "onboarding-status-badge", func(buf io.Writer) error {
			return renderOnboardingStatusBadgeFragment(buf, r.Context(), deps)
		})
	})
}

// handleAgentInstallDefaults returns the smart, OS-aware defaults the UI
// should pre-fill into the install form. The Detected struct is included so
// the UI can render "we suggested user-mode because you're not root" copy.
func handleAgentInstallDefaults(w http.ResponseWriter, deps onboardingDeps) {
	d := installer.DetectDefaults()
	if deps.PlatformEndpoint != "" {
		d.Options.Endpoint = deps.PlatformEndpoint
	}
	view := agentInstallView{
		Defaults:       &d,
		InstallEnabled: deps.Installer != nil,
		CLIHint:        cliHint(d.Options),
	}
	writeJSON(w, deps.Logger, http.StatusOK, view)
}

// handleAgentInstallState returns the probed state for the smart-default
// options. Optional query string overrides (?certs_dir=&binary_dir=&user=)
// let the UI re-probe after the operator edits the form.
func handleAgentInstallState(w http.ResponseWriter, deps onboardingDeps) {
	opts := installer.DetectDefaults().Options
	if deps.PlatformEndpoint != "" {
		opts.Endpoint = deps.PlatformEndpoint
	}
	state := installer.Probe(opts)
	view := agentInstallView{
		State:          &state,
		InstallEnabled: deps.Installer != nil,
		CLIHint:        cliHint(opts),
	}
	writeJSON(w, deps.Logger, http.StatusOK, view)
}

// handleAgentInstall accepts a JSON body with installer.Options overrides
// and dispatches to the injected Installer. With no Installer present, it
// returns 503 with a CLI hint so the dashboard remains useful in
// advisory-only mode (the safer production default).
//
// Response shape adapts to the caller:
//
//   - HX-Request: true → returns the install-status HTML fragment so HTMX
//     can swap it directly into #install-fragment. Also sets
//     HX-Trigger: refresh-agent-state so the stepper/mode-chip header
//     updates the instant install finishes (no waiting for the next poll).
//   - else → JSON for scripted clients / curl debugging.
func handleAgentInstall(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	// The ?user_mode=true query param is the "Retry in --user mode" recovery
	// path surfaced by the permission-error remediation UI. It explicitly
	// recomputes BinaryDir/CertsDir for user-mode (rather than reusing the
	// failed attempt's paths), because the previous install almost certainly
	// failed *because* the smart-default chose system paths and the dashboard
	// lacks the privileges to write there.
	var opts installer.Options
	if r.URL.Query().Get("user_mode") == "true" {
		opts = installer.Options{
			UserMode:  true,
			BinaryDir: installer.DefaultBinaryDir(true),
			CertsDir:  installer.DefaultCertsDir(true),
		}
	} else {
		opts = installer.DetectDefaults().Options
	}
	if deps.PlatformEndpoint != "" {
		opts.Endpoint = deps.PlatformEndpoint
	}
	if err := decodeOptionalJSON(r, &opts); err != nil {
		writeJSON(w, deps.Logger, http.StatusBadRequest, agentInstallView{
			Error: "invalid request body: " + err.Error(),
		})
		return
	}

	hx := isHXRequest(r)

	if deps.Installer == nil {
		state := installer.Probe(opts)
		view := agentInstallView{
			State:          &state,
			InstallEnabled: false,
			CLIHint:        cliHint(opts),
			Error:          "dashboard install API not enabled — run the CLI command in cli_hint",
		}
		if hx {
			writeInstallStatusHTML(w, deps, http.StatusServiceUnavailable, &view)
		} else {
			writeJSON(w, deps.Logger, http.StatusServiceUnavailable, view)
		}
		return
	}

	if err := deps.Installer.Install(r.Context(), opts); err != nil {
		deps.Logger.Error("agent install action failed",
			"code", string(LogCodeAgentInstall),
			"error", err,
			"user_mode", opts.UserMode,
			"binary_dir", opts.BinaryDir,
			"certs_dir", opts.CertsDir,
			"endpoint", opts.Endpoint,
			"category", string(categorizeInstallError(err)),
			"hx_request", hx)
		state := installer.Probe(opts)
		view := agentInstallView{
			State:          &state,
			InstallEnabled: true,
			Error:          err.Error(),
			ErrorCategory:  categorizeInstallError(err),
			CLIHint:        cliHint(opts),
		}
		if hx {
			writeInstallStatusHTML(w, deps, http.StatusInternalServerError, &view)
		} else {
			writeJSON(w, deps.Logger, http.StatusInternalServerError, view)
		}
		return
	}
	state := installer.Probe(opts)
	view := agentInstallView{
		State:          &state,
		InstallEnabled: true,
	}
	// Notify the polling header so the stepper / CTA / mode chip update
	// immediately on success — no waiting for the 10s heartbeat.
	w.Header().Set("HX-Trigger", "refresh-agent-state")
	// After-Settle fires after the new install-status DOM is in place so the
	// browser can smooth-scroll to the enroll card without racing the swap.
	// The target is hard-coded because a successful install on a fresh host
	// always leaves enrollment as the next action; if the operator was just
	// re-running install while already enrolled, the scroll lands on a known
	// landmark and does no harm.
	w.Header().Set("HX-Trigger-After-Settle", `{"scroll-to-step":{"target":"#enroll-card"}}`)
	if hx {
		writeInstallStatusHTML(w, deps, http.StatusOK, &view)
	} else {
		writeJSON(w, deps.Logger, http.StatusOK, view)
	}
}

// isHXRequest reports whether the request was made by HTMX (which sets
// HX-Request: true on every fetch). Used to fork response shape between
// HTML (for in-page swaps) and JSON (for scripted clients).
func isHXRequest(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// writeInstallStatusHTML renders the install-status fragment with the
// post-action state baked in so the operator sees the result of their
// click without a second round-trip. Errors propagate through the
// existing buffered fragment writer pattern.
func writeInstallStatusHTML(w http.ResponseWriter, deps onboardingDeps, status int, view *agentInstallView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fragView := installStatusFragmentView{
		State:          deref(view.State),
		Detected:       installer.DetectDefaults().Detected,
		CLIHint:        view.CLIHint,
		InstallEnabled: view.InstallEnabled,
		Error:          view.Error,
		ErrorCategory:  view.ErrorCategory,
	}
	if err := installStatusFragmentTmpl.Execute(w, fragView); err != nil {
		if deps.Logger != nil {
			deps.Logger.Error("install-status fragment template render failed",
				"code", string(LogCodeInstallStatusRender),
				"error", err,
				"install_enabled", fragView.InstallEnabled,
				"has_error", fragView.Error != "",
				"error_category", string(fragView.ErrorCategory))
		}
	}
}

// deref safely dereferences an installer.State pointer, returning the zero
// value when nil so the template never panics on missing state.
func deref(s *installer.State) installer.State {
	if s == nil {
		return installer.State{}
	}
	return *s
}

// handleAgentUninstall implements the destructive counterpart to install.
// Two-step inline confirmation flow:
//
//   - POST /api/v1/agent/install/uninstall (no query) → renders a confirm
//     fragment so the operator must explicitly opt in to the destructive
//     action. Mirrors the HTMX-aware HTML/JSON branch the install endpoint
//     uses; non-HX clients get the confirmation as JSON.
//   - POST /api/v1/agent/install/uninstall?confirm=true → dispatches the
//     uninstall, then renders the updated install-status fragment with
//     HX-Trigger: refresh-agent-state so the stepper resets to "install".
//
// Confirmation copy explicitly states what is and isn't removed: service
// registration is stopped + deregistered; binary and certs are kept in
// place so the operator can re-install without re-enrolling.
func handleAgentUninstall(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	hx := isHXRequest(r)

	opts := installer.DetectDefaults().Options
	if deps.PlatformEndpoint != "" {
		opts.Endpoint = deps.PlatformEndpoint
	}

	if deps.Installer == nil {
		state := installer.Probe(opts)
		view := agentInstallView{
			State:          &state,
			InstallEnabled: false,
			CLIHint:        cliHint(opts),
			Error:          "dashboard install API not enabled — run `kite-collector uninstall` from a terminal",
		}
		if hx {
			writeInstallStatusHTML(w, deps, http.StatusServiceUnavailable, &view)
		} else {
			writeJSON(w, deps.Logger, http.StatusServiceUnavailable, view)
		}
		return
	}

	confirmed := r.URL.Query().Get("confirm") == "true"
	if !confirmed {
		state := installer.Probe(opts)
		if hx {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := uninstallConfirmTmpl.Execute(w, uninstallConfirmView{State: state}); err != nil {
				deps.Logger.Error("uninstall-confirm fragment template render failed",
					"code", string(LogCodeUninstallConfirmRender),
					"error", err,
					"request_path", r.URL.Path,
					"binary_present", state.BinaryPresent,
					"service_state", state.ServiceState)
			}
			return
		}
		writeJSON(w, deps.Logger, http.StatusOK, agentInstallView{
			State: &state,
			Error: "confirmation required — POST with ?confirm=true",
		})
		return
	}

	if err := deps.Installer.Uninstall(r.Context(), opts); err != nil {
		deps.Logger.Error("agent uninstall action failed",
			"code", string(LogCodeAgentUninstall),
			"error", err,
			"user_mode", opts.UserMode,
			"binary_dir", opts.BinaryDir,
			"hx_request", hx,
			"request_path", r.URL.Path)
		state := installer.Probe(opts)
		view := agentInstallView{
			State:          &state,
			InstallEnabled: true,
			Error:          err.Error(),
			CLIHint:        cliHint(opts),
		}
		if hx {
			writeInstallStatusHTML(w, deps, http.StatusInternalServerError, &view)
		} else {
			writeJSON(w, deps.Logger, http.StatusInternalServerError, view)
		}
		return
	}

	state := installer.Probe(opts)
	view := agentInstallView{
		State:          &state,
		InstallEnabled: true,
	}
	// Notify the polling header so the stepper rolls back to "install" as
	// the next action without waiting for the 10s heartbeat.
	w.Header().Set("HX-Trigger", "refresh-agent-state")
	if hx {
		writeInstallStatusHTML(w, deps, http.StatusOK, &view)
	} else {
		writeJSON(w, deps.Logger, http.StatusOK, view)
	}
}

// uninstallConfirmView feeds the destructive-action confirmation fragment.
// Carries the probed State so the confirm copy can name the actual paths
// that will be kept (operators trust copy more when it cites real paths).
type uninstallConfirmView struct {
	State installer.State
}

var uninstallConfirmTmpl = template.Must(template.New("uninstall-confirm").Parse(`
<div class="install-status uninstall-confirm">
  <p class="badge badge-orange">about to uninstall</p>
  <p>This <strong>stops the service</strong> and <strong>removes the OS registration</strong>.
     The following are <strong>kept in place</strong> so you can re-install without re-enrolling:</p>
  <ul class="muted small">
    <li>binary at <code>{{.State.BinaryPath}}</code></li>
    <li>certificate store at <code>{{.State.CertsDir}}</code></li>
  </ul>
  <form hx-post="/api/v1/agent/install/uninstall?confirm=true"
        hx-target="#install-fragment"
        hx-swap="innerHTML"
        hx-disabled-elt="find button"
        style="display:inline">
    <button class="btn btn-primary" type="submit">Yes, uninstall</button>
  </form>
  <form hx-get="/fragments/install-status"
        hx-target="#install-fragment"
        hx-swap="innerHTML"
        style="display:inline">
    <button class="btn btn-outline" type="submit">Cancel</button>
  </form>
</div>
`))

// handleAgentState returns the aggregated "after state" the dashboard uses
// to render the post-install summary. It is the single endpoint the UI hits
// to answer "are we up?" — composing install, identity, check stamps, and
// streaming health into one round-trip.
func handleAgentState(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	opts := installer.DetectDefaults().Options
	if deps.PlatformEndpoint != "" {
		opts.Endpoint = deps.PlatformEndpoint
	}
	state := installer.Probe(opts)
	view := agentStateView{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Install:     state,
		NextAction:  state.NextAction,
	}
	if deps.Store != nil {
		if idView := loadIdentityStateView(r.Context(), deps); idView != nil {
			view.Identity = idView
		}
	}
	if deps.StreamCtrl != nil {
		view.Stream = streamViewFromCtrl(deps.StreamCtrl)
	}
	view.OverallStatus = overallStatus(view)
	writeJSON(w, deps.Logger, http.StatusOK, view)
}

// loadIdentityStateView pulls the enrolled identity stamps from the store
// and adapts them for the JSON wire. Returns nil when no identity exists,
// which the caller serializes as a missing field rather than empty struct.
func loadIdentityStateView(ctx context.Context, deps onboardingDeps) *identityStateView {
	id, err := deps.Store.GetEnrolledIdentity(ctx)
	if err != nil {
		if errors.Is(err, sqlite.ErrNoIdentity) {
			return &identityStateView{Enrolled: false}
		}
		deps.Logger.Warn("agent-state identity lookup failed",
			"code", string(LogCodeAgentStateIdentity),
			"error", err,
			"err_kind", fmt.Sprintf("%T", err))
		return nil
	}
	v := &identityStateView{
		Enrolled:         true,
		FingerprintShort: shortFingerprint(id.ApiKeyFingerprint),
		FirstEnrolledAt:  id.FirstEnrolledAt.Format(time.RFC3339),
		LastEnrolledAt:   id.LastEnrolledAt.Format(time.RFC3339),
	}
	if id.LastCheckPassedAt != nil {
		v.LastCheckPassedAt = id.LastCheckPassedAt.Format(time.RFC3339)
	}
	if id.LastCheckFailedAt != nil {
		v.LastCheckFailedAt = id.LastCheckFailedAt.Format(time.RFC3339)
	}
	return v
}

// streamViewFromCtrl adapts the StreamController.Status() to the JSON wire.
// Kept out of handleAgentState so the dependency on StreamController stays
// in one place and the JSON wire can evolve without touching the handler.
func streamViewFromCtrl(c StreamController) *streamStateView {
	s := c.Status()
	v := &streamStateView{
		State:        s.NormalizeState(),
		BacklogDepth: s.BacklogDepth,
		TotalSent:    s.TotalSent,
		Error:        s.LastErrorText,
	}
	if !s.LastEventAt.IsZero() {
		v.LastEventAt = s.LastEventAt.Format(time.RFC3339)
	}
	return v
}

// overallStatus collapses the per-component states into a single token the UI
// can render as a top-of-page badge. The order mirrors NextAction's flow.
func overallStatus(v agentStateView) string {
	if v.NextAction != installer.ActionReady {
		return v.NextAction
	}
	if v.Identity == nil || !v.Identity.Enrolled {
		return installer.ActionEnroll
	}
	if v.Stream != nil && v.Stream.State == "degraded" {
		return "degraded"
	}
	if v.Stream != nil && v.Stream.State == "running" {
		return "streaming"
	}
	return installer.ActionReady
}

// cliHint composes the equivalent `kite-collector install …` command line a
// user can paste to perform the install themselves. We always show this even
// when the dashboard can do the install itself, because copy-pastable hints
// are a low-cost way to teach the CLI and survive a dashboard outage.
func cliHint(opts installer.Options) string {
	parts := []string{"kite-collector", "install"}
	if opts.UserMode {
		parts = append(parts, "--user")
	}
	if opts.BinaryDir != "" {
		parts = append(parts, "--binary-dir", quoteForCLI(opts.BinaryDir))
	}
	if opts.CertsDir != "" {
		parts = append(parts, "--certs-dir", quoteForCLI(opts.CertsDir))
	}
	if opts.Endpoint != "" {
		parts = append(parts, "--endpoint", quoteForCLI(opts.Endpoint))
	}
	return strings.Join(parts, " ")
}

// quoteForCLI wraps a value in double quotes when it contains a space; we do
// not attempt full POSIX/Windows shell escaping because the only characters
// the smart defaults emit are path separators and (rarely) Windows backslashes.
func quoteForCLI(v string) string {
	if strings.ContainsAny(v, " \t") {
		return `"` + v + `"`
	}
	return v
}

// decodeOptionalJSON decodes the JSON body into v but treats EOF / empty body
// as "no overrides" rather than an error. The install endpoint is designed
// to work as POST with empty body (use all smart defaults) or with a partial
// override JSON.
func decodeOptionalJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	defer func() { _ = r.Body.Close() }()
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("decode json body: %w", err)
	}
	return nil
}

// writeJSON serializes v as JSON with the canonical content-type. Errors are
// logged but never propagated to the caller — by the time we are writing the
// body the response status has already been committed.
func writeJSON(w http.ResponseWriter, logger *slog.Logger, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		if logger != nil {
			logger.Error("dashboard: agent install json encode", "error", err)
		}
		http.Error(w, "internal encode error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// ===========================================================================
// HTMX install-status fragment
// ===========================================================================

type installStatusFragmentView struct {
	CLIHint        string
	Error          string
	ErrorCategory  installErrorCategory
	State          installer.State
	Detected       installer.Detected
	InstallEnabled bool
}

var installStatusFragmentTmpl = template.Must(template.New("install-status").Funcs(template.FuncMap{
	"actionLabel": actionLabel,
	"actionBadge": actionBadge,
	"checkmark": func(ok bool) string {
		if ok {
			return "✓"
		}
		return "—"
	},
}).Parse(`
<div class="install-status">
  <p>
    <span class="badge {{actionBadge .State.NextAction}}">{{actionLabel .State.NextAction}}</span>
    <span class="muted small">detected {{.Detected.OS}}/{{.Detected.Arch}}{{if .Detected.Hostname}} on <code>{{.Detected.Hostname}}</code>{{end}}</span>
  </p>
  <table class="kv">
    <tr><td>binary</td><td>{{checkmark .State.BinaryPresent}} <code>{{.State.BinaryPath}}</code></td></tr>
    <tr><td>certs dir</td><td>{{checkmark .State.CertsDirExists}} <code>{{.State.CertsDir}}</code></td></tr>
    <tr><td>enrolled</td><td>{{checkmark .State.CertsEnrolled}}</td></tr>
    <tr><td>service</td><td>{{.State.ServiceState}}</td></tr>
    <tr><td>mode</td><td>{{if .State.UserMode}}user{{else}}system{{end}}</td></tr>
  </table>
  {{if .Error}}
    <p class="badge badge-red">install error: {{.Error}}</p>
    {{if eq .ErrorCategory "permission"}}
      <p class="muted small">This dashboard isn't running with elevated privileges. The fastest fix
         is to install in user mode — no sudo required, paths reroute to your home
         directory.</p>
      <form hx-post="/api/v1/agent/install?user_mode=true"
            hx-target="#install-fragment"
            hx-swap="innerHTML">
        <button class="btn btn-primary" type="submit">Retry in --user mode</button>
        <span class="muted small">&nbsp;or restart the dashboard with <code>sudo</code> and try again.</span>
      </form>
      <details><summary class="muted small">Or run the equivalent CLI command</summary>
        <div class="cli-hint-wrap">
        <pre class="cli-hint"><code>{{.CLIHint}}</code></pre>
        <button type="button" class="btn-copy" data-copy="{{.CLIHint}}" onclick="copyFromBtn(this)" title="Copy the CLI command to clipboard" aria-label="Copy CLI install command to clipboard">copy</button>
      </div>
      </details>
    {{else if eq .ErrorCategory "service_manager"}}
      <p class="muted small">The OS service manager (systemd / launchd / SCM) isn't reachable
         from this process. The binary copy may have succeeded; the service
         registration step failed. Run the CLI command on a host with the
         expected init system, or omit service registration:</p>
      <div class="cli-hint-wrap">
        <pre class="cli-hint"><code>{{.CLIHint}}</code></pre>
        <button type="button" class="btn-copy" data-copy="{{.CLIHint}}" onclick="copyFromBtn(this)" title="Copy the CLI command to clipboard" aria-label="Copy CLI install command to clipboard">copy</button>
      </div>
    {{else if eq .ErrorCategory "disk_write"}}
      <p class="muted small">The target install path is read-only or out of disk space.
         Pick a writable <code>--binary-dir</code> and rerun:</p>
      <div class="cli-hint-wrap">
        <pre class="cli-hint"><code>{{.CLIHint}}</code></pre>
        <button type="button" class="btn-copy" data-copy="{{.CLIHint}}" onclick="copyFromBtn(this)" title="Copy the CLI command to clipboard" aria-label="Copy CLI install command to clipboard">copy</button>
      </div>
    {{else}}
      <p class="muted small">Try <a href="#install-card" hx-get="/fragments/install-status" hx-target="#install-fragment">refresh state</a> or run the CLI command below for a clearer error trace.</p>
      <div class="cli-hint-wrap">
        <pre class="cli-hint"><code>{{.CLIHint}}</code></pre>
        <button type="button" class="btn-copy" data-copy="{{.CLIHint}}" onclick="copyFromBtn(this)" title="Copy the CLI command to clipboard" aria-label="Copy CLI install command to clipboard">copy</button>
      </div>
    {{end}}
  {{else if .InstallEnabled}}
    <details class="install-preview" {{if not .State.BinaryPresent}}open{{end}}>
      <summary>What will happen</summary>
      <ul class="muted small">
        <li>Copy this binary to <code>{{.State.BinaryPath}}</code></li>
        <li>Create certificate store at <code>{{.State.CertsDir}}</code></li>
        <li>Register the kite-collector service with the OS service manager</li>
      </ul>
    </details>
    <form hx-post="/api/v1/agent/install"
          hx-target="#install-fragment"
          hx-swap="innerHTML"
          hx-disabled-elt="find button"
          hx-indicator="#install-indicator">
      <button class="btn" type="submit">Install now (smart defaults · ≈5s)</button>
      <span id="install-indicator" class="htmx-indicator muted small"> installing&hellip;</span>
    </form>
    {{if .State.BinaryPresent}}
    <p class="muted small uninstall-footer">
      <a href="#" hx-post="/api/v1/agent/install/uninstall"
         hx-target="#install-fragment"
         hx-swap="innerHTML">Uninstall agent</a>
      &mdash; stops the service and removes the OS registration. Binary &amp; certs kept.
    </p>
    {{end}}
  {{else}}
    <p class="muted small">Install API is advisory-only. Run on the host:</p>
    <div class="cli-hint-wrap">
      <pre class="cli-hint"><code>{{.CLIHint}}</code></pre>
      <button type="button" class="btn-copy" data-copy="{{.CLIHint}}" onclick="copyFromBtn(this)" title="Copy the CLI command to clipboard" aria-label="Copy CLI install command to clipboard">copy</button>
    </div>
  {{end}}
</div>
`))

// renderInstallStatusFragment renders the install card. Errors propagate so
// the buffered fragment writer rolls back the partial response per the
// existing onboarding pattern.
func renderInstallStatusFragment(w io.Writer, deps onboardingDeps) error {
	d := installer.DetectDefaults()
	if deps.PlatformEndpoint != "" {
		d.Options.Endpoint = deps.PlatformEndpoint
	}
	state := installer.Probe(d.Options)
	view := installStatusFragmentView{
		State:          state,
		Detected:       d.Detected,
		CLIHint:        cliHint(d.Options),
		InstallEnabled: deps.Installer != nil,
	}
	if err := installStatusFragmentTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render install-status: %w", err)
	}
	return nil
}

// actionLabel turns a NextAction token into the human-readable copy the
// status badge uses. Kept as a helper so the JSON wire and the HTML wire
// pull from the same source of truth.
func actionLabel(action string) string {
	switch action {
	case installer.ActionInstall:
		return "install agent"
	case installer.ActionRegisterService:
		return "register service"
	case installer.ActionEnroll:
		return "enroll"
	case installer.ActionStartService:
		return "start service"
	case installer.ActionReady:
		return "ready"
	}
	return action
}

// actionBadge maps a NextAction token to one of the existing dashboard badge
// classes so the install card visually matches the rest of the onboarding.
func actionBadge(action string) string {
	switch action {
	case installer.ActionReady:
		return "badge-green"
	case installer.ActionStartService:
		return "badge-orange"
	case installer.ActionEnroll, installer.ActionRegisterService:
		return "badge-blue"
	case installer.ActionInstall:
		return "badge-gray"
	}
	return "badge-gray"
}

// ===========================================================================
// Onboarding header (stepper + mode chip + primary CTA)
// ===========================================================================

// stepStatus is the per-step status the stepper template renders. The four
// states (done / current / pending / blocked) drive both icon and CSS class
// so the stepper communicates progress at a glance.
type stepStatus struct {
	Key    string // canonical token (install|enroll|check|stream)
	Label  string // human-readable
	Anchor string // #card-id to scroll into view on click
	Status string // done | current | pending | blocked
	Detail string // optional one-line summary under the step
}

// onboardingHeaderView is what the header template consumes. It composes the
// stepper, the mode chip (agent vs inspector + privilege hint), and the
// "Next: <action>" primary CTA into a single rendering pass so the header
// stays internally consistent under HTMX swap.
type onboardingHeaderView struct {
	LastScan      *lastScanSummary
	OverallStatus string
	NextAnchor    string
	ModeLabel     string
	ModeBadge     string
	PrivilegeHint string
	NextAction    string
	NextLabel     string
	Steps         []stepStatus
	ShowWelcome   bool
	ShowLauncher  bool
	ShowScanCTA   bool
	WriteEnabled  bool
	InspectorOnly bool
}

// lastScanSummary is the launcher's "did a scan happen, when, and how did
// it land?" summary. Surfaces in the launcher panel so the operator gets
// immediate feedback after the first scan completes — instead of staring at
// generic exploration links wondering if the scan actually finished.
type lastScanSummary struct {
	StartedAt    string // RFC3339 timestamp for the title tooltip
	RelativeTime string // pre-formatted "5m ago" / "2h ago" for inline display
	Status       string // scan_run.status (queued | running | completed | failed | …)
	BadgeClass   string // CSS badge class derived from Status
	Completed    bool   // true when CompletedAt is set
}

var onboardingHeaderTmpl = template.Must(template.New("onboarding-header").Funcs(template.FuncMap{
	"actionLabel": actionLabel,
}).Parse(`
<header class="onboarding-header">
  <div class="onboarding-header-row">
    <div class="onboarding-title">
      <h1>Kite Collector onboarding</h1>
      {{if .ShowWelcome}}
      <p class="muted small">Get your agent online in four steps &middot; usually under 2&nbsp;minutes.</p>
      {{else}}
      <p class="muted small">All set &mdash; your agent is up. Use the cards below to verify or re-run any step.</p>
      {{end}}
    </div>
    <div class="onboarding-mode">
      <span class="badge {{.ModeBadge}}">{{.ModeLabel}}</span>
      {{if .PrivilegeHint}}<span class="muted small">{{.PrivilegeHint}}</span>{{end}}
    </div>
  </div>

  <nav class="stepper" aria-label="Onboarding progress">
    <ol>
      {{range .Steps}}
      <li class="step step-{{.Status}}"{{if eq .Status "current"}} aria-current="step"{{end}}>
        <a href="{{.Anchor}}">
          <span class="step-marker" aria-hidden="true">{{if eq .Status "done"}}&#10003;{{else}}&nbsp;{{end}}</span>
          <span class="step-label">{{.Label}}</span>
          {{if .Detail}}<span class="step-detail muted small">{{.Detail}}</span>{{end}}
        </a>
      </li>
      {{end}}
    </ol>
  </nav>

  {{if and (ne .NextAction "ready") (ne .NextAction "streaming")}}
  <div class="cta-bar">
    <a class="btn btn-primary" href="{{.NextAnchor}}">
      Next: {{.NextLabel}} &rarr;
    </a>
    {{if and (eq .NextAction "install") (not .WriteEnabled)}}
    <span class="muted small">Install API is advisory-only &mdash; the CTA jumps to a copy-pasteable CLI command.</span>
    {{end}}
  </div>
  {{end}}

  {{if .ShowLauncher}}
  <div class="launcher-panel">
    <h3>You're all set. What next?</h3>
    {{if .ShowScanCTA}}
    <div class="launcher-first-scan">
      {{if .LastScan}}
        <p>
          <span class="badge {{.LastScan.BadgeClass}}">{{.LastScan.Status}}</span>
          <strong>Last scan {{.LastScan.RelativeTime}}</strong>
          <span class="muted small" title="{{.LastScan.StartedAt}}">&middot; started {{.LastScan.StartedAt}}</span>
        </p>
        <form hx-post="/api/v1/scan"
              hx-target="#first-scan-status"
              hx-swap="innerHTML"
              hx-disabled-elt="find button">
          <button class="btn" type="submit">Run another scan</button>
          <div id="first-scan-status" class="muted small">&nbsp;</div>
        </form>
      {{else}}
        <p><strong>Run your first scan</strong> &mdash; discover assets, software, and
           vulnerabilities on this host. Usually 30&nbsp;seconds to 2&nbsp;minutes.
           Without it, the tabs below show empty tables.</p>
        <form hx-post="/api/v1/scan"
              hx-target="#first-scan-status"
              hx-swap="innerHTML"
              hx-disabled-elt="find button">
          <button class="btn btn-primary" type="submit">Run scan now</button>
          <div id="first-scan-status" class="muted small">&nbsp;</div>
        </form>
      {{end}}
    </div>
    {{end}}
    <ul class="launcher-links">
      <li><a href="/assets">View asset inventory &rarr;</a><span class="muted small"> hosts, software, network interfaces</span></li>
      <li><a href="/findings">View configuration findings &rarr;</a><span class="muted small"> hardening checks against your config</span></li>
      <li><a href="/scans">Recent scans &rarr;</a><span class="muted small"> when each source last ran, what it found</span></li>
      <li><a href="/tables">Inspect raw tables &rarr;</a><span class="muted small"> Datasette-style browser over local SQLite</span></li>
    </ul>
    <p class="muted small">Need help? <a href="/api/v1/support-bundle">Download a support bundle</a> with version, identity stamps, and the last probe run.</p>
  </div>
  {{end}}
</header>
`))

// renderOnboardingHeaderFragment composes the stepper / mode chip / CTA from
// the current agent state. It mirrors the data handleAgentState exposes via
// JSON so the visual progress and the API contract cannot drift.
func renderOnboardingHeaderFragment(w io.Writer, ctx context.Context, deps onboardingDeps) error {
	// Reuse the aggregate state computation so the visual progress and the
	// /api/v1/agent/state JSON are always in lock-step.
	d := installer.DetectDefaults()
	if deps.PlatformEndpoint != "" {
		d.Options.Endpoint = deps.PlatformEndpoint
	}
	state := installer.Probe(d.Options)
	stateView := agentStateView{
		Install:    state,
		NextAction: state.NextAction,
	}
	if deps.Store != nil {
		stateView.Identity = loadIdentityStateView(ctx, deps)
	}
	if deps.StreamCtrl != nil {
		stateView.Stream = streamViewFromCtrl(deps.StreamCtrl)
	}
	stateView.OverallStatus = overallStatus(stateView)

	showLauncher := stateView.OverallStatus == "ready" || stateView.OverallStatus == "streaming"
	view := onboardingHeaderView{
		NextAction:    stateView.NextAction,
		NextLabel:     actionLabel(stateView.NextAction),
		NextAnchor:    anchorForAction(stateView.NextAction),
		OverallStatus: stateView.OverallStatus,
		ShowWelcome:   !showLauncher,
		ShowLauncher:  showLauncher,
		ShowScanCTA:   showLauncher && deps.ScanEnabled,
		WriteEnabled:  deps.Installer != nil,
		InspectorOnly: deps.Installer == nil,
		Steps:         buildStepperSteps(stateView, d.Detected),
		LastScan:      loadLastScanSummary(ctx, deps),
	}
	view.ModeLabel, view.ModeBadge, view.PrivilegeHint = headerModeDescriptor(deps, d.Detected)

	if err := onboardingHeaderTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render onboarding-header: %w", err)
	}
	return nil
}

// loadLastScanSummary returns the launcher's "did a scan happen, when, and
// how did it land?" view for the most recent scan_run. Returns nil when
// no scan_run exists (the fresh-onboarding case) — the template's
// {{if .LastScan}} branch hides the summary line.
//
// Errors are swallowed back to nil because surfacing a "couldn't load
// last scan" message in the launcher is more confusing than just hiding
// the summary; the polling header will retry every 10s anyway.
func loadLastScanSummary(ctx context.Context, deps onboardingDeps) *lastScanSummary {
	if deps.Store == nil {
		return nil
	}
	run, err := deps.Store.GetLatestScanRun(ctx)
	if err != nil || run == nil {
		return nil
	}
	out := &lastScanSummary{
		StartedAt:    run.StartedAt.UTC().Format(time.RFC3339),
		RelativeTime: humanizeRelativeTime(time.Since(run.StartedAt)),
		Status:       string(run.Status),
		Completed:    run.CompletedAt != nil,
	}
	// Map scan status → badge class. Treat anything that isn't explicitly
	// completed/running as gray so unknown future status values degrade
	// gracefully rather than rendering with the wrong color.
	switch out.Status {
	case "completed":
		out.BadgeClass = "badge-green"
	case "running", "queued":
		out.BadgeClass = "badge-blue"
	case "failed", "cancelled":
		out.BadgeClass = "badge-red"
	default:
		out.BadgeClass = "badge-gray"
	}
	return out
}

// buildStepperSteps maps the four-step canonical onboarding flow to per-step
// status tokens based on the current aggregate state. The mapping is the
// single source of truth for the stepper UI — if NextAction grows a new
// token, this is the only place to teach it where the step belongs.
func buildStepperSteps(s agentStateView, _ installer.Detected) []stepStatus {
	steps := []stepStatus{
		{Key: "install", Label: "Install agent", Anchor: "#install-card"},
		{Key: "enroll", Label: "Enroll token", Anchor: "#enroll-card"},
		{Key: "check", Label: "Connection check", Anchor: "#check-card"},
		{Key: "stream", Label: "Streaming", Anchor: "#stream-card"},
	}

	enrolled := s.Identity != nil && s.Identity.Enrolled
	checked := enrolled && s.Identity.LastCheckPassedAt != ""
	streaming := s.Stream != nil && (s.Stream.State == "running" || s.Stream.State == "degraded")

	// Step 1 — install. Done when binary + (service registered).
	switch s.Install.NextAction {
	case installer.ActionInstall:
		steps[0].Status = "current"
	case installer.ActionRegisterService:
		steps[0].Status = "current"
		steps[0].Detail = "binary present — register service"
	default:
		steps[0].Status = "done"
		steps[0].Detail = "binary + service registered"
	}

	// Step 2 — enroll. Done when identity present.
	switch {
	case !enrolled && steps[0].Status == "done":
		steps[1].Status = "current"
	case enrolled:
		steps[1].Status = "done"
		if s.Identity.FingerprintShort != "" {
			steps[1].Detail = "key " + s.Identity.FingerprintShort
		}
	default:
		steps[1].Status = "pending"
	}

	// Step 3 — check. Done when last_check_passed_at is set.
	switch {
	case !checked && enrolled:
		steps[2].Status = "current"
	case checked:
		steps[2].Status = "done"
		steps[2].Detail = "all probes passed"
	default:
		steps[2].Status = "pending"
	}

	// Step 4 — stream. Done when stream is running.
	switch {
	case streaming:
		steps[3].Status = "done"
		steps[3].Detail = s.Stream.State
	case checked:
		steps[3].Status = "current"
	default:
		steps[3].Status = "pending"
	}

	return steps
}

// anchorForAction maps a NextAction token to the in-page anchor the primary
// CTA scrolls to. Defaults to the install card so the CTA always lands on
// something even if a new token slips through.
func anchorForAction(action string) string {
	switch action {
	case installer.ActionInstall, installer.ActionRegisterService:
		return "#install-card"
	case installer.ActionEnroll:
		return "#enroll-card"
	case installer.ActionStartService:
		return "#stream-card"
	case installer.ActionReady, "streaming":
		return "#check-card"
	}
	return "#install-card"
}

// headerModeDescriptor returns the (label, badge class, privilege hint) for
// the mode chip. The mode is "Agent" when an Installer is wired (the dashboard
// can perform real installs), otherwise "Inspector". The privilege hint is
// surfaced eagerly so the operator knows *before* clicking install whether
// they will hit a permission error.
func headerModeDescriptor(deps onboardingDeps, det installer.Detected) (label, badge, hint string) {
	switch {
	case deps.Installer != nil && det.Privileged:
		return "Agent · write-enabled", "badge-green", "running with privileges — install will succeed"
	case deps.Installer != nil:
		return "Agent · write-enabled", "badge-orange",
			"non-privileged process — system install may fail; prefer --user mode"
	default:
		return "Inspector · read-only", "badge-gray",
			"install API returns a CLI hint instead of executing"
	}
}

// statusBadgeView feeds the compact topbar onboarding-status badge that
// renders on every dashboard page. The badge gives operators glance-level
// agent health without having to navigate to /onboarding — closes the
// cross-page visibility gap where iterations 1-17 polished /onboarding but
// the rest of the dashboard had no health signal.
type statusBadgeView struct {
	Class string // CSS class: status-ready | status-streaming | status-degraded | status-pending | status-install
	Glyph string // single-char visual: ✓ ! · ○
	Label string // short human-readable summary for the badge title attribute
}

var onboardingStatusBadgeTmpl = template.Must(template.New("status-badge").Parse(`
<a class="topbar-status {{.Class}}"
   href="/onboarding"
   hx-get="/onboarding"
   hx-target="#content"
   hx-push-url="true"
   title="{{.Label}}">
  <span aria-hidden="true">{{.Glyph}}</span>
  <span class="sr-only">{{.Label}}</span>
</a>
`))

// renderOnboardingStatusBadgeFragment renders the compact topbar badge. It
// reuses the same aggregated agentStateView (and overallStatus rollup) the
// /onboarding header uses, so the topbar badge and /onboarding visible state
// always agree on which step the operator is at.
func renderOnboardingStatusBadgeFragment(w io.Writer, ctx context.Context, deps onboardingDeps) error {
	d := installer.DetectDefaults()
	if deps.PlatformEndpoint != "" {
		d.Options.Endpoint = deps.PlatformEndpoint
	}
	state := installer.Probe(d.Options)
	sv := agentStateView{Install: state, NextAction: state.NextAction}
	if deps.Store != nil {
		sv.Identity = loadIdentityStateView(ctx, deps)
	}
	if deps.StreamCtrl != nil {
		sv.Stream = streamViewFromCtrl(deps.StreamCtrl)
	}
	sv.OverallStatus = overallStatus(sv)

	view := badgeViewFor(sv.OverallStatus)
	if err := onboardingStatusBadgeTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render onboarding-status-badge: %w", err)
	}
	return nil
}

// badgeViewFor maps the aggregated overall_status to the topbar badge's
// CSS class, glyph, and label. Single source of truth for the topbar
// status vocabulary so a status-enum addition has exactly one place to
// teach the visual mapping.
func badgeViewFor(overallStatus string) statusBadgeView {
	switch overallStatus {
	case "streaming":
		return statusBadgeView{Class: "status-streaming", Glyph: "✓", Label: "Agent streaming — all healthy"}
	case installer.ActionReady:
		return statusBadgeView{Class: "status-ready", Glyph: "✓", Label: "Agent ready — onboarding complete"}
	case "degraded":
		return statusBadgeView{Class: "status-degraded", Glyph: "!", Label: "Agent degraded — check the onboarding page"}
	case installer.ActionEnroll, installer.ActionStartService, installer.ActionRegisterService:
		return statusBadgeView{Class: "status-pending", Glyph: "·", Label: "Onboarding in progress — " + overallStatus}
	case installer.ActionInstall:
		return statusBadgeView{Class: "status-install", Glyph: "○", Label: "Agent not yet installed — open Onboarding to start"}
	default:
		return statusBadgeView{Class: "status-pending", Glyph: "·", Label: "Agent status: " + overallStatus}
	}
}
