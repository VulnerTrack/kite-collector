package dashboard

import (
	"context"
	"fmt"
	"html/template"
	"io"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// The simplified onboarding flow: three steps shown one at a time instead of
// four always-visible panels. Done steps collapse to one-line receipts (with
// a Details toggle that lazy-loads the full panel), exactly one step renders
// expanded with one primary action, and the connection check stops being a
// step of its own — it is an automatic gate inside "Start streaming", since
// an operator never runs it for its own sake.
//
// The layout is server-rendered from the same aggregate state the header and
// topbar badge use, replacing the client-side wizard JS that used to scrape
// stepper DOM classes to decide which card to show.

// onboardingStepView is one row of the three-step flow.
type onboardingStepView struct {
	Key    string // install | connect | stream
	CardID string // stable element id (#install-card, #enroll-card, #stream-card)
	Title  string
	Status string // done | current | pending
	// Receipt is the one-line summary a done step collapses to.
	Receipt string
	// Pending is the muted hint on a not-yet-reachable step.
	Pending string
	// FragmentURL lazy-loads the step's full panel (current step and the
	// Details toggle of a done step). The stream step wires its two panels
	// directly in the template.
	FragmentURL string
}

// onboardingStepsView is the data model for onboardingStepsTemplate.
type onboardingStepsView struct {
	Steps       []onboardingStepView
	AllDone     bool
	ShowScanCTA bool
	LastScan    *lastScanSummary
}

// buildOnboardingSteps folds the canonical four-step state (buildStepperSteps
// stays the single source of truth) into the three-step presentation: the
// check step's progress is absorbed into the stream step.
func buildOnboardingSteps(s agentStateView, det installer.Detected) []onboardingStepView {
	four := buildStepperSteps(s, det)
	install, enroll, stream := four[0], four[1], four[3]

	installView := onboardingStepView{
		Key: "install", CardID: "install-card", Title: "Install",
		FragmentURL: "/fragments/install-status",
	}
	if install.Status == "done" {
		installView.Status = "done"
		installView.Receipt = install.Detail
	} else {
		// Install is the first step: it is current whenever it isn't done.
		installView.Status = "current"
	}

	connectView := onboardingStepView{
		Key: "connect", CardID: "enroll-card", Title: "Connect this collector",
		FragmentURL: "/fragments/enroll-form",
		Pending:     "sign in to authorize this collector",
	}
	switch enroll.Status {
	case "done":
		connectView.Status = "done"
		connectView.Receipt = "Connected"
		if enroll.Detail != "" {
			connectView.Receipt = "Connected · " + enroll.Detail
		}
	case "current":
		connectView.Status = "current"
	default:
		connectView.Status = "pending"
	}

	streamView := onboardingStepView{
		Key: "stream", CardID: "stream-card", Title: "Start streaming",
		Pending: "the connection check runs automatically before streaming starts",
	}
	switch {
	case stream.Status == "done":
		streamView.Status = "done"
		streamView.Receipt = "Streaming · " + stream.Detail
	case connectView.Status == "done":
		// Enrolled: streaming is the one thing left, whether or not a check
		// has passed yet — the check renders inside this step as its gate.
		streamView.Status = "current"
	default:
		streamView.Status = "pending"
	}

	return []onboardingStepView{installView, connectView, streamView}
}

var onboardingStepsTmpl = template.Must(
	template.New("onboarding-steps").Parse(onboardingStepsTemplate))

// renderOnboardingStepsFragment renders the three-step flow from the current
// aggregate agent state. It re-renders on every refresh-agent-state trigger,
// so completing an action collapses the finished step and expands the next
// without any client-side step bookkeeping.
func renderOnboardingStepsFragment(w io.Writer, ctx context.Context, deps onboardingDeps) error {
	stateView, detected := computeAgentStateView(ctx, deps)
	steps := buildOnboardingSteps(stateView, detected)

	allDone := true
	for _, s := range steps {
		if s.Status != "done" {
			allDone = false
			break
		}
	}
	view := onboardingStepsView{
		Steps:       steps,
		AllDone:     allDone,
		ShowScanCTA: allDone && deps.ScanEnabled,
		LastScan:    loadLastScanSummary(ctx, deps),
	}
	if err := onboardingStepsTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render onboarding-steps: %w", err)
	}
	return nil
}

const onboardingStepsTemplate = `<div class="onb-steps">
{{- range .Steps }}
{{- if eq .Status "done" }}
<div class="onb-step onb-step-done" id="{{.CardID}}">
  <svg class="onb-glyph" width="22" height="22" viewBox="0 0 22 22" aria-hidden="true"><circle cx="11" cy="11" r="10" fill="rgba(34,197,94,0.12)" stroke="#22C55E" stroke-width="1.5"></circle><path d="M6.5 11.5l3 3L15.5 8" stroke="#118d57" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"></path></svg>
  <div class="onb-step-line">
    <span class="onb-step-title">{{.Title}}</span>
    {{if .Receipt}}<span class="muted small">{{.Receipt}}</span>{{end}}
  </div>
  {{if .FragmentURL}}
  <details class="onb-step-details">
    <summary>Details</summary>
    <div hx-get="{{.FragmentURL}}" hx-trigger="toggle once from:closest details" hx-swap="innerHTML">
      <span class="muted small">Loading&hellip;</span>
    </div>
  </details>
  {{end}}
</div>
{{- else if eq .Status "current" }}
<section class="card onb-step onb-step-current" id="{{.CardID}}" aria-current="step">
  <div class="onb-step-head">
    <svg class="onb-glyph" width="22" height="22" viewBox="0 0 22 22" aria-hidden="true"><circle cx="11" cy="11" r="10" fill="rgba(225,29,72,0.1)" stroke="#e11d48" stroke-width="1.5"></circle><circle cx="11" cy="11" r="4" fill="#e11d48"></circle></svg>
    <h2>{{.Title}}</h2>
  </div>
  {{if eq .Key "install"}}
  <p class="muted onb-step-copy">Smart defaults pre-filled from your OS &mdash; the panel below auto-detects what&rsquo;s already in place.</p>
  <div id="install-fragment" hx-get="{{.FragmentURL}}" hx-trigger="load" hx-swap="innerHTML">
    <div class="htmx-indicator">Detecting host&hellip;</div>
  </div>
  {{end}}
  {{if eq .Key "connect"}}
  <p class="muted onb-step-copy">Sign in with VulnerTrack in your browser to authorize this collector.</p>
  <div id="enroll-fragment" hx-get="{{.FragmentURL}}" hx-trigger="load" hx-swap="innerHTML">
    <div class="htmx-indicator">Loading enroll form&hellip;</div>
  </div>
  <p class="muted small onb-trust-line">The enrollment credential stays on this machine &mdash; only its <code>sha256[:8]</code> fingerprint is ever shown.</p>
  <details class="trust-panel onb-trust">
    <summary>What gets stored?</summary>
    <ul>
      <li><strong>Stored locally only.</strong> The enrollment credential is AES-256-GCM wrapped and written to your local SQLite DB at the certs-dir path.</li>
      <li><strong>Wrap key is in-memory.</strong> A fresh 32-byte AEAD wrap key is generated on each dashboard startup. Restarting the dashboard invalidates the wrapped blob; you&rsquo;ll see &ldquo;fingerprint mismatch&rdquo; and need to re-enroll. This is by design &mdash; the at-rest blob is useless without the in-memory wrap key.</li>
      <li><strong>No exfiltration before streaming.</strong> Until you press &ldquo;Start streaming&rdquo;, no agent data leaves this host. The connection check sends only synthetic probes &mdash; never real machine data.</li>
      <li><strong>Secret never logged.</strong> Only the first 8 hex chars of the SHA-256 fingerprint appear in logs, the dashboard UI, or the support bundle.</li>
    </ul>
  </details>
  {{end}}
  {{if eq .Key "stream"}}
  <p class="muted onb-step-copy">The connection check runs first &mdash; five synthetic probes (DNS, TLS, endpoint reach, clock skew, OTLP handshake), never machine data. Then start streaming; stop any time from this page, no restart needed.</p>
  <div id="check-fragment" hx-get="/fragments/connection-check" hx-trigger="load" hx-swap="innerHTML">
    <div class="htmx-indicator">Loading probe panel&hellip;</div>
  </div>
  <div id="stream-fragment" hx-get="/fragments/stream-status" hx-trigger="load, every 3s" hx-swap="innerHTML">
    <div class="htmx-indicator">Loading stream status&hellip;</div>
  </div>
  {{end}}
</section>
{{- else }}
<div class="onb-step onb-step-pending" id="{{.CardID}}">
  <svg class="onb-glyph" width="22" height="22" viewBox="0 0 22 22" aria-hidden="true"><circle cx="11" cy="11" r="10" fill="none" stroke="#C4CDD5" stroke-width="1.5"></circle></svg>
  <span class="onb-step-title">{{.Title}}</span>
  {{if .Pending}}<span class="muted small">{{.Pending}}</span>{{end}}
</div>
{{- end }}
{{- end }}
{{- if .AllDone }}
<section class="card onb-step onb-step-current onb-ready" id="ready-card">
  <div class="onb-step-head">
    <svg class="onb-glyph" width="22" height="22" viewBox="0 0 22 22" aria-hidden="true"><circle cx="11" cy="11" r="10" fill="rgba(34,197,94,0.12)" stroke="#22C55E" stroke-width="1.5"></circle><path d="M6.5 11.5l3 3L15.5 8" stroke="#118d57" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"></path></svg>
    <h2>Collector ready</h2>
    {{if .LastScan}}<span class="badge {{.LastScan.BadgeClass}}">last scan {{.LastScan.RelativeTime}}</span>{{end}}
  </div>
  <p class="muted onb-step-copy">Install, enrollment, and streaming are all in place.</p>
  <div class="onb-ready-actions">
    {{if .ShowScanCTA}}
    <form hx-post="/api/v1/scan" hx-target="#onb-scan-status" hx-swap="innerHTML">
      <button class="btn" type="submit">{{if .LastScan}}Run another scan{{else}}Run first scan{{end}}</button>
    </form>
    {{end}}
    <a class="btn btn-outline" href="/machines" hx-get="/machines" hx-target="#content" hx-push-url="true">Explore machines</a>
  </div>
  <div id="onb-scan-status"></div>
</section>
{{- end }}
</div>`
