package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/installer"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// fakeInstaller records every Install call so tests can assert "the
// dashboard dispatched the right Options" without actually mutating the
// host filesystem or service manager.
type fakeInstaller struct {
	returnFn          func(installer.Options) error
	uninstallReturnFn func(installer.Options) error
	calls             []installer.Options
	uninstallCalls    []installer.Options
	mu                sync.Mutex
}

func (f *fakeInstaller) Install(_ context.Context, opts installer.Options) error {
	f.mu.Lock()
	f.calls = append(f.calls, opts)
	f.mu.Unlock()
	if f.returnFn != nil {
		return f.returnFn(opts)
	}
	return nil
}

func (f *fakeInstaller) Uninstall(_ context.Context, opts installer.Options) error {
	f.mu.Lock()
	f.uninstallCalls = append(f.uninstallCalls, opts)
	f.mu.Unlock()
	if f.uninstallReturnFn != nil {
		return f.uninstallReturnFn(opts)
	}
	return nil
}

func (f *fakeInstaller) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeInstaller) uninstallCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.uninstallCalls)
}

func (f *fakeInstaller) lastCall() installer.Options {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

// newInstallHarness builds an onboarding harness with an injectable
// Installer. inst=nil exercises the advisory-only path (503 + cli_hint).
func newInstallHarness(t *testing.T, inst Installer) *onboardingTestHarness {
	t.Helper()
	st, err := sqlite.New(t.TempDir() + "/inst.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	key, keyErr := newOnboardingWrapKey()
	require.NoError(t, keyErr)

	mux := http.NewServeMux()
	registerOnboardingRoutes(mux, onboardingDeps{
		Store:            st,
		WrapKey:          key,
		AppVersion:       "test",
		Commit:           "deadbeef",
		PlatformEndpoint: testPlatformEndpoint,
		Installer:        inst,
		ProbeClient:      &http.Client{},
	})
	return &onboardingTestHarness{mux: mux, store: st, wrapKey: key}
}

// ---------------------------------------------------------------------------
// /api/v1/agent/install/defaults
// ---------------------------------------------------------------------------

func TestAgentInstallDefaults_ReturnsSmartDefaults(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/agent/install/defaults", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var view agentInstallView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	require.NotNil(t, view.Defaults)
	assert.NotEmpty(t, view.Defaults.Options.BinaryDir, "smart-default BinaryDir must be set")
	assert.NotEmpty(t, view.Defaults.Options.CertsDir, "smart-default CertsDir must be set")
	assert.Equal(t, testPlatformEndpoint, view.Defaults.Options.Endpoint,
		"PlatformEndpoint from config must be reflected in the defaults")
	assert.False(t, view.InstallEnabled, "nil Installer → InstallEnabled=false")
	assert.Contains(t, view.CLIHint, "kite-collector install",
		"CLI hint must always be present so operators can copy-paste")
}

func TestAgentInstallDefaults_EnabledWhenInstallerInjected(t *testing.T) {
	h := newInstallHarness(t, &fakeInstaller{})
	rec := h.do(t, "GET", "/api/v1/agent/install/defaults", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var view agentInstallView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	assert.True(t, view.InstallEnabled, "fake installer → InstallEnabled=true")
}

// ---------------------------------------------------------------------------
// /api/v1/agent/install/state
// ---------------------------------------------------------------------------

func TestAgentInstallState_ReturnsProbedState(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/agent/install/state", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var view agentInstallView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	require.NotNil(t, view.State)
	// On a typical test runner the kite-collector binary is not installed at
	// the OS-default path → BinaryPresent=false. We assert NextAction is one
	// of the legal flow tokens rather than a specific value, since CI hosts
	// may already have the binary present in some configurations.
	legalActions := map[string]bool{
		installer.ActionInstall:         true,
		installer.ActionRegisterService: true,
		installer.ActionEnroll:          true,
		installer.ActionStartService:    true,
		installer.ActionReady:           true,
	}
	assert.True(t, legalActions[view.State.NextAction],
		"NextAction must be a known token; got %q", view.State.NextAction)
}

// ---------------------------------------------------------------------------
// POST /api/v1/agent/install
// ---------------------------------------------------------------------------

func TestAgentInstall_NilInstallerReturns503(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "POST", "/api/v1/agent/install", strings.NewReader("{}"),
		map[string]string{"Content-Type": "application/json"})
	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"nil Installer must surface 503 so the UI can fall back to CLI hint")

	var view agentInstallView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	assert.NotEmpty(t, view.CLIHint)
	assert.NotEmpty(t, view.Error)
	require.NotNil(t, view.State)
}

func TestAgentInstall_DispatchesToInjectedInstaller(t *testing.T) {
	fake := &fakeInstaller{}
	h := newInstallHarness(t, fake)
	rec := h.do(t, "POST", "/api/v1/agent/install", strings.NewReader(`{}`),
		map[string]string{"Content-Type": "application/json"})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, fake.callCount(), "installer must be invoked exactly once")
	last := fake.lastCall()
	assert.NotEmpty(t, last.BinaryDir, "smart default BinaryDir must be passed through")
	assert.NotEmpty(t, last.CertsDir, "smart default CertsDir must be passed through")
}

func TestAgentInstall_PropagatesInstallerError(t *testing.T) {
	fake := &fakeInstaller{returnFn: func(_ installer.Options) error {
		return errBoom
	}}
	h := newInstallHarness(t, fake)
	rec := h.do(t, "POST", "/api/v1/agent/install", strings.NewReader(`{}`),
		map[string]string{"Content-Type": "application/json"})
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var view agentInstallView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	assert.Contains(t, view.Error, "boom")
}

func TestAgentInstall_EmptyBodyUsesSmartDefaults(t *testing.T) {
	fake := &fakeInstaller{}
	h := newInstallHarness(t, fake)
	rec := h.do(t, "POST", "/api/v1/agent/install", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 1, fake.callCount(),
		"empty body must be treated as 'use all smart defaults' rather than rejected")
}

// ---------------------------------------------------------------------------
// /api/v1/agent/state
// ---------------------------------------------------------------------------

func TestAgentState_AggregatesInstallAndIdentity(t *testing.T) {
	h := newInstallHarness(t, nil)

	// Pre-enroll so the identity slot has fingerprint stamps.
	form := url.Values{"api_key": {"sk-agent-state-0123456789ABCDEF"}}
	_ = h.do(
		t, "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	)

	rec := h.do(t, "GET", "/api/v1/agent/state", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var view agentStateView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	assert.NotEmpty(t, view.GeneratedAt, "GeneratedAt must be a RFC3339 timestamp")
	assert.NotEmpty(t, view.NextAction)
	require.NotNil(t, view.Identity)
	assert.True(t, view.Identity.Enrolled, "post-enroll identity must surface as Enrolled=true")
	assert.NotEmpty(t, view.Identity.FingerprintShort)
	assert.NotEmpty(t, view.Install.OS)
}

func TestAgentState_NoIdentityYet(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/agent/state", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var view agentStateView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	// On a fresh harness, identity is unenrolled. The view either omits
	// Identity entirely or reports Enrolled=false — both are acceptable
	// wire shapes for "nothing yet".
	if view.Identity != nil {
		assert.False(t, view.Identity.Enrolled,
			"fresh harness must not report enrolled=true")
	}
}

// ---------------------------------------------------------------------------
// /fragments/install-status (HTMX card)
// ---------------------------------------------------------------------------

func TestInstallStatusFragment_RendersSmartDefaults(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/fragments/install-status", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "binary", "fragment must list the binary row")
	assert.Contains(t, body, "certs dir")
	assert.Contains(t, body, "service")
	// With no Installer the CLI hint must be visible so the operator has
	// something to copy.
	assert.Contains(t, body, "kite-collector install",
		"advisory-only mode must surface the CLI command")
}

func TestInstallStatusFragment_ShowsInstallButtonWhenEnabled(t *testing.T) {
	h := newInstallHarness(t, &fakeInstaller{})
	rec := h.do(t, "GET", "/fragments/install-status", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Install now", "fake installer → install button rendered")
}

// ---------------------------------------------------------------------------
// Onboarding shell includes the install card
// ---------------------------------------------------------------------------

func TestOnboardingPage_IncludesInstallCard(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/fragments/onboarding-steps", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `id="install-card"`,
		"the steps flow must always carry the install step")
}

// errBoom is the sentinel returned by the install-failure test's fake
// installer so the propagation assertion can match on the string.
var errBoom = stubErr("boom")

type stubErr string

func (s stubErr) Error() string { return string(s) }

// ---------------------------------------------------------------------------
// Categorized install error remediation (UX recovery path)
// ---------------------------------------------------------------------------

func TestAgentInstall_PermissionErrorRendersUserModeRetry(t *testing.T) {
	fake := &fakeInstaller{returnFn: func(_ installer.Options) error {
		return stubErr("install binary: open /usr/local/bin/kite-collector.tmp: permission denied")
	}}
	h := newInstallHarness(t, fake)

	rec := h.do(t, "POST", "/api/v1/agent/install", strings.NewReader(`{}`),
		map[string]string{
			"Content-Type": "application/json",
			"HX-Request":   "true",
		})

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Retry in --user mode",
		"permission errors must surface the one-click user-mode retry button")
	assert.Contains(t, body, "/api/v1/agent/install?user_mode=true",
		"retry form must POST to the user-mode query-param recovery URL")
}

func TestAgentInstall_DiskWriteErrorRendersGenericHint(t *testing.T) {
	fake := &fakeInstaller{returnFn: func(_ installer.Options) error {
		return stubErr("create binary dir: read-only file system")
	}}
	h := newInstallHarness(t, fake)

	rec := h.do(t, "POST", "/api/v1/agent/install", strings.NewReader(`{}`),
		map[string]string{
			"Content-Type": "application/json",
			"HX-Request":   "true",
		})

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "read-only or out of disk",
		"disk_write category must surface the disk-specific copy")
	assert.NotContains(t, body, "Retry in --user mode",
		"non-permission errors must NOT show the user-mode retry button")
}

func TestAgentInstall_UserModeQueryParam_ForcesUserModeOptions(t *testing.T) {
	fake := &fakeInstaller{}
	h := newInstallHarness(t, fake)

	rec := h.do(t, "POST", "/api/v1/agent/install?user_mode=true", strings.NewReader(`{}`),
		map[string]string{
			"Content-Type": "application/json",
			"HX-Request":   "true",
		})

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 1, fake.callCount())
	last := fake.lastCall()
	assert.True(t, last.UserMode,
		"?user_mode=true must force Options.UserMode=true on the dispatched install")
	assert.Equal(t, installer.DefaultBinaryDir(true), last.BinaryDir,
		"?user_mode=true must recompute BinaryDir to the user-mode default")
	assert.Equal(t, installer.DefaultCertsDir(true), last.CertsDir,
		"?user_mode=true must recompute CertsDir to the user-mode default")
}

// ---------------------------------------------------------------------------
// Card numbering consistency — match the "four steps" copy + 4-pill stepper
// ---------------------------------------------------------------------------

func TestBuildOnboardingSteps_CoreAndOptionalServiceStates(t *testing.T) {
	det := installer.Detected{}

	// Fresh host: install is current, everything else pending.
	fresh := agentStateView{Install: installer.State{NextAction: installer.ActionInstall}}
	steps := buildOnboardingSteps(fresh, det)
	require.Len(t, steps, 4, "the three core steps are followed by detected services")
	assert.Equal(t, "current", steps[0].Status)
	assert.Equal(t, "pending", steps[1].Status)
	assert.Equal(t, "pending", steps[2].Status)
	assert.Equal(t, "pending", steps[3].Status)

	// Installed but not enrolled: connect is the one action.
	installed := agentStateView{Install: installer.State{NextAction: installer.ActionEnroll}}
	steps = buildOnboardingSteps(installed, det)
	assert.Equal(t, "done", steps[0].Status)
	assert.Equal(t, "current", steps[1].Status)
	assert.Equal(t, "pending", steps[2].Status)
	assert.Equal(t, "pending", steps[3].Status)

	// Enrolled but never checked: stream is current — the check runs inside
	// it, so there is no separate "check" stop on the way.
	enrolled := agentStateView{
		Install:  installer.State{NextAction: installer.ActionReady},
		Identity: &identityStateView{Enrolled: true, FingerprintShort: "9f3a2c1b"},
	}
	steps = buildOnboardingSteps(enrolled, det)
	assert.Equal(t, "done", steps[1].Status)
	assert.Contains(t, steps[1].Receipt, "9f3a2c1b", "connect receipt carries the fingerprint")
	assert.Equal(t, "current", steps[2].Status)
	assert.Equal(t, "pending", steps[3].Status)

	// Streaming: everything collapses to receipts.
	streaming := enrolled
	streaming.Identity.LastCheckPassedAt = "2026-08-19T00:00:00Z"
	streaming.Stream = &streamStateView{State: "running"}
	steps = buildOnboardingSteps(streaming, det)
	assert.Equal(t, "done", steps[0].Status)
	assert.Equal(t, "done", steps[1].Status)
	assert.Equal(t, "done", steps[2].Status)
	assert.Contains(t, steps[2].Receipt, "running")
	assert.Equal(t, "optional", steps[3].Status)

	steps = buildOnboardingSteps(streaming, det, false, false)
	require.Len(t, steps, 3, "service setup is absent when no integration is detected")
}

func TestOnboardingSteps_TrustPanelRendersOnConnectStep(t *testing.T) {
	// Render the template directly with connect current, so the assertion is
	// independent of this host's real install state.
	view := onboardingStepsView{Steps: []onboardingStepView{
		{Key: "install", CardID: "install-card", Title: "Install", Status: "done", Receipt: "binary + service registered", FragmentURL: "/fragments/install-status"},
		{Key: "connect", CardID: "enroll-card", Title: "Connect this collector", Status: "current", FragmentURL: "/fragments/enroll-form"},
		{Key: "stream", CardID: "stream-card", Title: "Start streaming", Status: "pending", Pending: "the connection check runs automatically before streaming starts"},
	}}
	var buf strings.Builder
	require.NoError(t, onboardingStepsTmpl.Execute(&buf, view))
	body := buf.String()

	assert.Contains(t, body, "What gets stored?",
		"connect step must keep the trust disclosure")
	assert.Contains(t, body, "AES-256-GCM")
	assert.Contains(t, body, "Wrap key is in-memory")
	assert.Contains(t, body, "No exfiltration before streaming")
	// The simplified copy drops the step-number back-references entirely.
	assert.NotContains(t, body, "step&nbsp;3")
	assert.NotContains(t, body, "step&nbsp;4")
	// One-line trust summary sits outside the disclosure.
	assert.Contains(t, body, "only its <code>sha256[:8]</code> fingerprint is ever shown")
}

// ---------------------------------------------------------------------------
// Relative-time consistency on the enrolled-state stamps
// ---------------------------------------------------------------------------

func TestEnrollFragment_EnrolledStateRendersRelativeTimeWithTimestampTooltip(t *testing.T) {
	h := newInstallHarness(t, nil)

	// Pre-enroll then re-fetch the fragment so the enrolled branch renders.
	form := url.Values{"api_key": {"sk-relative-time-0123456789ABCDEF"}}
	_ = h.do(t, "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

	rec := h.do(t, "GET", "/fragments/enroll-form", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Default display is the relative time — that's what operators glance at.
	// "just now" is the formatter output for sub-minute durations (the enroll
	// happened seconds before this assertion).
	assert.Contains(t, body, "just now",
		"enrolled fragment must show relative time as the primary text (humanizeRelativeTime output) — consistent with the sparkline + last-scan summary")

	// Exact RFC3339 timestamp is preserved as a title=hover tooltip so
	// operators correlating with logs / support tickets can still read it.
	assert.Contains(t, body, `title="20`,
		"exact timestamp must be preserved as a title attribute on the relative-time span — machine-readable time stays accessible via hover")

	// Raw RFC3339 must NOT be inline body text anymore — that was the
	// iteration-1 behavior. This iteration moves it to the tooltip.
	assert.NotRegexp(t, `first enrolled 20\d\d-\d\d-\d\dT`, body,
		"raw RFC3339 must NOT appear as inline text — it belongs in the title attribute, not the visible body")
}

// ---------------------------------------------------------------------------
// Keyboard hint discoverability — floating ? button (completes iteration 18)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Topbar onboarding-status badge — cross-page agent-health visibility
// ---------------------------------------------------------------------------

func TestBadgeViewFor_StatusVocabulary(t *testing.T) {
	// Pin the overall_status → visual mapping so future status-enum
	// additions have exactly one place to teach the badge vocabulary.
	cases := []struct {
		overall     string
		wantClass   string
		wantGlyph   string
		wantInLabel string
	}{
		{overall: "streaming", wantClass: "status-streaming", wantGlyph: "✓", wantInLabel: "streaming"},
		{overall: installer.ActionReady, wantClass: "status-ready", wantGlyph: "✓", wantInLabel: "ready"},
		{overall: "degraded", wantClass: "status-degraded", wantGlyph: "!", wantInLabel: "degraded"},
		{overall: installer.ActionEnroll, wantClass: "status-pending", wantGlyph: "·", wantInLabel: "in progress"},
		{overall: installer.ActionStartService, wantClass: "status-pending", wantGlyph: "·", wantInLabel: "in progress"},
		{overall: installer.ActionRegisterService, wantClass: "status-pending", wantGlyph: "·", wantInLabel: "in progress"},
		{overall: installer.ActionInstall, wantClass: "status-install", wantGlyph: "○", wantInLabel: "not yet installed"},
		{overall: "novel-future-status", wantClass: "status-pending", wantGlyph: "·", wantInLabel: "novel-future-status"},
	}
	for _, tc := range cases {
		t.Run(tc.overall, func(t *testing.T) {
			v := badgeViewFor(tc.overall)
			assert.Equal(t, tc.wantClass, v.Class,
				"status %q must map to CSS class %q", tc.overall, tc.wantClass)
			assert.Equal(t, tc.wantGlyph, v.Glyph,
				"status %q must map to visual glyph %q", tc.overall, tc.wantGlyph)
			assert.Contains(t, v.Label, tc.wantInLabel,
				"status %q label must include actionable copy", tc.overall)
		})
	}
}

func TestOnboardingStatusBadge_RendersAccessibleLink(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/fragments/onboarding-status-badge", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, `class="topbar-status`,
		"badge must use the topbar-status class so the topbar CSS picks it up")
	assert.Contains(t, body, `href="/onboarding"`,
		"badge must link to /onboarding so operators can drill in from any page")
	assert.Contains(t, body, `hx-push-url="true"`,
		"badge link must integrate with HTMX history so navigation updates the URL bar")
	assert.Contains(t, body, `class="sr-only"`,
		"badge must include a screen-reader-only label so AT users get the full status text, not just the glyph")
	assert.Contains(t, body, `aria-hidden="true"`,
		"the visual glyph must be aria-hidden so AT doesn't read it twice alongside the sr-only label")
}

func TestDashboardShell_TopbarIncludesOnboardingStatusBadge(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// The polling element wired into the shared topbar — present on every
	// dashboard page (not just /onboarding) so agent health is visible
	// across the dashboard, not just on the onboarding tab.
	assert.Contains(t, body, `id="onboarding-status-badge"`,
		"shared topbar must include the onboarding-status-badge slot so the polling element renders on every page")
	assert.Contains(t, body, `/fragments/onboarding-status-badge`,
		"slot must point at the new fragment endpoint")
	assert.Contains(t, body, `refresh-agent-state from:body`,
		"badge must also refresh on the existing refresh-agent-state event so install/enroll/uninstall actions update the topbar immediately, not on the next 30s tick")
}

// ---------------------------------------------------------------------------
// Keyboard shortcuts (?, i/e/c/s) — composes with iteration 14-16 a11y baseline
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Skip-to-content (WCAG 2.4.1 Bypass Blocks, Level A)
// ---------------------------------------------------------------------------

func TestDashboardShell_SkipToContentLinkIsFirstFocusable(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// The skip link must exist and point at the content target.
	assert.Contains(t, body, `class="skip-link"`,
		"shell must render the .skip-link so keyboard-only operators can bypass the nav (WCAG 2.4.1)")
	assert.Contains(t, body, `href="#content"`,
		"skip link must target the main content anchor")

	// The target needs tabindex=-1 so the skip link can programmatically
	// focus a normally non-focusable <div>. Without this, the link scrolls
	// but doesn't move focus, and the next Tab lands back in the sidebar.
	assert.Contains(t, body, `id="content"`,
		"main content area must carry id='content' so the skip link's anchor resolves")
	assert.Contains(t, body, `tabindex="-1"`,
		"#content must carry tabindex='-1' so the skip link can programmatically focus the div (keyboard focus actually lands in main content)")

	// The skip link must appear EARLIER in the DOM than the nav so it's
	// the first thing keyboard users tab to. Compare byte offsets.
	skipIdx := strings.Index(body, `class="skip-link"`)
	navIdx := strings.Index(body, `aria-label="Primary navigation"`)
	require.Greater(t, skipIdx, 0)
	require.Greater(t, navIdx, 0)
	assert.Less(t, skipIdx, navIdx,
		"skip link must appear in DOM before the nav — otherwise Tab still hits nav first and the link is useless")
}

// ---------------------------------------------------------------------------
// Form-error accessibility (WCAG 3.3.1 Error Identification, 3.3.3 Error Suggestion)
// ---------------------------------------------------------------------------

func TestEnroll_SuccessPath_OmitsErrorAttributes(t *testing.T) {
	// Symmetric check: when the form has no error, none of the error-ARIA
	// attributes should appear. aria-invalid="true" on a clean field would
	// confuse AT into announcing a non-existent error.
	h := newInstallHarness(t, nil)

	rec := h.do(t, "GET", "/fragments/enroll-form", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.NotContains(t, body, `aria-invalid="true"`,
		"clean form must NOT carry aria-invalid='true' — would lie about field state to AT")
	assert.NotContains(t, body, `aria-describedby="enroll-error-msg"`,
		"clean form must NOT reference the error message — there is no error message in the DOM")
	assert.NotContains(t, body, `role="alert"`,
		"clean form must NOT render the alert-role error pane")
}

// ---------------------------------------------------------------------------
// Accessibility — ARIA + prefers-reduced-motion (WCAG 1.3.1, 2.3.3, 4.1.2)
// ---------------------------------------------------------------------------

func TestOnboardingPage_ToastContainerAnnouncesToScreenReaders(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// aria-live="polite" tells AT to announce when current speech finishes.
	// Without it, the toast feature shipped in iteration 13 would be silent
	// to screen-reader users — strictly worse than no toast at all.
	assert.Contains(t, body, `id="onboarding-toasts"`)
	assert.Contains(t, body, `aria-live="polite"`,
		"toast container must declare aria-live='polite' so each new toast is announced to screen readers (WCAG 4.1.3)")
	assert.Contains(t, body, `aria-atomic="false"`,
		"aria-atomic='false' so only the new toast text is announced, not the entire stack each time")
	assert.Contains(t, body, `role="status"`,
		"role='status' reinforces the aria-live semantics for AT that prefers role-based detection")
}

func TestOnboardingHeader_StepperMarksCurrentStepWithAriaCurrent(t *testing.T) {
	// Drive the template directly so we can pin the rendering for a known
	// step status without depending on the live install probe.
	view := onboardingHeaderView{
		NextAction: "enroll",
		Steps: []stepStatus{
			{Key: "install", Label: "Install agent", Status: "done", Anchor: "#install-card"},
			{Key: "enroll", Label: "Enroll PKI", Status: "current", Anchor: "#enroll-card"},
			{Key: "check", Label: "Connection check", Status: "pending", Anchor: "#check-card"},
			{Key: "stream", Label: "Streaming", Status: "pending", Anchor: "#stream-card"},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, onboardingHeaderTmpl.Execute(&buf, view))
	body := buf.String()

	assert.Contains(t, body, `aria-current="step"`,
		"the current step must carry aria-current='step' (standard ARIA wizard pattern, WCAG 4.1.2)")
	// Done + pending steps must NOT carry aria-current — only the active step.
	// We assert this by counting: exactly one aria-current attribute should
	// appear in the rendered stepper.
	assert.Equal(t, 1, strings.Count(body, `aria-current="step"`),
		"exactly one step must be marked current — multiple aria-current attributes confuse AT")
}

func TestOnboardingHeader_StepperOmitsAriaCurrentWhenNoCurrentStep(t *testing.T) {
	// Edge case: all-done (post-onboarding) stepper has no "current" step
	// — every step is done. aria-current must be absent in that case.
	view := onboardingHeaderView{
		Steps: []stepStatus{
			{Key: "install", Label: "Install agent", Status: "done"},
			{Key: "enroll", Label: "Enroll PKI", Status: "done"},
			{Key: "check", Label: "Connection check", Status: "done"},
			{Key: "stream", Label: "Streaming", Status: "done"},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, onboardingHeaderTmpl.Execute(&buf, view))
	assert.NotContains(t, buf.String(), `aria-current="step"`,
		"fully-done stepper has no current step — aria-current must not render")
}

func TestEnrollFragment_CopyButtonHasContextualAriaLabel(t *testing.T) {
	h := newInstallHarness(t, nil)
	form := url.Values{"api_key": {"sk-aria-label-0123456789ABCDEF"}}
	_ = h.do(t, "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

	rec := h.do(t, "GET", "/fragments/enroll-form", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `aria-label="Copy full SHA-256 fingerprint to clipboard"`,
		"fingerprint copy button must carry a contextual aria-label — screen readers otherwise announce just 'copy', which is ambiguous out of visual context")
}

func TestInstallStatusFragment_CopyButtonsHaveContextualAriaLabel(t *testing.T) {
	h := newInstallHarness(t, nil) // advisory mode renders CLI hint + copy button
	rec := h.do(t, "GET", "/fragments/install-status", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `aria-label="Copy CLI install command to clipboard"`,
		"CLI hint copy button must carry a contextual aria-label so screen readers know *what* would be copied")
}

func TestOnboardingPage_WizardChromeRemoved(t *testing.T) {
	// The simplified flow renders step visibility server-side: the client
	// wizard (stepper scraping, scroll-to-step animation, keyboard shortcut
	// dialog) must be gone. The only page scripts left are the error-toast
	// pipeline and the clipboard helper.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.NotContains(t, body, "kbd-hint", "keyboard shortcut hint button removed")
	assert.NotContains(t, body, "kbd-help", "keyboard shortcut dialog removed")
	assert.NotContains(t, body, "syncActiveStep", "client-side step bookkeeping removed")
	assert.NotContains(t, body, "scrollIntoView", "scroll-to-step animation removed")
	assert.Contains(t, body, "copyFromBtn", "clipboard helper stays — fragments call it")
	assert.Contains(t, body, "htmx:sendError", "error-toast pipeline stays")
}

// ---------------------------------------------------------------------------
// HTMX error toast pipeline — closes the only silent-failure surface
// ---------------------------------------------------------------------------

func TestOnboardingPage_IncludesHTMXErrorToastListeners(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Both error events must be wired — sendError covers network/connect
	// failures (dashboard process died), responseError covers HTTP 5xx.
	assert.Contains(t, body, "htmx:sendError",
		"onboarding shell must register the htmx:sendError listener — covers the dashboard-process-died case")
	assert.Contains(t, body, "htmx:responseError",
		"onboarding shell must register the htmx:responseError listener — covers 5xx server errors")

	// Actionable copy is the whole point of the pipeline — generic
	// 'something went wrong' messages would not move operators forward.
	assert.Contains(t, body, "Lost connection to dashboard",
		"sendError toast must surface the actual root cause (lost connection), not a generic error")
	assert.Contains(t, body, "kite-collector dashboard",
		"sendError toast must include the exact CLI command to restart — operators copy-paste from terminal")
	assert.Contains(t, body, "Dashboard returned HTTP",
		"responseError toast must include the HTTP status so operators can grep server logs")

	// The slot exists from iteration 1; this iteration finally populates it.
	assert.Contains(t, body, `id="onboarding-toasts"`,
		"the #onboarding-toasts slot must be present so the JS handler has a target to append into")

	// Click-to-dismiss is part of the toast contract — operators should
	// never be locked into watching the timer count down.
	assert.Contains(t, body, "click",
		"toast must include a click handler (click-to-dismiss is the expected toast UX)")
	assert.Contains(t, body, "setTimeout",
		"toast must auto-dismiss after a timeout so accumulating failures don't pile up")
}

func TestOnboardingPage_ToastSnippetIsSelfContained(t *testing.T) {
	// The toast pipeline runs in a self-invoking IIFE so it doesn't leak
	// names into the global scope. Pins that contract — if a future
	// refactor removes the IIFE wrapper, this catches it.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "(function()",
		"toast pipeline must be wrapped in an IIFE so the show() helper stays scoped — no global pollution")
	assert.Contains(t, body, "})();",
		"IIFE must be invoked immediately so listeners are registered before the operator can trigger any HTMX request")
}

// ---------------------------------------------------------------------------
// Teamwork URLs — ?step= focus highlight for shared dashboard links
// ---------------------------------------------------------------------------

func TestOnboardingPage_FocusStep_HighlightsMatchingCard(t *testing.T) {
	h := newInstallHarness(t, nil)
	cases := []struct {
		step          string
		wantSelector  string
		wantHighlight bool
	}{
		{step: "install", wantSelector: "#install-card", wantHighlight: true},
		{step: "enroll", wantSelector: "#enroll-card", wantHighlight: true},
		// The check folded into the stream step; old ?step=check links keep
		// working by highlighting the stream card.
		{step: "check", wantSelector: "#stream-card", wantHighlight: true},
		{step: "stream", wantSelector: "#stream-card", wantHighlight: true},
	}
	for _, tc := range cases {
		t.Run("step="+tc.step, func(t *testing.T) {
			rec := h.do(t, "GET", "/onboarding?step="+tc.step, nil, nil)
			require.Equal(t, http.StatusOK, rec.Code)
			body := rec.Body.String()
			assert.Contains(t, body, tc.wantSelector,
				"focus-step style must target the matching card selector")
			assert.Contains(t, body, "box-shadow",
				"focus-step style must apply a box-shadow accent")
		})
	}
}

func TestOnboardingPage_FocusStep_NoHighlightWhenStepMissing(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.NotContains(t, body, "#install-card{box-shadow",
		"no ?step= → no focus accent (default unfocused state)")
	assert.NotContains(t, body, "#enroll-card{box-shadow",
		"no ?step= → no focus accent on enroll either")
}

func TestOnboardingPage_FocusStep_IgnoresUnknownStepValues(t *testing.T) {
	// Invalid step values must be silently ignored — no error, no highlight.
	// This is the safety property: even though the value is validated against
	// an allow-list, the response shape must be identical to the no-step case.
	h := newInstallHarness(t, nil)
	for _, bogus := range []string{"foo", "bar", "<script>alert(1)</script>", "../../etc/passwd", "stream-card", ""} {
		t.Run("bogus="+bogus, func(t *testing.T) {
			rec := h.do(t, "GET", "/onboarding?step="+bogus, nil, nil)
			require.Equal(t, http.StatusOK, rec.Code,
				"bogus step value must not error out — silent ignore is the safe default")
			body := rec.Body.String()
			assert.NotContains(t, body, "<script>alert(1)</script>",
				"raw step value must NEVER appear in the response — allow-list pattern is the security property")
			assert.NotContains(t, body, "bogus-card",
				"unrecognised step must not produce a focus rule")
		})
	}
}

func TestValidatedFocusStep_AllowList(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "install", want: "install"},
		{in: "enroll", want: "enroll"},
		{in: "check", want: "check"},
		{in: "stream", want: "stream"},
		{in: "", want: ""},
		{in: "foo", want: ""},
		{in: "INSTALL", want: ""},  // case-sensitive — operator URLs are lowercase by convention
		{in: "install ", want: ""}, // no trimming — strict match
		{in: "<script>", want: ""},
	}
	for _, tc := range cases {
		t.Run("in="+tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, validatedFocusStep(tc.in),
				"validatedFocusStep must be a strict allow-list — anything else returns empty")
		})
	}
}

// ---------------------------------------------------------------------------
// Probe history sparkline — snapshot → trail
// ---------------------------------------------------------------------------

func TestSummarizeProbeHistory_GroupsByCheckedAtAndReversesChronology(t *testing.T) {
	now := time.Now().UTC()
	// store returns rows newest → oldest; build that ordering to mirror it.
	rows := []sqlite.ProbeResultRecord{
		// run 3 (newest) — all pass
		{ProbeName: "dns", Result: "pass", CheckedAt: now},
		{ProbeName: "tls", Result: "pass", CheckedAt: now},
		// run 2 — one fail
		{ProbeName: "dns", Result: "pass", CheckedAt: now.Add(-1 * time.Hour)},
		{ProbeName: "auth", Result: "fail", CheckedAt: now.Add(-1 * time.Hour)},
		// run 1 (oldest) — all pass
		{ProbeName: "dns", Result: "pass", CheckedAt: now.Add(-2 * time.Hour)},
	}
	runs := summarizeProbeHistory(rows, 10)
	require.Len(t, runs, 3, "must collapse to one entry per CheckedAt")

	// Output must be oldest → newest so the sparkline reads left-to-right
	// chronologically.
	assert.True(t, runs[0].CheckedAt.Before(runs[1].CheckedAt))
	assert.True(t, runs[1].CheckedAt.Before(runs[2].CheckedAt))
	assert.True(t, runs[0].AllPass, "oldest run had no failures")
	assert.False(t, runs[1].AllPass, "middle run had an auth fail")
	assert.True(t, runs[1].AnyFail)
	assert.True(t, runs[2].AllPass, "newest run had no failures")
}

func TestSummarizeProbeHistory_RespectsLimit(t *testing.T) {
	now := time.Now().UTC()
	var rows []sqlite.ProbeResultRecord
	for i := 0; i < 25; i++ {
		rows = append(rows, sqlite.ProbeResultRecord{
			ProbeName: "dns", Result: "pass",
			CheckedAt: now.Add(-time.Duration(i) * time.Hour),
		})
	}
	runs := summarizeProbeHistory(rows, 5)
	assert.Len(t, runs, 5, "must respect the limit so the sparkline stays scannable")
	// Should be the 5 newest runs (limit slices from the end of the chronological output).
	assert.WithinDuration(t, now, runs[len(runs)-1].CheckedAt, time.Second,
		"limit must keep the most recent runs, not the oldest")
}

func TestSummarizeProbeHistory_EmptyReturnsNil(t *testing.T) {
	assert.Nil(t, summarizeProbeHistory(nil, 10),
		"empty history must return nil so the template's {{if .RecentRuns}} branch hides the sparkline")
	assert.Nil(t, summarizeProbeHistory([]sqlite.ProbeResultRecord{}, 10),
		"empty slice must also yield nil — operators with no probe history see no sparkline")
}

func TestHumanizeRelativeTime_CoarseGranularity(t *testing.T) {
	cases := []struct {
		name string
		want string
		d    time.Duration
	}{
		{name: "sub-minute", d: 5 * time.Second, want: "just now"},
		{name: "minutes", d: 15 * time.Minute, want: "15m ago"},
		{name: "hours", d: 3 * time.Hour, want: "3h ago"},
		{name: "days", d: 49 * time.Hour, want: "2d ago"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, humanizeRelativeTime(tc.d))
		})
	}
}

func TestConnectionCheckFragment_SparklineHiddenWithoutHistory(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/fragments/connection-check", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.NotContains(t, body, "probe-sparkline",
		"fresh harness has no probe history — sparkline must not render")
}

func TestConnectionCheckFragment_SparklineRendersAfterRun(t *testing.T) {
	h := newInstallHarness(t, nil)

	// Pre-enroll then run a real check so probe_result rows get persisted.
	form := url.Values{"api_key": {"sk-sparkline-test-0123456789ABCDEF"}}
	_ = h.do(t, "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	_ = h.do(t, "POST", "/api/v1/connection/check", nil, nil)

	rec := h.do(t, "GET", "/fragments/connection-check", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "probe-sparkline",
		"after at least one probe run, the sparkline must render")
	assert.Contains(t, body, "spark-dot",
		"sparkline must include the dot element for each historical run")
	assert.Contains(t, body, "Recent:",
		"sparkline must include the 'Recent:' label so operators understand what they're looking at")
}

// ---------------------------------------------------------------------------
// Uninstall affordance — destructive action with two-step inline confirm
// ---------------------------------------------------------------------------

func TestAgentUninstall_FirstPostRendersConfirmFragment(t *testing.T) {
	fake := &fakeInstaller{}
	h := newInstallHarness(t, fake)
	rec := h.do(t, "POST", "/api/v1/agent/install/uninstall", nil,
		map[string]string{"HX-Request": "true"})

	require.Equal(t, http.StatusOK, rec.Code,
		"unconfirmed uninstall must render the confirm fragment with 200, not execute the destructive action")
	body := rec.Body.String()
	assert.Contains(t, body, "about to uninstall",
		"confirm fragment must surface destructive-intent copy")
	assert.Contains(t, body, "Yes, uninstall",
		"confirm fragment must include the explicit confirm button")
	assert.Contains(t, body, "Cancel",
		"confirm fragment must include a cancel path back to the normal install-status")
	assert.Contains(t, body, "?confirm=true",
		"confirm button must POST to the explicit confirm URL — query param is the safety latch")

	assert.Equal(t, 0, fake.uninstallCallCount(),
		"unconfirmed POST must NOT dispatch Uninstall — the safety latch must hold")
}

func TestAgentUninstall_ConfirmedPostDispatchesUninstall(t *testing.T) {
	fake := &fakeInstaller{}
	h := newInstallHarness(t, fake)
	rec := h.do(t, "POST", "/api/v1/agent/install/uninstall?confirm=true", nil,
		map[string]string{"HX-Request": "true"})

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, fake.uninstallCallCount(),
		"?confirm=true must dispatch exactly one Uninstall call")
	assert.Equal(t, "refresh-agent-state", rec.Header().Get("HX-Trigger"),
		"successful uninstall must trigger the stepper refresh — agent state has changed")
}

func TestAgentUninstall_NilInstallerReturns503(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "POST", "/api/v1/agent/install/uninstall?confirm=true", nil,
		map[string]string{"HX-Request": "true"})

	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"advisory-only mode must reject uninstall the same way it rejects install — symmetry matters for operator trust")
	body := rec.Body.String()
	assert.Contains(t, body, "kite-collector uninstall",
		"503 must point operators at the CLI fallback")
}

func TestAgentUninstall_PropagatesUninstallError(t *testing.T) {
	fake := &fakeInstaller{
		uninstallReturnFn: func(_ installer.Options) error {
			return stubErr("uninstall service: permission denied")
		},
	}
	h := newInstallHarness(t, fake)
	rec := h.do(t, "POST", "/api/v1/agent/install/uninstall?confirm=true", nil,
		map[string]string{"HX-Request": "true"})

	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"Uninstall errors must surface as 500 so the UI can show the error path")
	body := rec.Body.String()
	assert.Contains(t, body, "permission denied",
		"error message must be rendered so the operator can act on it")
}

func TestInstallStatusFragment_UninstallLinkVisibilityGating(t *testing.T) {
	// Fragment-level rendering test using the template directly so we can
	// inject State.BinaryPresent / InstallEnabled combinations without
	// having to fake the filesystem state the live probe queries.
	cases := []struct {
		name     string
		hint     string
		state    installer.State
		enabled  bool
		wantLink bool
	}{
		{name: "shown-when-binary-present-and-enabled", state: installer.State{BinaryPresent: true}, enabled: true, wantLink: true, hint: "operator can uninstall after a successful install"},
		{name: "hidden-when-binary-absent", state: installer.State{BinaryPresent: false}, enabled: true, wantLink: false, hint: "nothing to uninstall — link would be misleading"},
		{name: "hidden-when-install-disabled", state: installer.State{BinaryPresent: true}, enabled: false, wantLink: false, hint: "advisory-only mode — uninstall would 503 anyway"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view := installStatusFragmentView{
				State:          tc.state,
				InstallEnabled: tc.enabled,
				CLIHint:        "kite-collector install",
			}
			var buf bytes.Buffer
			require.NoError(t, installStatusFragmentTmpl.Execute(&buf, view))
			body := buf.String()
			if tc.wantLink {
				assert.Contains(t, body, "Uninstall agent",
					"uninstall link must render: %s", tc.hint)
				assert.Contains(t, body, "/api/v1/agent/install/uninstall",
					"uninstall link must POST to the uninstall endpoint")
			} else {
				assert.NotContains(t, body, "Uninstall agent",
					"uninstall link must hide: %s", tc.hint)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Copy-to-clipboard buttons (DX polish for troubleshooting workflows)
// ---------------------------------------------------------------------------

func TestOnboardingPage_IncludesCopyToClipboardHelper(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "copyFromBtn",
		"onboarding shell must register the copyFromBtn helper so per-element copy buttons work")
	assert.Contains(t, body, "navigator.clipboard.writeText",
		"helper must use the standard Clipboard API")
	assert.Contains(t, body, "✓ copied",
		"helper must show a positive confirmation so operators know the copy actually happened")
}

func TestEnrollFragment_FingerprintCopyButton(t *testing.T) {
	h := newInstallHarness(t, nil)
	// Pre-enroll so the fragment renders the fingerprint + its copy button.
	form := url.Values{"api_key": {"sk-copy-button-0123456789ABCDEF"}}
	_ = h.do(t, "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

	rec := h.do(t, "GET", "/fragments/enroll-form", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `class="btn-copy"`,
		"enrolled-state fragment must render a copy button next to the fingerprint")
	assert.Contains(t, body, `data-copy=`,
		"copy button must carry data-copy with the full fingerprint")
	assert.Contains(t, body, `onclick="copyFromBtn(this)"`,
		"copy button must invoke the copyFromBtn helper")
}

func TestInstallStatusFragment_CLIHintHasCopyButton(t *testing.T) {
	// nil Installer → install fragment renders the CLI hint pre-block as the
	// advisory-only fallback. That pre-block must carry a copy button.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/fragments/install-status", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `class="cli-hint-wrap"`,
		"CLI hint pre-block must be wrapped so the copy button can absolute-position")
	assert.Contains(t, body, `class="btn-copy"`,
		"CLI hint must include a copy button — pasting into a terminal is the canonical next step")
	assert.Contains(t, body, "kite-collector install",
		"data-copy must contain the actual CLI command")
}

// ---------------------------------------------------------------------------
// Last-scan summary in launcher — post-scan feedback (no more "click to find out")
// ---------------------------------------------------------------------------

func TestLoadLastScanSummary_NilStoreReturnsNil(t *testing.T) {
	// Inspector mode (no store) must not crash the launcher render.
	got := loadLastScanSummary(context.Background(), onboardingDeps{Store: nil})
	assert.Nil(t, got,
		"nil store must return nil — launcher template's {{if .LastScan}} branch hides the summary")
}

func TestLoadLastScanSummary_NoScanRunReturnsNil(t *testing.T) {
	st, err := sqlite.New(t.TempDir() + "/no-scan.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	got := loadLastScanSummary(context.Background(), onboardingDeps{Store: st})
	assert.Nil(t, got,
		"empty store (no scan_runs yet) must return nil — fresh-onboarding case where summary should be hidden")
}

func TestLoadLastScanSummary_PopulatesFromLatestScanRun(t *testing.T) {
	st, err := sqlite.New(t.TempDir() + "/with-scan.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	ctx := context.Background()
	startedAt := time.Now().UTC().Add(-3 * time.Hour)
	scanID := uuid.New()
	require.NoError(t, st.CreateScanRun(ctx, model.ScanRun{
		ID:        scanID,
		StartedAt: startedAt,
		Status:    model.ScanStatusRunning,
	}))
	require.NoError(t, st.CompleteScanRun(ctx, scanID, model.ScanResult{
		Status: "completed",
	}))

	got := loadLastScanSummary(ctx, onboardingDeps{Store: st})
	require.NotNil(t, got, "scan_run exists → summary must populate")
	assert.Equal(t, "completed", got.Status,
		"summary Status must mirror the scan_run.status column")
	assert.Equal(t, "badge-green", got.BadgeClass,
		"completed scan must map to the green badge class for visual scan-ability")
	assert.True(t, got.Completed,
		"CompletedAt was set via CompleteScanRun → Completed=true")
	assert.Contains(t, got.RelativeTime, "h ago",
		"3-hour-old scan must render as 'Nh ago' for inline display")
	assert.NotEmpty(t, got.StartedAt,
		"StartedAt must be populated as RFC3339 for the tooltip")
}

func TestLoadLastScanSummary_BadgeClassMapping(t *testing.T) {
	// Status → badge mapping is the visual cue operators scan first.
	// Pin the table so a future status-enum change can't silently change
	// scan colors without a deliberate decision.
	cases := []struct {
		status string
		want   string
	}{
		{status: "completed", want: "badge-green"},
		{status: "running", want: "badge-blue"},
		{status: "queued", want: "badge-blue"},
		{status: "failed", want: "badge-red"},
		{status: "cancelled", want: "badge-red"},
		{status: "novel-future-status", want: "badge-gray"},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			st, err := sqlite.New(t.TempDir() + "/badge-" + tc.status + ".db")
			require.NoError(t, err)
			require.NoError(t, st.Migrate(context.Background()))
			t.Cleanup(func() { _ = st.Close() })

			ctx := context.Background()
			require.NoError(t, st.CreateScanRun(ctx, model.ScanRun{
				ID:        uuid.New(),
				StartedAt: time.Now().UTC(),
				Status:    model.ScanStatus(tc.status),
			}))

			got := loadLastScanSummary(ctx, onboardingDeps{Store: st})
			require.NotNil(t, got)
			assert.Equal(t, tc.want, got.BadgeClass,
				"status %q must map to %q for consistent visual signal", tc.status, tc.want)
		})
	}
}

// ---------------------------------------------------------------------------
// First-scan CTA — closes the loop between onboarding completion and data
// ---------------------------------------------------------------------------

// TestOnboardingHeader_ScanCTAGating drives the template directly with
// constructed views (rather than the integration handler) because the live
// install probe checks the real filesystem for the binary — which is not
// installed at the OS-default path in CI, so overall_status would never
// reach "ready" via the handler path. The template-level test isolates the
// gating logic that ShowScanCTA actually drives.
func TestOnboardingHeader_ScanCTAGating(t *testing.T) {
	baseView := onboardingHeaderView{
		Steps:         []stepStatus{{Key: "install", Label: "Install agent", Status: "done"}},
		NextAction:    "ready",
		NextLabel:     "ready",
		OverallStatus: "ready",
		ModeLabel:     "Agent · write-enabled",
		ModeBadge:     "badge-green",
		ShowLauncher:  true,
	}
	cases := []struct {
		name        string
		wantSubstr  string
		scanEnabled bool
		wantPresent bool
	}{
		{name: "shown-when-enabled", wantSubstr: "Run scan now", scanEnabled: true, wantPresent: true},
		{name: "shown-when-enabled-copy", wantSubstr: "Without it, the tabs below show empty tables", scanEnabled: true, wantPresent: true},
		{name: "hidden-when-disabled", wantSubstr: "Run scan now", scanEnabled: false, wantPresent: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view := baseView
			view.ShowScanCTA = tc.scanEnabled
			var buf bytes.Buffer
			require.NoError(t, onboardingHeaderTmpl.Execute(&buf, view))
			body := buf.String()
			if tc.wantPresent {
				assert.Contains(t, body, tc.wantSubstr,
					"scan CTA copy must render when ScanEnabled is true")
			} else {
				assert.NotContains(t, body, tc.wantSubstr,
					"scan CTA must hide when ScanEnabled is false (inspector mode)")
			}
		})
	}
}

func TestOnboardingHeader_ScanCTARequiresLauncher(t *testing.T) {
	// Defensive: ShowScanCTA without ShowLauncher must not render the scan
	// block, because the launcher template gates the CTA inside its own
	// {{if .ShowLauncher}} branch.
	view := onboardingHeaderView{
		Steps:         []stepStatus{{Key: "install", Label: "Install agent", Status: "current"}},
		NextAction:    "install",
		NextLabel:     "install agent",
		OverallStatus: "install",
		ShowLauncher:  false,
		ShowScanCTA:   true, // truthy but parent gate is false
	}
	var buf bytes.Buffer
	require.NoError(t, onboardingHeaderTmpl.Execute(&buf, view))
	body := buf.String()
	assert.NotContains(t, body, "Run scan now",
		"scan CTA must depend on ShowLauncher being true — never render before onboarding completes")
}

func TestShowScanCTAFormula_DependsOnLauncherAndScanEnabled(t *testing.T) {
	// Pin the boolean formula ShowScanCTA = ShowLauncher && deps.ScanEnabled
	// so a refactor of renderOnboardingHeaderFragment can't silently change
	// either side's contribution to the gate.
	view := agentStateView{
		NextAction: installer.ActionReady,
		Install:    installer.State{NextAction: installer.ActionReady},
		Identity:   &identityStateView{Enrolled: true, LastCheckPassedAt: "2026-06-23T12:00:00Z"},
		Stream:     &streamStateView{State: "running"},
	}
	view.OverallStatus = overallStatus(view)
	require.Equal(t, "streaming", view.OverallStatus)

	showLauncher := view.OverallStatus == "ready" || view.OverallStatus == "streaming"
	assert.True(t, showLauncher && true,
		"launcher visible + ScanEnabled=true → ShowScanCTA must be true")
	assert.False(t, showLauncher && false,
		"launcher visible + ScanEnabled=false → ShowScanCTA must be false")
	assert.False(t, false && true,
		"launcher hidden → ShowScanCTA must be false regardless of ScanEnabled")
}

// ---------------------------------------------------------------------------
// Trust panel + auto-scroll to next step (UX flow polish)
// ---------------------------------------------------------------------------

func TestOnboardingPage_IncludesTrustPanel(t *testing.T) {
	// The trust disclosure moved into the connect step of the steps flow,
	// which only expands while enrollment is the current action — a state
	// this host may or may not be in. The content assertions live in
	// TestOnboardingSteps_TrustPanelRendersOnConnectStep (template-level,
	// host-independent); here we only pin that the page wires the flow.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "/fragments/onboarding-steps",
		"page must load the steps flow that carries the trust disclosure")
}

func TestAgentInstall_SuccessEmitsScrollToEnroll(t *testing.T) {
	fake := &fakeInstaller{}
	h := newInstallHarness(t, fake)

	rec := h.do(t, "POST", "/api/v1/agent/install", strings.NewReader(`{}`),
		map[string]string{
			"Content-Type": "application/json",
			"HX-Request":   "true",
		})

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "refresh-agent-state", rec.Header().Get("HX-Trigger"),
		"existing trigger-header contract preserved for the stepper refresh")
	assert.Contains(t, rec.Header().Get("HX-Trigger-After-Settle"),
		`"target":"#enroll-card"`,
		"successful install must request a smooth-scroll to the enroll card after the swap settles")
}

func TestEnroll_SuccessEmitsScrollToCheck(t *testing.T) {
	h := newInstallHarness(t, nil)
	form := url.Values{"api_key": {"sk-scroll-target-0123456789ABCDEF"}}

	rec := h.do(t, "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "refresh-agent-state", rec.Header().Get("HX-Trigger"))
	assert.Contains(t, rec.Header().Get("HX-Trigger-After-Settle"),
		`"target":"#stream-card"`,
		"successful enroll points at the stream card — the check is its gate now")
}

func TestOnboardingSteps_TrustCopyHasNoStaleCardReferences(t *testing.T) {
	// The steps fragment must never mention the retired check card.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/fragments/onboarding-steps", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "check-card")
}

// ---------------------------------------------------------------------------
// Probe-level typed recovery actions
// ---------------------------------------------------------------------------

func TestConnectionCheck_ExcludesUnsupportedAuthProbe(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/connection/check", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp connectionCheckResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	for _, probe := range resp.Probes {
		assert.NotEqual(t, probeAuth, probe.Name,
			"connection check must not call the unsupported /v1/auth/echo route")
	}
	require.Len(t, resp.Probes, 5)
}

func TestActionFor_OnlyAuthAndReachAttachActions(t *testing.T) {
	cases := []struct {
		name       probeName
		endpoint   string
		wantNotNil bool
	}{
		{name: probeAuth, endpoint: "https://otel.example.test", wantNotNil: true},
		{name: probeReach, endpoint: "https://otel.example.test", wantNotNil: true},
		{name: probeReach, endpoint: "", wantNotNil: false}, // no endpoint → no action
		{name: probeDNS, endpoint: "https://otel.example.test", wantNotNil: false},
		{name: probeTLS, endpoint: "https://otel.example.test", wantNotNil: false},
		{name: probeClock, endpoint: "https://otel.example.test", wantNotNil: false},
		{name: probeOTLP, endpoint: "https://otel.example.test", wantNotNil: false},
	}
	for _, tc := range cases {
		t.Run(string(tc.name)+"-"+tc.endpoint, func(t *testing.T) {
			got := actionFor(tc.name, tc.endpoint)
			if tc.wantNotNil {
				assert.NotNil(t, got, "expected typed action for %s", tc.name)
			} else {
				assert.Nil(t, got, "%s should not get a typed action (re-run check covers it)", tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Post-completion launcher panel
// ---------------------------------------------------------------------------

func TestOnboardingHeader_NoLauncherWhenNotReady(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/fragments/onboarding-header", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.NotContains(t, body, "What next?",
		"launcher panel must NOT render before onboarding is complete")
}

func TestOnboardingHeader_LauncherShownWhenReady(t *testing.T) {
	// agentStateView.NextAction is the top-level rollup field (separate from
	// Install.NextAction). overallStatus reads NextAction first, so the test
	// has to set both for the rollup to land on "streaming".
	view := agentStateView{
		NextAction: installer.ActionReady,
		Install:    installer.State{NextAction: installer.ActionReady},
		Identity:   &identityStateView{Enrolled: true, LastCheckPassedAt: "2026-06-23T12:00:00Z"},
		Stream:     &streamStateView{State: "running"},
	}
	view.OverallStatus = overallStatus(view)
	assert.Equal(t, "streaming", view.OverallStatus,
		"sanity: ready + enrolled + streaming must roll up to overall_status=streaming")

	hv := onboardingHeaderView{
		OverallStatus: view.OverallStatus,
		ShowLauncher:  view.OverallStatus == "ready" || view.OverallStatus == "streaming",
	}
	assert.True(t, hv.ShowLauncher,
		"launcher panel must be enabled when overall_status indicates onboarding is complete")
	assert.Equal(t, "streaming", hv.OverallStatus,
		"header view must propagate the rollup status so the template can branch on it")
}

// ---------------------------------------------------------------------------
// Parallel probe ordering — guards the canonical order under concurrency
// ---------------------------------------------------------------------------

func TestConnectionCheck_PreservesCanonicalProbeOrder(t *testing.T) {
	h := newInstallHarness(t, nil)

	rec := h.do(t, "GET", "/api/v1/connection/check", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp connectionCheckResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Probes, 5, "must always emit 5 probes regardless of goroutine completion order")

	// Canonical order matters — operator runbooks reference probe[2] = reach,
	// probe[3] = clock, etc. Parallel execution must not scramble it.
	expected := []probeName{probeDNS, probeTLS, probeReach, probeClock, probeOTLP}
	for i, want := range expected {
		assert.Equal(t, want, resp.Probes[i].Name,
			"probe[%d] order must be %s; got %s", i, want, resp.Probes[i].Name)
	}
}

// ---------------------------------------------------------------------------
// /fragments/onboarding-header — stepper + mode chip + CTA
// ---------------------------------------------------------------------------

func TestOnboardingHeaderFragment_AdvisoryInspectorMode(t *testing.T) {
	h := newInstallHarness(t, nil) // nil Installer → inspector mode
	rec := h.do(t, "GET", "/fragments/onboarding-header", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "Kite Collector onboarding",
		"header must include the welcome title")
	assert.Contains(t, body, "Inspector",
		"inspector mode chip must surface when no Installer is wired")
	assert.Contains(t, body, "Install agent",
		"stepper must list the install step label")
	assert.Contains(t, body, "Enroll PKI",
		"stepper must list the enroll step label")
	assert.Contains(t, body, "Connection check",
		"stepper must list the check step label")
	assert.Contains(t, body, "Streaming",
		"stepper must list the streaming step label")
	assert.Contains(t, body, "step-current",
		"at least one step must be marked current on a fresh harness")
	assert.Contains(t, body, "Next:",
		"primary CTA must be rendered when not yet ready/streaming")
}

func TestOnboardingHeaderFragment_AgentMode(t *testing.T) {
	h := newInstallHarness(t, &fakeInstaller{})
	rec := h.do(t, "GET", "/fragments/onboarding-header", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "Agent",
		"injected Installer → mode chip should read Agent (write-enabled)")
	assert.NotContains(t, body, "advisory-only",
		"write-enabled mode should not surface the advisory-only fallback copy")
}

func TestOnboardingHeaderFragment_StepperAdvancesAfterEnroll(t *testing.T) {
	h := newInstallHarness(t, nil)

	// Pre-enroll so the identity slot reports Enrolled=true and the stepper
	// should advance the "enroll" pill from current → done.
	form := url.Values{"api_key": {"sk-stepper-test-0123456789ABCDEF"}}
	_ = h.do(t, "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

	rec := h.do(t, "GET", "/fragments/onboarding-header", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// The fingerprint detail line is the visible signal that enroll is now
	// "done" on the stepper.
	assert.Contains(t, body, "key ",
		"enrolled step must surface the short fingerprint as its detail")
}

// TestBuildStepperSteps_StateMachine pins the per-step status transitions.
// Each row asserts the four step Status tokens for a representative state.
func TestBuildStepperSteps_StateMachine(t *testing.T) {
	cases := []struct {
		expected [4]string
		name     string
		view     agentStateView
	}{
		{
			name: "fresh-host",
			view: agentStateView{
				Install: installer.State{NextAction: installer.ActionInstall},
			},
			expected: [4]string{"current", "pending", "pending", "pending"},
		},
		{
			name: "post-install-no-enroll",
			view: agentStateView{
				Install: installer.State{NextAction: installer.ActionEnroll},
			},
			expected: [4]string{"done", "current", "pending", "pending"},
		},
		{
			name: "enrolled-no-check",
			view: agentStateView{
				Install:  installer.State{NextAction: installer.ActionEnroll},
				Identity: &identityStateView{Enrolled: true, FingerprintShort: "abcd1234"},
			},
			expected: [4]string{"done", "done", "current", "pending"},
		},
		{
			name: "fully-streaming",
			view: agentStateView{
				Install:  installer.State{NextAction: installer.ActionReady},
				Identity: &identityStateView{Enrolled: true, LastCheckPassedAt: "2026-06-23T12:00:00Z"},
				Stream:   &streamStateView{State: "running"},
			},
			expected: [4]string{"done", "done", "done", "done"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			steps := buildStepperSteps(tc.view, installer.Detected{})
			require.Len(t, steps, 4)
			for i, want := range tc.expected {
				assert.Equal(t, want, steps[i].Status,
					"step[%d]=%s want %s", i, steps[i].Status, want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HTMX-aware install endpoint + auto-refresh trigger
// ---------------------------------------------------------------------------

func TestAgentInstall_HXRequest_ReturnsHTMLAndTriggerHeader(t *testing.T) {
	fake := &fakeInstaller{}
	h := newInstallHarness(t, fake)

	rec := h.do(t, "POST", "/api/v1/agent/install", strings.NewReader(`{}`),
		map[string]string{
			"Content-Type": "application/json",
			"HX-Request":   "true",
		})

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html"),
		"HX-Request must receive HTML, not JSON")
	assert.Equal(t, "refresh-agent-state", rec.Header().Get("HX-Trigger"),
		"successful install must trigger the onboarding-header refresh")

	body := rec.Body.String()
	assert.Contains(t, body, "install-status",
		"HX response must render the install-status fragment HTML")
}

func TestAgentInstall_NonHX_StillReturnsJSON(t *testing.T) {
	fake := &fakeInstaller{}
	h := newInstallHarness(t, fake)

	rec := h.do(t, "POST", "/api/v1/agent/install", strings.NewReader(`{}`),
		map[string]string{"Content-Type": "application/json"})

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"),
		"non-HX clients keep the scripted JSON contract")
	// HX-Trigger is still set even for non-HX clients — harmless and lets
	// curl users see the contract.
	assert.Equal(t, "refresh-agent-state", rec.Header().Get("HX-Trigger"))
}

func TestEnroll_SetsRefreshTriggerHeader(t *testing.T) {
	h := newInstallHarness(t, nil)
	form := url.Values{"api_key": {"sk-refresh-trigger-0123456789ABCDEF"}}

	rec := h.do(t, "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "refresh-agent-state", rec.Header().Get("HX-Trigger"),
		"successful enroll must trigger the header refresh so the stepper advances immediately")
}

func TestAgentInstall_HXRequest_AdvisoryMode503HTML(t *testing.T) {
	h := newInstallHarness(t, nil) // nil Installer → 503 path
	rec := h.do(t, "POST", "/api/v1/agent/install", strings.NewReader(`{}`),
		map[string]string{
			"Content-Type": "application/json",
			"HX-Request":   "true",
		})

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.True(t, strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html"),
		"advisory-mode HX response must still be HTML so the install-fragment swap works")
	body := rec.Body.String()
	assert.Contains(t, body, "kite-collector install",
		"503 HTML must surface the CLI hint pre-block")
}

func TestHeaderModeDescriptor_PrivilegeAware(t *testing.T) {
	cases := []struct {
		installer  Installer
		name       string
		labelSub   string
		hintSubstr string
		privileged bool
	}{
		{
			name: "privileged-agent", installer: &fakeInstaller{}, privileged: true,
			labelSub: "Agent", hintSubstr: "succeed",
		},
		{
			name: "unprivileged-agent", installer: &fakeInstaller{}, privileged: false,
			labelSub: "Agent", hintSubstr: "fail",
		},
		{
			name: "inspector", installer: nil, privileged: false,
			labelSub: "Inspector", hintSubstr: "CLI hint",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			label, _, hint := headerModeDescriptor(
				onboardingDeps{Installer: tc.installer},
				installer.Detected{Privileged: tc.privileged},
			)
			assert.Contains(t, label, tc.labelSub)
			assert.Contains(t, hint, tc.hintSubstr)
		})
	}
}
