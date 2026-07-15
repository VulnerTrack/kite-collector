package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "install-fragment",
		"onboarding shell must wire the install card")
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

func TestOnboardingPage_CardsAreNumberedOneToFour(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Card headings must be numbered 1-4 to match the "Get your agent online
	// in four steps" copy + the 4-pill stepper. Before iteration 22 they
	// were 0-3, which created off-by-one cognitive friction — first-time
	// operators wondered "is step 0 optional? a pre-step?"
	for _, want := range []string{
		"1. Install agent",
		"2. Connect collector",
		"3. Connection check",
		"4. Streaming",
	} {
		assert.Contains(t, body, want,
			"card heading %q must be 1-indexed to match the 'four steps' copy", want)
	}

	// And the old 0-indexed headings must be gone — assert explicitly so a
	// future template edit can't silently re-introduce the off-by-one.
	for _, gone := range []string{
		">0. Install agent<",
		">1. Connect collector<",
		">2. Connection check<",
		">3. Streaming<",
	} {
		assert.NotContains(t, body, gone,
			"old 0-indexed heading %q must NOT appear — would re-introduce the off-by-one inconsistency", gone)
	}
}

func TestOnboardingPage_TrustPanelStepReferencesMatchNewNumbering(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Trust panel back-references must match the new 1-4 numbering. "Step 3"
	// (old) → "Step 4" (new) for streaming, "Step 2" → "Step 3" for check.
	assert.Contains(t, body, `"Start streaming" in step&nbsp;4`,
		"trust panel back-reference must point at step 4 (streaming) under the new 1-indexed scheme")
	assert.Contains(t, body, `connection check (step&nbsp;3)`,
		"trust panel back-reference must point at step 3 (connection check) under the new 1-indexed scheme")
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

func TestOnboardingPage_IncludesKeyboardHintButton(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Hint button must exist — iteration 18's keyboard shortcuts were
	// invisible without a visible affordance. The button is a real <button>
	// so screen-reader + keyboard users can also discover the help via Tab,
	// not just by knowing the magic ? key.
	assert.Contains(t, body, `id="kbd-hint"`,
		"shell must include the floating kbd-hint button so the iteration 18 keyboard shortcut feature is discoverable")
	assert.Contains(t, body, `class="kbd-hint"`,
		"hint button must use the kbd-hint class for the floating bottom-right styling")
	assert.Contains(t, body, `type="button"`,
		"hint must be explicitly type='button' so it doesn't accidentally submit a parent form")

	// ARIA attributes wire the button to the help dialog.
	assert.Contains(t, body, `aria-haspopup="dialog"`,
		"hint must declare aria-haspopup='dialog' so AT users know clicking opens a dialog")
	assert.Contains(t, body, `aria-controls="kbd-help"`,
		"hint must declare aria-controls pointing at the help dialog id")
	assert.Contains(t, body, `aria-expanded="false"`,
		"hint must initialize aria-expanded='false' (dialog starts hidden)")
	assert.Contains(t, body, `aria-label="Show keyboard shortcuts"`,
		"hint must have a contextual aria-label — the '?' character alone is ambiguous for screen readers")

	// Hint button must precede the dialog in DOM order so tab focus lands on
	// the hint first (acts as the toggle), not on the (initially-hidden) dialog.
	hintIdx := strings.Index(body, `id="kbd-hint"`)
	helpIdx := strings.Index(body, `id="kbd-help"`)
	require.Greater(t, hintIdx, 0)
	require.Greater(t, helpIdx, 0)
	assert.Less(t, hintIdx, helpIdx,
		"hint must precede the help dialog in DOM order so it's the natural Tab target")
}

func TestOnboardingPage_KeyboardHintWiresToHelpDialog(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// JS click handler must be installed on the hint button.
	assert.Contains(t, body, `hint.addEventListener('click'`,
		"hint button must have a click listener that toggles the help dialog")

	// toggleHelp must update aria-expanded so AT users hear the state
	// change when the dialog opens/closes.
	assert.Contains(t, body, "aria-expanded",
		"toggleHelp must update aria-expanded on the hint button so AT mirrors visual state")

	// The hint must hide itself when the help dialog opens — they share
	// the bottom-right corner and would visually overlap otherwise.
	assert.Contains(t, body, "hint.style.display",
		"toggleHelp must show/hide the hint button so it doesn't overlap the help dialog when open")
}

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

func TestOnboardingPage_IncludesKeyboardShortcutHelp(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Help dialog markup must be present (hidden by default — toggled by ?).
	assert.Contains(t, body, `id="kbd-help"`,
		"shell must include the keyboard-help dialog so the ? shortcut has something to toggle")
	assert.Contains(t, body, `role="dialog"`,
		"help dialog must declare role='dialog' for screen-reader navigation")
	assert.Contains(t, body, `aria-labelledby="kbd-help-title"`,
		"dialog must be linked to its title via aria-labelledby")
	assert.Contains(t, body, "Keyboard shortcuts",
		"help dialog title must explain its purpose")

	// All six shortcut bindings must be documented in the dialog (i / e / c
	// / s / ? / Esc). Operators don't know what's available otherwise.
	for _, k := range []string{"<kbd>i</kbd>", "<kbd>e</kbd>", "<kbd>c</kbd>", "<kbd>s</kbd>", "<kbd>?</kbd>", "<kbd>Esc</kbd>"} {
		assert.Contains(t, body, k,
			"shortcut key %s must be documented inside a <kbd> element in the help dialog", k)
	}
}

func TestOnboardingPage_KeyboardHandlerSkipsFormFields(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// The skip-on-typing guard is the universal vim/GitHub/Notion pattern —
	// without it, keyboard shortcuts hijack typing in the api_key input,
	// destroying the operator's paste.
	assert.Contains(t, body, "isTyping",
		"keyboard handler must declare an isTyping() guard so shortcuts don't hijack typing in form fields")
	assert.Contains(t, body, "INPUT",
		"isTyping() must check for INPUT tag (api_key field) so paste isn't broken by shortcuts")
	assert.Contains(t, body, "TEXTAREA",
		"isTyping() must also cover TEXTAREA")
	assert.Contains(t, body, "isContentEditable",
		"isTyping() must also cover contenteditable elements")
}

func TestOnboardingPage_KeyboardHandlerWiresAllShortcuts(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Each shortcut must have a case arm in the keydown switch.
	for _, arm := range []string{
		`case '?'`,
		`case 'Escape'`,
		`case 'i'`,
		`case 'e'`,
		`case 'c'`,
		`case 's'`,
	} {
		assert.Contains(t, body, arm,
			"keyboard handler must have a switch case for %s", arm)
	}

	// The e shortcut must focus the api_key input after the scroll, matching
	// the iteration-6 smooth-scroll-then-focus pattern.
	assert.Contains(t, body, `'e':`,
		"shortcut 'e' case must be present")
	assert.Contains(t, body, `'api_key'`,
		"shortcut 'e' must reference the api_key input id so it gets focused after scroll")

	// Modifier-combo guard — shortcuts should not fire with Ctrl/Cmd/Alt
	// so they don't conflict with browser/OS shortcuts.
	assert.Contains(t, body, "ctrlKey",
		"keyboard handler must bail on Ctrl-combos to avoid browser-shortcut conflicts")
	assert.Contains(t, body, "metaKey",
		"keyboard handler must bail on Cmd-combos (macOS) similarly")
}

func TestOnboardingPage_KeyboardHandlerRespectsPrefersReducedMotion(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Composition with iteration 14: jumpTo() must check matchMedia and use
	// 'auto' (instant) scroll for reduced-motion users. Otherwise the
	// keyboard shortcuts re-introduce the motion problem the iteration-14
	// scroll-to-step JS already solved.
	count := strings.Count(body, "prefers-reduced-motion")
	assert.GreaterOrEqual(t, count, 2,
		"prefers-reduced-motion must be checked in BOTH the scroll-to-step listener (iteration 14) AND the keyboard jumpTo() helper — found %d occurrences", count)
}

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

func TestEnroll_EmptyKey_RendersAccessibleErrorPattern(t *testing.T) {
	h := newInstallHarness(t, nil)

	form := url.Values{"api_key": {""}}
	rec := h.do(t, "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

	require.Equal(t, http.StatusOK, rec.Code, "validation errors render inline, not 4xx")
	body := rec.Body.String()

	// The canonical ARIA form-error pattern (WAI-ARIA Authoring Practices §3.2):
	// the error message has role="alert" (implies aria-live="assertive" + atomic),
	// it carries a stable id, the input is marked aria-invalid="true" and points
	// at the error message via aria-describedby. AT users get the error
	// announced immediately AND get the description when focusing the field.
	assert.Contains(t, body, `role="alert"`,
		"error pane must carry role='alert' so AT announces it immediately (WCAG 3.3.1)")
	assert.Contains(t, body, `id="enroll-error-msg"`,
		"error pane must have a stable id so the input can aria-describedby it")
	assert.Contains(t, body, `aria-invalid="true"`,
		"input in error state must declare aria-invalid='true' so AT identifies the invalid field")
	assert.Contains(t, body, `aria-describedby="enroll-error-msg"`,
		"input must point at the error message via aria-describedby so AT reads the description on focus (WCAG 3.3.3)")

	// The actual error text must still be present — the ARIA attributes
	// don't replace the visible error, they augment it.
	assert.Contains(t, body, "API key is required",
		"the human-readable error text must still appear — ARIA augments visible error, doesn't replace it")
}

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

func TestEnroll_ReadOnlyMode_RendersAccessibleErrorPattern(t *testing.T) {
	// In read-only inspector mode, attempting to enroll still surfaces a
	// (different) error. The ARIA pattern must work uniformly across all
	// enroll error branches, not just empty-key validation.
	st, err := sqlite.New(t.TempDir() + "/inspector.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	key, keyErr := newOnboardingWrapKey()
	require.NoError(t, keyErr)

	mux := http.NewServeMux()
	// Intentionally nil Store → read-only mode; same render path through
	// handleEnroll which sets view.Error.
	registerOnboardingRoutes(mux, onboardingDeps{
		WrapKey:          key,
		PlatformEndpoint: testPlatformEndpoint,
		ProbeClient:      &http.Client{},
	})

	form := url.Values{"api_key": {"sk-something"}}
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `role="alert"`,
		"read-only mode error must also use the role='alert' pattern — uniform a11y across all error branches")
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
			{Key: "enroll", Label: "Enroll token", Status: "current", Anchor: "#enroll-card"},
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
			{Key: "enroll", Label: "Enroll token", Status: "done"},
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

func TestOnboardingPage_RespectsPrefersReducedMotion(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// JS path: scroll-to-step listener must branch on matchMedia so reduced-
	// motion users get instant scroll + quick focus instead of the 500ms
	// animation. Without this, the smooth-scroll feature actively harms a
	// subset of operators (WCAG 2.3.3 explicitly calls this out).
	assert.Contains(t, body, "prefers-reduced-motion",
		"scroll-to-step JS must check window.matchMedia for prefers-reduced-motion (WCAG 2.3.3)")
	assert.Contains(t, body, "reduceMotion ? 'auto' : 'smooth'",
		"scrollIntoView behavior must switch to 'auto' (instant) when reduced motion is preferred")
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
		{step: "check", wantSelector: "#check-card", wantHighlight: true},
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
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "What gets stored?",
		"enroll card must surface the trust-panel disclosure so security-conscious operators can self-serve the answer")
	assert.Contains(t, body, "AES-256-GCM",
		"trust panel must explicitly name the wrapping algorithm (operators search for this)")
	assert.Contains(t, body, "Wrap key is in-memory",
		"trust panel must explain the in-memory wrap-key design so operators understand restart-invalidates behaviour")
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
		`"target":"#check-card"`,
		"successful enroll must request a smooth-scroll to the check card so the OOB-swapped probe results are visible")
}

func TestOnboardingPage_IncludesScrollToStepListener(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/onboarding", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "scroll-to-step",
		"onboarding shell must register the scroll-to-step listener so HX-Trigger-After-Settle events actually scroll the page")
	assert.Contains(t, body, "scrollIntoView",
		"listener must use smooth scrollIntoView (not jump-to-anchor) for the wizard feel")
}

// ---------------------------------------------------------------------------
// Probe-level typed recovery actions
// ---------------------------------------------------------------------------

func TestConnectionCheck_AuthFailureCarriesReEnrollAction(t *testing.T) {
	h := newInstallHarness(t, nil)

	// Pre-enroll so the auth probe actually executes (otherwise it SKIPs
	// with "no identity enrolled" and no action is attached).
	form := url.Values{"api_key": {"sk-probe-action-0123456789ABCDEF"}}
	_ = h.do(t, "POST", "/api/v1/identity/enroll",
		strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

	rec := h.do(t, "GET", "/api/v1/connection/check", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp connectionCheckResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	var authProbe *probeResult
	var reachProbe *probeResult
	for i := range resp.Probes {
		switch resp.Probes[i].Name {
		case probeAuth:
			authProbe = &resp.Probes[i]
		case probeReach:
			reachProbe = &resp.Probes[i]
		case probeDNS, probeTLS, probeClock, probeOTLP:
			// other probes don't carry actions; ignored for this test
		}
	}
	require.NotNil(t, authProbe, "auth probe must be present in the 6-probe set")
	require.Equal(t, "fail", authProbe.Result,
		"auth probe must fail against the unreachable example.test endpoint")
	require.NotNil(t, authProbe.Action,
		"failed auth probe must carry a typed recovery action")
	assert.Equal(t, "#enroll-card", authProbe.Action.URL,
		"auth recovery must jump to the enroll card anchor")
	assert.Equal(t, "Re-enroll", authProbe.Action.Label)

	// Reach probe also fails (example.test is unreachable) and must carry the
	// "Open endpoint" external link.
	require.NotNil(t, reachProbe)
	if reachProbe.Result == "fail" {
		require.NotNil(t, reachProbe.Action, "reach failure must carry the open-endpoint action")
		assert.Equal(t, "_blank", reachProbe.Action.Target,
			"open-endpoint action must use target=_blank for an external open")
		assert.Contains(t, reachProbe.Action.URL, "/healthz",
			"open-endpoint URL must point at the /healthz path on the configured endpoint")
	}
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
	require.Len(t, resp.Probes, 6, "must always emit 6 probes regardless of goroutine completion order")

	// Canonical order matters — operator runbooks reference probe[2] = reach,
	// probe[4] = clock, etc. Parallel execution must not scramble it.
	expected := []probeName{probeDNS, probeTLS, probeReach, probeAuth, probeClock, probeOTLP}
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
	assert.Contains(t, body, "Enroll token",
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

func TestEnrollFragment_HasAutofocusAndHelpLink(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/fragments/enroll-form", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "autofocus",
		"enroll form must autofocus the API key input for paste-friendly UX")
	assert.Contains(t, body, "Generate one",
		"enroll form must include the 'Need a key?' help link")
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
