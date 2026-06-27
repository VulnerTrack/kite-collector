package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// TestDashboardLaunchBanner_AgentModeShowsInstallTargets asserts that on a
// first-time host (binary not yet present), the banner surfaces (a) the
// listen URL on its own line so headless operators can find it, (b) the
// agent mode label, and (c) the smart-default install paths so the
// operator knows what the install button would target. The empty
// installer.State{} models the fresh-install case.
func TestDashboardLaunchBanner_AgentModeShowsInstallTargets(t *testing.T) {
	var buf bytes.Buffer
	printDashboardLaunchBanner(&buf, dashboardLaunchInfo{
		Addr:          "127.0.0.1:9090",
		DB:            "/var/lib/kite-collector/kite.db",
		CertsDir:      "/var/lib/kite-collector",
		State:         installer.State{}, // first-run: nothing installed
		EnableInstall: true,
		WithAgent:     true,
		NoBrowser:     false,
	})
	out := buf.String()

	assert.Contains(t, out, "http://127.0.0.1:9090",
		"banner must surface the listen URL — operators in --no-browser sessions rely on this line")
	assert.Contains(t, out, "agent (full stack",
		"agent mode must be labelled explicitly so operators know they have install + scan capabilities")
	assert.Contains(t, out, "Install would target",
		"first-run banner must surface install targets so operators see what install would mutate before clicking")
	assert.Contains(t, out, "binary",
		"install targets must list the binary path")
	assert.Contains(t, out, "certs",
		"install targets must list the certs directory")
	assert.Contains(t, out, "/var/lib/kite-collector/kite.db",
		"banner must echo the database path so operators can confirm the override took effect")
	assert.NotContains(t, out, "Install status:",
		"first-run banner must NOT render the status report — that's the repeat-operator surface")
}

// TestDashboardLaunchBanner_RepeatOperatorShowsStatusReport asserts that
// when the binary is already present, the banner pivots from orientation
// copy ("will install at...") to status report ("installed at..., service
// running"). This is the repeat-operator surface — the second-most-common
// scenario after first-time install.
func TestDashboardLaunchBanner_RepeatOperatorShowsStatusReport(t *testing.T) {
	var buf bytes.Buffer
	printDashboardLaunchBanner(&buf, dashboardLaunchInfo{
		Addr: "127.0.0.1:9090",
		DB:   "/var/lib/kite-collector/kite.db",
		State: installer.State{
			BinaryPath:     "/usr/local/bin/kite-collector",
			CertsDir:       "/var/lib/kite-collector",
			BinaryPresent:  true,
			CertsDirExists: true,
			CertsEnrolled:  true,
			ServiceState:   installer.ServiceRunning,
			NextAction:     installer.ActionReady,
		},
		WithAgent: true,
	})
	out := buf.String()

	assert.Contains(t, out, "Install status:",
		"repeat-operator banner must render the status report header")
	assert.Contains(t, out, "/usr/local/bin/kite-collector",
		"status report must echo the actual installed binary path")
	assert.Contains(t, out, "✓",
		"status report must use checkmarks for present components — operators scan visually")
	assert.Contains(t, out, installer.ServiceRunning,
		"status report must surface the live service state")
	assert.NotContains(t, out, "Install would target",
		"repeat-operator banner must NOT show the first-run orientation copy — it's misleading after install")
	assert.NotContains(t, out, "next    →",
		"NextAction=ready must NOT render a 'next' hint — there's nothing left to do")
}

// TestDashboardLaunchBanner_PartialInstallShowsNextAction asserts that when
// the agent is mid-onboarding (binary installed but not enrolled), the
// status report surfaces the NextAction recommendation so the operator can
// pick up where they left off.
func TestDashboardLaunchBanner_PartialInstallShowsNextAction(t *testing.T) {
	var buf bytes.Buffer
	printDashboardLaunchBanner(&buf, dashboardLaunchInfo{
		Addr: "127.0.0.1:9090",
		DB:   "/var/lib/kite-collector/kite.db",
		State: installer.State{
			BinaryPath:     "/usr/local/bin/kite-collector",
			CertsDir:       "/var/lib/kite-collector",
			BinaryPresent:  true,
			CertsDirExists: true,
			CertsEnrolled:  false, // not enrolled yet
			ServiceState:   installer.ServiceStopped,
			NextAction:     installer.ActionEnroll,
		},
		WithAgent: true,
	})
	out := buf.String()

	assert.Contains(t, out, "next    →",
		"partial install must surface the NextAction so operators can pick up where they stopped")
	assert.Contains(t, out, installer.ActionEnroll,
		"NextAction value must appear verbatim so operators can copy it / cross-reference docs")
	assert.Contains(t, out, "see /onboarding",
		"NextAction hint must point operators at the /onboarding dashboard route for guided recovery")
}

func TestDashboardLaunchBanner_NoBrowserFlagAnnotates(t *testing.T) {
	var buf bytes.Buffer
	printDashboardLaunchBanner(&buf, dashboardLaunchInfo{
		Addr:      "127.0.0.1:9090",
		WithAgent: true,
		NoBrowser: true,
	})
	assert.Contains(t, buf.String(), "browser auto-open disabled",
		"--no-browser must add an annotation so operators in SSH sessions know they need to open the URL themselves")
}

func TestDashboardLaunchBanner_InspectorModeHidesInstallTargets(t *testing.T) {
	var buf bytes.Buffer
	printDashboardLaunchBanner(&buf, dashboardLaunchInfo{
		Addr:          "127.0.0.1:9090",
		EnableInstall: false,
		WithAgent:     false,
	})
	out := buf.String()
	assert.Contains(t, out, "inspector (read-only)",
		"inspector mode must be labelled — operators must know they can't install from this dashboard")
	assert.NotContains(t, out, "Install would target",
		"inspector mode must NOT surface install targets — they're misleading when install is disabled")
}

func TestDashboardLaunchBanner_FramesWithBorderAndUrlIsFirstLine(t *testing.T) {
	var buf bytes.Buffer
	printDashboardLaunchBanner(&buf, dashboardLaunchInfo{
		Addr:      "127.0.0.1:9090",
		WithAgent: true,
	})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// First and last non-empty lines should be the border so the banner is
	// visually framed in a terminal scrollback.
	assert.True(t, strings.HasPrefix(lines[0], "─"),
		"first line must be a border so the banner is visually framed")
	assert.True(t, strings.HasPrefix(lines[len(lines)-1], "─"),
		"last line must be a border so the banner is visually framed")
	// The URL line must come within the first 5 lines so operators see it
	// without scrolling past version output.
	foundURL := false
	for i, line := range lines {
		if i >= 6 {
			break
		}
		if strings.Contains(line, "http://") {
			foundURL = true
			break
		}
	}
	assert.True(t, foundURL,
		"URL must appear in the first 5 banner lines — operators scan top-down for it")
}
