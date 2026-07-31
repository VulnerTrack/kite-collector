package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDashboardModeLabel pins the canonical mode tag the dashboard subcommand
// logs at boot. Surface area is small but it's the operator-facing signal for
// "which dashboard am I running" — easy to silently regress otherwise.
func TestDashboardModeLabel(t *testing.T) {
	cases := []struct {
		name          string
		mode          string
		withAgent     bool
		enableInstall bool
	}{
		{name: "agent-mode-wins", withAgent: true, enableInstall: true, mode: "agent"},
		{name: "agent-mode-even-without-install", withAgent: true, enableInstall: false, mode: "agent"},
		{name: "inspector-with-install", withAgent: false, enableInstall: true, mode: "inspector+install"},
		{name: "pure-inspector", withAgent: false, enableInstall: false, mode: "inspector"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.mode, dashboardModeLabel(tc.withAgent, tc.enableInstall))
		})
	}
}

// TestNewDashboardCmd_HasDefaultOnFlags asserts the user-facing contract that
// the dashboard subcommand boots write-enabled by default — operators should
// not have to pass any flags to get the install / agent capabilities.
func TestNewDashboardCmd_HasDefaultOnFlags(t *testing.T) {
	cmd := newDashboardCmd()
	enableInstall := cmd.Flags().Lookup("enable-install")
	withAgent := cmd.Flags().Lookup("with-agent")

	if assert.NotNil(t, enableInstall, "--enable-install flag must exist") {
		assert.Equal(t, "true", enableInstall.DefValue, "--enable-install must default to true")
	}
	if assert.NotNil(t, withAgent, "--with-agent flag must exist") {
		assert.Equal(t, "true", withAgent.DefValue, "--with-agent must default to true")
	}

	db := cmd.Flags().Lookup("db")
	if assert.NotNil(t, db, "--db flag must exist") {
		assert.NotEqual(t, "./kite.db", db.DefValue,
			"--db default must be the OS-appropriate path, not the legacy ./kite.db")
	}

	certs := cmd.Flags().Lookup("certs-dir")
	if assert.NotNil(t, certs, "--certs-dir flag must exist") {
		assert.NotEmpty(t, certs.DefValue, "--certs-dir must have an OS-appropriate default")
	}
}

func TestDashboardLoginURL_UsesLocalKiteRoute(t *testing.T) {
	assert.Equal(t,
		"http://127.0.0.1:9090/kite-login?collector=http%3A%2F%2F127.0.0.1%3A9090",
		dashboardLoginURL(":9090"))
	assert.Equal(t,
		"http://127.0.0.1:9090/kite-login?collector=http%3A%2F%2F127.0.0.1%3A9090",
		dashboardLoginURL("0.0.0.0:9090"))
}

func TestResolveAgentDBPath(t *testing.T) {
	assert.Equal(t,
		filepath.Join("/var/lib/kite-collector", "kite.db"),
		resolveAgentDBPath("", "/var/lib/kite-collector"),
	)
	assert.Equal(t, "/custom/inventory.db",
		resolveAgentDBPath("/custom/inventory.db", "/var/lib/kite-collector"),
	)
	assert.Equal(t, "kite.db", resolveAgentDBPath("", ""))
}

func TestRunPlatformLoginEnroll_PrintsLocalURLBeforeOAuthRedirect(t *testing.T) {
	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/kite-login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(
			w,
			r,
			"https://app.vulnertrack.com/kite/signin/oauth/?authorization_id=test",
			http.StatusSeeOther,
		)
	})
	mux.HandleFunc("/api/v1/enrollment/wait/{id}", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"complete": true})
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	addr := listener.Addr().String()
	var runErr error
	var transitioned bool
	output := captureStdout(t, func() {
		runErr = runPlatformLoginEnrollWithDeps(
			addr,
			"unused.db",
			"unused.yaml",
			true,
			false,
			platformEnrollDeps{
				transitionService: func(bool) (string, error) {
					transitioned = true
					return "restarted", nil
				},
				openBrowser: func(string) {},
			},
		)
	})

	assert.NoError(t, runErr)
	assert.True(t, transitioned)
	assert.Contains(t, output, "http://"+addr+"/kite-login?")
	assert.False(t, strings.Contains(output, "app.vulnertrack.com"),
		"the CLI must not bypass the local response that sets OAuth state and PKCE cookies")
}

func TestPrintPlatformEnrollmentComplete_ServiceStarted(t *testing.T) {
	output := captureStdout(t, func() {
		printPlatformEnrollmentComplete("http://127.0.0.1:9090/", "started")
	})

	assert.Contains(t, output, "Enrollment complete.")
	assert.Contains(t, output, "Welcome to Kite!")
	assert.Contains(t, output, "Collector service started automatically.")
	assert.Contains(t, output, "Kite is running at http://127.0.0.1:9090")
	assert.NotContains(t, output, "Press Ctrl+C to stop.")
}

func TestPrintPlatformEnrollmentComplete_NoInstalledService(t *testing.T) {
	output := captureStdout(t, func() {
		printPlatformEnrollmentComplete("http://127.0.0.1:9090", "")
	})

	assert.Contains(t, output, "Enrollment complete.")
	assert.Contains(t, output, "Welcome to Kite!")
	assert.Contains(t, output, "No installed collector service was found")
	assert.NotContains(t, output, "Press Ctrl+C to stop.")
}
