package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kardianos/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				waitDashboard: func(string, time.Duration) bool {
					return true
				},
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

func TestDashboardEnrollmentWaitComplete(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		wantComplete bool
		wantError    bool
	}{
		{
			name:         "pending",
			status:       http.StatusOK,
			body:         `{"complete":false}`,
			wantComplete: false,
		},
		{
			name:         "complete",
			status:       http.StatusOK,
			body:         `{"complete":true}`,
			wantComplete: true,
		},
		{
			name:   "non-200-remains-pending",
			status: http.StatusServiceUnavailable,
			body:   `{"complete":true}`,
		},
		{
			name:      "malformed-json",
			status:    http.StatusOK,
			body:      `{`,
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(server.Close)

			complete, err := dashboardEnrollmentWaitComplete(
				context.Background(),
				http.Client{Timeout: time.Second},
				server.URL,
			)
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantComplete, complete)
		})
	}
}

func TestCloseTemporaryEnrollmentResources_ClosesInOrder(t *testing.T) {
	var order []string
	err := closeTemporaryEnrollmentResources(
		func(context.Context) error {
			order = append(order, "dashboard")
			return nil
		},
		func() error {
			order = append(order, "store")
			return nil
		},
	)

	require.NoError(t, err)
	assert.Equal(t, []string{"dashboard", "store"}, order)
}

func TestCloseTemporaryEnrollmentResources_AttemptsBothAndReportsErrors(t *testing.T) {
	shutdownErr := errors.New("listener stuck")
	storeErr := errors.New("encrypt failed")
	var storeClosed bool

	err := closeTemporaryEnrollmentResources(
		func(context.Context) error { return shutdownErr },
		func() error {
			storeClosed = true
			return storeErr
		},
	)

	require.Error(t, err)
	assert.True(t, storeClosed, "the encrypted store must be closed even when dashboard shutdown fails")
	assert.ErrorIs(t, err, shutdownErr)
	assert.Contains(t, err.Error(), "encrypt failed")
}

func TestCompletePlatformEnrollment_StartsServiceAndOpensLiveDashboard(t *testing.T) {
	var (
		gotUserMode bool
		waitedURL   string
		openedURL   string
	)
	err := completePlatformEnrollment(
		"http://127.0.0.1:9090/",
		false,
		true,
		platformEnrollDeps{
			transitionService: func(userMode bool) (string, error) {
				gotUserMode = userMode
				return "started", nil
			},
			waitDashboard: func(rawURL string, timeout time.Duration) bool {
				waitedURL = rawURL
				assert.Equal(t, 10*time.Second, timeout)
				return true
			},
			openBrowser: func(rawURL string) { openedURL = rawURL },
		},
	)

	require.NoError(t, err)
	assert.True(t, gotUserMode)
	assert.Equal(t, "http://127.0.0.1:9090/machines", waitedURL)
	assert.Equal(t, waitedURL, openedURL)
}

func TestCompletePlatformEnrollment_HeadlessDoesNotWaitOrOpenBrowser(t *testing.T) {
	waited := false
	opened := false
	err := completePlatformEnrollment(
		"http://127.0.0.1:9090",
		true,
		false,
		platformEnrollDeps{
			transitionService: func(bool) (string, error) { return "started", nil },
			waitDashboard: func(string, time.Duration) bool {
				waited = true
				return true
			},
			openBrowser: func(string) { opened = true },
		},
	)

	require.NoError(t, err)
	assert.False(t, waited)
	assert.False(t, opened)
}

func TestCompletePlatformEnrollment_PropagatesServiceFailure(t *testing.T) {
	transitionErr := errors.New("permission denied")
	err := completePlatformEnrollment(
		"http://127.0.0.1:9090",
		false,
		false,
		platformEnrollDeps{
			transitionService: func(bool) (string, error) { return "", transitionErr },
			waitDashboard:     func(string, time.Duration) bool { return true },
			openBrowser:       func(string) { t.Fatal("browser must not open after service failure") },
		},
	)

	require.Error(t, err)
	assert.ErrorIs(t, err, transitionErr)
	assert.Contains(t, err.Error(), "enrollment succeeded but service transition failed")
}

func TestTransitionEnrolledServiceWithOps(t *testing.T) {
	tests := []struct {
		name        string
		status      service.Status
		statusErr   error
		startErr    error
		restartErr  error
		wantAction  string
		wantErrText string
		wantStart   int
		wantRestart int
	}{
		{
			name:      "service-not-installed",
			statusErr: service.ErrNotInstalled,
		},
		{
			name:       "stopped-service-starts",
			status:     service.StatusStopped,
			wantAction: "started",
			wantStart:  1,
		},
		{
			name:        "running-service-restarts",
			status:      service.StatusRunning,
			wantAction:  "restarted",
			wantRestart: 1,
		},
		{
			name:        "status-error",
			statusErr:   errors.New("status unavailable"),
			wantErrText: "query installed service",
		},
		{
			name:        "start-error",
			status:      service.StatusStopped,
			startErr:    errors.New("start denied"),
			wantStart:   1,
			wantErrText: "start service",
		},
		{
			name:        "restart-error",
			status:      service.StatusRunning,
			restartErr:  errors.New("restart denied"),
			wantRestart: 1,
			wantErrText: "restart service",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			startCalls := 0
			restartCalls := 0
			action, err := transitionEnrolledServiceWithOps(enrolledServiceOps{
				status: func() (service.Status, error) {
					return tc.status, tc.statusErr
				},
				start: func() error {
					startCalls++
					return tc.startErr
				},
				restart: func() error {
					restartCalls++
					return tc.restartErr
				},
			})

			if tc.wantErrText != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrText)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantAction, action)
			}
			assert.Equal(t, tc.wantStart, startCalls)
			assert.Equal(t, tc.wantRestart, restartCalls)
		})
	}
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
