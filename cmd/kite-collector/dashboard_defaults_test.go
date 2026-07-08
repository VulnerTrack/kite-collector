package main

import (
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
