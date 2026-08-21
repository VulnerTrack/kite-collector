package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/installer"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
	"github.com/vulnertrack/kite-collector/internal/streamctrl"
)

func TestUseColor_SuppressedOutsideTTYs(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	assert.False(t, useColor(os.Stderr), "NO_COLOR always wins")

	require.NoError(t, os.Unsetenv("NO_COLOR"))
	assert.False(t, useColor(&bytes.Buffer{}), "non-file writers never color")

	f, err := os.CreateTemp(t.TempDir(), "banner")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	assert.False(t, useColor(f), "a regular file is not a terminal")
}

func TestStateGlyph(t *testing.T) {
	assert.Equal(t, "✓", stateGlyph(true))
	assert.Equal(t, "✗", stateGlyph(false))
}

func TestEnrollmentSummary(t *testing.T) {
	assert.Equal(t, "agent.pem + ca.pem + agent-key.pem present",
		enrollmentSummary(installer.State{CertsEnrolled: true}))
	assert.Equal(t, "(empty — run `enroll` to populate)",
		enrollmentSummary(installer.State{CertsDirExists: true}))
	assert.Equal(t, "(certs dir missing)", enrollmentSummary(installer.State{}))
}

func TestPrivilegeSuffix(t *testing.T) {
	assert.Equal(t, " (privileged)", privilegeSuffix(true))
	assert.Equal(t, " (non-privileged — system install may fail; prefer --user mode)",
		privilegeSuffix(false))
}

func TestDoctorDatabaseCheck_MissingHealthyPendingCorrupt(t *testing.T) {
	ctx := context.Background()

	missing := doctorDatabaseCheck(ctx, filepath.Join(t.TempDir(), "kite.db"))
	assert.Equal(t, doctorWarn, missing.Status)
	assert.Contains(t, missing.Detail, "not created yet")
	assert.Equal(t, "created automatically by the first scan", missing.Hint)

	healthyPath := seedDiffDB(t, t.TempDir())
	healthy := doctorDatabaseCheck(ctx, healthyPath)
	assert.Equal(t, doctorPass, healthy.Status)
	assert.Contains(t, healthy.Detail, "migrations applied")

	// Removing one schema_migrations row (RepairMigration) leaves that
	// version pending, which doctor reports as a warn, not a fail.
	encStore, err := openSQLiteStore(healthyPath, config.IdentityConfig{})
	require.NoError(t, err)
	st, ok := encStore.Store.(*sqlite.SQLiteStore)
	require.True(t, ok)
	infos, err := st.MigrationStatus(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, infos)
	require.NoError(t, st.RepairMigration(ctx, infos[len(infos)-1].Version))
	require.NoError(t, encStore.Close())

	pending := doctorDatabaseCheck(ctx, healthyPath)
	assert.Equal(t, doctorWarn, pending.Status)
	assert.Contains(t, pending.Detail, "1 migration(s) pending")
	assert.Contains(t, pending.Hint, "kite-collector migrate")

	corruptPath := filepath.Join(t.TempDir(), "kite.db")
	require.NoError(t, os.WriteFile(corruptPath, bytes.Repeat([]byte{0x5A}, 64), 0o600))
	corrupt := doctorDatabaseCheck(ctx, corruptPath)
	assert.Equal(t, doctorFail, corrupt.Status)
	assert.Contains(t, corrupt.Detail, "open failed: ")
	assert.Contains(t, corrupt.Hint, "corrupt or locked")
}

func TestDashboardStreamAdapter_StartStopStatus(t *testing.T) {
	adapter := dashboardStreamAdapter{inner: streamctrl.New(nil)}
	ctx := context.Background()

	st := adapter.Status()
	assert.Equal(t, "idle", st.State)
	assert.Equal(t, int64(0), st.TotalSent)
	assert.Equal(t, 0, st.BacklogDepth)
	assert.Empty(t, st.LastErrorText)

	require.NoError(t, adapter.Start(ctx))
	assert.Equal(t, "running", adapter.Status().State)

	require.NoError(t, adapter.Stop(ctx))
	assert.Equal(t, "stopped", adapter.Status().State)
}

func TestRunEndpoints_TableFromConfig(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "kite-collector.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte(`
endpoints:
  - name: primary
    address: otel.example:4317
    priority: 1
    routes: [logs, metrics]
    tls:
      enabled: true
  - name: mtls-ep
    address: otel2.example:4317
    priority: 2
    tls:
      enabled: true
      cert_file: /x/agent.pem
  - name: plain
    address: otel3.example:4317
`), 0o600))

	out := captureStdout(t, func() {
		require.NoError(t, runEndpoints(cfgFile))
	})

	assert.Contains(t, out, "NAME")
	assert.Contains(t, out, "primary")
	assert.Contains(t, out, "logs,metrics")
	assert.Contains(t, out, "TLS")
	assert.Contains(t, out, "mTLS")
	assert.Contains(t, out, "(none)", "route-less endpoint renders a placeholder")
	assert.Contains(t, out, "none", "no-TLS endpoint labelled none")
}

func TestRunEndpoints_NoEndpointsConfigured(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "kite-collector.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("log_level: info\n"), 0o600))

	out := captureStdout(t, func() {
		require.NoError(t, runEndpoints(cfgFile))
	})
	assert.Equal(t, "No endpoints configured.\n", out)
}

func TestRunCheckOTLP_InvalidEndpointURL(t *testing.T) {
	err := runCheckOTLP("://not-a-url", t.TempDir(), time.Second, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse endpoint")
}

func TestRunCheckOTLP_ClosedLoopbackPortFailsTCPStage(t *testing.T) {
	// Reserve a loopback port, then close it so the dial is guaranteed to
	// be refused locally — no traffic ever leaves the host.
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	var checkErr error
	out := captureStdout(t, func() {
		checkErr = runCheckOTLP("http://"+addr, t.TempDir(), 500*time.Millisecond, false)
	})

	require.Error(t, checkErr)
	assert.Equal(t, "one or more connectivity checks failed", checkErr.Error())
	assert.Contains(t, out, "tcp-dial")
	assert.Contains(t, out, "✗")
}
