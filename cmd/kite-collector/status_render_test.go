package main

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

func TestShortCommit(t *testing.T) {
	assert.Equal(t, "", shortCommit(""))
	assert.Equal(t, "abcdefg", shortCommit("abcdefg"), "exactly 7 chars stays whole")
	assert.Equal(t, "abcdefg", shortCommit("abcdefgh"), "8 chars truncates to 7")
	assert.Equal(t, "1234567", shortCommit("1234567890abcdef"))
}

func TestFmtByteSize(t *testing.T) {
	assert.Equal(t, "0 B", fmtByteSize(0))
	assert.Equal(t, "1023 B", fmtByteSize(1023))
	assert.Equal(t, "1.0 KB", fmtByteSize(1024))
	assert.Equal(t, "1.5 KB", fmtByteSize(1536))
	assert.Equal(t, "1.0 MB", fmtByteSize(1024*1024))
	assert.Equal(t, "1.00 GB", fmtByteSize(1024*1024*1024))
	assert.Equal(t, "2.50 GB", fmtByteSize(int64(2.5*1024*1024*1024)))
}

func TestRelativeAge(t *testing.T) {
	now := time.Now()
	assert.Equal(t, "just now", relativeAge(now.Add(-30*time.Second)))
	assert.Equal(t, "5m ago", relativeAge(now.Add(-5*time.Minute-time.Second)))
	assert.Equal(t, "3h ago", relativeAge(now.Add(-3*time.Hour-time.Minute)))
	assert.Equal(t, "2d ago", relativeAge(now.Add(-49*time.Hour)))
}

// renderToString runs renderStatusReport against a buffer-backed command.
func renderToString(t *testing.T, r statusReport) string {
	t.Helper()
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	renderStatusReport(cmd, r)
	return buf.String()
}

func TestRenderStatusReport_EnrolledRunningSystem(t *testing.T) {
	out := renderToString(t, statusReport{
		Version: "1.2.3",
		Commit:  "abcdef1234567890",
		Service: statusService{State: "running", Present: true},
		Enrollment: statusEnrollment{
			State:          "enrolled",
			Enrolled:       true,
			CertNotAfter:   "2027-03-04T05:06:07Z",
			CertDaysLeft:   120,
			FirstEnrolled:  "2026-01-15T10:00:00Z",
			KeyFingerprint: "fp-42",
		},
		Endpoint: "https://otel.example",
		LastScan: &statusScan{
			StartedAt:     "2026-08-20T01:02:03Z",
			Ago:           "3h ago",
			Status:        "completed",
			TotalMachines: 12,
			NewMachines:   2,
		},
		Database:   statusDatabase{Path: "/var/lib/kite/kite.db", Size: "1.5 KB", Exists: true},
		NextAction: "ready",
	})

	assert.Contains(t, out, "1.2.3 (abcdef1)")
	assert.Contains(t, out, "running (system)")
	assert.Contains(t, out, "enrolled · cert expires 2027-03-04 (120d)")
	assert.Contains(t, out, "first enrolled 2026-01-15 · key fp-42")
	assert.Contains(t, out, "https://otel.example")
	assert.Contains(t, out, "2026-08-20T01:02:03Z (3h ago) · completed · 12 machines, 2 new")
	assert.Contains(t, out, "/var/lib/kite/kite.db (1.5 KB)")
	assert.Contains(t, out, "ready")
	assert.NotContains(t, out, "⚠")
}

func TestRenderStatusReport_ExpiredCertAndWarnings(t *testing.T) {
	out := renderToString(t, statusReport{
		Version: "dev",
		Service: statusService{State: "not installed", UserMode: true},
		Enrollment: statusEnrollment{
			State:        "enrolled",
			Enrolled:     true,
			CertNotAfter: "2026-01-01T00:00:00Z",
			CertDaysLeft: -10,
			Warning:      "agent.pem unreadable: permission denied",
		},
		Database:   statusDatabase{Path: "/x/kite.db", Warning: "could not open: locked"},
		NextAction: "install",
	})

	assert.Contains(t, out, "not installed (user)")
	assert.Contains(t, out, "cert EXPIRED 2026-01-01")
	assert.NotContains(t, out, "cert expires")
	assert.Contains(t, out, "⚠ agent.pem unreadable: permission denied")
	assert.Contains(t, out, "none yet")
	assert.Contains(t, out, "/x/kite.db (not created yet)")
	assert.Contains(t, out, "⚠ could not open: locked")
	assert.Contains(t, out, "run: kite-collector install")
}

func TestRenderStatusReport_NotEnrolledUsesPlainState(t *testing.T) {
	out := renderToString(t, statusReport{
		Version:    "dev",
		Service:    statusService{State: "stopped", Present: true},
		Enrollment: statusEnrollment{State: "not enrolled"},
		Database:   statusDatabase{Path: "/x/kite.db"},
		NextAction: "enroll",
	})

	assert.Contains(t, out, "stopped (system)")
	assert.Contains(t, out, "not enrolled")
	assert.Contains(t, out, "run: kite-collector enroll")
	assert.NotContains(t, out, "Endpoint", "empty endpoint row must be omitted")
}

func TestFillStatusFromStore_ReadsIdentityAndLatestScan(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "kite.db")
	ctx := context.Background()

	encStore, err := openSQLiteStore(dbPath, config.IdentityConfig{})
	require.NoError(t, err)
	require.NoError(t, encStore.Migrate(ctx))
	st, ok := encStore.Store.(*sqlite.SQLiteStore)
	require.True(t, ok)

	enrolledAt := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	require.NoError(t, st.UpsertEnrolledIdentity(ctx, sqlite.EnrolledIdentity{
		ApiKeyFingerprint: "fp-status",
		ApiKeyWrapped:     []byte("wrapped"),
		FirstEnrolledAt:   enrolledAt,
		LastEnrolledAt:    enrolledAt,
	}))
	started := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	require.NoError(t, st.CreateScanRun(ctx, model.ScanRun{
		ID:            uuid.New(),
		StartedAt:     started,
		Status:        model.ScanStatusCompleted,
		TotalMachines: 7,
		NewMachines:   3,
	}))
	require.NoError(t, encStore.Close())

	report := statusReport{}
	fillStatusFromStore(ctx, dbPath, &report)

	assert.Empty(t, report.Database.Warning)
	assert.Equal(t, "2026-02-03T04:05:06Z", report.Enrollment.FirstEnrolled)
	assert.Equal(t, "fp-status", report.Enrollment.KeyFingerprint)
	require.NotNil(t, report.LastScan)
	assert.Equal(t, started.Format(time.RFC3339), report.LastScan.StartedAt)
	assert.Equal(t, "completed", report.LastScan.Status)
	assert.Equal(t, 7, report.LastScan.TotalMachines)
	assert.Equal(t, 3, report.LastScan.NewMachines)
	assert.Equal(t, "2h ago", report.LastScan.Ago)
}

func TestFillStatusFromStore_UnopenableStoreDegradesToWarning(t *testing.T) {
	// A directory where the db file should be makes the open fail without
	// touching anything outside the temp tree.
	dbPath := t.TempDir()

	report := statusReport{}
	fillStatusFromStore(context.Background(), dbPath, &report)

	assert.Contains(t, report.Database.Warning, "could not open: ")
	assert.Empty(t, report.Enrollment.FirstEnrolled)
	assert.Nil(t, report.LastScan)
}
