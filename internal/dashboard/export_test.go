package dashboard

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// exportTestContext is a fully-populated ReportContext so every header
// line renders.
var exportTestContext = ReportContext{
	ReportID:         "rep-123",
	GeneratedAtUTC:   "2026-08-21T12:00:00Z",
	GeneratedAtLocal: "2026-08-21 05:00:00 PDT",
	ScanRunID:        "scan-9",
	AppName:          "kite-collector",
	AppVersion:       "0.53.2",
	Commit:           "abc1234",
	Hostname:         "test-host",
	OS:               "linux",
	Arch:             "amd64",
	DBPath:           "/tmp/kite.db",
}

// seedExportStore builds one real store shared by the export tests: a
// machine with software and one finding.
func seedExportStore(t *testing.T) (*sqlite.SQLiteStore, model.Machine) {
	t.Helper()
	st, err := sqlite.New(t.TempDir() + "/export.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	m := model.Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "web-01",
		MachineType:     model.MachineTypeServer,
		OSFamily:        "linux",
		OSVersion:       "6.9",
		IsAuthorized:    model.AuthorizationAuthorized,
		IsManaged:       model.ManagedManaged,
		Environment:     "prod",
		Owner:           "ops@example.com",
		DiscoverySource: "agent",
		FirstSeenAt:     time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		LastSeenAt:      time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC),
	}
	ctx := context.Background()
	require.NoError(t, st.UpsertMachine(ctx, m))

	runID := uuid.Must(uuid.NewV7())
	require.NoError(t, st.CreateScanRun(ctx, model.ScanRun{
		ID:        runID,
		StartedAt: time.Now().UTC(),
		Status:    model.ScanStatusRunning,
	}))

	require.NoError(t, st.UpsertSoftware(ctx, m.ID, []model.InstalledSoftware{{
		ID:             uuid.Must(uuid.NewV7()),
		SoftwareName:   "openssl",
		Version:        "3.3.1",
		Vendor:         "openssl",
		CPE23:          "cpe:2.3:a:openssl:openssl:3.3.1:*:*:*:*:*:*:*",
		PackageManager: "dpkg",
	}}))

	require.NoError(t, st.InsertFindings(ctx, []model.ConfigFinding{{
		ID:        uuid.Must(uuid.NewV7()),
		MachineID: m.ID,
		ScanRunID: runID,
		Auditor:   "ssh",
		CheckID:   "ssh-001",
		Title:     "Root login permitted",
		Severity:  model.SeverityHigh,
		Timestamp: time.Now().UTC(),
	}}))

	return st, m
}

// Every CSV export carries the traceability header block, then exact rows.
func TestExportMachinesCSV(t *testing.T) {
	st, _ := seedExportStore(t)
	var buf bytes.Buffer
	require.NoError(t, exportMachinesCSV(&buf, context.Background(), st, exportTestContext))

	out := buf.String()
	for _, must := range []string{
		"# Report ID: rep-123",
		"# Scan Run: scan-9",
		"# Application: kite-collector 0.53.2 (commit abc1234)",
		"# Host: test-host (linux/amd64)",
		"# Database: /tmp/kite.db",
		"hostname,machine_type,os_family",
		"web-01,server,linux,6.9,authorized,managed,prod,ops@example.com,agent,2026-08-01T00:00:00Z,2026-08-21T10:00:00Z",
	} {
		assert.Contains(t, out, must)
	}
}

func TestExportSoftwareCSV(t *testing.T) {
	st, _ := seedExportStore(t)
	var buf bytes.Buffer
	require.NoError(t, exportSoftwareCSV(&buf, context.Background(), st, exportTestContext))

	out := buf.String()
	assert.Contains(t, out, "hostname,software_name,version")
	assert.Contains(t, out, "web-01,openssl,3.3.1,openssl,cpe:2.3:a:openssl:openssl:3.3.1:*:*:*:*:*:*:*,dpkg,")
}

func TestExportFindingsCSV(t *testing.T) {
	st, _ := seedExportStore(t)
	var buf bytes.Buffer
	require.NoError(t, exportFindingsCSV(&buf, context.Background(), st, exportTestContext))

	out := buf.String()
	assert.Contains(t, out, "check_id,severity,title,auditor")
	assert.Contains(t, out, "ssh-001,high,Root login permitted,ssh")
}

// exportTableCSV validates the table name before issuing SQL and streams
// the introspected rows; unknown tables fail without leaking SQL.
func TestExportTableCSV(t *testing.T) {
	st, m := seedExportStore(t)
	var buf bytes.Buffer
	require.NoError(t, exportTableCSV(&buf, context.Background(), st, exportTestContext, "machines"))
	out := buf.String()
	assert.Contains(t, out, "# Report ID: rep-123")
	assert.Contains(t, out, "hostname", "the introspected column header renders")
	assert.Contains(t, out, m.Hostname)

	err := exportTableCSV(&bytes.Buffer{}, context.Background(), st, exportTestContext, "no_such_table")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no_such_table")
}

// The empty-scan-run header branch: no Scan Run line when unset.
func TestWriteCSVHeader_OmitsEmptyScanRun(t *testing.T) {
	rc := exportTestContext
	rc.ScanRunID = ""
	var buf bytes.Buffer
	writeCSVHeader(&buf, rc)
	assert.NotContains(t, buf.String(), "# Scan Run:")
	assert.Equal(t, 5, strings.Count(buf.String(), "\n"), "exactly the five metadata lines")
}

func TestStringifyCSV(t *testing.T) {
	assert.Equal(t, "", stringifyCSV(nil))
	assert.Equal(t, "plain", stringifyCSV("plain"))
	assert.Equal(t, "deadbeef", stringifyCSV([]byte{0xde, 0xad, 0xbe, 0xef}))
	assert.Equal(t, "2026-08-21T10:00:00Z",
		stringifyCSV(time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)))
	assert.Equal(t, "true", stringifyCSV(true))
	assert.Equal(t, "false", stringifyCSV(false))
	assert.Equal(t, "42", stringifyCSV(int64(42)))
	assert.Equal(t, "3.5", stringifyCSV(3.5))
}
