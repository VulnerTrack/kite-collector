package sqlite

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/network"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safenet"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// newBareStore opens a SQLite store WITHOUT running migrations — used to
// exercise "no such table" tolerance paths and cheap ad-hoc schemas.
func newBareStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "bare.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// ---------------------------------------------------------------------------
// Maintenance: VacuumInto, Optimize, Checkpoint
// ---------------------------------------------------------------------------

func TestVacuumInto_CopiesConsistentSnapshot(t *testing.T) {
	ctx := context.Background()
	s := newBareStore(t)

	_, err := s.RawDB().ExecContext(ctx,
		`CREATE TABLE vac_t (id INTEGER PRIMARY KEY, v TEXT NOT NULL)`)
	require.NoError(t, err)
	_, err = s.RawDB().ExecContext(ctx, `INSERT INTO vac_t (id, v) VALUES (1, 'alpha'), (2, 'beta')`)
	require.NoError(t, err)

	dst := filepath.Join(t.TempDir(), "copy.db")
	require.NoError(t, s.VacuumInto(ctx, dst))

	copyStore, err := New(dst)
	require.NoError(t, err)
	defer func() { _ = copyStore.Close() }()

	var n int
	require.NoError(t, copyStore.RawDB().QueryRowContext(ctx, `SELECT COUNT(*) FROM vac_t`).Scan(&n))
	assert.Equal(t, 2, n)
	var v string
	require.NoError(t, copyStore.RawDB().QueryRowContext(ctx, `SELECT v FROM vac_t WHERE id = 2`).Scan(&v))
	assert.Equal(t, "beta", v)

	// VACUUM INTO refuses to overwrite an existing destination.
	err = s.VacuumInto(ctx, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vacuum into")
}

func TestMaintenance_ErrorsAfterClose(t *testing.T) {
	ctx := context.Background()
	s, err := New(filepath.Join(t.TempDir(), "closed.db"))
	require.NoError(t, err)
	require.NoError(t, s.Close())

	assert.Error(t, s.Optimize(ctx))
	assert.Error(t, s.Checkpoint(ctx))
	assert.Error(t, s.VacuumInto(ctx, filepath.Join(t.TempDir(), "x.db")))
}

// ---------------------------------------------------------------------------
// Closed-store sweep: every store method must surface (not swallow) the error
// ---------------------------------------------------------------------------

func TestClosedStore_MethodsReturnErrors(t *testing.T) {
	ctx := context.Background()
	s, err := New(filepath.Join(t.TempDir(), "closed_sweep.db"))
	require.NoError(t, err)
	require.NoError(t, s.Close())

	id := uuid.Must(uuid.NewV7())
	now := time.Now().UTC()

	_, err = s.MigrationStatus(ctx)
	assert.Error(t, err, "MigrationStatus")
	assert.Error(t, s.RepairMigration(ctx, "any"), "RepairMigration")

	_, err = s.GetMachineByID(ctx, id)
	assert.Error(t, err, "GetMachineByID")
	_, err = s.GetMachineByNaturalKey(ctx, "key")
	assert.Error(t, err, "GetMachineByNaturalKey")
	_, err = s.GetMachinesByNaturalKeys(ctx, []string{"key"})
	assert.Error(t, err, "GetMachinesByNaturalKeys")
	_, err = s.ListMachines(ctx, store.MachineFilter{})
	assert.Error(t, err, "ListMachines")
	_, err = s.GetStaleMachines(ctx, time.Hour)
	assert.Error(t, err, "GetStaleMachines")
	_, _, err = s.UpsertMachines(ctx, []model.Machine{makeMachine("h", model.MachineTypeServer)})
	assert.Error(t, err, "UpsertMachines")

	evt := model.MachineEvent{
		ID: id, EventType: model.EventMachineDiscovered,
		MachineID: id, ScanRunID: id,
		Severity: model.SeverityLow, Timestamp: now,
	}
	assert.Error(t, s.InsertEvent(ctx, evt), "InsertEvent")
	assert.Error(t, s.InsertEvents(ctx, []model.MachineEvent{evt}), "InsertEvents")
	_, err = s.ListEvents(ctx, store.EventFilter{})
	assert.Error(t, err, "ListEvents")

	assert.Error(t, s.CreateScanRun(ctx, model.ScanRun{ID: id, StartedAt: now}), "CreateScanRun")
	assert.Error(t, s.CompleteScanRun(ctx, id, model.ScanResult{}), "CompleteScanRun")
	_, err = s.GetLatestScanRun(ctx)
	assert.Error(t, err, "GetLatestScanRun")
	_, err = s.ListScanRuns(ctx, 10)
	assert.Error(t, err, "ListScanRuns")
	_, err = s.GetScanRun(ctx, id)
	assert.Error(t, err, "GetScanRun")
	assert.Error(t, s.MarkScanCancelRequested(ctx, id, now), "MarkScanCancelRequested")

	assert.Error(t, s.UpsertSoftware(ctx, id, []model.InstalledSoftware{{ID: id, MachineID: id}}), "UpsertSoftware")
	_, err = s.ListSoftware(ctx, id)
	assert.Error(t, err, "ListSoftware")

	finding := model.ConfigFinding{
		ID: id, MachineID: id, ScanRunID: id,
		Auditor: "a", CheckID: "c", Title: "t",
		Severity: model.SeverityLow, Timestamp: now,
	}
	assert.Error(t, s.InsertFindings(ctx, []model.ConfigFinding{finding}), "InsertFindings")
	_, err = s.ListFindings(ctx, store.FindingFilter{})
	assert.Error(t, err, "ListFindings")

	incident := model.RuntimeIncident{
		ID: id, IncidentType: model.IncidentPanicRecovered,
		Component: "c", ErrorMessage: "m", Severity: "high", CreatedAt: now,
	}
	assert.Error(t, s.InsertRuntimeIncident(ctx, incident), "InsertRuntimeIncident")
	_, err = s.ListRuntimeIncidents(ctx, store.IncidentFilter{})
	assert.Error(t, err, "ListRuntimeIncidents")

	assert.Error(t, s.RecordHeartbeat(ctx, model.ProbeHeartbeat{ID: id, ScanRunID: id, CreatedAt: now}), "RecordHeartbeat")
	_, err = s.ListHeartbeats(ctx, store.HeartbeatFilter{})
	assert.Error(t, err, "ListHeartbeats")

	assert.Error(t, s.UpsertEnrolledIdentity(ctx, EnrolledIdentity{}), "UpsertEnrolledIdentity")
	_, err = s.GetEnrolledIdentity(ctx)
	assert.Error(t, err, "GetEnrolledIdentity")
	assert.Error(t, s.DeleteEnrolledIdentity(ctx), "DeleteEnrolledIdentity")
	assert.Error(t, s.UpdateIdentityCheckStamp(ctx, &now, nil), "UpdateIdentityCheckStamp")
	assert.Error(t, s.InsertProbeResult(ctx, ProbeResultRecord{ProbeName: "p"}), "InsertProbeResult")
	_, err = s.ListProbeResults(ctx, 5)
	assert.Error(t, err, "ListProbeResults")

	assert.Error(t, s.WriteScanEvent(ctx, network.ScanEvent{ScanID: "s1", StartedAt: now}), "WriteScanEvent")
	assert.Error(t, s.WriteOpenPorts(ctx, "s1", []network.OpenPort{{IPAddress: "10.0.0.1", Port: 22}}), "WriteOpenPorts")
	assert.Error(t, s.WriteGuardEvent(ctx, safenet.GuardEvent{
		GuardType: safenet.GuardIPCountCap, Action: safenet.GuardActionCapped, TriggeredAt: now,
	}), "WriteGuardEvent")
	_, err = s.ListNetworkScanEvents(ctx, NetworkScanEventFilter{})
	assert.Error(t, err, "ListNetworkScanEvents")
	_, err = s.ListNetworkOpenPorts(ctx, NetworkOpenPortFilter{})
	assert.Error(t, err, "ListNetworkOpenPorts")
	_, err = s.ListSafetyGuardEvents(ctx, SafetyGuardEventFilter{})
	assert.Error(t, err, "ListSafetyGuardEvents")

	view := store.SavedView{Name: "n", Slug: "s", Join: store.JoinFilter{
		Base: "machines", Join: "events", OnBase: "id", OnJoin: "machine_id",
		Columns: []store.JoinColumn{{Table: "machines", Column: "hostname"}},
	}}
	assert.Error(t, s.SaveView(ctx, view), "SaveView")
	_, err = s.ListSavedViews(ctx)
	assert.Error(t, err, "ListSavedViews")
	_, err = s.GetSavedViewBySlug(ctx, "s")
	assert.Error(t, err, "GetSavedViewBySlug")
	assert.Error(t, s.DeleteSavedView(ctx, "s"), "DeleteSavedView")

	_, err = s.ListLoadedDrivers(ctx, LoadedDriverFilter{})
	assert.Error(t, err, "ListLoadedDrivers")
	_, err = s.ListDeviceBindings(ctx, DeviceBindingFilter{})
	assert.Error(t, err, "ListDeviceBindings")
	assert.Error(t, s.MarkLoadedDriversSynced(ctx, []string{"x"}), "MarkLoadedDriversSynced")

	_, err = s.ListContentTables(ctx)
	assert.Error(t, err, "ListContentTables")
	_, err = s.DescribeTable(ctx, "machines")
	assert.Error(t, err, "DescribeTable")
	_, err = s.GetRowReport(ctx, "machines", map[string]string{"id": id.String()})
	assert.Error(t, err, "GetRowReport")
	_, err = s.ListJoinedRows(ctx, view.Join)
	assert.Error(t, err, "ListJoinedRows")
}

// ---------------------------------------------------------------------------
// Bare (un-migrated) store: dashboard read paths degrade to empty results
// ---------------------------------------------------------------------------

func TestBareStore_ReadPathsDegradeGracefully(t *testing.T) {
	ctx := context.Background()
	s := newBareStore(t)

	machines, err := s.GetMachinesByNaturalKeys(ctx, []string{"k1"})
	require.NoError(t, err)
	assert.Nil(t, machines)

	findings, err := s.ListFindings(ctx, store.FindingFilter{})
	require.NoError(t, err)
	assert.Nil(t, findings)

	runs, err := s.ListScanRuns(ctx, 5)
	require.NoError(t, err)
	assert.NotNil(t, runs)
	assert.Empty(t, runs)

	probes, err := s.ListProbeResults(ctx, 0)
	require.NoError(t, err)
	assert.Nil(t, probes)

	_, err = s.GetEnrolledIdentity(ctx)
	assert.ErrorIs(t, err, ErrNoIdentity)

	drivers, err := s.ListLoadedDrivers(ctx, LoadedDriverFilter{MachineID: "m", Limit: 3, Offset: 1})
	require.NoError(t, err)
	assert.Empty(t, drivers)

	bindings, err := s.ListDeviceBindings(ctx, DeviceBindingFilter{MachineID: "m", Limit: 3, Offset: 1})
	require.NoError(t, err)
	assert.Empty(t, bindings)

	// Un-migrated runtime_incidents is NOT tolerated — write paths must fail.
	_, err = s.ListRuntimeIncidents(ctx, store.IncidentFilter{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no such table")
}

// ---------------------------------------------------------------------------
// Machines: GetMachineByID, GetMachinesByNaturalKeys, corrupt rows
// ---------------------------------------------------------------------------

func TestMachineLookups(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	m1 := makeMachine("lookup-01", model.MachineTypeServer)
	m1.OSFamily = "linux"
	m2 := makeMachine("lookup-02", model.MachineTypeWorkstation)
	require.NoError(t, s.UpsertMachine(ctx, m1))
	require.NoError(t, s.UpsertMachine(ctx, m2))
	m1.ComputeNaturalKey()
	m2.ComputeNaturalKey()

	t.Run("get by id happy", func(t *testing.T) {
		got, err := s.GetMachineByID(ctx, m1.ID)
		require.NoError(t, err)
		assert.Equal(t, m1.ID, got.ID)
		assert.Equal(t, "lookup-01", got.Hostname)
		assert.Equal(t, "linux", got.OSFamily)
		assert.Equal(t, model.MachineTypeServer, got.MachineType)
	})

	t.Run("get by id not found", func(t *testing.T) {
		got, err := s.GetMachineByID(ctx, uuid.Must(uuid.NewV7()))
		assert.Nil(t, got)
		assert.ErrorIs(t, err, store.ErrNotFound)
	})

	t.Run("batch natural keys empty input", func(t *testing.T) {
		got, err := s.GetMachinesByNaturalKeys(ctx, nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("batch natural keys mixed hit and miss", func(t *testing.T) {
		got, err := s.GetMachinesByNaturalKeys(ctx, []string{m1.NaturalKey, m2.NaturalKey, "absent-key"})
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, "lookup-01", got[m1.NaturalKey].Hostname)
		assert.Equal(t, "lookup-02", got[m2.NaturalKey].Hostname)
		_, present := got["absent-key"]
		assert.False(t, present, "missing keys must be absent from the map")
	})

	t.Run("list machines offset", func(t *testing.T) {
		all, err := s.ListMachines(ctx, store.MachineFilter{})
		require.NoError(t, err)
		require.Len(t, all, 2)

		page, err := s.ListMachines(ctx, store.MachineFilter{Limit: 1, Offset: 1})
		require.NoError(t, err)
		require.Len(t, page, 1)
		assert.Equal(t, all[1].ID, page[0].ID)
	})

	t.Run("corrupt machine rows surface scan errors", func(t *testing.T) {
		insertCorrupt := func(id, firstSeen, lastSeen string) {
			t.Helper()
			_, execErr := s.RawDB().ExecContext(ctx, `
				INSERT INTO machines (id, machine_type, hostname, is_authorized, is_managed,
					discovery_source, first_seen_at, last_seen_at)
				VALUES (?, 'server', ?, 'unknown', 'unknown', 'test', ?, ?)`,
				id, "corrupt-"+id, firstSeen, lastSeen)
			require.NoError(t, execErr)
		}
		removeCorrupt := func(id string) {
			t.Helper()
			_, execErr := s.RawDB().ExecContext(ctx, `DELETE FROM machines WHERE id = ?`, id)
			require.NoError(t, execErr)
		}
		valid := time.Now().UTC().Format(time.RFC3339)

		insertCorrupt("bad-uuid", valid, valid)
		_, err := s.ListMachines(ctx, store.MachineFilter{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse machine id")
		removeCorrupt("bad-uuid")

		goodID := uuid.Must(uuid.NewV7()).String()
		insertCorrupt(goodID, "not-a-time", valid)
		_, err = s.ListMachines(ctx, store.MachineFilter{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse first_seen_at")
		removeCorrupt(goodID)

		goodID = uuid.Must(uuid.NewV7()).String()
		insertCorrupt(goodID, valid, "not-a-time")
		_, err = s.ListMachines(ctx, store.MachineFilter{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse last_seen_at")
		removeCorrupt(goodID)
	})
}

// ---------------------------------------------------------------------------
// Scan runs: GetScanRun, MarkScanCancelRequested, corrupt rows
// ---------------------------------------------------------------------------

func TestScanRunLifecycleExtras(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	completed := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	full := model.ScanRun{
		ID:               uuid.Must(uuid.NewV7()),
		StartedAt:        completed.Add(-time.Minute),
		CompletedAt:      &completed,
		Status:           model.ScanStatusCompleted,
		TotalMachines:    10,
		NewMachines:      2,
		UpdatedMachines:  3,
		AnalyzedMachines: 4,
		StaleMachines:    1,
		CoveragePercent:  87.5,
		ErrorCount:       1,
		ScopeConfig:      `{"cidr":"10.0.0.0/24"}`,
		DiscoverySources: `["network"]`,
		TriggerSource:    "api",
		TriggeredBy:      "cn=agent-1",
	}
	require.NoError(t, s.CreateScanRun(ctx, full))

	t.Run("get scan run exact fields", func(t *testing.T) {
		got, err := s.GetScanRun(ctx, full.ID)
		require.NoError(t, err)
		assert.Equal(t, full.ID, got.ID)
		assert.Equal(t, model.ScanStatusCompleted, got.Status)
		require.NotNil(t, got.CompletedAt)
		assert.True(t, got.CompletedAt.Equal(completed))
		assert.Equal(t, 10, got.TotalMachines)
		assert.Equal(t, 2, got.NewMachines)
		assert.Equal(t, 3, got.UpdatedMachines)
		assert.Equal(t, 4, got.AnalyzedMachines)
		assert.Equal(t, 1, got.StaleMachines)
		assert.InDelta(t, 87.5, got.CoveragePercent, 0.0001)
		assert.Equal(t, 1, got.ErrorCount)
		assert.Equal(t, `{"cidr":"10.0.0.0/24"}`, got.ScopeConfig)
		assert.Equal(t, `["network"]`, got.DiscoverySources)
		assert.Equal(t, "api", got.TriggerSource)
		assert.Equal(t, "cn=agent-1", got.TriggeredBy)
		assert.Nil(t, got.CancelRequestedAt)
	})

	t.Run("get scan run not found", func(t *testing.T) {
		got, err := s.GetScanRun(ctx, uuid.Must(uuid.NewV7()))
		assert.Nil(t, got)
		assert.ErrorIs(t, err, store.ErrNotFound)
	})

	t.Run("mark cancel requested roundtrip", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Second)
		require.NoError(t, s.MarkScanCancelRequested(ctx, full.ID, at))

		got, err := s.GetScanRun(ctx, full.ID)
		require.NoError(t, err)
		require.NotNil(t, got.CancelRequestedAt)
		assert.True(t, got.CancelRequestedAt.Equal(at))
		// Status untouched by a cancel request.
		assert.Equal(t, model.ScanStatusCompleted, got.Status)
	})

	t.Run("mark cancel requested not found", func(t *testing.T) {
		err := s.MarkScanCancelRequested(ctx, uuid.Must(uuid.NewV7()), time.Now().UTC())
		assert.ErrorIs(t, err, store.ErrNotFound)
	})

	t.Run("create duplicate id fails", func(t *testing.T) {
		err := s.CreateScanRun(ctx, model.ScanRun{ID: full.ID, StartedAt: time.Now().UTC()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create scan run")
	})

	t.Run("list scan runs clamps limit above 1000", func(t *testing.T) {
		runs, err := s.ListScanRuns(ctx, 5000)
		require.NoError(t, err)
		assert.Len(t, runs, 1)
	})

	t.Run("corrupt rows surface parse errors", func(t *testing.T) {
		insert := func(id, startedAt, completedAt, cancelAt string) {
			t.Helper()
			_, execErr := s.RawDB().ExecContext(ctx, `
				INSERT INTO scan_runs (id, started_at, completed_at, status, cancel_requested_at)
				VALUES (?, ?, NULLIF(?, ''), 'running', NULLIF(?, ''))`,
				id, startedAt, completedAt, cancelAt)
			require.NoError(t, execErr)
		}
		remove := func(id string) {
			t.Helper()
			_, execErr := s.RawDB().ExecContext(ctx, `DELETE FROM scan_runs WHERE id = ?`, id)
			require.NoError(t, execErr)
		}
		valid := time.Now().UTC().Format(time.RFC3339)

		insert("bad-run-id", valid, "", "")
		_, err := s.ListScanRuns(ctx, 100)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse scan run id")
		remove("bad-run-id")

		id := uuid.Must(uuid.NewV7()).String()
		insert(id, "garbage", "", "")
		_, err = s.ListScanRuns(ctx, 100)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse started_at")
		remove(id)

		id = uuid.Must(uuid.NewV7()).String()
		insert(id, valid, "garbage", "")
		_, err = s.ListScanRuns(ctx, 100)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse completed_at")
		remove(id)

		id = uuid.Must(uuid.NewV7()).String()
		insert(id, valid, "", "garbage")
		_, err = s.ListScanRuns(ctx, 100)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse cancel_requested_at")
		remove(id)

		// GetLatestScanRun hits the same corrupt row via its error branch.
		id = uuid.Must(uuid.NewV7()).String()
		insert(id, "9999-99-99", "", "")
		_, err = s.GetLatestScanRun(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get latest scan run")
		remove(id)
	})
}

// ---------------------------------------------------------------------------
// Events: filters, FK violations, corrupt rows
// ---------------------------------------------------------------------------

func TestEventsFiltersAndErrors(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	machine := makeMachine("evt-host", model.MachineTypeServer)
	require.NoError(t, s.UpsertMachine(ctx, machine))
	runA := makeScanRun(t, s)
	runB := makeScanRun(t, s)

	base := time.Now().UTC().Truncate(time.Second)
	mkEvent := func(run uuid.UUID, offsetSec int) model.MachineEvent {
		return model.MachineEvent{
			ID:        uuid.Must(uuid.NewV7()),
			EventType: model.EventMachineDiscovered,
			MachineID: machine.ID,
			ScanRunID: run,
			Severity:  model.SeverityLow,
			Details:   `{"k":"v"}`,
			Timestamp: base.Add(time.Duration(offsetSec) * time.Second),
		}
	}
	e1 := mkEvent(runA.ID, 0)
	e2 := mkEvent(runB.ID, 1)
	e3 := mkEvent(runB.ID, 2)
	require.NoError(t, s.InsertEvents(ctx, []model.MachineEvent{e1, e2, e3}))

	t.Run("filter by scan run id", func(t *testing.T) {
		got, err := s.ListEvents(ctx, store.EventFilter{ScanRunID: &runB.ID})
		require.NoError(t, err)
		require.Len(t, got, 2)
		for _, e := range got {
			assert.Equal(t, runB.ID, e.ScanRunID)
		}
	})

	t.Run("limit and offset", func(t *testing.T) {
		// timestamp DESC: e3, e2, e1 — offset 1 limit 1 lands on e2.
		got, err := s.ListEvents(ctx, store.EventFilter{Limit: 1, Offset: 1})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, e2.ID, got[0].ID)
		assert.Equal(t, `{"k":"v"}`, got[0].Details)
	})

	t.Run("insert event fk violation", func(t *testing.T) {
		bad := mkEvent(runA.ID, 3)
		bad.MachineID = uuid.Must(uuid.NewV7()) // no such machine
		err := s.InsertEvent(ctx, bad)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insert event")

		err = s.InsertEvents(ctx, []model.MachineEvent{bad})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insert event")
	})

	t.Run("corrupt event id surfaces scan error", func(t *testing.T) {
		_, err := s.RawDB().ExecContext(ctx, `
			INSERT INTO events (id, event_type, machine_id, scan_run_id, severity, timestamp)
			VALUES ('not-a-uuid', 'MachineDiscovered', ?, ?, 'low', ?)`,
			machine.ID.String(), runA.ID.String(), base.Format(time.RFC3339))
		require.NoError(t, err)

		_, err = s.ListEvents(ctx, store.EventFilter{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse event id")

		_, err = s.RawDB().ExecContext(ctx, `DELETE FROM events WHERE id = 'not-a-uuid'`)
		require.NoError(t, err)
	})
}

// ---------------------------------------------------------------------------
// Software: FK violation and corrupt row
// ---------------------------------------------------------------------------

func TestUpsertSoftware_ErrorStates(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	machine := makeMachine("sw-host", model.MachineTypeServer)
	require.NoError(t, s.UpsertMachine(ctx, machine))

	t.Run("unknown machine violates fk", func(t *testing.T) {
		ghost := uuid.Must(uuid.NewV7())
		err := s.UpsertSoftware(ctx, ghost, []model.InstalledSoftware{
			{ID: uuid.Must(uuid.NewV7()), MachineID: ghost, SoftwareName: "x", Version: "1"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insert software")
	})

	t.Run("corrupt software id surfaces scan error", func(t *testing.T) {
		_, err := s.RawDB().ExecContext(ctx, `
			INSERT INTO installed_software (id, machine_id, software_name, version)
			VALUES ('not-a-uuid', ?, 'ghostware', '0.1')`, machine.ID.String())
		require.NoError(t, err)

		_, err = s.ListSoftware(ctx, machine.ID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse software id")

		_, err = s.RawDB().ExecContext(ctx, `DELETE FROM installed_software WHERE id = 'not-a-uuid'`)
		require.NoError(t, err)
	})
}

// ---------------------------------------------------------------------------
// Config findings: insert, upsert-preserving-first-seen, filters
// ---------------------------------------------------------------------------

func TestFindingsRoundtripAndFilters(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	machineA := makeMachine("find-a", model.MachineTypeServer)
	machineB := makeMachine("find-b", model.MachineTypeServer)
	require.NoError(t, s.UpsertMachine(ctx, machineA))
	require.NoError(t, s.UpsertMachine(ctx, machineB))
	runA := makeScanRun(t, s)
	runB := makeScanRun(t, s)

	base := time.Now().UTC().Truncate(time.Second)
	f1 := model.ConfigFinding{
		ID:          uuid.Must(uuid.NewV7()),
		MachineID:   machineA.ID,
		ScanRunID:   runA.ID,
		Auditor:     "ssh_audit",
		CheckID:     "CIS-5.2.8",
		Title:       "PermitRootLogin enabled",
		Severity:    model.SeverityCritical,
		Evidence:    "PermitRootLogin yes",
		Expected:    "PermitRootLogin no",
		Remediation: "edit sshd_config",
		CISControl:  "5.2.8",
		Timestamp:   base,
	}
	f2 := model.ConfigFinding{
		ID:        uuid.Must(uuid.NewV7()),
		MachineID: machineB.ID,
		ScanRunID: runB.ID,
		Auditor:   "fs_audit",
		CheckID:   "CIS-1.1.1",
		Title:     "tmp not noexec",
		Severity:  model.SeverityLow,
		Evidence:  "rw,relatime",
		Timestamp: base.Add(time.Second),
	}
	require.NoError(t, s.InsertFindings(ctx, []model.ConfigFinding{f1, f2}))

	t.Run("empty batch is a no-op", func(t *testing.T) {
		require.NoError(t, s.InsertFindings(ctx, nil))
	})

	t.Run("list all exact fields", func(t *testing.T) {
		got, err := s.ListFindings(ctx, store.FindingFilter{})
		require.NoError(t, err)
		require.Len(t, got, 2)
		// timestamp DESC: f2 first.
		assert.Equal(t, f2.ID, got[0].ID)
		assert.Equal(t, f1.ID, got[1].ID)

		g := got[1]
		assert.Equal(t, machineA.ID, g.MachineID)
		assert.Equal(t, runA.ID, g.ScanRunID)
		assert.Equal(t, "ssh_audit", g.Auditor)
		assert.Equal(t, "CIS-5.2.8", g.CheckID)
		assert.Equal(t, "PermitRootLogin enabled", g.Title)
		assert.Equal(t, model.SeverityCritical, g.Severity)
		assert.Equal(t, "PermitRootLogin yes", g.Evidence)
		assert.Equal(t, "PermitRootLogin no", g.Expected)
		assert.Equal(t, "edit sshd_config", g.Remediation)
		assert.Equal(t, "5.2.8", g.CISControl)
		assert.True(t, g.Timestamp.Equal(base))
		// FirstSeenAt defaults to the finding's timestamp on first insert.
		assert.True(t, g.FirstSeenAt.Equal(base))
	})

	t.Run("filters", func(t *testing.T) {
		byMachine, err := s.ListFindings(ctx, store.FindingFilter{MachineID: &machineA.ID})
		require.NoError(t, err)
		require.Len(t, byMachine, 1)
		assert.Equal(t, f1.ID, byMachine[0].ID)

		byRun, err := s.ListFindings(ctx, store.FindingFilter{ScanRunID: &runB.ID})
		require.NoError(t, err)
		require.Len(t, byRun, 1)
		assert.Equal(t, f2.ID, byRun[0].ID)

		byAuditor, err := s.ListFindings(ctx, store.FindingFilter{Auditor: "fs_audit"})
		require.NoError(t, err)
		require.Len(t, byAuditor, 1)
		assert.Equal(t, f2.ID, byAuditor[0].ID)

		bySeverity, err := s.ListFindings(ctx, store.FindingFilter{Severity: string(model.SeverityCritical)})
		require.NoError(t, err)
		require.Len(t, bySeverity, 1)
		assert.Equal(t, f1.ID, bySeverity[0].ID)

		none, err := s.ListFindings(ctx, store.FindingFilter{Auditor: "nope"})
		require.NoError(t, err)
		assert.Empty(t, none)

		page, err := s.ListFindings(ctx, store.FindingFilter{Limit: 1, Offset: 1})
		require.NoError(t, err)
		require.Len(t, page, 1)
		assert.Equal(t, f1.ID, page[0].ID)
	})

	t.Run("re-insert updates evidence but preserves first_seen_at", func(t *testing.T) {
		rescan := f1
		rescan.ScanRunID = runB.ID
		rescan.Evidence = "PermitRootLogin without-password"
		rescan.Timestamp = base.Add(2 * time.Hour)
		rescan.FirstSeenAt = time.Time{}
		require.NoError(t, s.InsertFindings(ctx, []model.ConfigFinding{rescan}))

		got, err := s.ListFindings(ctx, store.FindingFilter{MachineID: &machineA.ID})
		require.NoError(t, err)
		require.Len(t, got, 1, "upsert must not duplicate the finding")
		assert.Equal(t, runB.ID, got[0].ScanRunID)
		assert.Equal(t, "PermitRootLogin without-password", got[0].Evidence)
		assert.True(t, got[0].Timestamp.Equal(base.Add(2*time.Hour)))
		assert.True(t, got[0].FirstSeenAt.Equal(base), "first_seen_at must survive the upsert")
	})

	t.Run("fk violation surfaces error", func(t *testing.T) {
		bad := f2
		bad.ID = uuid.Must(uuid.NewV7())
		bad.MachineID = uuid.Must(uuid.NewV7())
		err := s.InsertFindings(ctx, []model.ConfigFinding{bad})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insert finding")
	})
}

// ---------------------------------------------------------------------------
// Runtime incidents
// ---------------------------------------------------------------------------

func TestRuntimeIncidents(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	run := makeScanRun(t, s)

	base := time.Now().UTC().Truncate(time.Second)
	incA := model.RuntimeIncident{
		ID:           uuid.Must(uuid.NewV7()),
		IncidentType: model.IncidentPanicRecovered,
		Component:    "network-scanner",
		ErrorMessage: "index out of range",
		StackTrace:   "goroutine 1 [running]:\nmain.main()",
		ScanRunID:    &run.ID,
		Severity:     "high",
		Recovered:    true,
		ErrorCode:    "KITE-E042",
		CreatedAt:    base,
	}
	incB := model.RuntimeIncident{
		ID:           uuid.Must(uuid.NewV7()),
		IncidentType: model.IncidentTimeoutExceeded,
		Component:    "http-connector",
		ErrorMessage: "deadline exceeded",
		Severity:     "critical",
		Recovered:    false,
		CreatedAt:    base.Add(time.Second),
	}
	require.NoError(t, s.InsertRuntimeIncident(ctx, incA))
	require.NoError(t, s.InsertRuntimeIncident(ctx, incB))

	t.Run("list all exact fields", func(t *testing.T) {
		got, err := s.ListRuntimeIncidents(ctx, store.IncidentFilter{})
		require.NoError(t, err)
		require.Len(t, got, 2)
		// created_at DESC: incB first.
		assert.Equal(t, incB.ID, got[0].ID)
		assert.Equal(t, incA.ID, got[1].ID)

		a := got[1]
		assert.Equal(t, model.IncidentPanicRecovered, a.IncidentType)
		assert.Equal(t, "network-scanner", a.Component)
		assert.Equal(t, "index out of range", a.ErrorMessage)
		assert.Equal(t, "goroutine 1 [running]:\nmain.main()", a.StackTrace)
		require.NotNil(t, a.ScanRunID)
		assert.Equal(t, run.ID, *a.ScanRunID)
		assert.Equal(t, "high", a.Severity)
		assert.True(t, a.Recovered)
		assert.Equal(t, "KITE-E042", a.ErrorCode)
		assert.True(t, a.CreatedAt.Equal(base))

		b := got[0]
		assert.Nil(t, b.ScanRunID)
		assert.Empty(t, b.StackTrace)
		assert.Empty(t, b.ErrorCode)
		assert.False(t, b.Recovered)
	})

	t.Run("filters", func(t *testing.T) {
		byRun, err := s.ListRuntimeIncidents(ctx, store.IncidentFilter{ScanRunID: &run.ID})
		require.NoError(t, err)
		require.Len(t, byRun, 1)
		assert.Equal(t, incA.ID, byRun[0].ID)

		byType, err := s.ListRuntimeIncidents(ctx, store.IncidentFilter{IncidentType: string(model.IncidentTimeoutExceeded)})
		require.NoError(t, err)
		require.Len(t, byType, 1)
		assert.Equal(t, incB.ID, byType[0].ID)

		// Timestamps persist at second precision; a fractional bound
		// would string-compare incorrectly against "…38Z". Use incB's
		// exact stamp — >= keeps incB and excludes incA.
		since := base.Add(time.Second)
		recent, err := s.ListRuntimeIncidents(ctx, store.IncidentFilter{Since: &since})
		require.NoError(t, err)
		require.Len(t, recent, 1)
		assert.Equal(t, incB.ID, recent[0].ID)

		page, err := s.ListRuntimeIncidents(ctx, store.IncidentFilter{Limit: 1, Offset: 1})
		require.NoError(t, err)
		require.Len(t, page, 1)
		assert.Equal(t, incA.ID, page[0].ID)
	})

	t.Run("check constraint rejects unknown incident type", func(t *testing.T) {
		bad := incB
		bad.ID = uuid.Must(uuid.NewV7())
		bad.IncidentType = "made_up_type"
		err := s.InsertRuntimeIncident(ctx, bad)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insert runtime incident")
	})

	t.Run("garbage created_at yields zero time not error", func(t *testing.T) {
		id := uuid.Must(uuid.NewV7())
		_, err := s.RawDB().ExecContext(ctx, `
			INSERT INTO runtime_incidents (id, incident_type, component, error_message, severity, recovered, created_at)
			VALUES (?, 'panic_recovered', 'c', 'm', 'low', 0, 'garbage')`, id.String())
		require.NoError(t, err)

		got, err := s.ListRuntimeIncidents(ctx, store.IncidentFilter{IncidentType: "panic_recovered"})
		require.NoError(t, err)
		var found bool
		for _, inc := range got {
			if inc.ID == id {
				found = true
				assert.True(t, inc.CreatedAt.IsZero())
			}
		}
		assert.True(t, found)

		_, err = s.RawDB().ExecContext(ctx, `DELETE FROM runtime_incidents WHERE id = ?`, id.String())
		require.NoError(t, err)
	})
}

// ---------------------------------------------------------------------------
// Network scan safety read paths
// ---------------------------------------------------------------------------

func TestNetworkScanSafetyListing(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	t1 := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 8, 21, 11, 0, 0, 0, time.UTC)
	completed := t1.Add(90 * time.Second)

	e1 := network.ScanEvent{
		ScanID: "scan-1", AgentID: "agent-a", ScopeHash: "hash-a",
		StartedAt: t1, CompletedAt: &completed,
		IPsEnumerated: 254, IPsScanned: 200, IPsResponsive: 5,
		PortsProbedJSON: `[22,443]`, Outcome: "completed", SafetyGuardCount: 1,
	}
	e2 := network.ScanEvent{
		ScanID: "scan-2", AgentID: "agent-b", ScopeHash: "hash-b",
		StartedAt: t2, IPsEnumerated: 16, IPsScanned: 16, IPsResponsive: 0,
		PortsProbedJSON: `[80]`, Outcome: "partial",
	}
	require.NoError(t, s.WriteScanEvent(ctx, e1))
	require.NoError(t, s.WriteScanEvent(ctx, e2))

	t.Run("scan events ordered desc with exact fields", func(t *testing.T) {
		got, err := s.ListNetworkScanEvents(ctx, NetworkScanEventFilter{})
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, "scan-2", got[0].ScanID)
		assert.Equal(t, "scan-1", got[1].ScanID)

		first := got[1]
		assert.Equal(t, "agent-a", first.AgentID)
		assert.Equal(t, "hash-a", first.ScopeHash)
		assert.Equal(t, t1.Format(time.RFC3339Nano), first.StartedAt)
		require.NotNil(t, first.CompletedAt)
		assert.Equal(t, completed.Format(time.RFC3339), *first.CompletedAt)
		assert.Equal(t, int64(254), first.IPsEnumerated)
		assert.Equal(t, int64(200), first.IPsScanned)
		assert.Equal(t, int64(5), first.IPsResponsive)
		assert.Equal(t, `[22,443]`, first.PortsProbedJSON)
		assert.Equal(t, "completed", first.Outcome)
		assert.Equal(t, int64(1), first.SafetyGuardCount)

		assert.Nil(t, got[0].CompletedAt, "the in-flight scan has no completed_at")
	})

	t.Run("scan events since limit offset", func(t *testing.T) {
		since := t1.Add(30 * time.Minute)
		got, err := s.ListNetworkScanEvents(ctx, NetworkScanEventFilter{Since: &since})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "scan-2", got[0].ScanID)

		got, err = s.ListNetworkScanEvents(ctx, NetworkScanEventFilter{Limit: 1, Offset: 1})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "scan-1", got[0].ScanID)
	})

	t.Run("open ports roundtrip and filters", func(t *testing.T) {
		p1 := network.OpenPort{IPAddress: "10.0.0.1", Port: 22, Protocol: "tcp", ProbeAt: t1.Add(time.Second)}
		p2 := network.OpenPort{IPAddress: "10.0.0.2", Port: 80, ProbeAt: t1.Add(2 * time.Second)} // empty protocol
		require.NoError(t, s.WriteOpenPorts(ctx, "scan-1", []network.OpenPort{p1, p2}))
		require.NoError(t, s.WriteOpenPorts(ctx, "scan-1", nil), "empty batch is a no-op")

		got, err := s.ListNetworkOpenPorts(ctx, NetworkOpenPortFilter{ScanID: "scan-1"})
		require.NoError(t, err)
		require.Len(t, got, 2)
		// probe_at DESC: p2 first.
		assert.Equal(t, "10.0.0.2", got[0].IPAddress)
		assert.Equal(t, 80, got[0].Port)
		assert.Equal(t, "tcp", got[0].Protocol, "empty protocol defaults to tcp")
		assert.Equal(t, "10.0.0.1", got[1].IPAddress)
		assert.Equal(t, 22, got[1].Port)
		assert.Equal(t, "scan-1", got[1].ScanID)
		assert.Equal(t, t1.Add(time.Second).Format(time.RFC3339Nano), got[1].ProbeAt)
		assert.NotEmpty(t, got[0].ID)

		// probe_at persists at second precision; use p1's exact stamp so
		// the strict > bound excludes p1 and keeps p2.
		since := t1.Add(time.Second)
		newer, err := s.ListNetworkOpenPorts(ctx, NetworkOpenPortFilter{Since: &since})
		require.NoError(t, err)
		require.Len(t, newer, 1)
		assert.Equal(t, "10.0.0.2", newer[0].IPAddress)

		none, err := s.ListNetworkOpenPorts(ctx, NetworkOpenPortFilter{ScanID: "no-such-scan"})
		require.NoError(t, err)
		assert.Empty(t, none)

		paged, err := s.ListNetworkOpenPorts(ctx, NetworkOpenPortFilter{ScanID: "scan-1", Limit: 1, Offset: 1})
		require.NoError(t, err)
		require.Len(t, paged, 1)
		assert.Equal(t, "10.0.0.1", paged[0].IPAddress)
	})

	t.Run("open ports fk requires scan event", func(t *testing.T) {
		err := s.WriteOpenPorts(ctx, "ghost-scan", []network.OpenPort{
			{IPAddress: "10.9.9.9", Port: 443, ProbeAt: t1},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insert open port")
	})

	t.Run("write validation", func(t *testing.T) {
		err := s.WriteScanEvent(ctx, network.ScanEvent{StartedAt: t1})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scan_id is required")

		err = s.WriteOpenPorts(ctx, "", []network.OpenPort{{IPAddress: "1.2.3.4", Port: 1}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scan_id is required")
	})

	t.Run("guard events roundtrip and filters", func(t *testing.T) {
		g1 := safenet.GuardEvent{
			GuardType:       safenet.GuardIPCountCap,
			Action:          safenet.GuardActionCapped,
			TriggeredAt:     t1,
			InputSummary:    "cidr 10.0.0.0/8",
			SourceComponent: "network-scanner",
			DetailsJSON:     `{"cap":4096}`,
			ScanID:          "scan-1",
		}
		g2 := safenet.GuardEvent{
			GuardType:       safenet.GuardSSRFScopeBlock,
			Action:          safenet.GuardActionRejected,
			TriggeredAt:     t2,
			InputSummary:    "169.254.169.254",
			SourceComponent: "http-connector",
			DetailsJSON:     `{}`,
		}
		require.NoError(t, s.WriteGuardEvent(ctx, g1))
		require.NoError(t, s.WriteGuardEvent(ctx, g2))

		got, err := s.ListSafetyGuardEvents(ctx, SafetyGuardEventFilter{})
		require.NoError(t, err)
		require.Len(t, got, 2)
		// triggered_at DESC: g2 first.
		assert.Equal(t, "ssrf_scope_block", got[0].GuardType)
		assert.Equal(t, "rejected", got[0].ActionTaken)
		assert.Nil(t, got[0].ScanID)

		first := got[1]
		assert.Equal(t, "ip_count_cap", first.GuardType)
		assert.Equal(t, "capped", first.ActionTaken)
		assert.Equal(t, t1.Format(time.RFC3339Nano), first.TriggeredAt)
		assert.Equal(t, "cidr 10.0.0.0/8", first.InputSummary)
		assert.Equal(t, "network-scanner", first.SourceComponent)
		assert.Equal(t, `{"cap":4096}`, first.DetailsJSON)
		require.NotNil(t, first.ScanID)
		assert.Equal(t, "scan-1", *first.ScanID)

		byType, err := s.ListSafetyGuardEvents(ctx, SafetyGuardEventFilter{GuardType: "ip_count_cap"})
		require.NoError(t, err)
		require.Len(t, byType, 1)
		assert.Equal(t, "ip_count_cap", byType[0].GuardType)

		since := t1.Add(time.Minute)
		newer, err := s.ListSafetyGuardEvents(ctx, SafetyGuardEventFilter{Since: &since})
		require.NoError(t, err)
		require.Len(t, newer, 1)
		assert.Equal(t, "ssrf_scope_block", newer[0].GuardType)

		paged, err := s.ListSafetyGuardEvents(ctx, SafetyGuardEventFilter{Limit: 1, Offset: 1})
		require.NoError(t, err)
		require.Len(t, paged, 1)
		assert.Equal(t, "ip_count_cap", paged[0].GuardType)
	})

	t.Run("guard event check constraint", func(t *testing.T) {
		err := s.WriteGuardEvent(ctx, safenet.GuardEvent{
			GuardType: "made_up_guard", Action: safenet.GuardActionLogged, TriggeredAt: t1,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insert safety_guard_events")
	})
}

// ---------------------------------------------------------------------------
// Identity: delete + AEAD edge cases
// ---------------------------------------------------------------------------

func TestEnrolledIdentityDelete(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	require.NoError(t, s.DeleteEnrolledIdentity(ctx), "deleting a missing identity is a no-op")

	id := EnrolledIdentity{
		ApiKeyFingerprint: APIKeyFingerprint("kite_test_key"),
		ApiKeyWrapped:     []byte{0x01, 0x02, 0x03},
	}
	require.NoError(t, s.UpsertEnrolledIdentity(ctx, id))

	got, err := s.GetEnrolledIdentity(ctx)
	require.NoError(t, err)
	assert.Equal(t, id.ApiKeyFingerprint, got.ApiKeyFingerprint)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, got.ApiKeyWrapped)

	require.NoError(t, s.DeleteEnrolledIdentity(ctx))
	_, err = s.GetEnrolledIdentity(ctx)
	assert.ErrorIs(t, err, ErrNoIdentity)
}

func TestAEADUnwrap_EdgeCases(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	t.Run("wrong key length", func(t *testing.T) {
		_, err := AEADUnwrap(key[:16], []byte("whatever"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key must be 32 bytes, got 16")
	})

	t.Run("ciphertext shorter than nonce", func(t *testing.T) {
		_, err := AEADUnwrap(key, []byte{0x01, 0x02, 0x03})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext too short")
	})

	t.Run("tampered blob fails authentication", func(t *testing.T) {
		wrapped, err := AEADWrap(key, []byte("secret"))
		require.NoError(t, err)
		wrapped[len(wrapped)-1] ^= 0xFF
		_, err = AEADUnwrap(key, wrapped)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authentication failed")
	})
}

// ---------------------------------------------------------------------------
// Heartbeats: remaining filters and corrupt rows
// ---------------------------------------------------------------------------

func TestListHeartbeats_SinceOffsetAndCorruptRows(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	scanID := newScanRun(t, s)

	base := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	mk := func(source string, offset time.Duration) model.ProbeHeartbeat {
		return model.ProbeHeartbeat{
			ID:           uuid.Must(uuid.NewV7()),
			ScanRunID:    scanID,
			Source:       source,
			Status:       model.HeartbeatOK,
			ItemsEmitted: 3,
			DurationMS:   150,
			BinaryHash:   "sha256:abc",
			Signature:    []byte{0xAA},
			CreatedAt:    base.Add(offset),
		}
	}
	hb1 := mk("network", 0)
	hb2 := mk("osquery", time.Second)
	hb3 := mk("vpn", 2*time.Second)
	require.NoError(t, s.RecordHeartbeat(ctx, hb1))
	require.NoError(t, s.RecordHeartbeat(ctx, hb2))
	require.NoError(t, s.RecordHeartbeat(ctx, hb3))

	t.Run("since filter", func(t *testing.T) {
		since := base.Add(time.Second)
		got, err := s.ListHeartbeats(ctx, store.HeartbeatFilter{Since: &since})
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, "vpn", got[0].Source)
		assert.Equal(t, "osquery", got[1].Source)
	})

	t.Run("limit and offset", func(t *testing.T) {
		got, err := s.ListHeartbeats(ctx, store.HeartbeatFilter{Limit: 1, Offset: 1})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "osquery", got[0].Source)
		assert.Equal(t, hb2.ID, got[0].ID)
		assert.Equal(t, 3, got[0].ItemsEmitted)
		assert.Equal(t, int64(150), got[0].DurationMS)
		assert.Equal(t, "sha256:abc", got[0].BinaryHash)
		assert.Equal(t, []byte{0xAA}, got[0].Signature)
	})

	t.Run("corrupt rows surface parse errors", func(t *testing.T) {
		insert := func(id, createdAt string) {
			t.Helper()
			_, execErr := s.RawDB().ExecContext(ctx, `
				INSERT INTO probe_heartbeats (id, scan_run_id, source, status, items_emitted,
					duration_ms, binary_hash, signature, created_at)
				VALUES (?, ?, 'corrupt-src', 'ok', 0, 0, '', X'', ?)`,
				id, scanID.String(), createdAt)
			require.NoError(t, execErr)
		}
		remove := func(id string) {
			t.Helper()
			_, execErr := s.RawDB().ExecContext(ctx, `DELETE FROM probe_heartbeats WHERE id = ?`, id)
			require.NoError(t, execErr)
		}

		insert("not-a-uuid", base.Format(time.RFC3339Nano))
		_, err := s.ListHeartbeats(ctx, store.HeartbeatFilter{Source: "corrupt-src"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse heartbeat id")
		remove("not-a-uuid")

		goodID := uuid.Must(uuid.NewV7()).String()
		insert(goodID, "garbage")
		_, err = s.ListHeartbeats(ctx, store.HeartbeatFilter{Source: "corrupt-src"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse heartbeat created_at")
		remove(goodID)
	})
}

// ---------------------------------------------------------------------------
// Saved views: corrupt persisted rows and unique violations
// ---------------------------------------------------------------------------

func TestSavedViews_CorruptRowsAndConstraints(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	insertRaw := func(slug, id, cols, createdAt string) {
		t.Helper()
		_, err := s.RawDB().ExecContext(ctx, `
			INSERT INTO saved_views (id, name, slug, base_table, join_table, join_type,
				on_base, on_join, columns, created_at)
			VALUES (?, ?, ?, 'machines', 'events', 'left', 'id', 'machine_id', ?, ?)`,
			id, "name-"+slug, slug, cols, createdAt)
		require.NoError(t, err)
	}

	t.Run("invalid id", func(t *testing.T) {
		insertRaw("bad-id", "not-a-uuid", `[]`, "2026-08-21T10:00:00.000000000Z")
		_, err := s.GetSavedViewBySlug(ctx, "bad-id")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid id")
	})

	t.Run("invalid columns json", func(t *testing.T) {
		insertRaw("bad-cols", uuid.Must(uuid.NewV7()).String(), `{broken`, "2026-08-21T10:00:00Z")
		_, err := s.GetSavedViewBySlug(ctx, "bad-cols")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode saved view columns")
	})

	t.Run("second-precision created_at tolerated", func(t *testing.T) {
		insertRaw("sec-precision", uuid.Must(uuid.NewV7()).String(),
			`[{"table":"machines","column":"hostname"}]`, "2026-08-21T10:00:00Z")
		got, err := s.GetSavedViewBySlug(ctx, "sec-precision")
		require.NoError(t, err)
		assert.Equal(t, time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC), got.CreatedAt.UTC())
		require.Len(t, got.Join.Columns, 1)
		assert.Equal(t, store.JoinColumn{Table: "machines", Column: "hostname"}, got.Join.Columns[0])
	})

	t.Run("garbage created_at rejected", func(t *testing.T) {
		insertRaw("bad-time", uuid.Must(uuid.NewV7()).String(), `[]`, "yesterday")
		_, err := s.GetSavedViewBySlug(ctx, "bad-time")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid created_at")
	})

	t.Run("not found", func(t *testing.T) {
		_, err := s.GetSavedViewBySlug(ctx, "no-such-slug")
		assert.ErrorIs(t, err, store.ErrNotFound)
	})

	t.Run("duplicate slug is a unique violation", func(t *testing.T) {
		view := store.SavedView{
			Name: "Dup View",
			Slug: "dup-view",
			Join: store.JoinFilter{
				Base: "machines", Join: "events", Type: store.JoinLeft,
				OnBase: "id", OnJoin: "machine_id",
				Columns: []store.JoinColumn{{Table: "machines", Column: "hostname"}},
			},
		}
		require.NoError(t, s.SaveView(ctx, view))

		dup := view
		dup.Name = "Other Name"
		err := s.SaveView(ctx, dup)
		require.Error(t, err)
		assert.True(t, ErrIsUniqueViolation(err), "duplicate slug must be detectable as a unique violation")

		assert.False(t, ErrIsUniqueViolation(nil))
		assert.False(t, ErrIsUniqueViolation(errors.New("boom")))

		require.NoError(t, s.DeleteSavedView(ctx, "dup-view"))
		_, err = s.GetSavedViewBySlug(ctx, "dup-view")
		assert.ErrorIs(t, err, store.ErrNotFound)
		require.NoError(t, s.DeleteSavedView(ctx, "dup-view"), "deleting an absent view is a no-op")
	})
}

// ---------------------------------------------------------------------------
// Small helpers: retry + duplicate-column matcher
// ---------------------------------------------------------------------------

func TestWithTransientRetry_NonPositiveAttemptsRunsOnce(t *testing.T) {
	calls := 0
	err := withTransientRetry(0, func() error {
		calls++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
}

func TestIsDuplicateColumnErr(t *testing.T) {
	assert.True(t, isDuplicateColumnErr(errors.New(`SQL logic error: duplicate column name: site (1)`)))
	assert.False(t, isDuplicateColumnErr(errors.New("no such table: machines")))
	assert.False(t, isDuplicateColumnErr(nil))
}

// ---------------------------------------------------------------------------
// Concurrency: parallel UpsertMachines batches against one store
// ---------------------------------------------------------------------------

func TestUpsertMachines_ParallelBatches(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	const (
		workers      = 8
		perWorker    = 10
		totalUnique  = workers * perWorker
		updateRounds = workers
	)

	// Phase 1: disjoint batches inserted concurrently — every row is new.
	var wg sync.WaitGroup
	insertCounts := make([]int, workers)
	insertErrs := make([]error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			batch := make([]model.Machine, 0, perWorker)
			for i := 0; i < perWorker; i++ {
				m := makeMachine(
					fmt.Sprintf("par-%02d-%02d", w, i),
					model.MachineTypeServer)
				batch = append(batch, m)
			}
			ins, upd, err := s.UpsertMachines(ctx, batch)
			insertErrs[w] = err
			insertCounts[w] = ins
			if err == nil && upd != 0 {
				insertErrs[w] = errors.New("unexpected updates in disjoint insert phase")
			}
		}(w)
	}
	wg.Wait()
	totalInserted := 0
	for w := 0; w < workers; w++ {
		require.NoError(t, insertErrs[w], "worker %d", w)
		totalInserted += insertCounts[w]
	}
	assert.Equal(t, totalUnique, totalInserted)

	all, err := s.ListMachines(ctx, store.MachineFilter{})
	require.NoError(t, err)
	require.Len(t, all, totalUnique)

	// Phase 2: every worker re-upserts the SAME shared batch concurrently.
	// Rows already exist, so each transaction must count them all as updates —
	// exercising the withTransientRetry path under real write contention.
	shared := make([]model.Machine, 0, perWorker)
	for i := 0; i < perWorker; i++ {
		m := all[i]
		m.OSFamily = "linux"
		shared = append(shared, m)
	}
	updateErrs := make([]error, updateRounds)
	updateCounts := make([]int, updateRounds)
	for w := 0; w < updateRounds; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			batch := make([]model.Machine, len(shared))
			copy(batch, shared)
			ins, upd, upErr := s.UpsertMachines(ctx, batch)
			updateErrs[w] = upErr
			updateCounts[w] = upd
			if upErr == nil && ins != 0 {
				updateErrs[w] = errors.New("unexpected inserts in update phase")
			}
		}(w)
	}
	wg.Wait()
	for w := 0; w < updateRounds; w++ {
		require.NoError(t, updateErrs[w], "update worker %d", w)
		assert.Equal(t, perWorker, updateCounts[w], "update worker %d must update the full batch", w)
	}

	// No duplicates were created by concurrent upserts of the same rows.
	final, err := s.ListMachines(ctx, store.MachineFilter{})
	require.NoError(t, err)
	assert.Len(t, final, totalUnique)
}
