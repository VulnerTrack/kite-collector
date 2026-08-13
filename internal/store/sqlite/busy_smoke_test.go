package sqlite

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safety"
)

// These tests pin the SQLite concurrency configuration that keeps
// multi-source scans from degenerating into SQLITE_BUSY storms.
//
// History: the DSN used mattn/go-sqlite3 parameter syntax
// (?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on), which
// modernc.org/sqlite — the driver this CGO-free build actually uses —
// ignores silently. The store therefore ran with journal_mode=delete,
// busy_timeout=0 and foreign_keys=0, and ~50 concurrent source goroutines
// writing heartbeats produced "database is locked (5) (SQLITE_BUSY)" on
// most telemetry writes (991/1000 failures in a 40-goroutine reproduction).
// The DSN now uses modernc's _pragma= form; these tests fail loudly if the
// pragmas ever stop taking effect (e.g. a driver swap re-introducing the
// syntax mismatch) or if concurrent writes start erroring again.

// TestPragmasEffective asserts the DSN pragmas actually apply to the pool's
// connections — the exact regression that caused the BUSY storms.
func TestPragmasEffective(t *testing.T) {
	s := newTestStore(t)

	for pragma, want := range map[string]string{
		// Persistent / file-level.
		"journal_mode":       "wal",
		"wal_autocheckpoint": "2000",
		"journal_size_limit": "67108864", // 64 MiB
		"synchronous":        "1",        // NORMAL
		"temp_store":         "2",        // MEMORY
		// Per-connection.
		"busy_timeout": "5000",
		"foreign_keys": "1",
		"cache_size":   "-32768",    // 32 MiB
		"mmap_size":    "268435456", // 256 MiB
	} {
		var got string
		require.NoError(t, s.RawDB().QueryRowContext(context.Background(), "PRAGMA "+pragma+";").Scan(&got),
			"PRAGMA %s", pragma)
		assert.Equal(t, want, got, "PRAGMA %s not applied via DSN", pragma)
	}

	// cache_spill reports its page-count threshold when enabled (0 = off).
	var spill int
	require.NoError(t, s.RawDB().QueryRowContext(context.Background(), "PRAGMA cache_spill;").Scan(&spill))
	assert.Positive(t, spill, "cache_spill must be enabled")
}

// TestMaintenancePragmas exercises the one-time / periodic maintenance
// helpers wired into initialization and Migrate.
func TestMaintenancePragmas(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.Optimize(ctx))
	require.NoError(t, s.Checkpoint(ctx))
}

// TestForeignKeysEnforced proves FK enforcement is really on: with the old
// broken DSN this insert succeeded silently. probe_heartbeats.scan_run_id
// REFERENCES scan_runs(id), so a heartbeat for a scan run that doesn't
// exist must be rejected.
func TestForeignKeysEnforced(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	err := s.RecordHeartbeat(ctx, model.ProbeHeartbeat{
		ID:        uuid.Must(uuid.NewV7()),
		ScanRunID: uuid.Must(uuid.NewV7()), // no such scan run
		Source:    "osquery",
		Signature: []byte{0x01},
		Status:    model.HeartbeatOK,
		CreatedAt: time.Now().UTC(),
	})
	require.Error(t, err, "heartbeat with dangling scan_run_id must violate the FK")
	assert.Contains(t, err.Error(), "FOREIGN KEY", "expected an FK violation, got: %v", err)
}

// TestHeavyWriteWorkload_NoBusy replays the scan write pattern at higher
// intensity than production: every discovery source goroutine emitting
// heartbeats and circuit-breaker health while machine batches upsert in
// parallel. All writes must succeed — with WAL + busy_timeout + a single
// write connection, contention is queueing, never an error.
func TestHeavyWriteWorkload_NoBusy(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	scanRun := model.ScanRun{
		ID:            uuid.Must(uuid.NewV7()),
		StartedAt:     time.Now().UTC(),
		Status:        model.ScanStatusRunning,
		TriggerSource: "cli",
	}
	require.NoError(t, s.CreateScanRun(ctx, scanRun))

	const (
		goroutines = 40 // ~50 registered sources in a real scan
		iterations = 25
	)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	record := func(err error) {
		if err != nil {
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
		}
	}

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			// One unique source per goroutine, mirroring the registry: a
			// source emits exactly ONE heartbeat per scan run (the schema
			// enforces UNIQUE(scan_run_id, source)) but many health
			// snapshots and machine upserts.
			source := fmt.Sprintf("src-%02d", g)
			record(s.RecordHeartbeat(ctx, model.ProbeHeartbeat{
				ID:        uuid.Must(uuid.NewV7()),
				ScanRunID: scanRun.ID,
				Source:    source,
				Signature: []byte{0x01},
				Status:    model.HeartbeatOK,
				CreatedAt: time.Now().UTC(),
			}))
			for i := 0; i < iterations; i++ {
				if i%2 == 0 {
					record(s.PersistSourceHealth(safety.SourceHealth{
						SourceName:       source,
						State:            safety.CircuitHealthy,
						FailureThreshold: 3,
						CooldownSeconds:  300,
					}))
				} else {
					_, _, err := s.UpsertMachines(ctx, []model.Machine{
						makeMachine(fmt.Sprintf("host-%s-%d", source, i), model.MachineTypeServer),
					})
					record(err)
				}
			}
		}(g)
	}
	wg.Wait()

	require.Empty(t, errs, "concurrent writes must never surface SQLITE_BUSY; first error: %v",
		func() error {
			if len(errs) > 0 {
				return errs[0]
			}
			return nil
		}())

	// The writes must also have landed — silence via dropped rows would
	// pass the error check while still losing telemetry.
	var heartbeats, health int
	require.NoError(t, s.RawDB().QueryRowContext(ctx, `SELECT COUNT(*) FROM probe_heartbeats`).Scan(&heartbeats))
	require.NoError(t, s.RawDB().QueryRowContext(ctx, `SELECT COUNT(*) FROM source_health`).Scan(&health))
	assert.Equal(t, goroutines, heartbeats, "every source's heartbeat must land")
	assert.Equal(t, goroutines, health, "every source's health snapshot must land")
}

// TestNewRejectsUnreadablePath keeps New's error path honest now that the
// pragma bootstrap happens at connection time instead of via post-open Execs.
func TestNewRejectsUnreadablePath(t *testing.T) {
	_, err := New(filepath.Join(t.TempDir(), "no-such-dir", "kite.db"))
	require.Error(t, err)
}

// TestHeavyWriteWorkload_MemoryBounded pins the memory cost of the store
// under the same heavy concurrent write pattern: total memory obtained from
// the OS by the process must stay under 1/8 of the machine's available
// memory. This guards the DSN's cache_size/mmap_size choices — a future
// bump (or a pragma applying per-connection across a widened pool) that
// makes the store memory-hungry fails here instead of on an endpoint.
func TestHeavyWriteWorkload_MemoryBounded(t *testing.T) {
	avail := memAvailableBytes(t)
	budget := avail / 8

	s := newTestStore(t)
	ctx := context.Background()

	scanRun := model.ScanRun{
		ID:            uuid.Must(uuid.NewV7()),
		StartedAt:     time.Now().UTC(),
		Status:        model.ScanStatusRunning,
		TriggerSource: "cli",
	}
	require.NoError(t, s.CreateScanRun(ctx, scanRun))

	var wg sync.WaitGroup
	for g := 0; g < 40; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			source := fmt.Sprintf("mem-src-%02d", g)
			_ = s.RecordHeartbeat(ctx, model.ProbeHeartbeat{
				ID:        uuid.Must(uuid.NewV7()),
				ScanRunID: scanRun.ID,
				Source:    source,
				Signature: []byte{0x01},
				Status:    model.HeartbeatOK,
				CreatedAt: time.Now().UTC(),
			})
			for i := 0; i < 25; i++ {
				_, _, _ = s.UpsertMachines(ctx, []model.Machine{
					makeMachine(fmt.Sprintf("mem-host-%s-%d", source, i), model.MachineTypeServer),
				})
			}
		}(g)
	}
	wg.Wait()

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	t.Logf("memory after heavy writes: Sys=%dMiB HeapAlloc=%dMiB budget(available/8)=%dMiB",
		ms.Sys/1024/1024, ms.HeapAlloc/1024/1024, budget/1024/1024)
	assert.Less(t, ms.Sys, budget,
		"store under heavy writes must stay below 1/8 of available memory")
}

// memAvailableBytes reads MemAvailable from /proc/meminfo. Skips on
// platforms without it — the budget is a Linux agent-host guarantee.
func memAvailableBytes(t *testing.T) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		t.Skipf("no /proc/meminfo on this platform: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		kb, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			break
		}
		return kb * 1024
	}
	t.Skip("MemAvailable not found in /proc/meminfo")
	return 0
}
