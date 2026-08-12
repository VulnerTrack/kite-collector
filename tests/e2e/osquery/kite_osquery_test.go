//go:build osquerysim

// Package osquery_e2e drives the real osquery discovery source against the
// simulated osqueryd (docker-compose.osquery.yml) over its actual extensions
// socket. Run via the kite-runner compose service:
//
//	make test-osquery-kite
//
// These tests verify the wire contract the unit suite can only fake: the
// hand-rolled Thrift client against a live daemon, loud-vs-silent error
// behavior, a real YARA match, and eventually-consistent FIM delivery.
package osquery_e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	osquerydisc "github.com/vulnertrack/kite-collector/internal/discovery/osquery"
)

const sigfile = "/etc/osquery/yara/kite.yar"

func socketPath(t *testing.T) string {
	t.Helper()
	sock := os.Getenv("KITE_OSQUERY_SOCKET")
	if sock == "" {
		t.Skip("KITE_OSQUERY_SOCKET not set; run via the kite-runner compose service")
	}
	return sock
}

func watchDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("OSQUERY_WATCH_DIR")
	if dir == "" {
		dir = "/var/kite/watch"
	}
	return dir
}

func ctxWithTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ---------------------------------------------------------------------------
// Transport: the hand-rolled Thrift client against the live daemon
// ---------------------------------------------------------------------------

func TestLive_PingAndVersion(t *testing.T) {
	client := osquerydisc.NewClient(socketPath(t))
	ctx := ctxWithTimeout(t)
	require.NoError(t, client.Ping(ctx))

	row, err := client.QueryOne(ctx, "SELECT version FROM osquery_info;")
	require.NoError(t, err)
	require.NotNil(t, row)
	assert.NotEmpty(t, row["version"])
	t.Logf("live osqueryd version: %s", row["version"])
}

func TestLive_LoudErrors_AreQueryErrors(t *testing.T) {
	client := osquerydisc.NewClient(socketPath(t))
	ctx := ctxWithTimeout(t)
	cases := map[string]string{
		"nonexistent table": "SELECT * FROM kite_no_such_table;",
		"syntax error":      "SELEC 1;",
		"unconstrained yara": "SELECT count(*) FROM yara;",
		"unconstrained hash": "SELECT count(*) FROM hash;",
	}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := client.Query(ctx, sql)
			require.Error(t, err, "daemon must reject: %s", sql)
			assert.True(t, osquerydisc.IsQueryError(err),
				"rejection must decode as a queryError, got: %v", err)
		})
	}
}

func TestLive_SilentZero_MissingSigfile(t *testing.T) {
	client := osquerydisc.NewClient(socketPath(t))
	rows, err := client.Query(ctxWithTimeout(t),
		"SELECT count FROM yara WHERE path='/etc/hostname' AND sigfile='/kite-nope.yar';")
	require.NoError(t, err, "missing sigfile must be SILENT, not an error")
	assert.Empty(t, rows)
}

func TestLive_ConcurrentQueries(t *testing.T) {
	client := osquerydisc.NewClient(socketPath(t))
	ctx := ctxWithTimeout(t)
	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, errs[n] = client.Query(ctx, "SELECT pid FROM osquery_info;")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		assert.NoError(t, err, "concurrent call %d", i)
	}
}

// ---------------------------------------------------------------------------
// Source: Discover end to end
// ---------------------------------------------------------------------------

func TestLive_Discover_HostIdentity(t *testing.T) {
	src := osquerydisc.New()
	machines, err := src.Discover(ctxWithTimeout(t), map[string]any{"socket": socketPath(t)})
	require.NoError(t, err)
	require.Len(t, machines, 1)

	m := machines[0]
	assert.NotEmpty(t, m.Hostname)
	assert.Equal(t, "linux", m.OSFamily)
	assert.NotEmpty(t, m.OSVersion)
	assert.Equal(t, "osquery", m.DiscoverySource)

	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(m.Tags), &tags))
	assert.NotEmpty(t, tags["osquery_version"])
}

func TestLive_Discover_YaraMatchOnPlantedCanary(t *testing.T) {
	canary := filepath.Join(watchDir(t), "yara",
		fmt.Sprintf("e2e-canary-%d.txt", time.Now().UnixNano()))
	require.NoError(t, os.MkdirAll(filepath.Dir(canary), 0o755))
	require.NoError(t, os.WriteFile(canary,
		[]byte("kite e2e canary: KITE-OSQUERY-SIM-YARA-CANARY\n"), 0o644))
	t.Cleanup(func() { _ = os.Remove(canary) })

	src := osquerydisc.New()
	machines, err := src.Discover(ctxWithTimeout(t), map[string]any{
		"socket":       socketPath(t),
		"yara_sigfile": sigfile,
		"yara_paths":   []any{canary},
	})
	require.NoError(t, err)
	require.Len(t, machines, 1)

	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(machines[0].Tags), &tags))
	assert.Equal(t, true, tags["yara_scanned"], "sigfile is baked into the sim image; scan must run")
	assert.Equal(t, float64(1), tags["yara_match_count"], "canary must match kite_sim_canary")
}

func TestLive_Discover_CleanFileNoMatch(t *testing.T) {
	clean := filepath.Join(watchDir(t), "yara",
		fmt.Sprintf("e2e-clean-%d.txt", time.Now().UnixNano()))
	require.NoError(t, os.MkdirAll(filepath.Dir(clean), 0o755))
	require.NoError(t, os.WriteFile(clean, []byte("nothing here\n"), 0o644))
	t.Cleanup(func() { _ = os.Remove(clean) })

	src := osquerydisc.New()
	machines, err := src.Discover(ctxWithTimeout(t), map[string]any{
		"socket":       socketPath(t),
		"yara_sigfile": sigfile,
		"yara_paths":   []any{clean},
	})
	require.NoError(t, err)

	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(machines[0].Tags), &tags))
	assert.Equal(t, true, tags["yara_scanned"])
	assert.Equal(t, float64(0), tags["yara_match_count"])
}

func TestLive_Discover_InvisibleSigfileSkipsScan(t *testing.T) {
	src := osquerydisc.New()
	machines, err := src.Discover(ctxWithTimeout(t), map[string]any{
		"socket":       socketPath(t),
		"yara_sigfile": "/definitely/not/there.yar",
		"yara_paths":   []any{"/etc/hostname"},
	})
	require.NoError(t, err)

	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(machines[0].Tags), &tags))
	_, scanned := tags["yara_scanned"]
	assert.False(t, scanned, "an invisible sigfile must skip the scan, not report clean")
}

// ---------------------------------------------------------------------------
// FIM: eventually-consistent delivery through the source
// ---------------------------------------------------------------------------

func TestLive_FileEvents_CanaryEventuallyVisible(t *testing.T) {
	fim := filepath.Join(watchDir(t), "fim",
		fmt.Sprintf("e2e-fim-%d.txt", time.Now().UnixNano()))
	require.NoError(t, os.MkdirAll(filepath.Dir(fim), 0o755))
	require.NoError(t, os.WriteFile(fim, []byte("fim canary\n"), 0o644))
	t.Cleanup(func() { _ = os.Remove(fim) })

	src := osquerydisc.New()
	cfg := map[string]any{"socket": socketPath(t)}
	deadline := time.Now().Add(60 * time.Second)
	for {
		events, err := src.FileEvents(ctxWithTimeout(t), cfg, time.Now().Add(-time.Hour).Unix())
		require.NoError(t, err)
		for _, ev := range events {
			if ev.TargetPath == fim {
				assert.NotEmpty(t, ev.Action)
				return // delivered
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("file event for %s never arrived (async budget 60s)", fim)
		}
		time.Sleep(time.Second)
	}
}

// TestLive_Discover_InlineRules exercises the sigrule path against the live
// daemon: an inline YARA rule (no daemon-side file) matches a planted canary,
// and a malformed inline rule is caught by the compile probe and skipped.
func TestLive_Discover_InlineRules(t *testing.T) {
	canary := filepath.Join(watchDir(t), "yara",
		fmt.Sprintf("e2e-inline-%d.txt", time.Now().UnixNano()))
	require.NoError(t, os.MkdirAll(filepath.Dir(canary), 0o755))
	require.NoError(t, os.WriteFile(canary,
		[]byte("inline probe: KITE-INLINE-CANARY\n"), 0o644))
	t.Cleanup(func() { _ = os.Remove(canary) })

	rule := `rule kite_inline { strings: $m = "KITE-INLINE-CANARY" condition: $m }`
	src := osquerydisc.New()
	machines, err := src.Discover(ctxWithTimeout(t), map[string]any{
		"socket":     socketPath(t),
		"yara_rules": rule,
		"yara_paths": []any{canary},
	})
	require.NoError(t, err)

	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(machines[0].Tags), &tags))
	assert.Equal(t, true, tags["yara_scanned"], "inline rule needs no sigfile; scan must run")
	assert.Equal(t, float64(1), tags["yara_match_count"])
}

func TestLive_Discover_MalformedInlineRuleSkips(t *testing.T) {
	src := osquerydisc.New()
	machines, err := src.Discover(ctxWithTimeout(t), map[string]any{
		"socket":     socketPath(t),
		"yara_rules": "rule broken {", // does not compile
		"yara_paths": []any{"/etc/hostname"},
	})
	require.NoError(t, err)

	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(machines[0].Tags), &tags))
	_, scanned := tags["yara_scanned"]
	assert.False(t, scanned, "malformed inline rule must be caught by the compile probe and skipped")
}

// TestLive_Discover_MissingPathNotReportedClean proves against the live
// daemon that a configured scan path which does not exist is treated as a
// coverage gap, not silently folded into a clean result. osquery emits no
// row for an unopenable file (doYARAScanPath only pushes on ERROR_SUCCESS).
func TestLive_Discover_MissingPathNotReportedClean(t *testing.T) {
	missing := filepath.Join(watchDir(t), "yara",
		fmt.Sprintf("does-not-exist-%d.txt", time.Now().UnixNano()))
	src := osquerydisc.New()
	machines, err := src.Discover(ctxWithTimeout(t), map[string]any{
		"socket":       socketPath(t),
		"yara_sigfile": sigfile,
		"yara_paths":   []any{missing}, // the only path, and it is absent
	})
	require.NoError(t, err)

	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(machines[0].Tags), &tags))
	_, scanned := tags["yara_scanned"]
	assert.False(t, scanned, "a missing scan target must not be reported as a clean scan")
}

func TestLive_Discover_MixedPresentAndMissingPaths(t *testing.T) {
	present := filepath.Join(watchDir(t), "yara",
		fmt.Sprintf("present-%d.txt", time.Now().UnixNano()))
	require.NoError(t, os.MkdirAll(filepath.Dir(present), 0o755))
	require.NoError(t, os.WriteFile(present, []byte("clean\n"), 0o644))
	t.Cleanup(func() { _ = os.Remove(present) })
	missing := filepath.Join(watchDir(t), "yara",
		fmt.Sprintf("absent-%d.txt", time.Now().UnixNano()))

	src := osquerydisc.New()
	machines, err := src.Discover(ctxWithTimeout(t), map[string]any{
		"socket":       socketPath(t),
		"yara_sigfile": sigfile,
		"yara_paths":   []any{present, missing},
	})
	require.NoError(t, err)

	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(machines[0].Tags), &tags))
	assert.Equal(t, true, tags["yara_scanned"], "the present path scanned")
	assert.Equal(t, float64(1), tags["yara_paths_unscannable"], "the absent path is a reported coverage gap")
}

// TestLive_FileEventsWindow_TracksEventsExpiry proves the FIM summary window
// tracks the daemon's real retention (events_expiry, 3600s in the sim) rather
// than a hardcoded 24h the daemon can never fill.
func TestLive_FileEventsWindow_TracksEventsExpiry(t *testing.T) {
	src := osquerydisc.New()
	machines, err := src.Discover(ctxWithTimeout(t), map[string]any{"socket": socketPath(t)})
	require.NoError(t, err)
	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(machines[0].Tags), &tags))
	assert.Equal(t, float64(3600), tags["file_events_window_secs"], "sim events_expiry default")
	_, old := tags["file_events_24h"]
	assert.False(t, old, "the misleading 24h tag must be gone")
}

// TestLive_FileEvents_RepeatedCallsAreConsistent guards the events_optimize
// landmine: with the load-bearing `time >` constraint, repeated file_events
// reads over the socket return a stable window, NOT a shrinking differential.
func TestLive_FileEvents_RepeatedCallsAreConsistent(t *testing.T) {
	fim := filepath.Join(watchDir(t), "fim",
		fmt.Sprintf("e2e-consistent-%d.txt", time.Now().UnixNano()))
	require.NoError(t, os.MkdirAll(filepath.Dir(fim), 0o755))
	require.NoError(t, os.WriteFile(fim, []byte("consistency canary\n"), 0o644))
	t.Cleanup(func() { _ = os.Remove(fim) })

	src := osquerydisc.New()
	cfg := map[string]any{"socket": socketPath(t)}
	since := time.Now().Add(-time.Hour).Unix()

	// Wait for the canary to appear.
	deadline := time.Now().Add(60 * time.Second)
	seen := func() bool {
		ev, err := src.FileEvents(ctxWithTimeout(t), cfg, since)
		require.NoError(t, err)
		for _, e := range ev {
			if e.TargetPath == fim {
				return true
			}
		}
		return false
	}
	for !seen() {
		if time.Now().After(deadline) {
			t.Fatalf("canary never appeared")
		}
		time.Sleep(time.Second)
	}
	// Now query several more times: the canary must remain visible every time
	// (a differential would drop it after the first read).
	for i := 0; i < 4; i++ {
		assert.True(t, seen(), "repeated read %d lost the event — events_optimize differential leaked in", i)
	}
}
