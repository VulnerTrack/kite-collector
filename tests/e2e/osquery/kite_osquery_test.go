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
