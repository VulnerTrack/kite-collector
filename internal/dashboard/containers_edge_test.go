package dashboard

// Edge-case and error-state coverage for the containers page, complementing
// the happy-path suite in containers_test.go:
//
//   - derived-stat math corners: cgroup v1, missing limits, counter resets,
//     host-network containers, page-cache clamping, absent online_cpus
//   - hostile/degenerate engine data: XSS attempts in names and labels,
//     arrays and strings in the stats document, empty environments
//   - engine failure modes: HTTP 500s, malformed JSON, per-container stats
//     404s mid-poll, missing images/history
//   - monitor lifecycle: lazy start, immediate first sample, stop/restart
//   - pause/bookmark contracts: paused fragments stop refreshing, URLs
//     carry the custom graph set end-to-end

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rawStats decodes a stats JSON literal for derive tests.
func rawStats(t *testing.T, doc string) map[string]any {
	t.Helper()
	var raw map[string]any
	require.NoError(t, json.Unmarshal([]byte(doc), &raw))
	return raw
}

func freshSeries() *containerSeries {
	return &containerSeries{series: map[string][]float64{}, latest: map[string]float64{}}
}

// -------------------------------------------------------------------------
// Derived-stat math corners
// -------------------------------------------------------------------------

func TestDeriveContainerStats_CgroupV1TotalInactiveFile(t *testing.T) {
	s := freshSeries()
	d := deriveContainerStats(rawStats(t, `{
		"memory_stats": {"usage": 300, "limit": 1000, "stats": {"total_inactive_file": 100}}
	}`), s)
	assert.Equal(t, float64(200), d["memory_bytes"], "v1 counter subtracted")
	assert.InDelta(t, 20.0, d["memory_percent"], 0.001)
}

func TestDeriveContainerStats_UsageBelowCacheClampsToZero(t *testing.T) {
	s := freshSeries()
	d := deriveContainerStats(rawStats(t, `{
		"memory_stats": {"usage": 100, "limit": 1000, "stats": {"inactive_file": 250}}
	}`), s)
	assert.Equal(t, float64(0), d["memory_bytes"], "never negative")
	assert.Equal(t, float64(0), d["memory_percent"])
}

func TestDeriveContainerStats_MissingLimitOmitsPercent(t *testing.T) {
	s := freshSeries()
	d := deriveContainerStats(rawStats(t, `{"memory_stats": {"usage": 100}}`), s)
	assert.Equal(t, float64(100), d["memory_bytes"])
	_, hasPct := d["memory_percent"]
	assert.False(t, hasPct, "no limit → no percent (and no division by zero)")
	_, hasLimit := d["memory_limit_bytes"]
	assert.False(t, hasLimit)
}

func TestDeriveContainerStats_CPUCounterResetSkipsSample(t *testing.T) {
	s := freshSeries()
	deriveContainerStats(rawStats(t, `{"cpu_stats": {"cpu_usage": {"total_usage": 2000000000}, "system_cpu_usage": 20000000000}}`), s)
	// Container restarted: cumulative counters went backwards.
	d := deriveContainerStats(rawStats(t, `{"cpu_stats": {"cpu_usage": {"total_usage": 1000000000}, "system_cpu_usage": 30000000000}}`), s)
	_, hasCPU := d["cpu_percent"]
	assert.False(t, hasCPU, "negative delta after a counter reset must not produce a bogus CPU%%")

	// The reset sample still becomes the new baseline: the NEXT delta works.
	d = deriveContainerStats(rawStats(t, `{"cpu_stats": {"cpu_usage": {"total_usage": 2000000000}, "system_cpu_usage": 40000000000}}`), s)
	assert.InDelta(t, 10.0, d["cpu_percent"], 0.001)
}

func TestDeriveContainerStats_MissingOnlineCPUsDefaultsToOne(t *testing.T) {
	s := freshSeries()
	deriveContainerStats(rawStats(t, `{"cpu_stats": {"cpu_usage": {"total_usage": 1000000000}, "system_cpu_usage": 10000000000}}`), s)
	d := deriveContainerStats(rawStats(t, `{"cpu_stats": {"cpu_usage": {"total_usage": 2000000000}, "system_cpu_usage": 20000000000}}`), s)
	assert.InDelta(t, 10.0, d["cpu_percent"], 0.001, "0.1 ratio × 1 CPU × 100")
}

func TestDeriveContainerStats_HostNetworkHasNoNetworksBlock(t *testing.T) {
	// --network=host containers report no "networks" key at all.
	s := freshSeries()
	d := deriveContainerStats(rawStats(t, `{"memory_stats": {"usage": 1, "limit": 2}}`), s)
	_, hasRX := d["net_rx_bytes"]
	assert.False(t, hasRX, "no networks block → no fabricated zero counters")
}

func TestFlattenNumericPaths_SkipsArraysAndStrings(t *testing.T) {
	paths := flattenNumericPaths(rawStats(t, `{
		"name": "/web",
		"id": "abc",
		"blkio_stats": {"io_service_bytes_recursive": [{"value": 5}]},
		"cpu_stats": {"cpu_usage": {"percpu_usage": [1, 2], "total_usage": 3}}
	}`))
	got := make([]string, 0, len(paths))
	for _, p := range paths {
		got = append(got, p.Path)
	}
	assert.Equal(t, []string{"cpu_stats.cpu_usage.total_usage"}, got,
		"strings and arrays are not addressable metrics")
}

func TestMetricSparkSVG_SingleValueAndTooltip(t *testing.T) {
	svg := string(metricSparkSVG([]float64{5}, "PIDs", 120, 24))
	assert.Contains(t, svg, "min 5 · max 5 · latest 5 (n=1)")
	assert.Contains(t, svg, `points="60.0,`, "single point centers horizontally")

	flat := string(metricSparkSVG([]float64{7, 7, 7}, "PIDs", 120, 24))
	assert.Contains(t, flat, "<polyline", "flat series still draws a line")
}

// -------------------------------------------------------------------------
// Hostile / degenerate engine data
// -------------------------------------------------------------------------

// newHostileEngineAPI returns an engine whose names, labels, and status
// strings all carry HTML injection attempts.
func newHostileEngineAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"Id":      "eee111222333444555666777",
			"Names":   []string{"/<script>alert(1)</script>"},
			"Image":   "evil/<img src=x onerror=alert(2)>:latest",
			"ImageID": "sha256:eeff00112233",
			"State":   "running",
			"Status":  "Up 1 hour <b>(healthy)</b>",
			"Created": 1700000000,
			"Labels": map[string]string{
				"com.docker.compose.project": `proj"><svg onload=alert(3)>`,
				"com.docker.compose.service": "<iframe>",
			},
		}})
	})
	mux.HandleFunc("/v1.43/images/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestContainersFragment_EscapesHostileEngineData(t *testing.T) {
	srv := newHostileEngineAPI(t)
	cc := newContainersController(srv.URL, nil)
	cc.disableMonitor = true

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil, nil, false, containerFilter{}))
	body := buf.String()

	assert.NotContains(t, body, "<script>alert(1)</script>")
	assert.NotContains(t, body, "<img src=x onerror")
	assert.NotContains(t, body, "<svg onload")
	assert.NotContains(t, body, "<iframe>")
	assert.Contains(t, body, "&lt;script&gt;alert(1)&lt;/script&gt;", "name renders escaped, not dropped")
}

func TestContainersFragment_InvalidGraphEchoIsEscaped(t *testing.T) {
	cc := newTestContainersController(t)

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil,
		[]string{`<script>alert(4)</script>`}, false, containerFilter{}))
	body := buf.String()
	assert.NotContains(t, body, "<script>alert(4)</script>")
	assert.Contains(t, body, "&lt;script&gt;alert(4)&lt;/script&gt;")
}

func TestContainersFragment_EmptyEngineRendersZeroState(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/v1.43/images/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cc := newContainersController(srv.URL, nil)
	cc.disableMonitor = true

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil, nil, false, containerFilter{}))
	body := buf.String()
	assert.Contains(t, body, "0 total")
	assert.NotContains(t, body, "Docker unavailable", "an empty engine is available, just idle")
}

func TestContainersFragment_LiteralNoneTagsRenderUntagged(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/v1.43/images/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"Id": "sha256:0011223344556677", "RepoTags": ["<none>:<none>"], "Size": 10, "Created": 1690000000}]`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cc := newContainersController(srv.URL, nil)
	cc.disableMonitor = true

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil, nil, false, containerFilter{}))
	assert.Contains(t, buf.String(), "&lt;untagged&gt;")
	assert.NotContains(t, buf.String(), "<none>")
}

func TestContainersFragment_UnresolvableCustomPathShowsCollecting(t *testing.T) {
	cc := newTestContainersController(t)
	custom := []string{"no_such.metric_anywhere"}
	cc.markViewed(custom)
	cc.tick(context.Background())

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), custom, nil, false, containerFilter{}))
	body := buf.String()
	assert.Contains(t, body, "no_such.metric_anywhere", "column still renders")
	assert.Contains(t, body, "collecting samples", "cells stay pending, no error")
}

// -------------------------------------------------------------------------
// Engine failure modes
// -------------------------------------------------------------------------

func TestContainersFragment_EngineHTTP500SurfacesError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "daemon exploded", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cc := newContainersController(srv.URL, nil)
	cc.disableMonitor = true

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil, nil, false, containerFilter{}))
	body := buf.String()
	assert.Contains(t, body, "Docker unavailable")
	assert.Contains(t, body, "HTTP 500")
}

func TestContainersFragment_MalformedListJSONSurfacesParseError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{definitely not json`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cc := newContainersController(srv.URL, nil)
	cc.disableMonitor = true

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil, nil, false, containerFilter{}))
	assert.Contains(t, buf.String(), "parse containers")
}

func TestContainersFragment_ImagesFailureDoesNotSinkThePage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"Id": "aaa111222333444555666777", "Names": ["/web"], "Image": "web:1", "ImageID": "sha256:ff00", "State": "running", "Status": "Up 1 hour", "Created": 1700000000, "Labels": {}}]`))
	})
	mux.HandleFunc("/v1.43/images/json", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "images broke", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cc := newContainersController(srv.URL, nil)
	cc.disableMonitor = true

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil, nil, false, containerFilter{}))
	body := buf.String()
	assert.Contains(t, body, "web", "container table renders")
	assert.Contains(t, body, "Could not list images")
}

func TestTick_OneContainerStats404DoesNotBlockOthers(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"Id": "aaa111222333444555666777", "Names": ["/alive"], "Image": "a:1", "ImageID": "sha256:aa", "State": "running", "Status": "Up 1 hour", "Created": 1700000000, "Labels": {}},
			{"Id": "bbb111222333444555666777", "Names": ["/dying"], "Image": "b:1", "ImageID": "sha256:bb", "State": "running", "Status": "Up 1 hour", "Created": 1700000000, "Labels": {}}
		]`))
	})
	mux.HandleFunc("/v1.43/containers/{id}/stats", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.PathValue("id"), "bbb") {
			// Died between the list call and the stats call.
			http.Error(w, "No such container", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"memory_stats": {"usage": 10, "limit": 100}, "pids_stats": {"current": 1}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cc := newContainersController(srv.URL, nil)
	cc.disableMonitor = true
	cc.markViewed(nil)
	cc.tick(context.Background())

	cc.mu.Lock()
	defer cc.mu.Unlock()
	require.Contains(t, cc.hist, "aaa111222333444555666777", "healthy container still sampled")
	assert.NotContains(t, cc.hist, "bbb111222333444555666777")
}

func TestImageLayersDrawer_Engine404RendersDrawerError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/images/{id}/history", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no such image", http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cc := newContainersController(srv.URL, nil)
	cc.disableMonitor = true

	var buf strings.Builder
	require.NoError(t, cc.renderImageLayers(&buf, context.Background(), "deadbeef0000"))
	body := buf.String()
	assert.Contains(t, body, "Could not load layer history")
	assert.Contains(t, body, "closeRowDrawer()", "drawer still gets a Close button")
}

func TestContainerDetail_EngineDownRendersDrawerError(t *testing.T) {
	cc := newContainersController("tcp://127.0.0.1:1", nil)
	cc.disableMonitor = true

	var buf strings.Builder
	require.NoError(t, cc.renderContainerDetail(&buf, context.Background(),
		"aaa111222333444555666777", nil, false))
	assert.Contains(t, buf.String(), "list containers")
	assert.Contains(t, buf.String(), "closeRowDrawer()")
}

// -------------------------------------------------------------------------
// Monitor lifecycle
// -------------------------------------------------------------------------

func TestMonitor_StartsOnFirstViewAndSamplesImmediately(t *testing.T) {
	srv := newMockEngineAPI(t)
	cc := newContainersController(srv.URL, nil)
	t.Cleanup(cc.stopMonitor)

	cc.markViewed(nil)

	// monitorLoop takes an immediate first sample; poll briefly for it.
	deadline := time.Now().Add(3 * time.Second)
	for {
		cc.mu.Lock()
		sampled := len(cc.hist) > 0
		cc.mu.Unlock()
		if sampled {
			break
		}
		require.True(t, time.Now().Before(deadline), "monitor never took its first sample")
		time.Sleep(20 * time.Millisecond)
	}
}

func TestMonitor_StopAndRestart(t *testing.T) {
	srv := newMockEngineAPI(t)
	cc := newContainersController(srv.URL, nil)
	t.Cleanup(cc.stopMonitor)

	cc.markViewed(nil)
	cc.mu.Lock()
	firstCh := cc.stopCh
	assert.True(t, cc.running)
	cc.mu.Unlock()

	cc.stopMonitor()
	cc.mu.Lock()
	assert.False(t, cc.running)
	cc.mu.Unlock()
	cc.stopMonitor() // idempotent: no double-close panic

	cc.markViewed(nil)
	cc.mu.Lock()
	assert.True(t, cc.running, "a fresh view restarts the monitor")
	assert.NotEqual(t, firstCh, cc.stopCh, "restart allocates a new stop channel")
	cc.mu.Unlock()
}

// -------------------------------------------------------------------------
// Pause / bookmark contracts
// -------------------------------------------------------------------------

func TestContainersFragment_PausedStopsRefreshAndKeepsGraphs(t *testing.T) {
	cc := newTestContainersController(t)
	custom := []string{"pids_stats.current"}

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), custom, nil, true, containerFilter{}))
	body := buf.String()

	assert.NotContains(t, body, "hx-trigger=\"every", "paused fragment must not auto-refresh")
	assert.Contains(t, body, ">Resume</a>")
	// Resume toggle and refresh wrapper both preserve the custom graph set.
	assert.Contains(t, body, "/fragments/containers?graph=pids_stats.current\"",
		"resume URL keeps graphs and drops paused")
	assert.Contains(t, body, `name="paused" value="1"`,
		"add-metric form preserves the paused state")
}

func TestContainersFragment_LiveWrapperURLCarriesGraphs(t *testing.T) {
	cc := newTestContainersController(t)
	custom := []string{"pids_stats.current"}

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), custom, nil, false, containerFilter{}))
	body := buf.String()

	assert.Contains(t, body, `hx-trigger="every 10s"`)
	assert.Contains(t, body, `hx-get="/fragments/containers?graph=pids_stats.current"`,
		"auto-refresh must re-request the customised view, not the default one")
}

func TestContainerDetail_AddURLAppendsToExistingGraphs(t *testing.T) {
	cc := newTestContainersController(t)
	custom := []string{"pids_stats.current"}
	cc.markViewed(custom)
	cc.tick(context.Background())

	var buf strings.Builder
	require.NoError(t, cc.renderContainerDetail(&buf, context.Background(),
		"aaa111222333444555666777", custom, false))
	body := buf.String()

	// A "Graph" link for another metric keeps the existing custom column.
	idx := strings.Index(body, "graph=memory_stats.usage")
	require.Greater(t, idx, -1)
	assert.Contains(t, body, "graph=pids_stats.current&amp;graph=memory_stats.usage",
		"add-URL must append, not replace")
}

func TestSnapshotJSON_IncludesCustomMetricValues(t *testing.T) {
	cc := newTestContainersController(t)
	custom := []string{"pids_stats.current"}
	cc.markViewed(custom)
	cc.tick(context.Background())

	view := cc.buildContainersView(context.Background(), custom, false, containerFilter{})
	body, err := json.Marshal(view)
	require.NoError(t, err)

	var snap struct {
		Columns []struct {
			StatPath string `json:"stat_path"`
			Custom   bool   `json:"custom"`
		} `json:"columns"`
		Groups []struct {
			Containers []struct {
				State   string `json:"state"`
				Metrics []struct {
					Display string  `json:"display"`
					Value   float64 `json:"value"`
					Has     bool    `json:"has"`
				} `json:"metrics"`
			} `json:"containers"`
		} `json:"groups"`
	}
	require.NoError(t, json.Unmarshal(body, &snap))
	require.Len(t, snap.Columns, len(defaultContainerGraphs)+1)
	assert.True(t, snap.Columns[len(snap.Columns)-1].Custom)
	assert.Equal(t, "pids_stats.current", snap.Columns[len(snap.Columns)-1].StatPath)

	found := false
	for _, g := range snap.Groups {
		for _, c := range g.Containers {
			if c.State != "running" {
				continue
			}
			require.Len(t, c.Metrics, len(snap.Columns))
			last := c.Metrics[len(c.Metrics)-1]
			if last.Has {
				assert.Equal(t, float64(7), last.Value)
				found = true
			}
		}
	}
	assert.True(t, found, "at least one running container reports the custom metric")
}

func TestContainersFragment_NamelessContainerStillRenders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"Id": "aaa111222333444555666777", "Names": [], "Image": "a:1", "ImageID": "sha256:aa", "State": "created", "Status": "Created", "Created": 1700000000, "Labels": {}}]`))
	})
	mux.HandleFunc("/v1.43/images/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cc := newContainersController(srv.URL, nil)
	cc.disableMonitor = true

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil, nil, false, containerFilter{}))
	assert.Contains(t, buf.String(), "1 total")
	assert.Contains(t, buf.String(), "created")
}

// TestFormatMetricValue_LargeNonIntegral guards the humanizer's fall-through
// ordering: a huge float that is not integral must not be fed to the count
// formatter.
func TestFormatMetricValue_LargeNonIntegral(t *testing.T) {
	assert.Equal(t, fmt.Sprintf("%.2f", 1e16+0.5), formatMetricValue(1e16+0.5, "weird.metric"))
}

// -------------------------------------------------------------------------
// Second-pass depth: buffer caps, TTL refresh, snapshot isolation,
// bounded parallelism, ordering, and remaining route branches.
// -------------------------------------------------------------------------

// TestRecord_RingBufferCapEvictsOldest pins the memory bound: series never
// exceed containerSeriesCap and evict FIFO, so a long-running monitor keeps
// exactly the trailing window.
func TestRecord_RingBufferCapEvictsOldest(t *testing.T) {
	cc := newContainersController("http://unused", nil)
	cc.disableMonitor = true
	cc.markViewed(nil)

	// memory_percent = usage/limit*100 = i/12 for limit 1200 — each sample
	// carries its iteration number so eviction order is observable.
	for i := 1; i <= containerSeriesCap+10; i++ {
		cc.record("c1", rawStats(t, fmt.Sprintf(
			`{"memory_stats": {"usage": %d, "limit": 1200}}`, i)))
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()
	series := cc.hist["c1"].series["derived.memory_percent"]
	require.Len(t, series, containerSeriesCap)
	assert.InDelta(t, float64(11)/1200*100, series[0], 0.001,
		"first 10 samples evicted, buffer starts at iteration 11")
	assert.InDelta(t, float64(containerSeriesCap+10)/1200*100, series[len(series)-1], 0.001)
}

// TestMarkViewed_RefreshesCustomPathTTL: a custom path that keeps being
// rendered survives the prune indefinitely; one that stops being rendered
// is evicted after the TTL.
func TestMarkViewed_RefreshesCustomPathTTL(t *testing.T) {
	cc := newTestContainersController(t)
	custom := []string{"pids_stats.current"}
	base := time.Now()
	cc.now = func() time.Time { return base }
	cc.markViewed(custom)
	cc.tick(context.Background())

	// Past the TTL, but the page is still being viewed with the path.
	cc.now = func() time.Time { return base.Add(customStatPathTTL + time.Minute) }
	cc.markViewed(custom)
	cc.tick(context.Background())
	cc.mu.Lock()
	_, alive := cc.customPaths["pids_stats.current"]
	cc.mu.Unlock()
	require.True(t, alive, "re-rendered path must survive the prune")

	// Another TTL passes with no renders → evicted.
	cc.now = func() time.Time { return base.Add(2*customStatPathTTL + 2*time.Minute) }
	cc.tick(context.Background())
	cc.mu.Lock()
	_, alive = cc.customPaths["pids_stats.current"]
	cc.mu.Unlock()
	assert.False(t, alive, "idle path evicted after TTL")
}

// TestSnapshotSeries_IsolatedCopy: mutating a render's snapshot must never
// corrupt the controller's history (renders happen outside the lock).
func TestSnapshotSeries_IsolatedCopy(t *testing.T) {
	cc := newContainersController("http://unused", nil)
	cc.disableMonitor = true
	cc.markViewed(nil)
	cc.record("c1", rawStats(t, `{"memory_stats": {"usage": 600, "limit": 1200}}`))

	snap := cc.snapshotSeries("c1")
	require.NotNil(t, snap)
	snap.series["derived.memory_percent"][0] = -999
	snap.latest["derived.memory_percent"] = -999

	fresh := cc.snapshotSeries("c1")
	assert.InDelta(t, 50.0, fresh.series["derived.memory_percent"][0], 0.001)
	assert.InDelta(t, 50.0, fresh.latest["derived.memory_percent"], 0.001)
}

// TestTick_BoundedParallelismHandlesManyContainers: 40 running containers
// with slow stats must all be sampled in one tick, with in-flight requests
// capped at statsFetchParallelism.
func TestTick_BoundedParallelismHandlesManyContainers(t *testing.T) {
	const n = 40
	var mu sync.Mutex
	inflight, maxInflight := 0, 0

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		rows := make([]string, 0, n)
		for i := 0; i < n; i++ {
			rows = append(rows, fmt.Sprintf(
				`{"Id": "c%02d111222333444555666777", "Names": ["/c%02d"], "Image": "a:1", "ImageID": "sha256:aa", "State": "running", "Status": "Up 1 hour", "Created": 1700000000, "Labels": {}}`, i, i))
		}
		_, _ = fmt.Fprintf(w, "[%s]", strings.Join(rows, ","))
	})
	mux.HandleFunc("/v1.43/containers/{id}/stats", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		inflight++
		if inflight > maxInflight {
			maxInflight = inflight
		}
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		inflight--
		mu.Unlock()
		_, _ = w.Write([]byte(`{"memory_stats": {"usage": 10, "limit": 100}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cc := newContainersController(srv.URL, nil)
	cc.disableMonitor = true
	cc.markViewed(nil)
	cc.tick(context.Background())

	cc.mu.Lock()
	sampled := len(cc.hist)
	cc.mu.Unlock()
	assert.Equal(t, n, sampled, "every running container sampled in one tick")
	mu.Lock()
	defer mu.Unlock()
	assert.LessOrEqual(t, maxInflight, statsFetchParallelism,
		"in-flight stats requests must respect the semaphore")
	assert.Greater(t, maxInflight, 1, "requests actually ran concurrently")
}

// TestComposeGroups_SortedProjectsStandaloneLast pins the reading order:
// compose projects alphabetically, the standalone bucket at the end.
func TestComposeGroups_SortedProjectsStandaloneLast(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"Id": "aaa111222333444555666777", "Names": ["/b1"], "Image": "a:1", "ImageID": "sha256:aa", "State": "running", "Status": "Up", "Created": 1700000000, "Labels": {"com.docker.compose.project": "beta"}},
			{"Id": "bbb111222333444555666777", "Names": ["/a1"], "Image": "a:1", "ImageID": "sha256:aa", "State": "running", "Status": "Up", "Created": 1700000000, "Labels": {"com.docker.compose.project": "alpha"}},
			{"Id": "ccc111222333444555666777", "Names": ["/solo"], "Image": "a:1", "ImageID": "sha256:aa", "State": "running", "Status": "Up", "Created": 1700000000, "Labels": {}}
		]`))
	})
	mux.HandleFunc("/v1.43/images/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cc := newContainersController(srv.URL, nil)
	cc.disableMonitor = true
	view := cc.buildContainersView(context.Background(), nil, false, containerFilter{})

	require.Len(t, view.Groups, 3)
	assert.Equal(t, "alpha", view.Groups[0].Project)
	assert.Equal(t, "beta", view.Groups[1].Project)
	assert.Equal(t, "standalone containers", view.Groups[2].Project)
}

func TestImageLayersDrawer_EmptyHistory(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/images/{id}/history", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cc := newContainersController(srv.URL, nil)
	cc.disableMonitor = true

	var buf strings.Builder
	require.NoError(t, cc.renderImageLayers(&buf, context.Background(), "deadbeef0000"))
	assert.Contains(t, buf.String(), "0 ancestor layers")
	assert.Contains(t, buf.String(), "0 B total")
}

func TestValidateStatPath_ExactLengthBoundaryAccepted(t *testing.T) {
	p := strings.Repeat("a", maxStatPathLen)
	got, err := validateStatPath(p)
	require.NoError(t, err)
	assert.Equal(t, p, got)
}

// TestRoute_GET_ContainersTab_HXFragmentOnly: the canonical /containers tab
// URL with HX-Request must return only the fragment (HTMX swap contract).
func TestRoute_GET_ContainersTab_HXFragmentOnly(t *testing.T) {
	mux := newContainersTestMux(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/containers", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "<h2>Containers</h2>")
	assert.NotContains(t, rec.Body.String(), "<html")
}

// TestTick_CancelledContextSetsMonitorNote: a tick that dies (context gone,
// engine hiccup) leaves a note the next render surfaces, instead of failing
// silently.
func TestTick_CancelledContextSetsMonitorNote(t *testing.T) {
	cc := newTestContainersController(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cc.tick(ctx)

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil, nil, false, containerFilter{}))
	assert.Contains(t, buf.String(), "Stats monitor:",
		"the failed poll must be visible on the page")
}
