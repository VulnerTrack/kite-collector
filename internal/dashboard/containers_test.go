package dashboard

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

	"github.com/vulnertrack/kite-collector/internal/config"
)

// -------------------------------------------------------------------------
// Mock Docker Engine API
// -------------------------------------------------------------------------

// newMockEngineAPI serves the Engine endpoints the containers page uses.
// Stats counters advance per call so CPU% is derivable from consecutive
// one-shot samples, exactly like a live daemon.
func newMockEngineAPI(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	statsCalls := map[string]int{}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"Id": "aaa111222333444555666777", "Names": ["/web"], "Image": "vie/web:1.0",
			 "ImageID": "sha256:feedfacefeedface", "State": "running",
			 "Status": "Up 2 hours (healthy)", "Created": 1700000000,
			 "Ports": [{"PrivatePort": 8080, "PublicPort": 80, "Type": "tcp"}],
			 "Labels": {"com.docker.compose.project": "vie", "com.docker.compose.service": "web"}},
			{"Id": "bbb111222333444555666777", "Names": ["/worker"], "Image": "vie/worker:1.0",
			 "ImageID": "sha256:feedfacefeedface", "State": "running",
			 "Status": "Up 2 hours (unhealthy)", "Created": 1700000000,
			 "Labels": {"com.docker.compose.project": "vie", "com.docker.compose.service": "worker"}},
			{"Id": "ccc111222333444555666777", "Names": ["/adhoc"], "Image": "alpine:3.19",
			 "ImageID": "sha256:0123456789ab", "State": "exited",
			 "Status": "Exited (0) 1 hour ago", "Created": 1700000000, "Labels": {}}
		]`))
	})

	statsHandler := func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		mu.Lock()
		statsCalls[id]++
		n := statsCalls[id]
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// total_usage grows 1e9/sample against 1e10 of system time on 2
		// CPUs → 20% CPU from the second sample on. Memory: 300 MiB usage
		// minus 100 MiB inactive_file over a 1 GiB limit → 200 MiB / ~19.5%.
		_, _ = fmt.Fprintf(w, `{
			"cpu_stats": {"cpu_usage": {"total_usage": %d}, "system_cpu_usage": %d, "online_cpus": 2},
			"precpu_stats": {"cpu_usage": {"total_usage": 0}, "system_cpu_usage": 0},
			"memory_stats": {"usage": 314572800, "limit": 1073741824, "stats": {"inactive_file": 104857600}},
			"pids_stats": {"current": 7},
			"networks": {"eth0": {"rx_bytes": 1000, "tx_bytes": 500}, "eth1": {"rx_bytes": 24, "tx_bytes": 1}}
		}`, int64(n)*1_000_000_000, int64(n)*10_000_000_000)
	}
	mux.HandleFunc("/v1.43/containers/{id}/stats", statsHandler)

	mux.HandleFunc("/v1.43/images/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"Id": "sha256:feedfacefeedface", "RepoTags": ["vie/web:1.0"], "Size": 104857600, "Created": 1690000000},
			{"Id": "sha256:aabbccddeeff0011", "RepoTags": null, "Size": 512, "Created": 1690000001}
		]`))
	})

	mux.HandleFunc("/v1.43/images/feedfacefeedface/history",
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
				{"Id": "sha256:feedfacefeedface", "Created": 1690000000,
				 "CreatedBy": "/bin/sh -c #(nop)  CMD [\"serve\"]", "Size": 0, "Tags": ["vie/web:1.0"]},
				{"Id": "<missing>", "Created": 1689990000,
				 "CreatedBy": "/bin/sh -c apt-get update && apt-get install -y curl", "Size": 52428800}
			]`))
		})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newTestContainersController wires a controller at the mock engine with
// the background monitor disabled so tests drive tick() deterministically.
func newTestContainersController(t *testing.T) *containersController {
	t.Helper()
	srv := newMockEngineAPI(t)
	cc := newContainersController(srv.URL, nil)
	cc.disableMonitor = true
	return cc
}

// -------------------------------------------------------------------------
// Derived stats + stat paths
// -------------------------------------------------------------------------

func statsSample(total, system int64) map[string]any {
	doc := fmt.Sprintf(`{
		"cpu_stats": {"cpu_usage": {"total_usage": %d}, "system_cpu_usage": %d, "online_cpus": 2},
		"memory_stats": {"usage": 314572800, "limit": 1073741824, "stats": {"inactive_file": 104857600}},
		"networks": {"eth0": {"rx_bytes": 1000, "tx_bytes": 500}, "eth1": {"rx_bytes": 24, "tx_bytes": 1}},
		"pids_stats": {"current": 7}
	}`, total, system)
	var raw map[string]any
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		panic(err)
	}
	return raw
}

func TestDeriveContainerStats_CPUFromConsecutiveSamples(t *testing.T) {
	s := &containerSeries{series: map[string][]float64{}, latest: map[string]float64{}}

	// First one-shot sample has no precpu baseline → no CPU% yet.
	d1 := deriveContainerStats(statsSample(1_000_000_000, 10_000_000_000), s)
	_, hasCPU := d1["cpu_percent"]
	assert.False(t, hasCPU, "first sample has no baseline, CPU%% must be absent")

	// Second sample: Δcpu=1e9 over Δsystem=1e10 on 2 CPUs → 20%.
	d2 := deriveContainerStats(statsSample(2_000_000_000, 20_000_000_000), s)
	assert.InDelta(t, 20.0, d2["cpu_percent"], 0.001)
}

func TestDeriveContainerStats_MemorySubtractsInactiveFile(t *testing.T) {
	s := &containerSeries{series: map[string][]float64{}, latest: map[string]float64{}}
	d := deriveContainerStats(statsSample(1, 10), s)

	// 300 MiB usage − 100 MiB inactive_file = 200 MiB (docker-CLI parity).
	assert.InDelta(t, float64(209715200), d["memory_bytes"], 0.1)
	assert.InDelta(t, 19.53, d["memory_percent"], 0.01)
}

func TestDeriveContainerStats_NetworksSummedAcrossInterfaces(t *testing.T) {
	s := &containerSeries{series: map[string][]float64{}, latest: map[string]float64{}}
	d := deriveContainerStats(statsSample(1, 10), s)

	assert.Equal(t, float64(1024), d["net_rx_bytes"], "eth0 + eth1 summed")
	assert.Equal(t, float64(501), d["net_tx_bytes"])
	assert.Equal(t, float64(7), d["pids"])
}

func TestResolveStatPath_DerivedRawAndMissing(t *testing.T) {
	raw := statsSample(1, 10)
	derived := map[string]float64{"cpu_percent": 42}

	v, ok := resolveStatPath(raw, derived, "derived.cpu_percent")
	require.True(t, ok)
	assert.Equal(t, 42.0, v)

	v, ok = resolveStatPath(raw, derived, "memory_stats.stats.inactive_file")
	require.True(t, ok)
	assert.Equal(t, float64(104857600), v)

	_, ok = resolveStatPath(raw, derived, "memory_stats.no_such_field")
	assert.False(t, ok)
	_, ok = resolveStatPath(raw, derived, "derived.no_such_metric")
	assert.False(t, ok)
	_, ok = resolveStatPath(raw, derived, "networks")
	assert.False(t, ok, "non-numeric node is not a metric")
}

func TestValidateStatPath(t *testing.T) {
	for _, ok := range []string{"pids_stats.current", "derived.cpu_percent", "networks.eth0.rx_bytes", "blkio-stats.total"} {
		got, err := validateStatPath(" " + ok + " ")
		require.NoError(t, err, ok)
		assert.Equal(t, ok, got)
	}
	for _, bad := range []string{"", "a..b", ".lead", "trail.", "has space", "semi;colon", "<script>", strings.Repeat("a", maxStatPathLen+1)} {
		_, err := validateStatPath(bad)
		assert.Error(t, err, "%q must be rejected", bad)
	}
}

func TestFlattenNumericPaths_SortedDottedLeaves(t *testing.T) {
	paths := flattenNumericPaths(statsSample(1, 10))

	byPath := map[string]float64{}
	order := make([]string, 0, len(paths))
	for _, p := range paths {
		byPath[p.Path] = p.Value
		order = append(order, p.Path)
	}
	assert.Equal(t, float64(7), byPath["pids_stats.current"])
	assert.Equal(t, float64(1000), byPath["networks.eth0.rx_bytes"])
	assert.Equal(t, float64(104857600), byPath["memory_stats.stats.inactive_file"])
	assert.IsIncreasing(t, order, "paths must be sorted for a scannable browser")
}

func TestFormatMetricValue(t *testing.T) {
	assert.Equal(t, "12.3%", formatMetricValue(12.34, "derived.cpu_percent"))
	assert.Equal(t, "200.0 MB", formatMetricValue(209715200, "derived.memory_bytes"))
	assert.Equal(t, "7", formatMetricValue(7, "pids_stats.current"))
	assert.Equal(t, "1,234,567", formatMetricValue(1234567, "some.counter"))
	assert.Equal(t, "3.14", formatMetricValue(3.14159, "some.ratio"))
}

func TestContainerStateIcon(t *testing.T) {
	icon, badge, label := containerStateIcon("running", "healthy")
	assert.Equal(t, "✔", icon)
	assert.Equal(t, "badge-green", badge)
	assert.Equal(t, "running · healthy", label)

	_, badge, _ = containerStateIcon("running", "unhealthy")
	assert.Equal(t, "badge-red", badge)
	_, badge, _ = containerStateIcon("exited", "")
	assert.Equal(t, "badge-gray", badge)
	_, badge, label = containerStateIcon("weird-state", "")
	assert.Equal(t, "badge-gray", badge)
	assert.Equal(t, "weird-state", label)
}

func TestTrimLayerInstruction(t *testing.T) {
	assert.Equal(t, `CMD ["serve"]`, trimLayerInstruction(`/bin/sh -c #(nop)  CMD ["serve"]`))
	assert.Equal(t, "RUN apt-get update", trimLayerInstruction("/bin/sh -c apt-get update"))
	assert.Equal(t, "COPY app /app", trimLayerInstruction("COPY app /app"))
}

func TestParseContainerGraphParams_DedupesCapsAndReportsInvalid(t *testing.T) {
	q := "graph=pids_stats.current&graph=pids_stats.current&graph=bad%20path"
	for i := 0; i < maxCustomGraphs+3; i++ {
		q += fmt.Sprintf("&graph=extra_%d.value", i)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/containers?"+q, nil)

	valid, invalid := parseContainerGraphParams(r)
	assert.Len(t, valid, maxCustomGraphs, "capped at maxCustomGraphs")
	assert.Equal(t, "pids_stats.current", valid[0])
	assert.Equal(t, []string{"bad path"}, invalid)
}

func TestContainersPageURL_CarriesGraphsAndPause(t *testing.T) {
	assert.Equal(t, "/containers", containersPageURL(nil, false))
	u := containersPageURL([]string{"pids_stats.current"}, true)
	assert.Contains(t, u, "graph=pids_stats.current")
	assert.Contains(t, u, "paused=1")
	assert.Equal(t, "/fragments/containers", containersFragmentURL(nil, false))
}

// -------------------------------------------------------------------------
// Controller renders (mock engine)
// -------------------------------------------------------------------------

func TestContainersFragment_AtAGlanceStateAndSummary(t *testing.T) {
	cc := newTestContainersController(t)
	cc.markViewed(nil)
	cc.tick(context.Background())

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil, nil, false, containerFilter{}))
	body := buf.String()

	assert.Contains(t, body, "<h2>Containers</h2>")
	assert.Contains(t, body, "3 total")
	assert.Contains(t, body, "2 running")
	assert.Contains(t, body, "1 unhealthy")
	assert.Contains(t, body, "1 exited")
	// Compose grouping: project section plus standalone bucket.
	assert.Contains(t, body, "vie")
	assert.Contains(t, body, "standalone containers")
	// Icon status + health at a glance.
	assert.Contains(t, body, "running · healthy")
	assert.Contains(t, body, "running · unhealthy")
	// Image cell links to the ancestor-layers drawer.
	assert.Contains(t, body, "/fragments/images/feedfacefeedface/layers")
	// Image inventory card with untagged handling.
	assert.Contains(t, body, "vie/web:1.0")
	assert.Contains(t, body, "&lt;untagged&gt;")
}

func TestContainersFragment_DefaultMetricsPopulateAfterTicks(t *testing.T) {
	cc := newTestContainersController(t)
	cc.markViewed(nil)
	cc.tick(context.Background())
	cc.tick(context.Background()) // CPU% needs two consecutive samples

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil, nil, false, containerFilter{}))
	body := buf.String()

	assert.Contains(t, body, "20.0%", "CPU%% derived from consecutive samples")
	assert.Contains(t, body, "19.5%", "memory%% with inactive_file subtracted")
	assert.Contains(t, body, "metric-spark", "sparklines rendered")
}

func TestContainersFragment_CustomGraphColumn(t *testing.T) {
	cc := newTestContainersController(t)
	custom := []string{"pids_stats.current"}
	cc.markViewed(custom)
	cc.tick(context.Background())

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), custom, nil, false, containerFilter{}))
	body := buf.String()

	assert.Contains(t, body, "pids_stats.current", "custom column header present")
	assert.Contains(t, body, ">7<", "current PID count rendered")
	assert.Contains(t, body, "Remove this metric column")
	// The snapshot link carries the customisation.
	assert.Contains(t, body, "/api/v1/containers/snapshot.json?graph=pids_stats.current")
}

func TestContainersFragment_InvalidGraphPathIsExplained(t *testing.T) {
	cc := newTestContainersController(t)
	cc.markViewed(nil)

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil, []string{"bad path"}, false, containerFilter{}))
	assert.Contains(t, buf.String(), "Ignored invalid stat path")
}

func TestContainersFragment_UnavailableEngineRendersHint(t *testing.T) {
	cc := newContainersController("tcp://127.0.0.1:1", nil)
	cc.disableMonitor = true

	var buf strings.Builder
	require.NoError(t, cc.renderContainersFragment(&buf, context.Background(), nil, nil, false, containerFilter{}))
	body := buf.String()
	assert.Contains(t, body, "Docker unavailable")
	assert.Contains(t, body, "KITE_DOCKER_HOST")
}

func TestContainerDetail_GraphsAndPathBrowser(t *testing.T) {
	cc := newTestContainersController(t)
	cc.markViewed(nil)
	cc.tick(context.Background())
	cc.tick(context.Background())

	var buf strings.Builder
	require.NoError(t, cc.renderContainerDetail(&buf, context.Background(),
		"aaa111222333444555666777", nil, false))
	body := buf.String()

	assert.Contains(t, body, "Metric graphs")
	assert.Contains(t, body, "CPU %")
	// Path browser lists every numeric stat path with a graph-it link.
	assert.Contains(t, body, "memory_stats.stats.inactive_file")
	assert.Contains(t, body, "graph=memory_stats.stats.inactive_file")
	assert.Contains(t, body, "networks.eth1.rx_bytes")
}

func TestContainerDetail_UnknownContainerRendersDrawerError(t *testing.T) {
	cc := newTestContainersController(t)

	var buf strings.Builder
	require.NoError(t, cc.renderContainerDetail(&buf, context.Background(), "nope", nil, false))
	assert.Contains(t, buf.String(), "not found")
	assert.Contains(t, buf.String(), "closeRowDrawer()")
}

func TestImageLayersDrawer_AncestorLayers(t *testing.T) {
	cc := newTestContainersController(t)

	var buf strings.Builder
	require.NoError(t, cc.renderImageLayers(&buf, context.Background(), "feedfacefeedface"))
	body := buf.String()

	assert.Contains(t, body, "2 ancestor layers")
	assert.Contains(t, body, "50.0 MB total")
	assert.Contains(t, body, "&lt;missing&gt;")
	assert.Contains(t, body, `CMD [&#34;serve&#34;]`, "#(nop) wrapper trimmed")
	assert.Contains(t, body, "RUN apt-get update", "shell wrapper trimmed to RUN")
	assert.Contains(t, body, "vie/web:1.0", "tags shown on the tagged layer")
}

func TestTick_PrunesGoneContainersAndExpiredCustomPaths(t *testing.T) {
	cc := newTestContainersController(t)
	custom := []string{"pids_stats.current"}
	cc.markViewed(custom)
	cc.tick(context.Background())

	cc.mu.Lock()
	cc.hist["gone111222333444555666777"] = &containerSeries{series: map[string][]float64{}, latest: map[string]float64{}}
	cc.mu.Unlock()

	// Jump the clock past the custom-path TTL, then tick again.
	base := time.Now()
	cc.now = func() time.Time { return base.Add(customStatPathTTL + time.Minute) }
	cc.tick(context.Background())

	cc.mu.Lock()
	defer cc.mu.Unlock()
	assert.NotContains(t, cc.hist, "gone111222333444555666777", "histories pruned for removed containers")
	assert.Empty(t, cc.customPaths, "idle custom paths expire")
	assert.Contains(t, cc.hist, "aaa111222333444555666777", "live containers keep history")
}

// -------------------------------------------------------------------------
// Routes + JSON snapshot
// -------------------------------------------------------------------------

func newContainersTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	cc := newTestContainersController(t)
	mux := http.NewServeMux()
	registerContainerRoutes(mux, cc, nil)
	return mux
}

func TestRoute_GET_ContainersFragment(t *testing.T) {
	mux := newContainersTestMux(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fragments/containers?graph=pids_stats.current", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "<h2>Containers</h2>")
	assert.NotContains(t, rec.Body.String(), "<html", "fragment only")
}

func TestRoute_GET_ContainersSnapshotJSON(t *testing.T) {
	mux := newContainersTestMux(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/containers/snapshot.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var snap map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &snap))
	assert.Equal(t, true, snap["available"])
	assert.Equal(t, float64(3), snap["total"])
	assert.Equal(t, float64(1), snap["compose_projects"])
	groups, ok := snap["groups"].([]any)
	require.True(t, ok)
	assert.Len(t, groups, 2, "compose project + standalone bucket")
}

func TestRoute_GET_ContainersPage_FullShellWithActiveNav(t *testing.T) {
	// Point the docker discovery source at the mock engine so this test
	// never touches a real daemon — and so the config→controller host
	// wiring in Serve() is exercised end to end.
	srv := newMockEngineAPI(t)
	handler := Serve(":0", testStore(t), testContext(), nil, Options{
		BaseConfig: &config.Config{Discovery: config.DiscoveryConfig{
			Sources: map[string]config.SourceConfig{"docker": {Host: srv.URL}},
		}},
	}).Handler
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/containers", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "<html", "plain GET returns the full shell")
	assert.Contains(t, body, "<h2>Containers</h2>")
	// Prefix match on the class attribute so the assertion survives both the
	// classic sidebar (`class="active"`) and the sidebar-tree variant
	// (`class="active sidenav-resource"`).
	assert.True(t, strings.Contains(body,
		`href="/containers" hx-get="/containers" hx-target="#content" hx-push-url="true" class="active`),
		"Containers nav link should be active")
}
