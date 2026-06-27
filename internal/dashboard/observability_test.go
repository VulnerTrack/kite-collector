package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// TestObservability_PageRendersAllSections asserts the /observability page
// includes all four expected sections (healthchecks, probe metrics, scan
// metrics, prometheus pointer) even on a fresh harness where probe/scan
// data is empty. Empty states should be handled gracefully.
func TestObservability_PageRendersAllSections(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "Local observability",
		"page must render the local-observability title")
	assert.Contains(t, body, "Healthchecks",
		"healthchecks panel must always render — operators need to know subsystem status even on a fresh install")
	assert.Contains(t, body, "Probe metrics",
		"probe metrics section must render — shows empty-state copy when no data")
	assert.Contains(t, body, "Scan metrics",
		"scan metrics section must render — shows empty-state copy when no data")
	assert.Contains(t, body, "Prometheus integration",
		"prometheus integration pointer must always render — operators wiring Grafana need to find /metrics")
	assert.Contains(t, body, `href="/metrics"`,
		"must link to the local /metrics endpoint for Prometheus scrapers")
	assert.Contains(t, body, "no data leaves this host",
		"must reaffirm the local-observability promise — no external scrapers required")
}

func TestObservability_HealthchecksReflectStoreState(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Every healthcheck subsystem must appear.
	for _, name := range []string{"Store", "Identity", "Last check", "Last scan", "OTLP endpoint"} {
		assert.Contains(t, body, name,
			"healthcheck row for %q must render", name)
	}
}

func TestRollupHealth_AnyFailIsDown(t *testing.T) {
	cases := []struct {
		name   string
		want   string
		checks []healthCheck
	}{
		{
			name:   "all-pass-is-healthy",
			checks: []healthCheck{{Status: "pass"}, {Status: "pass"}},
			want:   "healthy",
		},
		{
			name:   "any-warn-is-degraded",
			checks: []healthCheck{{Status: "pass"}, {Status: "warn"}},
			want:   "degraded",
		},
		{
			name:   "any-fail-is-down",
			checks: []healthCheck{{Status: "pass"}, {Status: "warn"}, {Status: "fail"}},
			want:   "down",
		},
		{
			name:   "empty-defaults-healthy",
			checks: nil,
			want:   "healthy",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			summary, _, _ := rollupHealth(tc.checks)
			assert.Equal(t, tc.want, summary,
				"rollup of %d checks must produce %q", len(tc.checks), tc.want)
		})
	}
}

func TestAggregateProbeMetrics_CanonicalOrderAndStats(t *testing.T) {
	// Build a synthetic probe-result history: 10 dns runs (8 pass, 2 fail),
	// 5 auth runs (4 pass, 1 fail), with deterministic latencies.
	var rows []sqlite.ProbeResultRecord
	for i := 0; i < 10; i++ {
		r := "pass"
		if i >= 8 {
			r = "fail"
		}
		rows = append(rows, sqlite.ProbeResultRecord{
			ProbeName: "dns", Result: r, LatencyMS: int64(10 * (i + 1)),
		})
	}
	for i := 0; i < 5; i++ {
		r := "pass"
		if i == 0 {
			r = "fail"
		}
		rows = append(rows, sqlite.ProbeResultRecord{
			ProbeName: "auth", Result: r, LatencyMS: int64(100 + 10*i),
		})
	}

	metrics := aggregateProbeMetrics(rows)
	require.Len(t, metrics, 2, "must produce one metric per probe with data")

	// Canonical order: dns before auth (matches connection-check rendering).
	assert.Equal(t, "dns", metrics[0].Name)
	assert.Equal(t, "auth", metrics[1].Name)

	// dns: 10 total, 8 passed → 80% pass rate.
	assert.Equal(t, 10, metrics[0].Total)
	assert.Equal(t, 8, metrics[0].Passed)
	assert.Equal(t, 2, metrics[0].Failed)
	assert.InDelta(t, 0.8, metrics[0].PassRate, 0.001)
	assert.Equal(t, "80.0%", metrics[0].PassPct)

	// dns latencies are 10..100ms; median is the 5th (50ms) using
	// nearest-rank, p95 is the 10th (100ms).
	assert.Equal(t, int64(50), metrics[0].MedianMS)
	assert.Equal(t, int64(100), metrics[0].P95MS)

	// auth: 5 total, 4 passed → 80%.
	assert.Equal(t, 5, metrics[1].Total)
	assert.Equal(t, 4, metrics[1].Passed)
	assert.Equal(t, "80.0%", metrics[1].PassPct)
}

func TestAggregateProbeMetrics_OmitsEmptyProbes(t *testing.T) {
	// Only one probe has data — the other five canonical probes must
	// NOT appear in the output (no zero-filled rows).
	rows := []sqlite.ProbeResultRecord{
		{ProbeName: "dns", Result: "pass", LatencyMS: 10},
	}
	metrics := aggregateProbeMetrics(rows)
	require.Len(t, metrics, 1)
	assert.Equal(t, "dns", metrics[0].Name)
}

func TestAggregateScanStats_TotalLatestAndAverage(t *testing.T) {
	now := time.Now().UTC()
	// 3 completed runs of 30s, 60s, 90s + 1 in-progress.
	completed := []time.Duration{30 * time.Second, 60 * time.Second, 90 * time.Second}
	var runs []model.ScanRun
	for _, d := range completed {
		started := now.Add(-d)
		ended := now
		runs = append(runs, model.ScanRun{
			ID: uuid.New(), StartedAt: started, CompletedAt: &ended,
			Status: model.ScanStatusCompleted,
		})
	}
	// In-progress run (newest, no CompletedAt).
	inProgressStart := now.Add(-10 * time.Second)
	runs = append([]model.ScanRun{{
		ID: uuid.New(), StartedAt: inProgressStart,
		Status: model.ScanStatusRunning,
	}}, runs...)

	stats := aggregateScanStats(runs)
	assert.Equal(t, 4, stats.Total, "all 4 runs counted")
	assert.Equal(t, "in progress", stats.LatestDuration,
		"latest is in-progress → duration must read 'in progress', not numeric")
	assert.Equal(t, "running", stats.LatestStatus)
	assert.Equal(t, "badge-blue", stats.LatestBadge)
	// Average is across only the 3 completed runs: (30+60+90)/3 = 60s.
	assert.Equal(t, "1m0s", stats.AverageDuration,
		"average must exclude the in-progress run (no CompletedAt yet)")
}

func TestAggregateScanStats_EmptyReturnsZero(t *testing.T) {
	stats := aggregateScanStats(nil)
	assert.Equal(t, 0, stats.Total)
	assert.Empty(t, stats.LatestStartedAt)
	assert.Empty(t, stats.AverageDuration)
}

func TestPercentileMS_NearestRank(t *testing.T) {
	// 10 values: nearest-rank p50 = idx 4 (5th value), p95 = idx 9 (10th).
	values := []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	assert.Equal(t, int64(50), percentileMS(values, 0.5))
	assert.Equal(t, int64(100), percentileMS(values, 0.95))
	assert.Equal(t, int64(10), percentileMS(values, 0.0001),
		"sub-1% percentile must return the smallest value (idx 0)")
}

func TestPercentileMS_EmptyReturnsZero(t *testing.T) {
	assert.Equal(t, int64(0), percentileMS(nil, 0.5))
	assert.Equal(t, int64(0), percentileMS([]int64{}, 0.95))
}

func TestObservabilityRoute_PlainGETReturnsFullShell(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "<html",
		"plain GET must return the full shell so reload/share-link work")
	assert.Contains(t, body, "Local observability",
		"shell must embed the observability fragment")
}

func TestObservabilityRoute_HXRequestReturnsFragmentOnly(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil,
		map[string]string{"HX-Request": "true"})
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.NotContains(t, body, "<html",
		"HX-Request must return fragment-only so nav swap doesn't nest a full doc")
	assert.Contains(t, body, "Local observability",
		"fragment must contain the observability content")
}

func TestObservabilityRoute_PopulatedFromRealProbeRuns(t *testing.T) {
	h := newInstallHarness(t, nil)
	ctx := context.Background()

	// Seed real probe rows.
	for i := 0; i < 6; i++ {
		require.NoError(t, h.store.InsertProbeResult(ctx, sqlite.ProbeResultRecord{
			ProbeName: "dns", Result: "pass", LatencyMS: 25, CheckedAt: time.Now().UTC(),
		}))
	}

	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// The probe metrics section must show real data, not the empty-state copy.
	assert.NotContains(t, body, "No probe runs yet",
		"with real probe data the empty-state copy must NOT appear")
	assert.Contains(t, body, "100.0%",
		"all-pass probe runs must aggregate to a 100% pass rate in the table")
}

// ---------------------------------------------------------------------------
// Inline-SVG charts — completes the user's "metrics, healthchecks, charts" ask
// ---------------------------------------------------------------------------

func TestLatencySparklineSVG_ProducesAccessibleChart(t *testing.T) {
	svg := string(latencySparklineSVG([]int64{10, 50, 30, 80, 20}, "dns"))

	// SVG must declare role="img" + aria-label naming the probe + run count
	// so AT users get the gist without seeing the visual.
	assert.Contains(t, svg, `role="img"`,
		"sparkline must declare role='img' so AT identifies it as a chart, not decorative")
	assert.Contains(t, svg, `aria-label="latency trend across last 5 dns probe runs`,
		"aria-label must name the probe + run count so AT users understand what the chart represents")
	assert.Contains(t, svg, `oldest left, newest right`,
		"aria-label must explain the temporal direction so AT users understand the time axis")

	// polyline element must be present with the right number of points
	// (5 input values → 5 'x,y ' pairs separated by spaces).
	assert.Contains(t, svg, `<polyline`,
		"sparkline must use polyline for the line chart")
	// Extract the points attribute and count point pairs (space-separated).
	pointsStart := strings.Index(svg, `points="`) + len(`points="`)
	pointsEnd := strings.Index(svg[pointsStart:], `"`) + pointsStart
	require.Greater(t, pointsEnd, pointsStart, "points attribute must be present and quoted")
	pointPairs := strings.Fields(svg[pointsStart:pointsEnd])
	assert.Len(t, pointPairs, 5,
		"polyline points= must contain one space-separated pair per input value (5 inputs → 5 pairs)")
	assert.Contains(t, svg, `stroke="currentColor"`,
		"stroke must use currentColor so the chart inherits the surrounding text color (works in dark mode)")
}

func TestLatencySparklineSVG_EmptyReturnsPlaceholder(t *testing.T) {
	svg := string(latencySparklineSVG(nil, "dns"))
	assert.NotContains(t, svg, `<svg`,
		"empty latency list must NOT render a zero-point SVG — placeholder text is clearer")
	assert.Contains(t, svg, "—",
		"empty-state placeholder must be a visible em-dash so the cell isn't blank")
}

func TestLatencySparklineSVG_SingleValueCentersHorizontally(t *testing.T) {
	// Single-value edge case: the polyline degenerates to a point. The x
	// coordinate must center (width/2 = 60) so the dot doesn't sit at the
	// left edge of the cell.
	svg := string(latencySparklineSVG([]int64{42}, "dns"))
	assert.Contains(t, svg, `60.0,`,
		"single-value sparkline must center the point at x=width/2 (60) rather than at the left edge")
}

func TestDurationBarsSVG_ProducesAccessibleChart(t *testing.T) {
	durs := []time.Duration{30 * time.Second, 60 * time.Second, 45 * time.Second}
	svg := string(durationBarsSVG(durs))

	assert.Contains(t, svg, `role="img"`,
		"bar chart must declare role='img' for AT identification")
	assert.Contains(t, svg, `aria-label="recent scan durations across last 3 completed runs`,
		"aria-label must name the data + run count for AT users")
	assert.Equal(t, 3, strings.Count(svg, "<rect"),
		"3 input durations → 3 bar rects")
	assert.Contains(t, svg, `fill="currentColor"`,
		"bars must use currentColor so they inherit theme color")
}

func TestDurationBarsSVG_EmptyReturnsPlaceholder(t *testing.T) {
	svg := string(durationBarsSVG(nil))
	assert.NotContains(t, svg, `<svg`,
		"empty duration list must NOT render an empty SVG")
	assert.Contains(t, svg, "—",
		"empty-state placeholder must be the visible em-dash")
}

func TestObservability_ProbeMetricsTableIncludesTrendColumn(t *testing.T) {
	h := newInstallHarness(t, nil)
	ctx := context.Background()
	// Seed varied latencies so the sparkline is meaningful.
	for i := 0; i < 8; i++ {
		require.NoError(t, h.store.InsertProbeResult(ctx, sqlite.ProbeResultRecord{
			ProbeName: "dns", Result: "pass", LatencyMS: int64(20 + i*10), CheckedAt: time.Now().UTC(),
		}))
	}

	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, `<th>Latency trend</th>`,
		"probe metrics table must include a Latency-trend column header (disambiguated from the iter-32 uptime-strip column)")
	assert.Contains(t, body, `class="spark-line"`,
		"populated probe metric row must render the sparkline SVG with the spark-line class")
	assert.Contains(t, body, `aria-label="latency trend across last 8 dns probe runs`,
		"sparkline aria-label must name the actual probe and run count from the data")
}

// ---------------------------------------------------------------------------
// Snapshot export — JSON dump for support / archiving / scripted monitoring
// ---------------------------------------------------------------------------

func TestObservabilitySnapshot_ReturnsDownloadableJSON(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.json", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	// Content type must be JSON.
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"),
		"snapshot endpoint must serve application/json")

	// Content-Disposition must trigger a browser download with a
	// timestamped filename so multiple snapshots don't collide in the
	// operator's Downloads folder.
	cd := rec.Header().Get("Content-Disposition")
	assert.Contains(t, cd, "attachment",
		"Content-Disposition must request browser-side download UX")
	assert.Contains(t, cd, "kite-observability-",
		"filename must include the kite-observability prefix for searchability")
	assert.Contains(t, cd, ".json",
		"filename must have a .json extension")

	// Body must be valid JSON with the expected top-level structure.
	var view observabilityView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view),
		"snapshot body must be valid JSON parseable into observabilityView")
	assert.NotEmpty(t, view.GeneratedAt,
		"snapshot must carry a generated_at timestamp so support tickets can correlate with logs")
	assert.NotEmpty(t, view.HealthSummary,
		"snapshot must include the health rollup")
	require.GreaterOrEqual(t, len(view.Health), 5,
		"snapshot must include all 5 subsystem health checks")
}

func TestObservabilitySnapshot_OmitsUIOnlySVGMarkup(t *testing.T) {
	// SVG sparkline markup is UI-only — it pollutes the JSON snapshot with
	// kilobytes of irrelevant <polyline> data and isn't machine-useful.
	// Iteration 29 added `json:"-"` tags on every template.HTML field;
	// this test pins that contract.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.json", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	body := rec.Body.String()
	assert.NotContains(t, body, "<svg",
		"snapshot JSON must NOT contain <svg> markup — that's UI-only and bloats the export")
	assert.NotContains(t, body, "<polyline",
		"snapshot JSON must NOT contain <polyline> elements — UI-only")
	assert.NotContains(t, body, `"trend_svg"`,
		"snapshot JSON must NOT include the TrendSVG field under any name — `json:\"-\"` tag must hold")
}

func TestObservabilitySnapshot_IncludesRuntimeStatsJSON(t *testing.T) {
	// Field-name contract test: scripted monitoring downstream depends on
	// stable JSON keys. Pin the snake-case field names that iteration 29's
	// JSON tags chose so a future struct-field rename can't silently break
	// downstream parsers.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.json", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	body := rec.Body.String()
	for _, key := range []string{
		`"go_version":`,
		`"heap_alloc":`,
		`"heap_sys":`,
		`"goroutines":`,
		`"uptime":`,
		`"health":`,
		`"health_summary":`,
		`"runtime":`,
		`"generated_at":`,
	} {
		assert.Contains(t, body, key,
			"snapshot must expose the %s JSON key — stable contract for scripted consumers", key)
	}
}

func TestObservabilityPage_IncludesSnapshotDownloadLink(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// The header copy must mention the snapshot download alongside the
	// existing Prometheus pointer so operators discover both integration
	// surfaces from the same paragraph.
	assert.Contains(t, body, `href="/api/v1/observability/snapshot.json"`,
		"observability page must link to the snapshot endpoint")
	assert.Contains(t, body, `download`,
		"snapshot link must use the HTML download attribute so click triggers Save-as")
	assert.Contains(t, body, "JSON snapshot",
		"link text must communicate that the file is a JSON snapshot")
	assert.Contains(t, body, "scripted monitoring",
		"context copy must surface the scripted-monitoring workflow so operators understand when to use the JSON export")
}

// ---------------------------------------------------------------------------
// Data-table row counts — "what data has the agent collected?" (iter 28)
// ---------------------------------------------------------------------------

func TestCollectRuntimeStats_DataTableCountsOnFreshStore(t *testing.T) {
	st, err := sqlite.New(t.TempDir() + "/data-counts.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	stats := collectRuntimeStats(context.Background(), onboardingDeps{Store: st})

	// Freshly-migrated store: all data tables exist but are empty.
	// The COUNT queries must succeed (HasDataRowCounts=true) AND report 0.
	assert.True(t, stats.HasDataRowCounts,
		"data-table COUNT queries must succeed on a freshly-migrated store — schema includes assets/events/config_findings")
	assert.Equal(t, "0", stats.AssetRows,
		"empty assets table must report 0 — operators see this on a fresh install")
	assert.Equal(t, "0", stats.EventRows,
		"empty events table must report 0")
	assert.Equal(t, "0", stats.FindingRows,
		"empty config_findings table must report 0")
}

func TestCollectRuntimeStats_DataTableCountsFallbackToPlaceholder(t *testing.T) {
	// nil store → all data-table placeholders should render the em-dash
	// so the template's empty-state copy is consistent across operational
	// and data-table rows.
	stats := collectRuntimeStats(context.Background(), onboardingDeps{Store: nil})
	assert.Equal(t, "—", stats.AssetRows,
		"nil store must surface the em-dash placeholder for assets")
	assert.Equal(t, "—", stats.EventRows,
		"nil store must surface the em-dash placeholder for events")
	assert.Equal(t, "—", stats.FindingRows,
		"nil store must surface the em-dash placeholder for findings")
	assert.False(t, stats.HasDataRowCounts,
		"HasDataRowCounts must be false when no store is wired")
}

func TestObservability_RuntimeCardRendersDataTableRows(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Section headers split operational from data tables visually.
	assert.Contains(t, body, "Operational tables",
		"runtime card must split operational tables (probe_result, scan_runs) under their own section header")
	assert.Contains(t, body, "what the agent has collected",
		"data-tables section header must include the operator-facing copy explaining what these rows are")

	// All three data-table rows must render.
	for _, label := range []string{
		"assets discovered",
		"events emitted",
		"findings surfaced",
	} {
		assert.Contains(t, body, ">"+label+"<",
			"runtime card must include the %q row so operators see what the agent has produced", label)
	}
}

// ---------------------------------------------------------------------------
// Process history ring buffer + heap/goroutine trend sparklines (iter 27)
// ---------------------------------------------------------------------------

func TestProcessHistory_RingBufferAppendsAndCaps(t *testing.T) {
	resetProcessHistoryForTest()
	// Sample twice the cap; only the last processHistoryCap samples must remain.
	for i := 0; i < processHistoryCap*2; i++ {
		recordProcessSample()
	}
	samples := processHistorySamples()
	assert.Len(t, samples, processHistoryCap,
		"ring buffer must cap at processHistoryCap regardless of total samples taken")
}

func TestProcessHistory_OrderIsOldestToNewest(t *testing.T) {
	resetProcessHistoryForTest()
	// Take a few samples spaced out — At timestamps must be strictly
	// increasing in the returned slice (oldest first, newest last) so the
	// sparkline reads left-to-right chronologically.
	for i := 0; i < 5; i++ {
		recordProcessSample()
		time.Sleep(2 * time.Millisecond)
	}
	samples := processHistorySamples()
	require.Len(t, samples, 5)
	for i := 1; i < len(samples); i++ {
		assert.True(t, samples[i].At.After(samples[i-1].At) || samples[i].At.Equal(samples[i-1].At),
			"sample[%d].At (%s) must be >= sample[%d].At (%s) — chronological order is the sparkline's reading direction",
			i, samples[i].At, i-1, samples[i-1].At)
	}
}

func TestProcessHistory_SnapshotIsolatedFromBuffer(t *testing.T) {
	// Mutating the returned snapshot must NOT affect future reads — the
	// helper must return a copy, not the underlying slice.
	resetProcessHistoryForTest()
	for i := 0; i < 3; i++ {
		recordProcessSample()
	}
	snap1 := processHistorySamples()
	require.Len(t, snap1, 3)
	snap1[0].Goroutines = 9999 // mutate the snapshot

	snap2 := processHistorySamples()
	require.Len(t, snap2, 3)
	assert.NotEqual(t, 9999, snap2[0].Goroutines,
		"second snapshot must not reflect the first snapshot's mutation — processHistorySamples must return a copy")
}

func TestSparklineSVG_GenericHelperEscapesAriaLabel(t *testing.T) {
	// The aria-label parameter accepts arbitrary strings; the helper must
	// HTML-escape them so caller-supplied text can't break out of the
	// attribute. Defensive even though current callers only pass internal
	// strings — the contract should be safe-by-default.
	svg := string(sparklineSVG([]int64{1, 2, 3}, `bad" onload="alert(1)`, "spark-line"))
	assert.NotContains(t, svg, `onload="alert(1)"`,
		"sparkline must HTML-escape the aria-label so attribute-injection is impossible")
	assert.Contains(t, svg, `&#34;`,
		"escaped quote must appear as the HTML entity in the attribute value")
}

func TestSparklineSVG_EmptyReturnsPlaceholder(t *testing.T) {
	svg := string(sparklineSVG(nil, "any-label", "any-class"))
	assert.NotContains(t, svg, "<svg",
		"empty input must render the placeholder, not a zero-point SVG")
	assert.Contains(t, svg, "—",
		"placeholder must be a visible em-dash so the cell isn't blank")
}

func TestCollectRuntimeStats_PopulatesTrendSVGs(t *testing.T) {
	resetProcessHistoryForTest()
	st, err := sqlite.New(t.TempDir() + "/trend.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	// Each collectRuntimeStats call records one sample. Call several times
	// so the trend sparklines have multiple points to render.
	for i := 0; i < 3; i++ {
		_ = collectRuntimeStats(context.Background(), onboardingDeps{Store: st})
	}
	stats := collectRuntimeStats(context.Background(), onboardingDeps{Store: st})

	heap := string(stats.HeapTrendSVG)
	goro := string(stats.GoroutineTrendSVG)

	assert.Contains(t, heap, `<svg`,
		"HeapTrendSVG must render as an inline SVG once samples exist")
	assert.Contains(t, heap, `aria-label="heap allocation trend`,
		"heap trend aria-label must name the metric for AT users")

	assert.Contains(t, goro, `<svg`,
		"GoroutineTrendSVG must render as an inline SVG once samples exist")
	assert.Contains(t, goro, `aria-label="goroutine count trend`,
		"goroutine trend aria-label must name the metric for AT users")
}

func TestObservability_RuntimeCardRendersTrendSparklines(t *testing.T) {
	resetProcessHistoryForTest()
	h := newInstallHarness(t, nil)

	// Render the page twice so the ring buffer has > 1 sample by the time
	// we assert on the trend SVG content.
	_ = h.do(t, "GET", "/observability", nil, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, `aria-label="heap allocation trend`,
		"runtime card must render the heap trend sparkline with its aria-label")
	assert.Contains(t, body, `aria-label="goroutine count trend`,
		"runtime card must render the goroutine trend sparkline with its aria-label")
	assert.Contains(t, body, "Heap &amp; goroutine sparklines show up to the last 60 samples",
		"footnote must explain the trend window so operators understand what they're looking at")
}

// ---------------------------------------------------------------------------
// Runtime & storage card — process telemetry + SQLite size + row counts
// ---------------------------------------------------------------------------

func TestHumanizeBytes_CoarseUnits(t *testing.T) {
	cases := []struct {
		want  string
		bytes int64
	}{
		{bytes: 0, want: "0 B"},
		{bytes: 500, want: "500 B"},
		{bytes: 1024, want: "1.0 KB"},
		{bytes: 1024 * 1024, want: "1.0 MB"},
		{bytes: 1024 * 1024 * 1024, want: "1.00 GB"},
		{bytes: 50 * 1024 * 1024, want: "50.0 MB"},
		{bytes: 5 * 1024 * 1024 * 1024, want: "5.00 GB"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, humanizeBytes(tc.bytes))
		})
	}
}

func TestHumanizeCount_ThousandsSeparators(t *testing.T) {
	cases := []struct {
		want string
		n    int64
	}{
		{n: 0, want: "0"},
		{n: 999, want: "999"},
		{n: 1000, want: "1,000"},
		{n: 12345, want: "12,345"},
		{n: 1234567, want: "1,234,567"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, humanizeCount(tc.n))
		})
	}
}

func TestHumanizeDuration_CoarseTwoUnits(t *testing.T) {
	cases := []struct {
		want string
		d    time.Duration
	}{
		{d: 500 * time.Millisecond, want: "just started"},
		{d: 12 * time.Second, want: "12s"},
		{d: 45 * time.Minute, want: "45m"},
		{d: 45*time.Minute + 30*time.Second, want: "45m 30s"},
		{d: 2 * time.Hour, want: "2h"},
		{d: 2*time.Hour + 17*time.Minute, want: "2h 17m"},
		{d: 5 * 24 * time.Hour, want: "5d"},
		{d: 5*24*time.Hour + 3*time.Hour, want: "5d 3h"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, humanizeDuration(tc.d))
		})
	}
}

func TestCollectRuntimeStats_PopulatesFromProcess(t *testing.T) {
	st, err := sqlite.New(t.TempDir() + "/runtime.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	stats := collectRuntimeStats(context.Background(), onboardingDeps{Store: st})

	assert.NotEmpty(t, stats.GoVersion,
		"GoVersion must be populated from runtime.Version() — operators need it for compatibility debugging")
	assert.True(t, strings.HasPrefix(stats.GoVersion, "go"),
		"GoVersion must match the runtime.Version() shape (starts with 'go')")
	assert.NotEmpty(t, stats.HeapAlloc,
		"HeapAlloc must be populated from runtime.MemStats.Alloc")
	assert.Greater(t, stats.Goroutines, 0,
		"Goroutines count must be positive — the test goroutine alone is enough")
	assert.NotEmpty(t, stats.Uptime,
		"Uptime must be populated — even on first call ensureStartTime sets the baseline")

	// DB stats — file exists after Migrate, COUNT(*) on the freshly-
	// migrated empty tables must return 0.
	assert.True(t, stats.HasDBSize,
		"DB stat must succeed on a freshly-migrated SQLite file")
	assert.NotEqual(t, "—", stats.DBSize,
		"DBSize must be populated (not the empty-placeholder)")
	assert.True(t, stats.HasStoreRowCounts,
		"row count queries must succeed on freshly-migrated tables")
	assert.Equal(t, "0", stats.ProbeResultRows,
		"empty probe_result table must report 0 rows")
	assert.Equal(t, "0", stats.ScanRunRows,
		"empty scan_runs table must report 0 rows")
}

func TestCollectRuntimeStats_NoStoreDegradesGracefully(t *testing.T) {
	stats := collectRuntimeStats(context.Background(), onboardingDeps{Store: nil})

	// Process telemetry must still populate even without a store.
	assert.NotEmpty(t, stats.GoVersion)
	assert.Greater(t, stats.Goroutines, 0)

	// Store-dependent fields must show the empty placeholder.
	assert.False(t, stats.HasDBSize)
	assert.Equal(t, "—", stats.DBSize)
	assert.False(t, stats.HasStoreRowCounts)
	assert.Equal(t, "—", stats.ProbeResultRows)
}

func TestObservability_RuntimeCardRendersOnPage(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Card title + all key telemetry rows must render.
	assert.Contains(t, body, "Runtime &amp; storage",
		"observability page must include the Runtime & storage card heading")
	for _, label := range []string{
		"Go version",
		"Heap allocated",
		"Heap system",
		"Goroutines",
		"Dashboard uptime",
		"SQLite path",
		"SQLite size",
		"probe_result rows",
		"scan_runs rows",
	} {
		assert.Contains(t, body, ">"+label+"<",
			"runtime card must include the %q row", label)
	}

	// Diagnostic-hint copy — tells operators what to watch for, same
	// pattern as iteration 25's stream-health "backlog above zero" note.
	assert.Contains(t, body, "leak symptoms",
		"runtime card must surface the diagnostic-hint copy so operators know what to look for")
	assert.Contains(t, body, "unbounded growth",
		"runtime card must call out unbounded DB growth as a watch-for signal")
}

func TestEnsureStartTime_IdempotentAcrossCalls(t *testing.T) {
	// The first call sets dashboardStartTime; subsequent calls must NOT
	// reset it (otherwise uptime would forever read "just started").
	ensureStartTime()
	t0 := dashboardStartTime
	time.Sleep(10 * time.Millisecond)
	ensureStartTime()
	assert.Equal(t, t0, dashboardStartTime,
		"ensureStartTime must be idempotent — subsequent calls must not reset the baseline")
}

// ---------------------------------------------------------------------------
// Auto-refresh — observability page must be live, not static
// ---------------------------------------------------------------------------

func TestObservability_PageSelfPollsEvery15Seconds(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// The outer wrapper must point HTMX at the fragment endpoint and
	// poll every 15s. outerHTML swap keeps the wrapper itself fresh so
	// the trigger persists across swaps (standard HTMX gotcha — innerHTML
	// would remove the hx-trigger element along with the content).
	assert.Contains(t, body, `id="observability-root"`,
		"observability page must wrap content in a polling root element")
	assert.Contains(t, body, `hx-get="/fragments/observability"`,
		"root element must point at the fragment endpoint for self-refresh")
	assert.Contains(t, body, `hx-trigger="every 15s"`,
		"observability page must auto-refresh every 15s — operators leave it open to watch state change")
	assert.Contains(t, body, `hx-swap="outerHTML"`,
		"swap must be outerHTML so the polling div replaces itself (hx-trigger survives across swaps)")
	assert.Contains(t, body, "Auto-refreshes every 15 seconds",
		"footer copy must tell operators the page is live so they don't manually reload")
}

// ---------------------------------------------------------------------------
// Stream health card — surfaces StreamController stats that have been
// collected since iteration 1 but never rendered on the observability page
// ---------------------------------------------------------------------------

func TestStreamStateBadge_VocabularyMatchesTopbarBadge(t *testing.T) {
	// Pin the state → badge mapping so iteration 19's topbar status badge
	// and iteration 25's stream-health card use the same color vocabulary.
	cases := []struct {
		state string
		want  string
	}{
		{state: "running", want: "badge-green"},
		{state: "degraded", want: "badge-orange"},
		{state: "stopped", want: "badge-red"},
		{state: "idle", want: "badge-blue"},
		{state: "novel-future-state", want: "badge-gray"},
	}
	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			assert.Equal(t, tc.want, streamStateBadge(tc.state))
		})
	}
}

func TestObservability_StreamCardNotWiredShowsReadOnlyNotice(t *testing.T) {
	// newInstallHarness wires deps without a StreamController, so the
	// stream-health card must render the inspector-mode notice instead
	// of an empty populated card.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "Stream health",
		"stream health section must always render — even in inspector mode (with empty-state copy)")
	assert.Contains(t, body, "No StreamController wired",
		"inspector mode must surface the read-only notice so operators know why no stats are shown")
	assert.Contains(t, body, "--with-agent=true",
		"empty-state copy must point operators at the flag that wires the StreamController")
}

func TestObservability_StreamCardPopulatedFromWiredController(t *testing.T) {
	// Use the existing fakeStreamController from onboarding_test.go to
	// inject a non-nil controller. We have to build the harness inline
	// because newInstallHarness doesn't accept a StreamController param.
	st, err := sqlite.New(t.TempDir() + "/stream-obs.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })

	key, keyErr := newOnboardingWrapKey()
	require.NoError(t, keyErr)

	fakeStream := &fakeStreamController{state: "running"}
	// Run a few simulated Start/Stop cycles so the harness has interesting
	// state to render. Note: fakeStreamController.Status() returns a
	// minimal StreamStatus; we just need a non-nil controller for the
	// view branch to take the populated path.
	_ = fakeStream.Start(context.Background())

	mux := http.NewServeMux()
	registerOnboardingRoutes(mux, onboardingDeps{
		Store:            st,
		WrapKey:          key,
		AppVersion:       "test",
		Commit:           "deadbeef",
		PlatformEndpoint: testPlatformEndpoint,
		ProbeClient:      &http.Client{},
		StreamCtrl:       fakeStream,
	})

	harness := &onboardingTestHarness{mux: mux, store: st, wrapKey: key}
	rec := harness.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// With a wired controller, the populated path must render — read-only
	// notice must NOT appear.
	assert.NotContains(t, body, "No StreamController wired",
		"with StreamController wired, the empty-state notice must not render")
	// The populated card must show the State / Events sent / Backlog depth
	// labels. The actual values come from the fake controller's Status().
	assert.Contains(t, body, ">State<",
		"populated stream-health card must include the State row")
	assert.Contains(t, body, ">Events sent<",
		"populated stream-health card must include the Events sent row")
	assert.Contains(t, body, ">Backlog depth<",
		"populated stream-health card must include the Backlog depth row")
	assert.Contains(t, body, ">Last event<",
		"populated stream-health card must include the Last event row")
	// Backlog warning copy must always appear when populated — it's the
	// diagnostic-hint sentence that helps operators interpret the numbers.
	assert.Contains(t, body, "Backlog depth above zero",
		"populated card must include the diagnostic-hint copy so operators know what to do with the numbers")
}

func TestObservability_SidebarLinkAddedToShell(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	// The sidebar nav must include an Observability link so operators
	// discover the surface from anywhere in the dashboard.
	assert.Contains(t, body, `href="/observability"`,
		"sidebar nav must include /observability link for cross-page discoverability")
	assert.True(t, strings.Contains(body, `>Observability<`),
		"sidebar nav link text must read 'Observability'")
}

// ---------------------------------------------------------------------------
// Iteration 30 — freshness chip + pause/resume control
// ---------------------------------------------------------------------------

func TestObservability_FreshnessChipLiveByDefault(t *testing.T) {
	// The default page render is "Live" — auto-refresh on, chip pulses,
	// and the toggle invites the operator to Pause. Operators need a
	// visible "the page is alive" signal because auto-refresh is otherwise
	// invisible until the next swap fires.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, `class="freshness-chip freshness-chip--live"`,
		"default render must mark the chip as live so operators see auto-refresh is on")
	assert.Contains(t, body, "Live &middot; refreshes every 15s",
		"chip copy must include the cadence so operators know how stale data can get")
	assert.Contains(t, body, `aria-label="Pause automatic refresh"`,
		"toggle anchor must have an accessible aria-label describing its action")
	assert.Contains(t, body, `href="/fragments/observability?paused=1"`,
		"toggle must link to the paused fragment URL so non-HTMX clients also work")
	assert.Contains(t, body, `hx-trigger="every 15s"`,
		"live wrapper must keep the 15s polling trigger so the page refreshes itself")
	assert.Contains(t, body, `role="status"`,
		"chip must be exposed as a status region so screen readers announce updates")
}

func TestObservability_FreshnessChipPausedOmitsAutoRefresh(t *testing.T) {
	// ?paused=1 freezes the page: the chip flips to Paused styling, the
	// hx-trigger attribute disappears from the wrapper (so HTMX stops
	// swapping), and the toggle invites the operator to Resume.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability?paused=1", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "freshness-chip--paused",
		"paused render must apply the paused chip styling so operators see the freeze visually")
	assert.Contains(t, body, "Paused &middot; last update",
		"paused chip copy must explain why nothing is changing")
	assert.Contains(t, body, `aria-label="Resume automatic refresh"`,
		"toggle must offer Resume action with an accessible label")
	assert.Contains(t, body, `href="/fragments/observability"`,
		"resume link must point at the unparameterized fragment URL")
	assert.NotContains(t, body, `hx-trigger="every 15s"`,
		"paused wrapper must omit hx-trigger entirely so HTMX stops the polling")
}

func TestObservability_FragmentRoutePausedQueryParam(t *testing.T) {
	// The fragment route (not just the page route) must honor the paused
	// query param so the HTMX toggle works without a full page reload.
	h := newInstallHarness(t, nil)

	live := h.do(t, "GET", "/fragments/observability", nil, nil)
	require.Equal(t, http.StatusOK, live.Code)
	assert.Contains(t, live.Body.String(), `hx-trigger="every 15s"`,
		"fragment route default must render with the live polling trigger")

	paused := h.do(t, "GET", "/fragments/observability?paused=1", nil, nil)
	require.Equal(t, http.StatusOK, paused.Code)
	assert.NotContains(t, paused.Body.String(), `hx-trigger="every 15s"`,
		"fragment route with paused=1 must omit the polling trigger")
	assert.Contains(t, paused.Body.String(), "freshness-chip--paused",
		"fragment route with paused=1 must render the paused chip styling")
}

func TestObservabilitySnapshot_FreshnessFieldsExcluded(t *testing.T) {
	// The freshness chip is UI-only — its fields are tagged json:"-" so the
	// snapshot endpoint stays free of dashboard-UI state. Pinning the
	// contract here so a future refactor that drops the json:"-" tags
	// (e.g., automated codegen) breaks loudly.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.json", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	for _, ban := range []string{
		`"Freshness"`,
		`"freshness"`,
		`"toggle_url"`,
		`"ToggleURL"`,
		`"paused"`,
	} {
		assert.NotContains(t, body, ban,
			"snapshot must NOT include %s — UI-only freshness state belongs only on the HTML page", ban)
	}
}

func TestSparklineSVG_IncludesTitleTooltipWithMinMaxLatest(t *testing.T) {
	// Native SVG <title> gives operators a hover tooltip with the actual
	// numbers behind the sparkline — no JS, no CSS, just the browser's
	// default tooltip on mouseover. Iteration 30 added this so sparklines
	// stop being decorative-only.
	svg := string(sparklineSVG([]int64{10, 20, 7, 42, 31}, "test", "spark-line"))

	assert.Contains(t, svg, "<title>",
		"sparkline SVG must include a <title> element for the native hover tooltip")
	assert.Contains(t, svg, "min 7",
		"tooltip must surface the minimum value across the series")
	assert.Contains(t, svg, "max 42",
		"tooltip must surface the maximum value across the series")
	assert.Contains(t, svg, "latest 31",
		"tooltip must surface the latest value — what the spark's right edge represents")
	assert.Contains(t, svg, "n=5",
		"tooltip must include the sample count so operators know the window size")
}

// ---------------------------------------------------------------------------
// Iteration 31 — recent-activity timeline + probe-row severity + page title
// ---------------------------------------------------------------------------

func TestProbeRowSeverity_ClassifiesByRecentFailures(t *testing.T) {
	// All pass: row stays clean (no warning class) — operator's eye
	// should glide past healthy probes.
	sev, cls := probeRowSeverity([]string{"pass", "pass", "pass", "pass"})
	assert.Equal(t, "ok", sev,
		"all-pass window must classify as ok so healthy probes don't visually compete")
	assert.Empty(t, cls, "ok severity must not apply a row class")

	// 1-4 failures in the window: degraded (orange tint) — visible but
	// not screaming. This is the "starting to drift" state.
	sev, cls = probeRowSeverity([]string{"fail", "pass", "pass", "pass", "pass", "pass"})
	assert.Equal(t, "degraded", sev,
		"any failure in the window must classify as degraded so newly-flaky probes pop")
	assert.Equal(t, "probe-row-degraded", cls)

	// 5+ failures: critical (red) — half the window failed, urgent.
	sev, cls = probeRowSeverity([]string{"fail", "fail", "fail", "fail", "fail", "pass"})
	assert.Equal(t, "critical", sev,
		"5+ failures in 10 must classify as critical so dying probes scream")
	assert.Equal(t, "probe-row-critical", cls)

	// Empty window: unknown (no data yet).
	sev, cls = probeRowSeverity(nil)
	assert.Equal(t, "unknown", sev,
		"empty window must classify as unknown — no data is not a failure")
	assert.Empty(t, cls)
}

func TestAggregateProbeMetrics_AttachesSeverityClass(t *testing.T) {
	// 5 fails + 5 passes in the last 10 — must end up critical.
	// Rows arrive newest-first; the first 10 in the slice form the
	// recent-results window the severity classifier reads.
	rows := []sqlite.ProbeResultRecord{}
	for i := 0; i < 5; i++ {
		rows = append(rows, sqlite.ProbeResultRecord{
			ProbeName: "dns", Result: "fail", LatencyMS: 5000,
			CheckedAt: time.Now(),
		})
	}
	for i := 0; i < 5; i++ {
		rows = append(rows, sqlite.ProbeResultRecord{
			ProbeName: "dns", Result: "pass", LatencyMS: 50,
			CheckedAt: time.Now(),
		})
	}
	metrics := aggregateProbeMetrics(rows)
	require.Len(t, metrics, 1)
	assert.Equal(t, "critical", metrics[0].Severity,
		"5 fails in the 10-row window must produce critical severity on the probeMetric")
	assert.Equal(t, "probe-row-critical", metrics[0].RowClass,
		"critical severity must surface its CSS class for the template")
}

func TestObservability_ProbeTableAppliesSeverityRowClass(t *testing.T) {
	h := newInstallHarness(t, nil)
	// Seed 5 recent failures so the row earns the critical class.
	for i := 0; i < 5; i++ {
		require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
			ProbeName: "dns", Result: "fail", LatencyMS: 5000, CheckedAt: time.Now().Add(-time.Duration(i) * time.Second),
		}))
	}
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `class="probe-row-critical"`,
		"probe table row must apply the severity class so degraded probes pop visually")
	assert.Contains(t, body, `data-severity="critical"`,
		"row must carry a data-severity attribute for downstream CSS/JS hooks")
}

func TestAggregateRecentActivity_InterleavesProbesAndScans(t *testing.T) {
	now := time.Now()
	probes := []sqlite.ProbeResultRecord{
		{ProbeName: "dns", Result: "pass", LatencyMS: 12, CheckedAt: now.Add(-1 * time.Minute)},
		{ProbeName: "tls", Result: "fail", LatencyMS: 0, Diagnostic: "handshake timeout", CheckedAt: now.Add(-3 * time.Minute)},
	}
	completedAt := now.Add(-2 * time.Minute)
	runs := []model.ScanRun{
		{
			ID:        uuid.New(),
			StartedAt: now.Add(-4 * time.Minute), CompletedAt: &completedAt,
			Status: model.ScanStatusCompleted, TriggerSource: "cli", TotalAssets: 12,
		},
	}
	events := aggregateRecentActivity(probes, runs, 20)
	require.NotEmpty(t, events)

	// Newest first — the t-1m probe must come before the t-4m scan-start.
	assert.True(t, events[0].At > events[len(events)-1].At,
		"events must be sorted newest-first")

	// Must include both probe events AND both scan endpoints (start + completion).
	kinds := map[string]int{}
	for _, e := range events {
		kinds[e.Kind]++
	}
	assert.Equal(t, 1, kinds["probe.pass"],
		"timeline must include the pass event for the dns probe")
	assert.Equal(t, 1, kinds["probe.fail"],
		"timeline must include the fail event for the tls probe")
	assert.Equal(t, 1, kinds["scan.started"],
		"timeline must include the scan-started event")
	assert.Equal(t, 1, kinds["scan.completed"],
		"timeline must include the scan-completed event so operators see both endpoints")

	// Probe-fail event must carry the diagnostic as detail — that's the
	// "WHY did it fail" signal operators actually need.
	for _, e := range events {
		if e.Kind == "probe.fail" {
			assert.Equal(t, "handshake timeout", e.Detail,
				"probe.fail event must surface the diagnostic message as detail")
			assert.Equal(t, "error", e.Severity,
				"probe.fail must carry error severity for the red dot")
		}
	}
}

func TestAggregateRecentActivity_RespectsLimit(t *testing.T) {
	now := time.Now()
	var probes []sqlite.ProbeResultRecord
	for i := 0; i < 50; i++ {
		probes = append(probes, sqlite.ProbeResultRecord{
			ProbeName: "dns", Result: "pass", LatencyMS: 10,
			CheckedAt: now.Add(-time.Duration(i) * time.Second),
		})
	}
	events := aggregateRecentActivity(probes, nil, 20)
	assert.Len(t, events, 20,
		"timeline must cap at the requested limit so the card stays scannable")
}

func TestObservability_RecentActivityCardRenders(t *testing.T) {
	h := newInstallHarness(t, nil)
	require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
		ProbeName: "dns", Result: "pass", LatencyMS: 12, CheckedAt: time.Now().Add(-30 * time.Second),
	}))
	require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
		ProbeName: "tls", Result: "fail", LatencyMS: 0, Diagnostic: "handshake timeout",
		CheckedAt: time.Now().Add(-1 * time.Minute),
	}))
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "Recent activity",
		"observability page must render the recent-activity card")
	assert.Contains(t, body, `class="activity-timeline"`,
		"activity card must use the timeline list class for layout/styling")
	assert.Contains(t, body, "probe dns passed",
		"probe.pass timeline event must render its label")
	assert.Contains(t, body, "probe tls failed",
		"probe.fail timeline event must render its label")
	assert.Contains(t, body, "handshake timeout",
		"probe.fail diagnostic must surface as the event detail")
}

func TestObservability_RecentActivityEmptyState(t *testing.T) {
	// Fresh store: no probe runs, no scans. Card must show the empty
	// state with a pointer to /onboarding, not blank or broken.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Recent activity",
		"empty-state must still render the card header so operators know the surface exists")
	assert.Contains(t, body, "No activity yet",
		"empty-state copy must explain why the timeline is empty and how to populate it")
	assert.Contains(t, body, `href="/onboarding"`,
		"empty-state must link to onboarding so operators know what to do next")
}

func TestObservability_PageTitleScriptReflectsHealth(t *testing.T) {
	// The inline page-title script lets a backgrounded tab show
	// "[DEGRADED]" / "[DOWN]" in the OS tab list — passive monitoring
	// without focus. Pin the script presence + behaviour so a refactor
	// that drops it breaks loudly.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "document.title",
		"observability fragment must include the page-title sync script")
	assert.Contains(t, body, "kite-collector dashboard",
		"title sync script must include the base title constant")
	// On a fresh harness with no identity/no scans, the rollup is
	// "down" (no identity check) so the script will set the [DOWN] prefix.
	// Asserting the script template string covers both branches.
	assert.Contains(t, body, `summary !== "healthy"`,
		"title sync script must branch on the health summary so healthy tabs stay clean")
}

func TestObservabilitySnapshot_IncludesRecentActivityJSON(t *testing.T) {
	// Iteration-31 added recent_activity to the snapshot. Pin the key
	// + event-shape so scripted consumers can depend on it.
	h := newInstallHarness(t, nil)
	require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
		ProbeName: "dns", Result: "pass", LatencyMS: 12, CheckedAt: time.Now(),
	}))
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.json", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var view observabilityView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	require.NotEmpty(t, view.RecentActivity,
		"snapshot must include the recent_activity feed when data exists")
	first := view.RecentActivity[0]
	assert.NotEmpty(t, first.At, "each event must carry the absolute timestamp")
	assert.NotEmpty(t, first.Kind, "each event must carry its kind")
	assert.NotEmpty(t, first.Severity, "each event must carry its severity for downstream colouring")
}

// ---------------------------------------------------------------------------
// Iteration 32 — per-probe uptime strip + page jump-nav
// ---------------------------------------------------------------------------

func TestUptimeStripSVG_RendersOneSquarePerResult(t *testing.T) {
	// results arrive newest-first; the strip must render N rects in
	// total — one per result — regardless of outcome mix.
	svg := string(uptimeStripSVG([]string{"pass", "fail", "pass", "skip", "pass"}, "dns"))
	require.Contains(t, svg, "<svg")
	rectCount := strings.Count(svg, "<rect")
	assert.Equal(t, 5, rectCount,
		"strip must emit exactly one <rect> per result so the visual count matches the data")
}

func TestUptimeStripSVG_ColorsByOutcome(t *testing.T) {
	svg := string(uptimeStripSVG([]string{"pass", "fail", "skip"}, "dns"))
	assert.Contains(t, svg, `fill="#16a34a"`,
		"pass squares must use green so healthy runs read as green at a glance")
	assert.Contains(t, svg, `fill="#dc2626"`,
		"fail squares must use red so failures read as failures (the dominant pattern in incident reviews)")
	assert.Contains(t, svg, `fill="#f59e0b"`,
		"skip squares must use amber — distinct from both pass and fail so they don't get conflated")
}

func TestUptimeStripSVG_NewestOnTheRight(t *testing.T) {
	// results[0] is the NEWEST result. It must end up rendered at the
	// largest X coordinate so "current status" is on the right edge —
	// the reading-direction convention every status-page uses.
	results := []string{"fail", "pass", "pass", "pass", "pass"}
	svg := string(uptimeStripSVG(results, "dns"))

	// With 5 results @ 8px square + 2px gap, the rightmost x is (5-1)*(8+2)=40.
	// That x position must carry the red fill (results[0]=="fail").
	assert.Contains(t, svg, `<rect x="40" y="0" width="8" height="16" fill="#dc2626"`,
		"newest result must render at the rightmost X position with the correct outcome colour")
}

func TestUptimeStripSVG_TooltipIncludesCounts(t *testing.T) {
	svg := string(uptimeStripSVG(
		[]string{"pass", "pass", "fail", "skip", "pass"}, "dns"))
	assert.Contains(t, svg, "<title>",
		"strip must include a <title> for native browser hover tooltip")
	assert.Contains(t, svg, "3 pass",
		"tooltip must surface the pass count so operators get the numbers without counting squares")
	assert.Contains(t, svg, "1 fail",
		"tooltip must surface the fail count — the single most operationally-relevant number")
	assert.Contains(t, svg, "1 skip",
		"tooltip must surface the skip count so operators distinguish skips from fails")
}

func TestUptimeStripSVG_EmptyReturnsPlaceholder(t *testing.T) {
	svg := string(uptimeStripSVG(nil, "dns"))
	assert.NotContains(t, svg, "<svg",
		"empty input must render the em-dash placeholder, not a 0-width SVG")
	assert.Contains(t, svg, "—",
		"placeholder must be a visible em-dash so the column isn't blank")
}

func TestUptimeStripSVG_EscapesProbeNameInAria(t *testing.T) {
	// Defensive: aria-label is generated server-side from a probe name
	// in the controlled six-probe set, but the helper must HTML-escape
	// it anyway so a future probe-name change can't break out of the
	// attribute.
	svg := string(uptimeStripSVG([]string{"pass"}, `bad"onerror="x`))
	assert.NotContains(t, svg, `onerror="x"`,
		"strip must escape the probeName so attribute-injection is impossible")
}

func TestObservability_ProbeTableRendersUptimeStripColumn(t *testing.T) {
	h := newInstallHarness(t, nil)
	// Seed a mix so the strip has both passes and fails.
	for i := 0; i < 5; i++ {
		require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
			ProbeName: "dns", Result: "pass", LatencyMS: 12,
			CheckedAt: time.Now().Add(-time.Duration(i) * time.Minute),
		}))
	}
	require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
		ProbeName: "dns", Result: "fail", LatencyMS: 0,
		CheckedAt: time.Now(),
	}))

	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, ">Last 20<",
		"probe table must include the Last-20 column header so operators know what the strip is")
	assert.Contains(t, body, `class="uptime-strip"`,
		"probe table must render the uptime-strip SVG inside the new column")
	assert.Contains(t, body, `class="uptime-cell"`,
		"the cell wrapping the strip must use the uptime-cell class for the nowrap layout")
}

func TestObservability_PageJumpNavRendersAllSections(t *testing.T) {
	// The jump-nav is a chip strip of links to every card on the page.
	// Pin presence + every section anchor + the matching card id so
	// adding/removing a card forces a deliberate nav update.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, `class="page-jumpnav"`,
		"observability page must render the jump-nav chip bar")
	assert.Contains(t, body, `aria-label="Observability page sections"`,
		"jump-nav must carry an accessible label for screen-reader landmark navigation")

	// Every chip + matching section id must exist.
	sections := []struct{ id, label string }{
		{"section-health", "Health"},
		{"section-activity", "Activity"},
		{"section-probes", "Probes"},
		{"section-scans", "Scans"},
		{"section-stream", "Stream"},
		{"section-runtime", "Runtime"},
		{"section-prometheus", "Prometheus"},
	}
	for _, s := range sections {
		assert.Contains(t, body, `href="#`+s.id+`"`,
			"jump-nav must include link to #%s — every card must be navigable", s.id)
		assert.Contains(t, body, `id="`+s.id+`"`,
			"card matching #%s must carry a matching id attribute so the anchor lands", s.id)
		assert.Contains(t, body, ">"+s.label+"<",
			"jump-nav must include a chip labelled %q", s.label)
	}
}

func TestDurationBarsSVG_IncludesTitleTooltip(t *testing.T) {
	// Same affordance for the scan-duration bar chart: hover gives min/
	// max/latest so operators can read the actual values without leaving
	// the page.
	svg := string(durationBarsSVG([]time.Duration{
		2 * time.Second,
		8 * time.Second,
		3 * time.Second,
	}))
	assert.Contains(t, svg, "<title>",
		"duration bars SVG must include a <title> element for the native hover tooltip")
	assert.Contains(t, svg, "min 2s",
		"tooltip must surface the shortest scan duration in the window")
	assert.Contains(t, svg, "max 8s",
		"tooltip must surface the longest scan duration in the window")
	assert.Contains(t, svg, "latest 3s",
		"tooltip must surface the most recent scan's duration")
}

// ---------------------------------------------------------------------------
// Iteration 33 — health rollup detail + recent-failures focused card
// ---------------------------------------------------------------------------

func TestRollupHealth_DetailNamesFailingAndWarningSubsystems(t *testing.T) {
	// All-pass: detail must be empty so the badge stays clean
	// ("healthy" with no trailing dash).
	_, _, detail := rollupHealth([]healthCheck{
		{Name: "Store", Status: "pass"},
		{Name: "OTLP endpoint", Status: "pass"},
	})
	assert.Empty(t, detail,
		"healthy rollup must produce empty detail so the badge reads cleanly")

	// One warning: detail names it.
	_, _, detail = rollupHealth([]healthCheck{
		{Name: "Store", Status: "pass"},
		{Name: "Last scan", Status: "warn"},
	})
	assert.Equal(t, "Last scan", detail,
		"single-warn rollup must name the warning subsystem in detail")

	// Mixed: failures lead, warnings follow — operators read left-to-
	// right so the urgent ones must come first.
	_, _, detail = rollupHealth([]healthCheck{
		{Name: "Store", Status: "pass"},
		{Name: "Identity", Status: "fail"},
		{Name: "Last scan", Status: "warn"},
		{Name: "OTLP endpoint", Status: "fail"},
	})
	assert.Equal(t, "Identity, OTLP endpoint, Last scan", detail,
		"detail must list failing subsystems before warnings so urgency reads left-to-right")
}

func TestObservability_HealthRollupRendersDetailBesideBadge(t *testing.T) {
	// Fresh harness has no identity → Identity check fails, Last check
	// warns, Last scan warns. Detail must surface those subsystem names
	// so the operator doesn't have to scroll to the Healthchecks card.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, `class="muted small health-rollup-detail"`,
		"degraded/down rollup must render the inline detail span beside the badge")
	// Identity check is failing on a fresh harness (no enrollment).
	assert.Contains(t, body, "Identity",
		"rollup detail must name the Identity subsystem when it fails so operators see what's broken without scrolling")
}

func TestExtractRecentFailures_FiltersFailsAndCapsAtLimit(t *testing.T) {
	now := time.Now()
	rows := []sqlite.ProbeResultRecord{
		{ProbeName: "dns", Result: "pass", CheckedAt: now.Add(-1 * time.Minute)},
		{ProbeName: "tls", Result: "fail", Diagnostic: "handshake timeout", LatencyMS: 5000, CheckedAt: now.Add(-2 * time.Minute)},
		{ProbeName: "auth", Result: "pass", CheckedAt: now.Add(-3 * time.Minute)},
		{ProbeName: "reach", Result: "fail", Diagnostic: "connection refused", LatencyMS: 10, CheckedAt: now.Add(-4 * time.Minute)},
		{ProbeName: "clock", Result: "skip", CheckedAt: now.Add(-5 * time.Minute)},
		{ProbeName: "otlp", Result: "fail", Diagnostic: "HTTP 500 from /v1/traces", LatencyMS: 200, CheckedAt: now.Add(-6 * time.Minute)},
	}

	failures := extractRecentFailures(rows, 5)
	require.Len(t, failures, 3,
		"only the 3 fail rows must surface — passes and skips are filtered out")

	// Newest-first preserved (input is newest-first from the store).
	assert.Equal(t, "tls", failures[0].ProbeName,
		"newest failure must be first so the most-recent error is at the top of the card")
	assert.Equal(t, "handshake timeout", failures[0].Diagnostic,
		"failure entry must carry the diagnostic message — the WHY behind the failure")
	assert.Equal(t, int64(5000), failures[0].LatencyMS,
		"failure entry must carry the pre-failure latency so timeout-vs-instant-reject is distinguishable")

	// Limit honoured even when more failures exist.
	limited := extractRecentFailures(rows, 2)
	assert.Len(t, limited, 2,
		"helper must cap at the requested limit so the card stays scannable")
}

func TestExtractRecentFailures_EmptyOnAllPass(t *testing.T) {
	rows := []sqlite.ProbeResultRecord{
		{ProbeName: "dns", Result: "pass"},
		{ProbeName: "tls", Result: "pass"},
	}
	failures := extractRecentFailures(rows, 5)
	assert.Empty(t, failures,
		"all-pass input must produce zero failures so the empty-state branch renders")
}

func TestObservability_RecentFailuresCardRendersDiagnostics(t *testing.T) {
	h := newInstallHarness(t, nil)
	require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
		ProbeName: "tls", Result: "fail", Diagnostic: "handshake timeout: dial tcp 10.0.0.1:443: i/o timeout",
		LatencyMS: 5000, CheckedAt: time.Now(),
	}))

	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "Recent failures",
		"observability page must render the recent-failures card title")
	assert.Contains(t, body, `id="section-failures"`,
		"failures card must have its section id so the jump-nav anchor lands")
	assert.Contains(t, body, `class="failure-list"`,
		"populated failures card must use the failure-list class for styling")
	assert.Contains(t, body, "handshake timeout",
		"failures card must surface the diagnostic message — the WHY behind the failure")
	assert.Contains(t, body, `<code class="failure-probe">tls</code>`,
		"failure row must render the probe name in the dedicated probe code element")
	assert.Contains(t, body, "5000 ms before failure",
		"failure row must surface the pre-failure latency so timeouts read distinctly")
}

func TestObservability_RecentFailuresEmptyStateIsPositive(t *testing.T) {
	// All probes passing — empty-state copy must be reassuring, not
	// alarming. Operators on a healthy agent shouldn't see "no data" as
	// if the card is broken.
	h := newInstallHarness(t, nil)
	for i := 0; i < 3; i++ {
		require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
			ProbeName: "dns", Result: "pass", LatencyMS: 12, CheckedAt: time.Now().Add(-time.Duration(i) * time.Minute),
		}))
	}

	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "No recent probe failures",
		"empty state must explicitly say no failures (not 'no data') so a healthy agent reads as healthy")
	assert.Contains(t, body, "operating normally",
		"empty state must be reassuring so the absence of failures reads as a positive signal")
	assert.Contains(t, body, `class="failure-empty-state"`,
		"empty state must apply the positive-state CSS class so the green-badge layout renders")
}

func TestObservability_JumpNavIncludesFailuresAnchor(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `href="#section-failures"`,
		"jump-nav must include the Failures anchor so operators can jump straight to the diagnostic card")
	assert.Contains(t, body, ">Failures<",
		"jump-nav must include the Failures chip label")
}

func TestObservabilitySnapshot_IncludesRecentFailuresJSON(t *testing.T) {
	h := newInstallHarness(t, nil)
	require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
		ProbeName: "tls", Result: "fail", Diagnostic: "handshake timeout",
		LatencyMS: 5000, CheckedAt: time.Now(),
	}))
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.json", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var view observabilityView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	require.NotEmpty(t, view.RecentFailures,
		"snapshot must include the recent_failures feed when failures exist")
	first := view.RecentFailures[0]
	assert.Equal(t, "tls", first.ProbeName,
		"snapshot failure must carry the probe name for scripted consumers")
	assert.Equal(t, "handshake timeout", first.Diagnostic,
		"snapshot failure must carry the diagnostic message so off-host tooling sees the WHY")
	assert.NotEmpty(t, first.At,
		"snapshot failure must carry the RFC3339 timestamp for time-based queries")
}

func TestObservabilitySnapshot_IncludesHealthDetailJSON(t *testing.T) {
	// The iter-33 health_detail field surfaces in the snapshot too — so
	// scripted local monitoring can alert on specific subsystems being
	// down without re-parsing the full healthchecks array.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.json", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	body := rec.Body.String()
	assert.Contains(t, body, `"health_detail":`,
		"snapshot must expose health_detail key so scripted consumers can alert on it")
	assert.Contains(t, body, "Identity",
		"on a fresh harness with no identity, snapshot health_detail must name the Identity subsystem")
}

// ---------------------------------------------------------------------------
// Iteration 34 — paste-ready Markdown snapshot endpoint
// ---------------------------------------------------------------------------

func TestObservabilitySnapshotMD_ServesTextPlain(t *testing.T) {
	// Content-type is text/plain so browsers render the markdown source
	// inline as visible text — operators select-all + copy + paste
	// into Slack/PR/ticket without leaving the tab.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.md", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"),
		"markdown snapshot must serve text/plain so browsers render the source visibly")
	cd := rec.Header().Get("Content-Disposition")
	assert.Contains(t, cd, "inline",
		"markdown snapshot must use inline disposition (not attachment) so it opens in the tab, not downloads")
	assert.Contains(t, cd, "kite-observability-",
		"filename must include the kite-observability prefix for searchability")
	assert.Contains(t, cd, ".md",
		"filename must use the .md extension so editors auto-detect markdown")
}

func TestObservabilitySnapshotMD_BodyIsMarkdownFormatted(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.md", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Top-level header + key sections — pin the section order so the
	// markdown format is stable across renders (downstream tooling can
	// regex-match section boundaries).
	assert.True(t, strings.HasPrefix(body, "# kite-collector observability"),
		"body must lead with an H1 so the paste reads as a complete report")
	assert.Contains(t, body, "**Health:**",
		"health rollup must use bold so it stands out in the rendered paste")
	assert.Contains(t, body, "## Healthchecks",
		"healthchecks section must be an H2 so it nests under the report title")
	assert.Contains(t, body, "## Recent failures",
		"recent failures section must appear in the markdown so the diagnostic story is in the paste")
	assert.Contains(t, body, "## Runtime",
		"runtime section must appear so support tickets carry version + uptime info")
	assert.Contains(t, body, "_Generated by kite-collector local observability",
		"footer must identify the source so a teammate seeing the paste knows where it came from")
}

func TestObservabilitySnapshotMD_HealthDetailRendersBesideRollup(t *testing.T) {
	// Iter-33 added health_detail to the JSON snapshot; the markdown
	// must surface the same detail beside the rollup so a teammate
	// reading the paste sees "degraded — Identity, Last scan" not
	// just "degraded".
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.md", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Fresh harness has no identity → rollup will name Identity in detail.
	assert.Regexp(t, `\*\*Health:\*\* (down|degraded) — .*Identity`, body,
		"markdown rollup must include the failing subsystem name beside the badge")
}

func TestObservabilitySnapshotMD_RecentFailuresRenderedAsBullets(t *testing.T) {
	h := newInstallHarness(t, nil)
	require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
		ProbeName: "tls", Result: "fail",
		Diagnostic: "handshake timeout: dial tcp 10.0.0.1:443: i/o timeout",
		LatencyMS:  5000, CheckedAt: time.Now(),
	}))
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.md", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// Bullet list (not a table) so multi-line diagnostics stay readable.
	assert.Contains(t, body, "- `tls`",
		"failure entry must use bullet+inline-code format for the probe name")
	assert.Contains(t, body, "handshake timeout",
		"failure entry must carry the diagnostic message — the actual paste-worthy signal")
	assert.Contains(t, body, "5000 ms before failure",
		"failure entry must surface the pre-failure latency so timeout-vs-instant-reject is distinguishable in the paste")
}

func TestObservabilitySnapshotMD_PositiveEmptyStateWhenNoFailures(t *testing.T) {
	// On a healthy agent, the markdown must emit a reassuring sentence
	// rather than a blank section. The paste should read as "all good"
	// to the teammate, not "I don't know what's happening".
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.md", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "_No recent probe failures",
		"empty failures section must use italic positive copy so a healthy report doesn't read as broken")
	assert.Contains(t, body, "operating normally",
		"positive empty-state must be unambiguously reassuring")
}

func TestRenderObservabilityMarkdown_EscapesPipesInTableCells(t *testing.T) {
	// A healthcheck Detail string with a pipe character must be escaped
	// so the markdown table doesn't fracture. Tested at the helper
	// level so the regression is caught even if the integration test
	// happens to avoid the case.
	view := observabilityView{
		GeneratedAt:   "2026-06-23T19:30:00Z",
		HealthSummary: "healthy",
		Health: []healthCheck{
			{Name: "Store", Status: "pass", Detail: "left | right pipes in detail"},
		},
	}
	md := renderObservabilityMarkdown(view)
	assert.Contains(t, md, `left \| right pipes`,
		"pipes inside table cells must be escaped so the rendered table doesn't break")
}

func TestRenderObservabilityMarkdown_CollapsesNewlinesInTableCells(t *testing.T) {
	// Multi-line diagnostics in a healthcheck Detail (rare but possible)
	// must collapse to a single line in the table cell — multiline cells
	// break Slack/GitHub markdown rendering.
	view := observabilityView{
		GeneratedAt:   "2026-06-23T19:30:00Z",
		HealthSummary: "down",
		Health: []healthCheck{
			{Name: "Store", Status: "fail", Detail: "first line\nsecond line"},
		},
	}
	md := renderObservabilityMarkdown(view)
	assert.Contains(t, md, "first line second line",
		"newlines inside table cells must collapse to single space so the row stays intact")
	assert.NotContains(t, md, "first line\nsecond line",
		"raw newlines inside table cells would fracture the markdown table")
}

func TestObservabilityPage_IncludesMarkdownLinkBesideJSON(t *testing.T) {
	// Both export formats must be discoverable from the page header so
	// operators pick the right one for their workflow without leaving
	// the tab.
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, `href="/api/v1/observability/snapshot.md"`,
		"observability page must link to the markdown snapshot endpoint")
	assert.Contains(t, body, "Markdown summary",
		"link text must communicate that this is a markdown summary (not raw data)")
	assert.Contains(t, body, "Slack",
		"context copy must surface the Slack/PR/ticket paste workflow so operators know when to use the markdown export")
}

// ---------------------------------------------------------------------------
// Iteration 35 — diagnostic classifier with remediation hints
// ---------------------------------------------------------------------------

func TestClassifyDiagnostic_KnownPatternsMap(t *testing.T) {
	// Table-driven: one row per pattern the classifier knows about.
	// Each pattern must produce a non-empty Kind + Message; only the
	// auth pattern carries an action URL today.
	cases := []struct {
		name       string
		diagnostic string
		wantKind   string
		wantURL    string
		mustSay    string // substring the message must include
	}{
		{
			name:       "401-is-auth",
			diagnostic: "HTTP 401 from /api/v1/echo",
			wantKind:   "auth",
			wantURL:    "/onboarding?step=enroll",
			mustSay:    "API key",
		},
		{
			name:       "unauthorized-is-auth",
			diagnostic: "platform returned Unauthorized: token rejected",
			wantKind:   "auth",
			wantURL:    "/onboarding?step=enroll",
			mustSay:    "Re-enroll",
		},
		{
			name:       "no-such-host-is-dns",
			diagnostic: "dial tcp: lookup platform.example.com: no such host",
			wantKind:   "dns",
			mustSay:    "DNS",
		},
		{
			name:       "connection-refused-is-network",
			diagnostic: "dial tcp 10.0.0.1:443: connection refused",
			wantKind:   "network",
			mustSay:    "unreachable",
		},
		{
			name:       "certificate-is-tls",
			diagnostic: "x509: certificate has expired or is not yet valid",
			wantKind:   "tls",
			mustSay:    "Certificate validation",
		},
		{
			name:       "handshake-is-tls",
			diagnostic: "remote error: tls handshake failure",
			wantKind:   "tls",
			mustSay:    "TLS handshake",
		},
		{
			name:       "i-o-timeout-is-timeout",
			diagnostic: "Get https://platform.example.com: dial tcp 10.0.0.1:443: i/o timeout",
			wantKind:   "timeout",
			mustSay:    "deadline",
		},
		{
			name:       "context-cancelled-is-transient",
			diagnostic: "Get https://platform: context canceled",
			wantKind:   "transient",
			mustSay:    "cancelled",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := classifyDiagnostic(tc.diagnostic)
			assert.Equal(t, tc.wantKind, h.Kind,
				"classifier must categorise %q under %q", tc.diagnostic, tc.wantKind)
			assert.Contains(t, h.Message, tc.mustSay,
				"classifier message must include %q so the remediation is actionable", tc.mustSay)
			if tc.wantURL != "" {
				assert.Equal(t, tc.wantURL, h.URL,
					"classifier must include the remediation URL when one is known")
				assert.NotEmpty(t, h.URLText,
					"classifier URL must carry anchor text so the link renders meaningfully")
			}
		})
	}
}

func TestClassifyDiagnostic_UnknownAndEmpty(t *testing.T) {
	// Empty input → empty hint. Unknown pattern → empty hint. The
	// template's `{{if .Hint.Message}}` guard depends on this so an
	// unclassifiable failure renders just the raw diagnostic.
	assert.Equal(t, diagnosticHint{}, classifyDiagnostic(""),
		"empty diagnostic must produce no hint")
	assert.Equal(t, diagnosticHint{}, classifyDiagnostic("some weird error nobody has seen before"),
		"unknown patterns must return zero-value hint so only the raw diagnostic renders")
}

func TestClassifyDiagnostic_AuthBeatsTimeoutWhenBothMatch(t *testing.T) {
	// Diagnostic that contains BOTH "401" AND "timeout" must classify
	// as auth — the more-specific signal wins. Without priority order,
	// the bare-timeout case could overwrite the auth detection.
	hint := classifyDiagnostic("HTTP 401 received after 5s timeout")
	assert.Equal(t, "auth", hint.Kind,
		"specific signals (401) must beat broad signals (timeout) when both match")
}

func TestExtractRecentFailures_PopulatesHint(t *testing.T) {
	now := time.Now()
	rows := []sqlite.ProbeResultRecord{
		{
			ProbeName: "tls", Result: "fail",
			Diagnostic: "remote error: tls handshake failure", LatencyMS: 5000, CheckedAt: now,
		},
		{
			ProbeName: "dns", Result: "fail",
			Diagnostic: "weird unclassifiable error", LatencyMS: 10, CheckedAt: now.Add(-1 * time.Minute),
		},
	}
	failures := extractRecentFailures(rows, 5)
	require.Len(t, failures, 2)

	// First (tls handshake) must carry a classified hint.
	assert.Equal(t, "tls", failures[0].Hint.Kind,
		"failure with known diagnostic must carry the classified hint")
	assert.Contains(t, failures[0].Hint.Message, "TLS handshake",
		"failure hint must include the plain-language explanation for the operator")

	// Second (unknown) must have zero-valued hint so the template skips.
	assert.Empty(t, failures[1].Hint.Kind,
		"failure with unknown diagnostic must carry zero-value hint so the template renders only the raw error")
	assert.Empty(t, failures[1].Hint.Message,
		"unknown hint message must stay empty so the hint block doesn't render with placeholder content")
}

func TestObservability_FailureCardRendersHintBlock(t *testing.T) {
	h := newInstallHarness(t, nil)
	require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
		ProbeName: "auth", Result: "fail",
		Diagnostic: "HTTP 401 from /api/v1/echo: invalid API key",
		LatencyMS:  120, CheckedAt: time.Now(),
	}))

	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, `class="failure-hint"`,
		"failures card must render the hint block when a known diagnostic is classified")
	assert.Contains(t, body, `data-kind="auth"`,
		"hint block must carry data-kind for CSS/JS hooks (and future filtering)")
	assert.Contains(t, body, "platform rejected the agent",
		"hint block must surface the plain-language remediation message")
	assert.Contains(t, body, `class="failure-hint-action"`,
		"auth hint must render the action link to /onboarding")
	assert.Contains(t, body, `href="/onboarding?step=enroll"`,
		"hint action link must point at the enrollment step so operators land in the right place")
	assert.Contains(t, body, "Open enrollment",
		"hint action anchor text must communicate the action verb")
}

func TestObservability_FailureCardSkipsHintWhenUnclassified(t *testing.T) {
	// Failure with an opaque diagnostic must render only the raw block,
	// NOT a hint block with placeholder copy.
	h := newInstallHarness(t, nil)
	require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
		ProbeName: "otlp", Result: "fail",
		Diagnostic: "really weird thing happened that we've never seen",
		LatencyMS:  50, CheckedAt: time.Now(),
	}))

	rec := h.do(t, "GET", "/observability", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "really weird thing happened",
		"failures card must still render the raw diagnostic for unknown patterns")
	assert.NotContains(t, body, `class="failure-hint"`,
		"unclassified failures must NOT render the hint block — better to show only the diagnostic than a wrong/empty hint")
}

func TestObservabilitySnapshotMD_IncludesHintBeneathFailure(t *testing.T) {
	// The markdown paste workflow must carry the hint too — operators
	// pasting an incident summary need the remediation context in the
	// paste, not just the raw error string.
	h := newInstallHarness(t, nil)
	require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
		ProbeName: "tls", Result: "fail",
		Diagnostic: "remote error: tls handshake failure", LatencyMS: 5000, CheckedAt: time.Now(),
	}))
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.md", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "  - **tls:**",
		"markdown failure list must render the hint as a nested bullet so remediation reads under the failure")
	assert.Contains(t, body, "TLS handshake failed",
		"markdown must include the plain-language hint message for the paste")
}

func TestObservabilitySnapshotMD_AuthHintIncludesActionLink(t *testing.T) {
	// Auth-class hints carry a URL; the markdown must render it as a
	// link so the paste reader can click straight through to the
	// remediation surface.
	h := newInstallHarness(t, nil)
	require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
		ProbeName: "auth", Result: "fail",
		Diagnostic: "HTTP 401 unauthorized", LatencyMS: 120, CheckedAt: time.Now(),
	}))
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.md", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "[Open enrollment](/onboarding?step=enroll)",
		"markdown auth hint must include the action URL as a clickable markdown link")
}

func TestObservabilitySnapshot_IncludesHintInJSON(t *testing.T) {
	// JSON snapshot must include the classified hint so scripted
	// consumers can alert on Kind=="auth" and route the ticket
	// appropriately — not every consumer reads the raw diagnostic.
	h := newInstallHarness(t, nil)
	require.NoError(t, h.store.InsertProbeResult(context.Background(), sqlite.ProbeResultRecord{
		ProbeName: "auth", Result: "fail",
		Diagnostic: "HTTP 401 unauthorized", LatencyMS: 120, CheckedAt: time.Now(),
	}))
	rec := h.do(t, "GET", "/api/v1/observability/snapshot.json", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var view observabilityView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	require.NotEmpty(t, view.RecentFailures)
	assert.Equal(t, "auth", view.RecentFailures[0].Hint.Kind,
		"snapshot failure must carry the classified hint kind for scripted alerting")
	assert.Contains(t, view.RecentFailures[0].Hint.Message, "API key",
		"snapshot failure hint must include the plain-language message for downstream tools")
	assert.Equal(t, "/onboarding?step=enroll", view.RecentFailures[0].Hint.URL,
		"snapshot failure hint must include the action URL for consumers that route to remediation surfaces")
}
