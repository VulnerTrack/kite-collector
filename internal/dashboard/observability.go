package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// dashboardStartTime captures the timestamp of the first call into the
// observability render path so the "Uptime" row in the Runtime & storage
// card has a meaningful baseline. Initialized lazily to avoid coupling
// observability concerns to package init() ordering. Protected by once
// so concurrent first-renders don't race the assignment.
var (
	dashboardStartTime time.Time
	startOnce          sync.Once
)

func ensureStartTime() {
	startOnce.Do(func() { dashboardStartTime = time.Now() })
}

// processSample is one in-memory snapshot of process telemetry. Iteration 27
// keeps a bounded ring buffer of these so the Runtime & storage card can
// render heap/goroutine TRENDS, not just point-in-time numbers — the
// difference between "spot a leak" and "see a number." Lost on restart by
// design (a restart resets the leak too).
type processSample struct {
	At         time.Time
	HeapAlloc  uint64
	Goroutines int
}

// processHistoryCap bounds the in-memory ring buffer. 60 samples ×
// iteration-25's 15s auto-refresh interval = 15 minutes of lookback —
// enough to spot a leak before it's catastrophic, short enough to keep
// memory negligible and the sparkline scannable.
const processHistoryCap = 60

var (
	processHistory   []processSample
	processHistoryMu sync.Mutex
)

// recordProcessSample appends the current heap + goroutine state to the
// ring buffer. Called from collectRuntimeStats so the buffer grows
// naturally with each observability render. Bounded by processHistoryCap
// with FIFO eviction when full.
func recordProcessSample() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	sample := processSample{
		At:         time.Now(),
		HeapAlloc:  ms.Alloc,
		Goroutines: runtime.NumGoroutine(),
	}
	processHistoryMu.Lock()
	processHistory = append(processHistory, sample)
	if len(processHistory) > processHistoryCap {
		processHistory = processHistory[len(processHistory)-processHistoryCap:]
	}
	processHistoryMu.Unlock()
}

// processHistorySamples returns a snapshot copy of the ring buffer in
// oldest→newest order so the resulting sparkline reads left-to-right
// chronologically. The copy isolates callers from concurrent mutation.
func processHistorySamples() []processSample {
	processHistoryMu.Lock()
	defer processHistoryMu.Unlock()
	out := make([]processSample, len(processHistory))
	copy(out, processHistory)
	return out
}

// resetProcessHistoryForTest clears the ring buffer between tests so test
// runs don't bleed sample data into each other.
func resetProcessHistoryForTest() {
	processHistoryMu.Lock()
	processHistory = nil
	processHistoryMu.Unlock()
}

// observabilityView is what the /observability page template consumes. It
// composes everything operators need to self-observe their local agent:
// healthchecks (is the data we collected actually showing up?), probe
// metrics (latency + pass-rate per probe), scan stats (counts + durations),
// and a pointer to the local Prometheus endpoint for tool integration.
//
// All data is read from the SQLite store the dashboard already has
// access to — no new scrapers, no external observability stack required.
// "Local-instance observability" by design.
type observabilityView struct {
	Stream         *streamHealth          `json:"stream,omitempty"`
	GeneratedAt    string                 `json:"generated_at"`
	Endpoint       string                 `json:"endpoint,omitempty"`
	HealthSummary  string                 `json:"health_summary"`
	HealthDetail   string                 `json:"health_detail,omitempty"` // iter-33: names of fail/warn subsystems beside the rollup badge
	HealthClass    string                 `json:"-"`                       // CSS class, UI-only
	ScanStats      scanStats              `json:"scan_stats"`
	Health         []healthCheck          `json:"health"`
	ProbeMetrics   []probeMetric          `json:"probe_metrics"`
	RecentActivity []activityEvent        `json:"recent_activity,omitempty"`
	RecentFailures []recentFailure        `json:"recent_failures,omitempty"`
	Runtime        runtimeStats           `json:"runtime"`
	Freshness      observabilityFreshness `json:"-"` // UI-only: chip state + pause/resume controls
	HasProbeData   bool                   `json:"has_probe_data"`
	HasScanData    bool                   `json:"has_scan_data"`
	HasActivity    bool                   `json:"-"`
	HasFailures    bool                   `json:"-"`
}

// recentFailure is one row in the iteration-33 "Recent failures" focused
// card — the diagnostic-first surface that answers the operator's #1
// debugging question on a degraded agent: WHY is it failing? Scrolling
// the 20-event activity timeline to cherry-pick failures buries the
// signal; this card surfaces nothing but failures (or a positive empty
// state when everything is healthy).
//
// Hint (iter-35) carries an actionable plain-language explanation
// derived from the diagnostic via classifyDiagnostic — turns
// "handshake timeout: dial tcp 10.0.0.1:443: i/o timeout" from an
// inscrutable error string into "TLS handshake failed. Likely cause:
// proxy, expired certificate, or unsupported cipher." Best-effort:
// unknown patterns leave Hint zero-valued so only the raw diagnostic
// renders.
type recentFailure struct {
	At         string         `json:"at"`          // RFC3339 — stable timestamp for the JSON snapshot
	AtRel      string         `json:"at_relative"` // "2m ago"
	ProbeName  string         `json:"probe_name"`
	Diagnostic string         `json:"diagnostic"` // the actual error message that fired
	Hint       diagnosticHint `json:"hint,omitempty"`
	LatencyMS  int64          `json:"latency_ms"` // included so timeout-style failures (high latency) read distinctly from instant rejections
}

// diagnosticHint is the actionable remediation context attached to a
// recentFailure by classifyDiagnostic. Zero value means "no hint
// available" — the page falls back to showing only the raw diagnostic.
type diagnosticHint struct {
	Kind    string `json:"kind,omitempty"`     // "auth" / "dns" / "network" / "tls" / "timeout" / "transient" — category badge
	Message string `json:"message,omitempty"`  // plain-language explanation + recommended next steps
	URL     string `json:"url,omitempty"`      // optional URL to the remediation surface (e.g., /onboarding)
	URLText string `json:"url_text,omitempty"` // anchor text for URL when present
}

// classifyDiagnostic maps a probe-failure diagnostic string to an
// actionable remediation hint. The classifier is intentionally simple
// — substring matching on the lowercased diagnostic — because the cost
// of misclassification is low (operator sees the raw diagnostic too
// and can disregard the hint) and the cost of "unknown" is also low
// (return zero value, render nothing extra).
//
// Patterns are checked in priority order: most-specific signals first
// (a "401" is unambiguously auth even if the word "timeout" appears
// somewhere too); broader signals later so "timeout" only catches what
// nothing more specific did.
func classifyDiagnostic(diagnostic string) diagnosticHint {
	if diagnostic == "" {
		return diagnosticHint{}
	}
	lc := strings.ToLower(diagnostic)
	switch {
	case strings.Contains(lc, "401") ||
		strings.Contains(lc, "unauthorized") ||
		strings.Contains(lc, "invalid api key") ||
		strings.Contains(lc, "invalid_api_key"):
		return diagnosticHint{
			Kind:    "auth",
			Message: "The platform rejected the agent's API key. Re-enroll the agent to refresh the key.",
			URL:     "/onboarding?step=enroll",
			URLText: "Open enrollment",
		}
	case strings.Contains(lc, "no such host") ||
		strings.Contains(lc, "name resolution") ||
		strings.Contains(lc, "dns lookup"):
		return diagnosticHint{
			Kind:    "dns",
			Message: "DNS cannot resolve the platform endpoint hostname. Check your DNS resolver, /etc/hosts, and the configured endpoint URL.",
		}
	case strings.Contains(lc, "connection refused") ||
		strings.Contains(lc, "econnrefused"):
		return diagnosticHint{
			Kind:    "network",
			Message: "The platform endpoint is unreachable on the configured port. Confirm the endpoint URL and that no firewall is blocking outbound traffic.",
		}
	case strings.Contains(lc, "x509") ||
		strings.Contains(lc, "certificate"):
		return diagnosticHint{
			Kind:    "tls",
			Message: "Certificate validation failed. The platform endpoint's TLS chain is rejected by the agent's trust store — check certificate expiry and the system CA bundle.",
		}
	case strings.Contains(lc, "handshake") ||
		strings.Contains(lc, "tls "):
		return diagnosticHint{
			Kind:    "tls",
			Message: "TLS handshake failed. Likely cause: a TLS-terminating proxy, expired certificate, or unsupported cipher between the agent and the platform endpoint.",
		}
	case strings.Contains(lc, "timeout") ||
		strings.Contains(lc, "deadline exceeded") ||
		strings.Contains(lc, "i/o timeout"):
		return diagnosticHint{
			Kind:    "timeout",
			Message: "Request exceeded the configured deadline. Could be transient network slowness or an overloaded platform endpoint — retry the check before escalating.",
		}
	case strings.Contains(lc, "context canceled") ||
		strings.Contains(lc, "context cancelled"):
		return diagnosticHint{
			Kind:    "transient",
			Message: "The probe was cancelled mid-flight, usually by a parent timeout or a graceful shutdown. Not a platform failure by itself — re-run the check to confirm.",
		}
	}
	return diagnosticHint{}
}

// activityEvent is one row in the iteration-31 "Recent activity" timeline —
// a unified chronological feed of probe outcomes + scan starts/completions.
// Answers the operator's single most common debugging question on a metrics
// page: "what just happened?" Crossing two cards (probes + scans) to spot
// "everything broke at 14:23" used to be manual; the timeline does it for them.
type activityEvent struct {
	At       string `json:"at"`          // RFC3339 — stable for the JSON snapshot
	AtRel    string `json:"at_relative"` // "2m ago" — human-friendly in the UI
	Kind     string `json:"kind"`        // probe.pass / probe.fail / probe.skip / scan.started / scan.completed / scan.failed / scan.cancelled
	Label    string `json:"label"`       // "probe dns failed" / "scan started"
	Detail   string `json:"detail,omitempty"`
	Severity string `json:"severity"` // success / warn / error / info
	Class    string `json:"-"`        // CSS class for the timeline-dot, UI-only
}

// observabilityFreshness drives the iteration-30 "Live · pause/resume" chip
// at the top of the observability fragment. The auto-refresh trigger
// (`hx-trigger="every 15s"`) is conditionally rendered based on Paused so
// the operator can freeze the page while inspecting a specific row without
// the DOM swapping out from under them. State lives in the fragment URL
// (`?paused=1`) — no JS, no client state, no cookies.
type observabilityFreshness struct {
	UpdatedAtUTC    string // RFC3339 timestamp of this render
	ToggleURL       string // /fragments/observability or /fragments/observability?paused=1
	ToggleLabel     string // "Pause" or "Resume"
	ToggleAriaLabel string // accessibility label on the toggle anchor
	WrapperGetURL   string // /fragments/observability with paused state preserved
	AutoRefreshSecs int    // 15 (matches hx-trigger)
	Paused          bool   // when true, hx-trigger is omitted and the chip flips to Paused
}

// runtimeStats is the process + storage telemetry view rendered in the
// observability page's "Runtime & storage" card. Surfaces the classic
// "is the dashboard leaking?" + "is the DB growing without bound?"
// signals that every observability stack needs but the dashboard wasn't
// rendering before iteration 26.
//
// All values are humanized server-side so the template stays dumb (no
// custom template funcs for byte/duration formatting).
type runtimeStats struct {
	GoVersion       string `json:"go_version"`
	HeapAlloc       string `json:"heap_alloc"`
	HeapSys         string `json:"heap_sys"`
	Uptime          string `json:"uptime"`
	DBPath          string `json:"db_path,omitempty"`
	DBSize          string `json:"db_size,omitempty"`
	ProbeResultRows string `json:"probe_result_rows,omitempty"`
	ScanRunRows     string `json:"scan_runs_rows,omitempty"`
	// Data-table row counts — answer the operator-facing question
	// "what data has my agent actually collected?" in the same card
	// that surfaces operational stats. Three counts: assets discovered,
	// events emitted, findings surfaced.
	AssetRows         string        `json:"asset_rows,omitempty"`
	EventRows         string        `json:"event_rows,omitempty"`
	FindingRows       string        `json:"finding_rows,omitempty"`
	HeapTrendSVG      template.HTML `json:"-"` // SVG markup, UI-only; not in the JSON snapshot
	GoroutineTrendSVG template.HTML `json:"-"`
	Goroutines        int           `json:"goroutines"`
	HasDBSize         bool          `json:"-"`
	HasStoreRowCounts bool          `json:"-"`
	HasDataRowCounts  bool          `json:"-"`
}

// streamHealth is the OTLP stream telemetry view rendered in the
// observability page's stream-health card. Surfaces the StreamController
// stats that have been collected since iteration 1 but never rendered.
// Answers the single most important post-onboarding question: "is the
// agent actually shipping events upstream?"
type streamHealth struct {
	State         string `json:"state"`
	StateBadge    string `json:"-"` // CSS class, UI-only
	LastEventAt   string `json:"last_event_at,omitempty"`
	LastEventAgo  string `json:"last_event_ago,omitempty"`
	LastErrorText string `json:"last_error,omitempty"`
	TotalSent     int64  `json:"total_sent"`
	BacklogDepth  int    `json:"backlog_depth"`
}

// healthCheck is one row in the healthchecks panel — a named subsystem
// with a pass/warn/fail status and a one-line explanation. The status
// values stay coarse on purpose; per-row "why" copy carries the nuance.
type healthCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Class  string `json:"-"` // CSS class, UI-only
}

// probeMetric aggregates the last N probe_result rows for a single probe
// name into the per-row stats the observability table renders. Median +
// p95 give operators the typical AND tail latency in two columns —
// pinpointing flaky-but-mostly-fine probes vs consistently-slow ones.
// TrendSVG is an inline-rendered sparkline of the latest latencies — the
// trend column in the metrics table.
type probeMetric struct {
	Name     string        `json:"name"`
	PassPct  string        `json:"pass_pct"`
	TrendSVG template.HTML `json:"-"` // SVG markup, UI-only
	// UptimeStripSVG is the iteration-32 status-page-style tape of
	// coloured squares for the LAST 20 runs of this probe. Green = pass,
	// red = fail, amber = skip. Oldest left, newest right. Higher info
	// density than the latency sparkline at the same column width: a
	// glance tells the operator "still passing?" instead of just "still
	// fast?".
	UptimeStripSVG template.HTML `json:"-"`
	// Severity is computed from the LAST 10 results per probe (more
	// sensitive than the all-time pass rate) so a probe that just started
	// failing pops visually even when the long-term average is still
	// healthy. Pinned values: ok / degraded / critical / unknown.
	Severity string `json:"severity"`
	// RowClass is the corresponding CSS class applied to the table row
	// so degraded probes stand out at a glance (left border + tinted bg).
	RowClass string  `json:"-"`
	Total    int     `json:"total"`
	Passed   int     `json:"passed"`
	Failed   int     `json:"failed"`
	Skipped  int     `json:"skipped"`
	PassRate float64 `json:"pass_rate"`
	MedianMS int64   `json:"median_ms"`
	P95MS    int64   `json:"p95_ms"`
}

// scanStats is the aggregate scan-history view: total count, latest run's
// timestamp + duration, average duration across the recent window. Lets
// operators see "are scans running on schedule and at consistent speed?"
// without leaving the dashboard. TrendSVG is an inline-rendered bar chart
// of recent completed-scan durations, surfaced below the stats table.
type scanStats struct {
	LatestStartedAt string        `json:"latest_started_at,omitempty"`
	LatestDuration  string        `json:"latest_duration,omitempty"`
	LatestStatus    string        `json:"latest_status,omitempty"`
	LatestBadge     string        `json:"-"` // CSS class, UI-only
	AverageDuration string        `json:"average_duration,omitempty"`
	TrendSVG        template.HTML `json:"-"` // SVG markup, UI-only
	Total           int           `json:"total"`
}

// renderObservabilityFragment is the HTML render entry point. Delegates
// aggregation to buildObservabilityView so the HTML page and the JSON
// snapshot endpoint share one source of truth for the data shape.
// paused (iteration 30) freezes auto-refresh so operators can inspect.
func renderObservabilityFragment(w io.Writer, ctx context.Context, deps onboardingDeps, paused bool) error {
	view := buildObservabilityView(ctx, deps)
	view.Freshness = newFreshness(paused)
	if err := observabilityTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render observability fragment: %w", err)
	}
	return nil
}

// newFreshness assembles the chip-state struct for the active vs paused
// render. The auto-refresh interval mirrors the wrapper's hx-trigger so
// the chip copy stays accurate even if the cadence changes.
func newFreshness(paused bool) observabilityFreshness {
	fr := observabilityFreshness{
		Paused:          paused,
		UpdatedAtUTC:    time.Now().UTC().Format(time.RFC3339),
		AutoRefreshSecs: 15,
	}
	if paused {
		fr.ToggleURL = "/fragments/observability"
		fr.ToggleLabel = "Resume"
		fr.ToggleAriaLabel = "Resume automatic refresh"
		// When paused, the wrapper still carries hx-get pointing at the
		// paused fragment so manual triggers (e.g., a user-armed refresh)
		// stay paused. The hx-trigger attribute itself is omitted in the
		// template — that's what actually stops the polling.
		fr.WrapperGetURL = "/fragments/observability?paused=1"
	} else {
		fr.ToggleURL = "/fragments/observability?paused=1"
		fr.ToggleLabel = "Pause"
		fr.ToggleAriaLabel = "Pause automatic refresh"
		fr.WrapperGetURL = "/fragments/observability"
	}
	return fr
}

// collectRuntimeStats gathers process + storage telemetry into a single
// view. Cheap to call — all data sources are in-process (runtime package,
// os.Stat, two COUNT(*) queries). Safe to invoke on every observability
// render (every 15s under the iteration-25 auto-refresh).
func collectRuntimeStats(ctx context.Context, deps onboardingDeps) runtimeStats {
	ensureStartTime()
	// Sample first so the current-render snapshot is the newest data point
	// in the trend sparklines — the rightmost line endpoint matches the
	// HeapAlloc/Goroutines values displayed point-in-time alongside.
	recordProcessSample()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	// Build the heap + goroutine trend sparklines from the in-memory ring
	// buffer. Up to 60 samples (15 minutes at the iteration-25 auto-refresh
	// cadence) so operators spot a leak forming before it's catastrophic.
	samples := processHistorySamples()
	heapValues := make([]int64, 0, len(samples))
	goroutineValues := make([]int64, 0, len(samples))
	for _, s := range samples {
		heapValues = append(heapValues, int64(s.HeapAlloc)) //#nosec G115 -- HeapAlloc bytes-since-start; even a leaking 24h process fits int64
		goroutineValues = append(goroutineValues, int64(s.Goroutines))
	}

	out := runtimeStats{
		GoVersion:       runtime.Version(),
		HeapAlloc:       humanizeBytes(int64(ms.Alloc)), //#nosec G115 -- ms.Alloc is bytes; fits int64 by definition
		HeapSys:         humanizeBytes(int64(ms.Sys)),   //#nosec G115 -- same
		Goroutines:      runtime.NumGoroutine(),
		Uptime:          humanizeDuration(time.Since(dashboardStartTime)),
		DBSize:          "—",
		ProbeResultRows: "—",
		ScanRunRows:     "—",
		// Data-table placeholders default to em-dash so the nil-Store
		// path (inspector mode) renders the same empty-state copy as
		// the operational rows. Populated below when Store is wired.
		AssetRows:   "—",
		EventRows:   "—",
		FindingRows: "—",
		HeapTrendSVG: sparklineSVG(heapValues,
			fmt.Sprintf("heap allocation trend across last %d samples (oldest left, newest right)", len(heapValues)),
			"spark-line"),
		GoroutineTrendSVG: sparklineSVG(goroutineValues,
			fmt.Sprintf("goroutine count trend across last %d samples (oldest left, newest right)", len(goroutineValues)),
			"spark-line"),
	}

	if deps.Store != nil {
		// DB file size — operators want to spot "my SQLite grew from 50MB
		// to 5GB" before the disk fills. Stat failures are silent; the
		// "—" placeholder makes the missing data obvious.
		out.DBPath = deps.Store.Path()
		if out.DBPath != "" {
			if fi, err := os.Stat(out.DBPath); err == nil {
				out.DBSize = humanizeBytes(fi.Size())
				out.HasDBSize = true
			}
		}

		// Row counts for the tables the observability page already reads
		// from (operational tables) PLUS the data tables (assets, events,
		// config_findings) that answer the operator's "what data has the
		// agent actually collected?" question. Failure of an individual
		// COUNT leaves the corresponding *Rows field at its em-dash
		// default (set in the struct literal above) — the card never
		// breaks the page because one peripheral query failed.
		if db := deps.Store.RawDB(); db != nil {
			var n int64
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM probe_result`).Scan(&n); err == nil {
				out.ProbeResultRows = humanizeCount(n)
				out.HasStoreRowCounts = true
			}
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_runs`).Scan(&n); err == nil {
				out.ScanRunRows = humanizeCount(n)
				out.HasStoreRowCounts = true
			}
			// Data tables. Treat any single success as "data row counts
			// are usable" — partial data is still useful even when one
			// table is missing on an older schema.
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets`).Scan(&n); err == nil {
				out.AssetRows = humanizeCount(n)
				out.HasDataRowCounts = true
			}
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n); err == nil {
				out.EventRows = humanizeCount(n)
				out.HasDataRowCounts = true
			}
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM config_findings`).Scan(&n); err == nil {
				out.FindingRows = humanizeCount(n)
				out.HasDataRowCounts = true
			}
		}
	}

	return out
}

// humanizeBytes renders a byte count in operator-friendly units. Coarse
// (KB/MB/GB at 1024 boundaries) — exact byte counts are rarely useful at
// the operator's "should I worry?" decision granularity.
func humanizeBytes(n int64) string {
	const k = int64(1024)
	switch {
	case n < k:
		return fmt.Sprintf("%d B", n)
	case n < k*k:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(k))
	case n < k*k*k:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(k*k))
	default:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(k*k*k))
	}
}

// humanizeCount renders an integer row count with thousands separators so
// "1234567" reads as "1,234,567" — easier to compare at a glance.
func humanizeCount(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	// Manual thousands separator (avoiding x/text dep for a 10-line helper).
	s := fmt.Sprintf("%d", n)
	out := make([]byte, 0, len(s)+len(s)/3)
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

// humanizeDuration renders an uptime as "5d 3h" / "2h 17m" / "45m" / "12s"
// — coarse, two-unit at most, prioritizing the largest unit. Operators
// reading "uptime: 5d 3h" need the day-level signal first; the hour-
// level refinement is secondary; seconds are noise above the minute.
func humanizeDuration(d time.Duration) string {
	if d < time.Second {
		return "just started"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) - m*60
		if s > 0 {
			return fmt.Sprintf("%dm %ds", m, s)
		}
		return fmt.Sprintf("%dm", m)
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) - h*60
		if m > 0 {
			return fmt.Sprintf("%dh %dm", h, m)
		}
		return fmt.Sprintf("%dh", h)
	}
	days := int(d.Hours()) / 24
	h := int(d.Hours()) - days*24
	if h > 0 {
		return fmt.Sprintf("%dd %dh", days, h)
	}
	return fmt.Sprintf("%dd", days)
}

// streamStateBadge maps the StreamController's NormalizeState() output to
// a badge class consistent with the rest of the dashboard's color
// vocabulary. Mirrors the iteration 19 topbar status badge mapping so
// the running/degraded/stopped color cues are uniform across surfaces.
func streamStateBadge(state string) string {
	switch state {
	case "running":
		return "badge-green"
	case "degraded":
		return "badge-orange"
	case "stopped":
		return "badge-red"
	case "idle":
		return "badge-blue"
	default:
		return "badge-gray"
	}
}

// computeHealthChecks runs each subsystem's quick health probe and returns
// the per-row results. Quick + read-only — no network calls, just store
// queries + config inspection. Designed to be safe to call every ~10s.
func computeHealthChecks(ctx context.Context, deps onboardingDeps) []healthCheck {
	checks := make([]healthCheck, 0, 5)

	// 1. Store — ping by reading any small thing.
	storeCheck := healthCheck{Name: "Store"}
	if deps.Store == nil {
		storeCheck.Status = "fail"
		storeCheck.Detail = "no SQLite store wired (inspector mode without --db)"
		storeCheck.Class = "badge-red"
	} else if _, err := deps.Store.ListProbeResults(ctx, 1); err != nil {
		storeCheck.Status = "fail"
		storeCheck.Detail = "store query failed: " + err.Error()
		storeCheck.Class = "badge-red"
	} else {
		storeCheck.Status = "pass"
		storeCheck.Detail = "SQLite responding to queries"
		storeCheck.Class = "badge-green"
	}
	checks = append(checks, storeCheck)

	// 2. Identity — has any enrollment happened?
	identityCheck := healthCheck{Name: "Identity"}
	if deps.Store == nil {
		identityCheck.Status = "warn"
		identityCheck.Detail = "no store — cannot determine enrollment"
		identityCheck.Class = "badge-orange"
	} else {
		id, err := deps.Store.GetEnrolledIdentity(ctx)
		switch {
		case errors.Is(err, sqlite.ErrNoIdentity):
			identityCheck.Status = "fail"
			identityCheck.Detail = "no API key enrolled — open /onboarding"
			identityCheck.Class = "badge-red"
		case err != nil:
			identityCheck.Status = "fail"
			identityCheck.Detail = "identity query failed: " + err.Error()
			identityCheck.Class = "badge-red"
		default:
			identityCheck.Status = "pass"
			identityCheck.Detail = "fingerprint " + shortFingerprint(id.ApiKeyFingerprint) +
				" · enrolled " + humanizeRelativeTime(time.Since(id.FirstEnrolledAt))
			identityCheck.Class = "badge-green"
		}
	}
	checks = append(checks, identityCheck)

	// 3. Last check — is the connection check fresh?
	checkCheck := healthCheck{Name: "Last check"}
	if deps.Store != nil {
		if id, err := deps.Store.GetEnrolledIdentity(ctx); err == nil {
			switch {
			case id.LastCheckPassedAt == nil && id.LastCheckFailedAt == nil:
				checkCheck.Status = "warn"
				checkCheck.Detail = "no check has run yet — visit /onboarding"
				checkCheck.Class = "badge-orange"
			case id.LastCheckFailedAt != nil &&
				(id.LastCheckPassedAt == nil || id.LastCheckFailedAt.After(*id.LastCheckPassedAt)):
				checkCheck.Status = "fail"
				checkCheck.Detail = "last check failed " + humanizeRelativeTime(time.Since(*id.LastCheckFailedAt))
				checkCheck.Class = "badge-red"
			case id.LastCheckPassedAt != nil:
				age := time.Since(*id.LastCheckPassedAt)
				if age > 24*time.Hour {
					checkCheck.Status = "warn"
					checkCheck.Detail = "last check passed " + humanizeRelativeTime(age) + " (>24h ago)"
					checkCheck.Class = "badge-orange"
				} else {
					checkCheck.Status = "pass"
					checkCheck.Detail = "passed " + humanizeRelativeTime(age)
					checkCheck.Class = "badge-green"
				}
			}
		} else {
			checkCheck.Status = "warn"
			checkCheck.Detail = "no identity — cannot check freshness"
			checkCheck.Class = "badge-orange"
		}
	} else {
		checkCheck.Status = "warn"
		checkCheck.Detail = "no store"
		checkCheck.Class = "badge-orange"
	}
	checks = append(checks, checkCheck)

	// 4. Last scan — has a scan run recently?
	scanCheck := healthCheck{Name: "Last scan"}
	if deps.Store != nil {
		if run, err := deps.Store.GetLatestScanRun(ctx); err == nil && run != nil {
			age := time.Since(run.StartedAt)
			switch {
			case run.CompletedAt == nil:
				scanCheck.Status = "warn"
				scanCheck.Detail = "scan in progress — started " + humanizeRelativeTime(age)
				scanCheck.Class = "badge-orange"
			case age > 7*24*time.Hour:
				scanCheck.Status = "warn"
				scanCheck.Detail = "last scan was " + humanizeRelativeTime(age) + " ago (>7 days)"
				scanCheck.Class = "badge-orange"
			default:
				scanCheck.Status = "pass"
				scanCheck.Detail = "last scan completed " + humanizeRelativeTime(age)
				scanCheck.Class = "badge-green"
			}
		} else {
			scanCheck.Status = "warn"
			scanCheck.Detail = "no scans yet — click 'Run scan' on /onboarding"
			scanCheck.Class = "badge-orange"
		}
	} else {
		scanCheck.Status = "warn"
		scanCheck.Detail = "no store"
		scanCheck.Class = "badge-orange"
	}
	checks = append(checks, scanCheck)

	// 5. OTLP endpoint — is it configured?
	endpointCheck := healthCheck{Name: "OTLP endpoint"}
	if deps.PlatformEndpoint == "" {
		endpointCheck.Status = "fail"
		endpointCheck.Detail = "no platform endpoint configured"
		endpointCheck.Class = "badge-red"
	} else {
		endpointCheck.Status = "pass"
		endpointCheck.Detail = deps.PlatformEndpoint
		endpointCheck.Class = "badge-green"
	}
	checks = append(checks, endpointCheck)

	return checks
}

// rollupHealth collapses the per-check statuses into an overall summary
// for the top-of-page badge: any fail → "down", any warn → "degraded",
// otherwise "healthy". Operators can glance at one badge to know if
// drilling into the per-row detail is warranted.
//
// detail (iter-33) is the comma-separated list of subsystem names that
// aren't passing — surfaced beside the badge so an operator sees
// "degraded — Identity, Last scan" without scrolling to the
// healthchecks card. Empty when everything passes.
func rollupHealth(checks []healthCheck) (summary, class, detail string) {
	var fails, warns []string
	for _, c := range checks {
		switch c.Status {
		case "fail":
			fails = append(fails, c.Name)
		case "warn":
			warns = append(warns, c.Name)
		}
	}
	// Failing subsystems lead; warning subsystems follow. Operators read
	// "Identity, Last scan" as "Identity is the urgent one" because of
	// the consistent ordering.
	detail = strings.Join(append(fails, warns...), ", ")
	switch {
	case len(fails) > 0:
		return "down", "badge-red", detail
	case len(warns) > 0:
		return "degraded", "badge-orange", detail
	default:
		return "healthy", "badge-green", ""
	}
}

// aggregateProbeMetrics groups probe_result rows by probe name and computes
// count + pass rate + median + p95 latency per group. Returns rows sorted
// in the canonical six-probe order (dns→tls→reach→auth→clock→otlp) so the
// table is consistent with the connection-check card.
func aggregateProbeMetrics(rows []sqlite.ProbeResultRecord) []probeMetric {
	type bucket struct {
		latencies []int64
		// recentLatencies keeps latencies in chronological order
		// (oldest→newest) for the sparkline. The store returns rows
		// newest-first; we prepend so the slice ends up oldest-first
		// which is the reading direction operators expect.
		recentLatencies []int64
		// recentResults keeps the LAST 20 outcomes (newest first, since
		// rows arrive newest-first). The first 10 drive iteration-31
		// row severity (more sensitive than all-time pass rate); the
		// full 20 drive iteration-32's per-probe uptime strip — the
		// status-page-style coloured-square tape that answers "is it
		// still passing?" at-a-glance.
		recentResults []string
		total         int
		passed        int
		failed        int
		skipped       int
	}
	const uptimeStripWindow = 20
	buckets := make(map[string]*bucket)
	for _, r := range rows {
		b, ok := buckets[r.ProbeName]
		if !ok {
			b = &bucket{}
			buckets[r.ProbeName] = b
		}
		b.total++
		switch r.Result {
		case "pass":
			b.passed++
		case "fail":
			b.failed++
		case "skip":
			b.skipped++
		}
		b.latencies = append(b.latencies, r.LatencyMS)
		// Prepend so the final slice is chronological (oldest → newest)
		// to match left-to-right reading of the sparkline.
		b.recentLatencies = append([]int64{r.LatencyMS}, b.recentLatencies...)
		if len(b.recentResults) < uptimeStripWindow {
			b.recentResults = append(b.recentResults, r.Result)
		}
	}

	canonical := []string{"dns", "tls", "reach", "auth", "clock", "otlp"}
	out := make([]probeMetric, 0, len(canonical))
	for _, name := range canonical {
		b, ok := buckets[name]
		if !ok || b.total == 0 {
			continue
		}
		pr := float64(b.passed) / float64(b.total)
		// Cap the trend window at 30 most-recent runs so the sparkline
		// stays scannable. Take the tail of the chronological slice.
		trend := b.recentLatencies
		if len(trend) > 30 {
			trend = trend[len(trend)-30:]
		}
		sev, cls := probeRowSeverity(b.recentResults)
		m := probeMetric{
			Name:           name,
			Total:          b.total,
			Passed:         b.passed,
			Failed:         b.failed,
			Skipped:        b.skipped,
			PassRate:       pr,
			PassPct:        fmt.Sprintf("%.1f%%", pr*100),
			MedianMS:       percentileMS(b.latencies, 0.5),
			P95MS:          percentileMS(b.latencies, 0.95),
			TrendSVG:       latencySparklineSVG(trend, name),
			UptimeStripSVG: uptimeStripSVG(b.recentResults, name),
			Severity:       sev,
			RowClass:       cls,
		}
		out = append(out, m)
	}
	return out
}

// probeRowSeverity classifies a probe by the LAST N (N≤10) outcomes. More
// sensitive than the all-time pass rate so a probe that just started
// failing pops even when the long-term average is still fine.
//   - 5+ failures in the window → critical
//   - 1-4 failures in the window → degraded
//   - 0 failures → ok
//   - empty window → unknown
func probeRowSeverity(recentResults []string) (severity, rowClass string) {
	if len(recentResults) == 0 {
		return "unknown", ""
	}
	failed := 0
	for _, r := range recentResults {
		if r == "fail" {
			failed++
		}
	}
	switch {
	case failed >= 5:
		return "critical", "probe-row-critical"
	case failed > 0:
		return "degraded", "probe-row-degraded"
	default:
		return "ok", ""
	}
}

// latencySparklineSVG renders the per-probe latency trend for the iteration
// 24 probe-metrics table. Thin wrapper around sparklineSVG with a probe-
// specific aria-label and the probe-sparkline CSS class.
func latencySparklineSVG(latencies []int64, probeName string) template.HTML {
	return sparklineSVG(latencies,
		fmt.Sprintf("latency trend across last %d %s probe runs (oldest left, newest right)", len(latencies), probeName),
		"spark-line")
}

// sparklineSVG renders an inline SVG line chart of int64 values. No JS,
// no charting library — just a <polyline> normalized to a small viewBox.
// Caller supplies aria-label and CSS class so the helper composes across
// surfaces (probe latencies, process heap trend, goroutine trend, …).
//
// Returns template.HTML — safe by construction because every substituted
// value is a controlled type: int64 values, fixed integer dimensions, and
// callers supply only their own internal strings (no operator-supplied
// text reaches the output).
func sparklineSVG(values []int64, ariaLabel, cssClass string) template.HTML {
	if len(values) == 0 {
		return template.HTML(`<span class="muted small">—</span>`)
	}
	const width, height = 120, 24
	minV, maxV := values[0], int64(1)
	for _, v := range values {
		if v > maxV {
			maxV = v
		}
		if v < minV {
			minV = v
		}
	}
	latestV := values[len(values)-1]

	// Native SVG <title> gives operators a hover tooltip with the actual
	// numbers — no JS, no CSS, browser-default UX. Pairs with aria-label
	// for assistive tech (aria-label is what screen readers announce;
	// <title> is what sighted users see on mouseover).
	tooltip := fmt.Sprintf("min %d · max %d · latest %d (n=%d)", minV, maxV, latestV, len(values))

	var b strings.Builder
	fmt.Fprintf(&b,
		`<svg role="img" aria-label="%s" class="%s" viewBox="0 0 %d %d" preserveAspectRatio="none">`,
		template.HTMLEscapeString(ariaLabel), template.HTMLEscapeString(cssClass), width, height)
	fmt.Fprintf(&b, `<title>%s</title>`, template.HTMLEscapeString(tooltip))
	b.WriteString(`<polyline fill="none" stroke="currentColor" stroke-width="1.5" points="`)
	for i, v := range values {
		var x float64
		if len(values) == 1 {
			x = float64(width) / 2
		} else {
			x = float64(i) * float64(width) / float64(len(values)-1)
		}
		// Invert Y — larger values render higher on the chart.
		y := float64(height) - (float64(v)/float64(maxV))*float64(height-2) - 1
		fmt.Fprintf(&b, "%.1f,%.1f ", x, y)
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String()) //#nosec G203 -- safe by construction: values are int64, dimensions are fixed integers, string inputs are HTML-escaped before substitution
}

// uptimeStripSVG renders the iteration-32 status-page-style tape: one
// coloured square per probe result over the last N runs. Oldest left,
// newest right (so the right edge is "what's the probe doing RIGHT
// NOW?"). Green = pass, red = fail, amber = skip, gray = unknown.
//
// Higher info density than the latency sparkline at the same width: a
// run of green squares with one red on the right = "just broke." A run
// of mixed = "flaky." A run of red = "down for a while now." Native
// SVG <title> gives a count tooltip on hover ("18 pass · 2 fail").
//
// Returns template.HTML — safe by construction: results values come
// from the curated outcome enum, probeName is HTML-escaped before
// substitution.
func uptimeStripSVG(results []string, probeName string) template.HTML {
	n := len(results)
	if n == 0 {
		return template.HTML(`<span class="muted small">—</span>`)
	}
	const sqW, sqH, gap = 8, 16, 2
	width := n*(sqW+gap) - gap

	var pass, fail, skip int
	for _, r := range results {
		switch r {
		case "pass":
			pass++
		case "fail":
			fail++
		case "skip":
			skip++
		}
	}
	tooltip := fmt.Sprintf("%d pass · %d fail · %d skip (last %d runs · oldest left, newest right)",
		pass, fail, skip, n)

	var b strings.Builder
	fmt.Fprintf(&b,
		`<svg role="img" aria-label="last %d %s runs status strip (oldest left, newest right)" class="uptime-strip" viewBox="0 0 %d %d">`,
		n, template.HTMLEscapeString(probeName), width, sqH)
	fmt.Fprintf(&b, `<title>%s</title>`, template.HTMLEscapeString(tooltip))

	// Render oldest-first so the visual position matches the reading
	// direction. results[0] is newest, results[n-1] is oldest → invert.
	for visualPos := 0; visualPos < n; visualPos++ {
		sliceIdx := n - 1 - visualPos
		x := visualPos * (sqW + gap)
		color := "#9ca3af" // gray default
		switch results[sliceIdx] {
		case "pass":
			color = "#16a34a"
		case "fail":
			color = "#dc2626"
		case "skip":
			color = "#f59e0b"
		}
		fmt.Fprintf(&b,
			`<rect x="%d" y="0" width="%d" height="%d" fill="%s" rx="1"/>`,
			x, sqW, sqH, color)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //#nosec G203 -- safe by construction: enum values + escaped probe name + fixed integers
}

// durationBarsSVG renders an inline SVG bar chart of scan durations.
// Bars are normalized to the longest duration in the set so the relative
// heights communicate "consistent" vs "one outlier" at a glance — exactly
// what operators want to know about scan timing.
func durationBarsSVG(durations []time.Duration) template.HTML {
	if len(durations) == 0 {
		return template.HTML(`<span class="muted small">—</span>`)
	}
	const width, height = 200, 32
	minD, maxD := durations[0], time.Duration(1)
	for _, d := range durations {
		if d > maxD {
			maxD = d
		}
		if d < minD {
			minD = d
		}
	}
	latestD := durations[len(durations)-1]
	tooltip := fmt.Sprintf("min %s · max %s · latest %s (n=%d)",
		minD.Round(time.Second), maxD.Round(time.Second),
		latestD.Round(time.Second), len(durations))

	barW := float64(width) / float64(len(durations))
	gap := barW * 0.15
	var b strings.Builder
	fmt.Fprintf(&b,
		`<svg role="img" aria-label="recent scan durations across last %d completed runs (oldest left, newest right)" class="spark-bars" viewBox="0 0 %d %d" preserveAspectRatio="none">`,
		len(durations), width, height)
	fmt.Fprintf(&b, `<title>%s</title>`, template.HTMLEscapeString(tooltip))
	for i, d := range durations {
		h := (float64(d) / float64(maxD)) * float64(height-2)
		if h < 1 {
			h = 1
		}
		x := float64(i)*barW + gap/2
		y := float64(height) - h
		fmt.Fprintf(&b,
			`<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="currentColor"/>`,
			x, y, barW-gap, h)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //#nosec G203 -- safe by construction: durations and dimensions are all numeric, no string interpolation from operator input
}

// percentileMS returns the p-th percentile (0.0–1.0) of latencies in
// milliseconds. Uses the nearest-rank method — simpler than linear
// interpolation and adequate for the small bucket sizes (200 rows max).
func percentileMS(latencies []int64, p float64) int64 {
	if len(latencies) == 0 {
		return 0
	}
	sorted := make([]int64, len(latencies))
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// extractRecentFailures returns up to `limit` most-recent probe failures
// with their diagnostic messages — the iteration-33 "Recent failures"
// focused-card feed. Input rows arrive newest-first from the store; the
// helper preserves that order so the most-recent failure is rendered
// at the top. Returns an empty slice when there are no failures (the
// caller renders a positive empty state).
func extractRecentFailures(rows []sqlite.ProbeResultRecord, limit int) []recentFailure {
	if limit <= 0 {
		return nil
	}
	out := make([]recentFailure, 0, limit)
	for _, r := range rows {
		if r.Result != "fail" {
			continue
		}
		out = append(out, recentFailure{
			At:         r.CheckedAt.UTC().Format(time.RFC3339),
			AtRel:      humanizeRelativeTime(time.Since(r.CheckedAt)),
			ProbeName:  r.ProbeName,
			Diagnostic: r.Diagnostic,
			Hint:       classifyDiagnostic(r.Diagnostic),
			LatencyMS:  r.LatencyMS,
		})
		if len(out) >= limit {
			break
		}
	}
	return out
}

// aggregateRecentActivity interleaves probe outcomes + scan starts/
// completions into a single chronological timeline (newest first) capped
// at `limit` events. Closes iteration 31's "what just happened?" workflow
// — the metrics page goes from snapshot-only to snapshot + recent history
// without leaving the operator's tab.
func aggregateRecentActivity(probes []sqlite.ProbeResultRecord, runs []model.ScanRun, limit int) []activityEvent {
	if limit <= 0 {
		return nil
	}
	events := make([]activityEvent, 0, len(probes)+len(runs)*2)

	for _, p := range probes {
		sev, cls, verb := probeOutcomeAnnotation(p.Result)
		ev := activityEvent{
			At:       p.CheckedAt.UTC().Format(time.RFC3339),
			AtRel:    humanizeRelativeTime(time.Since(p.CheckedAt)),
			Kind:     "probe." + p.Result,
			Label:    fmt.Sprintf("probe %s %s", p.ProbeName, verb),
			Severity: sev,
			Class:    cls,
		}
		switch {
		case p.Result == "fail" && p.Diagnostic != "":
			ev.Detail = p.Diagnostic
		case p.LatencyMS > 0:
			ev.Detail = fmt.Sprintf("%d ms", p.LatencyMS)
		}
		events = append(events, ev)
	}

	for _, r := range runs {
		// Always emit a "scan started" event.
		events = append(events, activityEvent{
			At:       r.StartedAt.UTC().Format(time.RFC3339),
			AtRel:    humanizeRelativeTime(time.Since(r.StartedAt)),
			Kind:     "scan.started",
			Label:    "scan started",
			Detail:   "trigger: " + r.TriggerSource,
			Severity: "info",
			Class:    "activity-info",
		})
		// And, when completed/failed/cancelled, an outcome event at the
		// completion time so the timeline shows BOTH endpoints of the run.
		if r.CompletedAt != nil {
			status := string(r.Status)
			sev, cls, verb := scanStatusAnnotation(status)
			dur := r.CompletedAt.Sub(r.StartedAt).Round(time.Second)
			events = append(events, activityEvent{
				At:       r.CompletedAt.UTC().Format(time.RFC3339),
				AtRel:    humanizeRelativeTime(time.Since(*r.CompletedAt)),
				Kind:     "scan." + status,
				Label:    "scan " + verb,
				Detail:   fmt.Sprintf("%s · %d assets", dur, r.TotalAssets),
				Severity: sev,
				Class:    cls,
			})
		}
	}

	sort.Slice(events, func(i, j int) bool { return events[i].At > events[j].At })
	if len(events) > limit {
		events = events[:limit]
	}
	return events
}

// probeOutcomeAnnotation maps a probe Result string to (severity, css class,
// verb). Verb feeds the timeline label ("probe dns FAILED").
func probeOutcomeAnnotation(result string) (severity, cssClass, verb string) {
	switch result {
	case "pass":
		return "success", "activity-success", "passed"
	case "fail":
		return "error", "activity-error", "failed"
	case "skip":
		return "warn", "activity-warn", "skipped"
	default:
		return "info", "activity-info", result
	}
}

// scanStatusAnnotation maps a ScanRun completed-state to (severity, class,
// verb). Mirrors probeOutcomeAnnotation's contract.
func scanStatusAnnotation(status string) (severity, cssClass, verb string) {
	switch status {
	case "completed":
		return "success", "activity-success", "completed"
	case "failed":
		return "error", "activity-error", "failed"
	case "cancelled":
		return "warn", "activity-warn", "cancelled"
	default:
		return "info", "activity-info", status
	}
}

// aggregateScanStats computes total count + latest + average duration from
// recent scan_runs. Designed for the operator's "are scans running on
// schedule and consistent in speed?" question — three numbers tell the
// story without rendering individual scan rows.
func aggregateScanStats(runs []model.ScanRun) scanStats {
	if len(runs) == 0 {
		return scanStats{}
	}
	// runs are newest-first from ListScanRuns.
	latest := runs[0]
	s := scanStats{
		Total:           len(runs),
		LatestStartedAt: latest.StartedAt.UTC().Format(time.RFC3339),
		LatestStatus:    string(latest.Status),
		LatestBadge:     scanStatusBadge(string(latest.Status)),
	}
	if latest.CompletedAt != nil {
		s.LatestDuration = latest.CompletedAt.Sub(latest.StartedAt).Round(time.Second).String()
	} else {
		s.LatestDuration = "in progress"
	}

	// Average completed-run duration across the window.
	var (
		totalDur     time.Duration
		completedCnt int
	)
	for _, r := range runs {
		if r.CompletedAt == nil {
			continue
		}
		totalDur += r.CompletedAt.Sub(r.StartedAt)
		completedCnt++
	}
	if completedCnt > 0 {
		avg := totalDur / time.Duration(completedCnt)
		s.AverageDuration = avg.Round(time.Second).String()
	} else {
		s.AverageDuration = "—"
	}

	// Build the duration sparkline-bars: chronological (oldest→newest)
	// completed-run durations only. In-progress runs are skipped because
	// their duration is undefined until completion.
	var bars []time.Duration
	for i := len(runs) - 1; i >= 0; i-- {
		r := runs[i]
		if r.CompletedAt == nil {
			continue
		}
		bars = append(bars, r.CompletedAt.Sub(r.StartedAt))
	}
	s.TrendSVG = durationBarsSVG(bars)
	return s
}

// scanStatusBadge maps a scan status string to a badge class, mirroring the
// vocabulary in iteration 17's last-scan summary so the two surfaces use
// the same visual signals.
func scanStatusBadge(status string) string {
	switch status {
	case "completed":
		return "badge-green"
	case "running", "queued":
		return "badge-blue"
	case "failed", "cancelled":
		return "badge-red"
	default:
		return "badge-gray"
	}
}

// observabilityTmpl renders the /observability page body — healthchecks
// panel, probe metrics table, scan stats card, Prometheus link.
var observabilityTmpl = template.Must(template.New("observability").Parse(`
<div id="observability-root"
     class="observability-page"
     hx-get="{{.Freshness.WrapperGetURL}}"
     {{if not .Freshness.Paused}}hx-trigger="every 15s"{{end}}
     hx-swap="outerHTML"
     hx-preserve="false">
<header class="onboarding-header observability-hero">
  <div class="onboarding-header-row">
    <div class="onboarding-title">
      <h1>Local observability</h1>
      <p class="muted small observability-hero-copy">
        Self-observability for the agent on this host. Health, probes, scans,
        streaming and runtime signals are computed from local state.
      </p>
      <div class="observability-actions" aria-label="Observability exports and integrations">
        <a href="/metrics" target="_blank" rel="noopener">Prometheus /metrics</a>
        <a href="/api/v1/observability/snapshot.json" download>JSON snapshot</a>
        <a href="/api/v1/observability/snapshot.md" target="_blank" rel="noopener">Markdown summary</a>
      </div>
    </div>
    <div class="onboarding-mode observability-status-panel">
      <span class="muted small observability-status-label">Agent status</span>
      <span class="badge {{.HealthClass}}">{{.HealthSummary}}</span>
      {{if .HealthDetail}}
        <span class="muted small health-rollup-detail" title="Subsystems not passing — drill into Healthchecks below for details">&mdash; {{.HealthDetail}}</span>
      {{end}}
      <span class="muted small">checked {{.GeneratedAt}}</span>
    </div>
  </div>
  <div class="freshness-chip {{if .Freshness.Paused}}freshness-chip--paused{{else}}freshness-chip--live{{end}}"
       aria-live="polite"
       role="status">
    <span class="freshness-chip-dot {{if .Freshness.Paused}}freshness-chip-dot--paused{{else}}freshness-chip-dot--live{{end}}"
          aria-hidden="true"></span>
    {{if .Freshness.Paused}}
      <span>Paused &middot; last update <code>{{.Freshness.UpdatedAtUTC}}</code> &middot; auto-refresh is off so the page won't swap while you inspect.</span>
    {{else}}
      <span>Live &middot; refreshes every {{.Freshness.AutoRefreshSecs}}s &middot; last update <code>{{.Freshness.UpdatedAtUTC}}</code></span>
    {{end}}
    <a class="freshness-chip-toggle"
       href="{{.Freshness.ToggleURL}}"
       hx-get="{{.Freshness.ToggleURL}}"
       hx-target="#observability-root"
       hx-swap="outerHTML"
       aria-label="{{.Freshness.ToggleAriaLabel}}">{{.Freshness.ToggleLabel}}</a>
  </div>
</header>

<nav class="page-jumpnav observability-jumpnav" aria-label="Observability page sections">
  <span class="page-jumpnav-label muted small">Jump to:</span>
  <a href="#section-health">Health</a>
  <a href="#section-failures">Failures</a>
  <a href="#section-activity">Activity</a>
  <a href="#section-probes">Probes</a>
  <a href="#section-scans">Scans</a>
  <a href="#section-stream">Stream</a>
  <a href="#section-runtime">Runtime</a>
  <a href="#section-prometheus">Prometheus</a>
</nav>

<div class="observability-grid">
<section class="card observability-card observability-card--health" id="section-health">
  <h2>Healthchecks</h2>
  <p class="muted">Per-subsystem status, recomputed on each page render.</p>
  <div class="observability-table-wrap">
  <table class="observability-table">
    <thead><tr><th>Subsystem</th><th>Status</th><th>Detail</th></tr></thead>
    <tbody>
    {{range .Health}}
      <tr>
        <td><code>{{.Name}}</code></td>
        <td><span class="badge {{.Class}}">{{.Status}}</span></td>
        <td class="muted small">{{.Detail}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  </div>
</section>

<section class="card observability-card observability-card--wide observability-card--probes" id="section-probes">
  <h2>Probe metrics</h2>
  {{if .HasProbeData}}
    <p class="muted">Aggregated across the last 200 probe runs.</p>
    <div class="observability-table-wrap">
    <table class="observability-table">
      <thead>
        <tr><th>Probe</th><th>Total</th><th>Passed</th><th>Failed</th><th>Skipped</th><th>Pass rate</th><th>Median latency</th><th>p95 latency</th><th title="Status-page-style tape of the last 20 runs — oldest left, newest right">Last 20</th><th>Latency trend</th></tr>
      </thead>
      <tbody>
      {{range .ProbeMetrics}}
        <tr class="{{.RowClass}}" data-severity="{{.Severity}}">
          <td><code>{{.Name}}</code></td>
          <td>{{.Total}}</td>
          <td>{{.Passed}}</td>
          <td>{{.Failed}}</td>
          <td>{{.Skipped}}</td>
          <td>{{.PassPct}}</td>
          <td>{{.MedianMS}} ms</td>
          <td>{{.P95MS}} ms</td>
          <td class="uptime-cell">{{.UptimeStripSVG}}</td>
          <td class="spark-cell">{{.TrendSVG}}</td>
        </tr>
      {{end}}
      </tbody>
    </table>
    </div>
  {{else}}
    <p class="muted">No probe runs yet. Run a connection check on <a href="/onboarding?step=check">step 3</a> to populate.</p>
  {{end}}
</section>

<section class="card observability-card observability-card--failures" id="section-failures">
  <h2>Recent failures</h2>
  {{if .HasFailures}}
    <p class="muted">Last {{len .RecentFailures}} probe failures with their diagnostic messages. The number-one debugging question — &ldquo;why is it failing?&rdquo; — answered without scrolling through every event.</p>
    <ul class="failure-list">
      {{range .RecentFailures}}
        <li class="failure-item">
          <div class="failure-row">
            <span class="failure-time" title="{{.At}}">{{.AtRel}}</span>
            <code class="failure-probe">{{.ProbeName}}</code>
            {{if .LatencyMS}}<span class="muted small">&middot; {{.LatencyMS}} ms before failure</span>{{end}}
          </div>
          {{if .Diagnostic}}
            <pre class="failure-diagnostic">{{.Diagnostic}}</pre>
          {{else}}
            <p class="muted small">no diagnostic captured for this failure</p>
          {{end}}
          {{if .Hint.Message}}
            <div class="failure-hint" data-kind="{{.Hint.Kind}}">
              <span class="failure-hint-kind">{{.Hint.Kind}}</span>
              <span class="failure-hint-msg">{{.Hint.Message}}</span>
              {{if .Hint.URL}}
                <a class="failure-hint-action" href="{{.Hint.URL}}">{{.Hint.URLText}} &rarr;</a>
              {{end}}
            </div>
          {{end}}
        </li>
      {{end}}
    </ul>
  {{else}}
    <p class="failure-empty-state">
      <span class="badge badge-green">healthy</span>
      No recent probe failures &middot; the agent is operating normally.
    </p>
  {{end}}
</section>

<section class="card observability-card observability-card--activity" id="section-activity">
  <h2>Recent activity</h2>
  {{if .HasActivity}}
    <p class="muted">Most recent 20 events from probes &amp; scans, interleaved by timestamp. Closes the &ldquo;what just happened?&rdquo; gap between the per-card snapshots.</p>
    <ol class="activity-timeline">
      {{range .RecentActivity}}
        <li class="activity-item {{.Class}}" data-kind="{{.Kind}}" data-severity="{{.Severity}}">
          <span class="activity-dot" aria-hidden="true"></span>
          <span class="activity-time" title="{{.At}}">{{.AtRel}}</span>
          <span class="activity-label">{{.Label}}</span>
          {{if .Detail}}<span class="activity-detail muted small">&middot; {{.Detail}}</span>{{end}}
        </li>
      {{end}}
    </ol>
  {{else}}
    <p class="muted">No activity yet. Run a check or trigger a scan from <a href="/onboarding">/onboarding</a>.</p>
  {{end}}
</section>

<section class="card observability-card" id="section-scans">
  <h2>Scan metrics</h2>
  {{if .HasScanData}}
    <div class="observability-table-wrap">
    <table class="kv observability-kv">
      <tr><td>Total scans</td><td>{{.ScanStats.Total}}</td></tr>
      <tr><td>Latest scan</td><td><span class="badge {{.ScanStats.LatestBadge}}">{{.ScanStats.LatestStatus}}</span> &middot; started {{.ScanStats.LatestStartedAt}}</td></tr>
      <tr><td>Latest duration</td><td>{{.ScanStats.LatestDuration}}</td></tr>
      <tr><td>Average duration (last 20)</td><td>{{.ScanStats.AverageDuration}}</td></tr>
      <tr><td>Recent durations</td><td class="spark-cell">{{.ScanStats.TrendSVG}}</td></tr>
    </table>
    </div>
  {{else}}
    <p class="muted">No scans yet. Trigger one from <a href="/onboarding">/onboarding</a>'s launcher panel.</p>
  {{end}}
</section>

<section class="card observability-card" id="section-stream">
  <h2>Stream health</h2>
  {{if .Stream}}
    <div class="observability-table-wrap">
    <table class="kv observability-kv">
      <tr><td>State</td><td><span class="badge {{.Stream.StateBadge}}">{{.Stream.State}}</span></td></tr>
      <tr><td>Events sent</td><td>{{.Stream.TotalSent}}</td></tr>
      <tr><td>Backlog depth</td><td>{{.Stream.BacklogDepth}}</td></tr>
      <tr><td>Last event</td><td>
        {{if .Stream.LastEventAgo}}
          <span title="{{.Stream.LastEventAt}}">{{.Stream.LastEventAgo}}</span>
        {{else}}
          <span class="muted small">no events yet</span>
        {{end}}
      </td></tr>
      {{if .Stream.LastErrorText}}
      <tr><td>Last error</td><td><span class="badge badge-red">{{.Stream.LastErrorText}}</span></td></tr>
      {{end}}
    </table>
    </div>
    <p class="muted small">Backlog depth above zero usually indicates a slow or unreachable OTLP collector. Sustained growth is the early warning before events start dropping.</p>
  {{else}}
    <p class="muted">No StreamController wired (inspector / read-only mode). Start the agent with <code>kite-collector dashboard</code> (default --with-agent=true) to populate.</p>
  {{end}}
</section>

<section class="card observability-card observability-card--wide" id="section-runtime">
  <h2>Runtime &amp; storage</h2>
  <p class="muted">Dashboard process telemetry + on-host SQLite store size. Watch the
     heap and goroutine counts for leak symptoms; watch DB size for unbounded growth.</p>
  <div class="observability-table-wrap">
  <table class="kv observability-kv">
    <tr><td>Go version</td><td><code>{{.Runtime.GoVersion}}</code></td></tr>
    <tr><td>Heap allocated</td><td>{{.Runtime.HeapAlloc}} <span class="spark-cell">{{.Runtime.HeapTrendSVG}}</span></td></tr>
    <tr><td>Heap system</td><td>{{.Runtime.HeapSys}}</td></tr>
    <tr><td>Goroutines</td><td>{{.Runtime.Goroutines}} <span class="spark-cell">{{.Runtime.GoroutineTrendSVG}}</span></td></tr>
    <tr><td>Dashboard uptime</td><td>{{.Runtime.Uptime}}</td></tr>
    {{if .Runtime.DBPath}}
    <tr><td>SQLite path</td><td><code>{{.Runtime.DBPath}}</code></td></tr>
    <tr><td>SQLite size</td><td>{{.Runtime.DBSize}}</td></tr>
    <tr><td colspan="2" class="kv-section-header"><span class="muted small">Operational tables</span></td></tr>
    <tr><td>probe_result rows</td><td>{{.Runtime.ProbeResultRows}}</td></tr>
    <tr><td>scan_runs rows</td><td>{{.Runtime.ScanRunRows}}</td></tr>
    <tr><td colspan="2" class="kv-section-header"><span class="muted small">Data tables &mdash; what the agent has collected</span></td></tr>
    <tr><td>assets discovered</td><td>{{.Runtime.AssetRows}}</td></tr>
    <tr><td>events emitted</td><td>{{.Runtime.EventRows}}</td></tr>
    <tr><td>findings surfaced</td><td>{{.Runtime.FindingRows}}</td></tr>
    {{end}}
  </table>
  </div>
  <p class="muted small">Heap &amp; goroutine sparklines show up to the last 60 samples (one per page render &middot; 15 minutes of in-memory history at the 15s auto-refresh cadence; lost on dashboard restart).</p>
</section>

<section class="card observability-card observability-card--wide observability-card--prometheus" id="section-prometheus">
  <h2>Prometheus integration</h2>
  <p class="muted">The agent exposes a Prometheus-format scrape endpoint at
     <a href="/metrics" target="_blank" rel="noopener"><code>/metrics</code></a>
     for ingestion by Grafana, VictoriaMetrics, or your existing observability stack.
     Probe duration histograms, scan counters, and HTTP request metrics are all
     surfaced there.</p>
</section>
</div>

<p class="muted small observability-footnote">Local observability — no data leaves this host. All stats are computed from the on-host SQLite store. <span class="muted small">Auto-refreshes every 15 seconds.</span></p>

<script>
  // Iteration-31 passive-monitoring affordance: a backgrounded tab shows
  // "[DEGRADED] kite-collector" in the OS tab list so operators glance
  // over and know the agent needs attention without having to refocus
  // the window. Re-runs on every HTMX swap of this fragment.
  (function() {
    try {
      var summary = "{{.HealthSummary}}";
      var base = "kite-collector dashboard";
      if (summary && summary !== "healthy") {
        document.title = "[" + summary.toUpperCase() + "] " + base;
      } else {
        document.title = base;
      }
    } catch (e) { /* defensive — never let title sync break the page */ }
  })();
</script>
</div>
`))

// registerObservabilityRoutes wires the observability page + fragment route
// + snapshot download endpoint. The snapshot endpoint is the machine-
// readable counterpart to the human-readable page — same data, JSON
// formatted, with a download Content-Disposition so browsers offer a
// "Save as" dialog. Closes the workflows iteration 29 identified:
// support tickets, pre/post-change archiving, scripted local monitoring.
func registerObservabilityRoutes(mux *http.ServeMux, deps onboardingDeps) {
	mux.HandleFunc("GET /observability", func(w http.ResponseWriter, r *http.Request) {
		serveObservabilityPage(w, r, deps)
	})
	mux.HandleFunc("GET /fragments/observability", func(w http.ResponseWriter, r *http.Request) {
		paused := r.URL.Query().Get("paused") == "1"
		renderOnboardingFragment(w, deps.Logger, "observability", func(buf io.Writer) error {
			return renderObservabilityFragment(buf, r.Context(), deps, paused)
		})
	})
	mux.HandleFunc("GET /api/v1/observability/snapshot.json", func(w http.ResponseWriter, r *http.Request) {
		handleObservabilitySnapshot(w, r, deps)
	})
	mux.HandleFunc("GET /api/v1/observability/snapshot.md", func(w http.ResponseWriter, r *http.Request) {
		handleObservabilitySnapshotMarkdown(w, r, deps)
	})
}

// handleObservabilitySnapshot serves the observability data as a downloadable
// JSON file. Reuses every helper that builds the page view so the snapshot
// and the rendered page can never disagree about what the data was at
// snapshot time. Filename includes the timestamp so multiple snapshots
// don't collide in the operator's Downloads folder.
func handleObservabilitySnapshot(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	view := buildObservabilityView(r.Context(), deps)

	body, err := json.MarshalIndent(view, "", "  ")
	if err != nil {
		if deps.Logger != nil {
			deps.Logger.Error("observability snapshot marshal failed",
				"code", string(LogCodeObservabilitySnapshotMarshal),
				"error", err,
				"request_path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
				"probe_count", len(view.ProbeMetrics),
				"failure_count", len(view.RecentFailures))
		}
		http.Error(w, "internal encode error", http.StatusInternalServerError)
		return
	}

	// RFC3339-style filename without colons (Windows-friendly) so the
	// operator's Downloads folder gets human-sortable snapshots.
	stamp := time.Now().UTC().Format("20060102T150405Z")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="kite-observability-%s.json"`, stamp))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	_, _ = w.Write(body)
}

// handleObservabilitySnapshotMarkdown serves the observability data as a
// paste-ready Markdown block — iteration-34's "share with a teammate"
// surface. text/plain content-type so browsers render the markdown
// source inline (the source IS the copy-paste payload; rendered form is
// what Slack/PR/Notion will produce on the other end). inline (not
// attachment) so operators can view in-browser, select-all, copy.
func handleObservabilitySnapshotMarkdown(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	view := buildObservabilityView(r.Context(), deps)
	body := renderObservabilityMarkdown(view)

	stamp := time.Now().UTC().Format("20060102T150405Z")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="kite-observability-%s.md"`, stamp))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	_, _ = io.WriteString(w, body)
}

// renderObservabilityMarkdown transforms an observabilityView into a
// paste-ready Markdown block. JSON is great for machines but illegible
// in Slack/PRs/tickets; Markdown renders natively in every code-review
// tool, chat client, and project tracker operators actually use during
// incidents.
//
// Output is deterministic for the same input so the format can be
// snapshotted/diffed/asserted in tests. Pipe characters in detail
// strings are escaped so they don't break the rendered tables.
func renderObservabilityMarkdown(view observabilityView) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# kite-collector observability — %s\n\n", view.GeneratedAt)

	// Health rollup leads — same shape as the badge at the top of the
	// HTML page so a teammate scanning the paste sees "what's wrong"
	// before anything else.
	fmt.Fprintf(&b, "**Health:** %s", view.HealthSummary)
	if view.HealthDetail != "" {
		fmt.Fprintf(&b, " — %s", view.HealthDetail)
	}
	b.WriteString("\n\n")

	// Healthchecks table.
	b.WriteString("## Healthchecks\n\n")
	b.WriteString("| Subsystem | Status | Detail |\n|---|---|---|\n")
	for _, c := range view.Health {
		fmt.Fprintf(&b, "| %s | %s | %s |\n",
			mdEscapePipe(c.Name), mdEscapePipe(c.Status), mdEscapePipe(c.Detail))
	}
	b.WriteString("\n")

	// Recent failures — the diagnostic-first surface from iter-33,
	// rendered as a bullet list so multi-line diagnostics stay readable
	// (no markdown-table cell-wrapping pain).
	b.WriteString("## Recent failures\n\n")
	if len(view.RecentFailures) == 0 {
		b.WriteString("_No recent probe failures — agent is operating normally._\n\n")
	} else {
		for _, f := range view.RecentFailures {
			fmt.Fprintf(&b, "- `%s` (%s · %d ms before failure): %s\n",
				f.ProbeName, f.At, f.LatencyMS, f.Diagnostic)
			if f.Hint.Message != "" {
				// Nested bullet so the hint reads as remediation under
				// the failure that triggered it, not as a sibling row.
				fmt.Fprintf(&b, "  - **%s:** %s", f.Hint.Kind, f.Hint.Message)
				if f.Hint.URL != "" {
					fmt.Fprintf(&b, " ([%s](%s))", f.Hint.URLText, f.Hint.URL)
				}
				b.WriteString("\n")
			}
		}
		b.WriteString("\n")
	}

	// Probe metrics table.
	if view.HasProbeData {
		b.WriteString("## Probe metrics\n\n")
		b.WriteString("| Probe | Total | Passed | Failed | Skipped | Pass rate | Median | p95 |\n")
		b.WriteString("|---|---|---|---|---|---|---|---|\n")
		for _, p := range view.ProbeMetrics {
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %s | %d ms | %d ms |\n",
				p.Name, p.Total, p.Passed, p.Failed, p.Skipped, p.PassPct, p.MedianMS, p.P95MS)
		}
		b.WriteString("\n")
	}

	// Stream health.
	if view.Stream != nil {
		b.WriteString("## Stream\n\n")
		fmt.Fprintf(&b, "- State: **%s**\n", view.Stream.State)
		fmt.Fprintf(&b, "- Events sent: %d\n", view.Stream.TotalSent)
		fmt.Fprintf(&b, "- Backlog depth: %d\n", view.Stream.BacklogDepth)
		if view.Stream.LastEventAgo != "" {
			fmt.Fprintf(&b, "- Last event: %s (%s)\n", view.Stream.LastEventAgo, view.Stream.LastEventAt)
		}
		if view.Stream.LastErrorText != "" {
			fmt.Fprintf(&b, "- Last error: `%s`\n", view.Stream.LastErrorText)
		}
		b.WriteString("\n")
	}

	// Scan stats.
	if view.HasScanData {
		b.WriteString("## Scans\n\n")
		fmt.Fprintf(&b, "- Total: %d\n", view.ScanStats.Total)
		fmt.Fprintf(&b, "- Latest: **%s** (started %s · ran %s)\n",
			view.ScanStats.LatestStatus, view.ScanStats.LatestStartedAt, view.ScanStats.LatestDuration)
		if view.ScanStats.AverageDuration != "" {
			fmt.Fprintf(&b, "- Average duration (last 20): %s\n", view.ScanStats.AverageDuration)
		}
		b.WriteString("\n")
	}

	// Runtime.
	b.WriteString("## Runtime\n\n")
	fmt.Fprintf(&b, "- Go: `%s`\n", view.Runtime.GoVersion)
	fmt.Fprintf(&b, "- Heap allocated: %s\n", view.Runtime.HeapAlloc)
	fmt.Fprintf(&b, "- Goroutines: %d\n", view.Runtime.Goroutines)
	fmt.Fprintf(&b, "- Uptime: %s\n", view.Runtime.Uptime)
	if view.Runtime.DBPath != "" {
		fmt.Fprintf(&b, "- SQLite: `%s` (%s)\n", view.Runtime.DBPath, view.Runtime.DBSize)
	}
	b.WriteString("\n")

	b.WriteString("---\n_Generated by kite-collector local observability — no data leaves this host._\n")
	return b.String()
}

// mdEscapePipe escapes `|` so the substring is safe inside a markdown
// table cell. The other table-breaker (`\n`) is collapsed to a single
// space so a multi-line diagnostic doesn't fracture the row.
func mdEscapePipe(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "|", `\|`)
}

// buildObservabilityView is the shared aggregation step extracted so both
// the HTML render path and the JSON snapshot endpoint compute the same
// observabilityView from the same helpers. Without this extraction the
// two surfaces could drift over time as new fields are added.
func buildObservabilityView(ctx context.Context, deps onboardingDeps) observabilityView {
	view := observabilityView{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Endpoint:    deps.PlatformEndpoint,
	}
	view.Health = computeHealthChecks(ctx, deps)
	view.HealthSummary, view.HealthClass, view.HealthDetail = rollupHealth(view.Health)

	var (
		probeRows []sqlite.ProbeResultRecord
		scanRows  []model.ScanRun
	)
	if deps.Store != nil {
		if rows, err := deps.Store.ListProbeResults(ctx, 200); err == nil && len(rows) > 0 {
			probeRows = rows
			view.ProbeMetrics = aggregateProbeMetrics(rows)
			view.HasProbeData = true
		}
		if runs, err := deps.Store.ListScanRuns(ctx, 20); err == nil && len(runs) > 0 {
			scanRows = runs
			view.ScanStats = aggregateScanStats(runs)
			view.HasScanData = true
		}
	}
	// Activity timeline composes probe + scan rows we already fetched —
	// no extra queries, no extra round-trips. The 20-event cap keeps the
	// card scannable while still surfacing enough history to spot a
	// pattern ("everything broke at 14:23").
	view.RecentActivity = aggregateRecentActivity(probeRows, scanRows, 20)
	view.HasActivity = len(view.RecentActivity) > 0

	// Recent failures (iter-33) — the diagnostic-first card placed right
	// after Healthchecks. Filters the already-fetched probe rows down to
	// the 5 most-recent failures and surfaces their diagnostic strings
	// front and centre. Empty when everything is healthy — the empty
	// state is positive copy ("agent operating normally").
	view.RecentFailures = extractRecentFailures(probeRows, 5)
	view.HasFailures = len(view.RecentFailures) > 0

	if deps.StreamCtrl != nil {
		s := deps.StreamCtrl.Status()
		sh := &streamHealth{
			State:         s.NormalizeState(),
			TotalSent:     s.TotalSent,
			BacklogDepth:  s.BacklogDepth,
			LastErrorText: s.LastErrorText,
		}
		sh.StateBadge = streamStateBadge(sh.State)
		if !s.LastEventAt.IsZero() {
			sh.LastEventAt = s.LastEventAt.UTC().Format(time.RFC3339)
			sh.LastEventAgo = humanizeRelativeTime(time.Since(s.LastEventAt))
		}
		view.Stream = sh
	}

	view.Runtime = collectRuntimeStats(ctx, deps)
	return view
}

// serveObservabilityPage renders either the full shell (with sidebar +
// topbar) for plain GETs, or just the fragment for HTMX swaps coming from
// the sidebar nav. Matches the existing tab-route pattern.
func serveObservabilityPage(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	paused := r.URL.Query().Get("paused") == "1"
	if r.Header.Get("HX-Request") == "true" {
		if err := renderObservabilityFragment(w, r.Context(), deps, paused); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if err := renderIndexPage(w, "observability", func(fragBuf io.Writer) error {
		return renderObservabilityFragment(fragBuf, r.Context(), deps, paused)
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
