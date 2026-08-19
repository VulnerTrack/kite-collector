// Containers page — live observability over the local Docker / Podman /
// docker-compose environment, modeled on lazydocker's three headline
// capabilities and adapted to this dashboard's HTMX + server-rendered-SVG
// idiom:
//
//  1. State at a glance: every container with an icon status + health,
//     grouped by compose project, refreshed automatically.
//  2. Custom metric graphs: sparkline columns for CPU/memory by default,
//     plus ANY numeric field of the Engine stats document by dotted
//     "stat path" (e.g. memory_stats.stats.pgmajfault) — the same idea as
//     lazydocker's `stats.graphs[].statPath` config, but driven by URL
//     query params so a customised view is bookmarkable and shareable.
//  3. Image ancestor layers: `docker history` for any image, rendered in
//     the row drawer.
//
// Stats collection follows the lazydocker practice of deriving CPU% from
// consecutive samples: a background monitor polls one-shot stats per
// running container, keeps a bounded ring buffer per metric, and stops
// itself when nobody has viewed the page for a while (this is an agent —
// it must stay quiet when unobserved).
package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulnertrack/kite-collector/internal/discovery/docker"
)

const (
	// containersPollInterval is the monitor's stats sampling cadence.
	containersPollInterval = 5 * time.Second
	// containersIdleStop stops the monitor after this long without a page
	// view so an unattended dashboard doesn't poll Docker forever.
	containersIdleStop = 3 * time.Minute
	// containerSeriesCap bounds each metric ring buffer: 120 samples at the
	// 5s cadence = 10 minutes of graph history per container per metric.
	containerSeriesCap = 120
	// customStatPathTTL evicts custom metric series nobody has rendered
	// recently, so abandoned experiments don't accumulate memory.
	customStatPathTTL = 10 * time.Minute
	// maxCustomGraphs caps the number of custom stat paths per request.
	maxCustomGraphs = 8
	// maxStatPathLen caps a single stat path's length.
	maxStatPathLen = 128
	// containersRefreshSecs is the page auto-refresh cadence (HTMX trigger).
	containersRefreshSecs = 10
	// statsFetchParallelism bounds concurrent one-shot stats requests per tick.
	statsFetchParallelism = 8
)

// derivedStatPrefix namespaces computed metrics ("derived.cpu_percent")
// apart from raw Engine stats document paths ("memory_stats.usage").
const derivedStatPrefix = "derived."

// defaultContainerGraphs are the always-on metric columns — the lazydocker
// default config (CPU%, Memory%) plus network totals, which its docs
// recommend as the first customisation.
var defaultContainerGraphs = []containerGraphSpec{
	{Caption: "CPU %", StatPath: "derived.cpu_percent"},
	{Caption: "Memory %", StatPath: "derived.memory_percent"},
}

// containerGraphSpec names one metric to collect and graph.
type containerGraphSpec struct {
	Caption  string `json:"caption"`
	StatPath string `json:"stat_path"`
}

// liveEngineClient is the slice of docker.LiveClient the controller needs;
// an interface so tests can point at a mock Engine API through the real
// HTTP client or substitute a fake outright.
type liveEngineClient interface {
	ListLive(ctx context.Context) ([]docker.LiveContainer, error)
	ContainerStats(ctx context.Context, id string) (map[string]any, error)
	ImageHistory(ctx context.Context, id string) ([]docker.ImageLayer, error)
	ListImagesLive(ctx context.Context) ([]docker.ImageInfo, error)
}

// containerSeries is the per-container metric history: ring buffers per
// stat path plus the previous CPU counters needed to derive CPU% from
// consecutive one-shot samples (the lazydocker RecordedStats practice).
type containerSeries struct {
	series       map[string][]float64
	latest       map[string]float64
	latestRaw    map[string]any
	prevCPUTotal float64
	prevSystem   float64
	updatedAt    time.Time
	hasPrev      bool
}

// containersController owns the background stats monitor and renders every
// containers surface. One instance per dashboard server.
type containersController struct {
	logger *slog.Logger
	// configuredHost is the docker source host from config ("" = autodetect).
	configuredHost string
	// newClient is swappable for tests; production uses docker.NewLiveClient.
	newClient func(host string) liveEngineClient

	mu          sync.Mutex
	hist        map[string]*containerSeries // container ID → history
	customPaths map[string]time.Time        // stat path → last requested
	lastViewed  time.Time
	running     bool
	stopCh      chan struct{}
	lastTickErr string
	now         func() time.Time // injectable clock for tests
	// disableMonitor keeps the background loop off so tests drive tick()
	// deterministically.
	disableMonitor bool
}

func newContainersController(configuredHost string, logger *slog.Logger) *containersController {
	if logger == nil {
		logger = slog.Default()
	}
	return &containersController{
		logger:         logger,
		configuredHost: configuredHost,
		newClient: func(host string) liveEngineClient {
			return docker.NewLiveClient(host)
		},
		hist:        map[string]*containerSeries{},
		customPaths: map[string]time.Time{},
		now:         time.Now,
	}
}

// client resolves the engine endpoint (config → KITE_DOCKER_HOST → socket
// autodetection) and returns a client for it, or "" when no engine is up.
func (cc *containersController) client() (liveEngineClient, string) {
	host := docker.ResolveHost(cc.configuredHost)
	if host == "" {
		return nil, ""
	}
	return cc.newClient(host), host
}

// markViewed records page activity, registers requested custom stat paths,
// and lazily starts the monitor. Called at the top of every render.
func (cc *containersController) markViewed(customPaths []string) {
	cc.mu.Lock()
	cc.lastViewed = cc.now()
	for _, p := range customPaths {
		cc.customPaths[p] = cc.lastViewed
	}
	shouldStart := !cc.running && !cc.disableMonitor
	if shouldStart {
		cc.running = true
		cc.stopCh = make(chan struct{})
	}
	stopCh := cc.stopCh
	cc.mu.Unlock()

	if shouldStart {
		go cc.monitorLoop(stopCh)
	}
}

// stopMonitor halts the background loop if one is running. The next page
// view restarts it. Safe to call at any time, including when idle-stop
// already ended the loop.
func (cc *containersController) stopMonitor() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.running {
		close(cc.stopCh)
		cc.running = false
	}
}

// monitorLoop samples stats on a fixed cadence until the page has been
// idle for containersIdleStop. A fresh page view restarts it.
func (cc *containersController) monitorLoop(stopCh chan struct{}) {
	// Immediate first sample so metric cells populate on the page's first
	// auto-refresh instead of one poll interval later.
	firstCtx, cancelFirst := context.WithTimeout(context.Background(), containersPollInterval)
	cc.tick(firstCtx)
	cancelFirst()

	ticker := time.NewTicker(containersPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
		}
		cc.mu.Lock()
		idle := cc.now().Sub(cc.lastViewed) > containersIdleStop
		if idle {
			cc.running = false
		}
		cc.mu.Unlock()
		if idle {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), containersPollInterval)
		cc.tick(ctx)
		cancel()
	}
}

// tick performs one sampling round: list containers, fetch one-shot stats
// for every running one in parallel, record metric points, prune state.
func (cc *containersController) tick(ctx context.Context) {
	client, _ := cc.client()
	if client == nil {
		cc.setTickErr("no Docker/Podman engine found")
		return
	}
	live, err := client.ListLive(ctx)
	if err != nil {
		cc.setTickErr(err.Error())
		cc.logger.Warn("dashboard: containers stats poll list failed",
			"code", string(LogCodeContainersList), "error", err)
		return
	}
	cc.setTickErr("")

	seen := map[string]bool{}
	sem := make(chan struct{}, statsFetchParallelism)
	var wg sync.WaitGroup
	for _, c := range live {
		seen[c.ID] = true
		if !strings.EqualFold(c.State, "running") {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			raw, statsErr := client.ContainerStats(ctx, id)
			if statsErr != nil {
				cc.logger.Warn("dashboard: container stats fetch failed",
					"code", string(LogCodeContainersStats),
					"container", shortID(id), "error", statsErr)
				return
			}
			cc.record(id, raw)
		}(c.ID)
	}
	wg.Wait()

	// Prune histories for containers the engine no longer reports, and
	// custom paths nobody has rendered within the TTL.
	cc.mu.Lock()
	for id := range cc.hist {
		if !seen[id] {
			delete(cc.hist, id)
		}
	}
	cutoff := cc.now().Add(-customStatPathTTL)
	for p, at := range cc.customPaths {
		if at.Before(cutoff) {
			delete(cc.customPaths, p)
		}
	}
	cc.mu.Unlock()
}

func (cc *containersController) setTickErr(msg string) {
	cc.mu.Lock()
	cc.lastTickErr = msg
	cc.mu.Unlock()
}

// record derives computed metrics from a raw stats sample and appends every
// active stat path's value to that container's ring buffers.
func (cc *containersController) record(id string, raw map[string]any) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	s := cc.hist[id]
	if s == nil {
		s = &containerSeries{series: map[string][]float64{}, latest: map[string]float64{}}
		cc.hist[id] = s
	}
	derived := deriveContainerStats(raw, s)
	s.latestRaw = raw
	s.updatedAt = cc.now()

	paths := make([]string, 0, len(defaultContainerGraphs)+len(cc.customPaths))
	for _, g := range defaultContainerGraphs {
		paths = append(paths, g.StatPath)
	}
	for p := range cc.customPaths {
		paths = append(paths, p)
	}
	for _, p := range paths {
		v, ok := resolveStatPath(raw, derived, p)
		if !ok {
			continue
		}
		s.latest[p] = v
		buf := append(s.series[p], v)
		if len(buf) > containerSeriesCap {
			buf = buf[len(buf)-containerSeriesCap:]
		}
		s.series[p] = buf
	}
}

// snapshotSeries returns a copy of one container's history so renders never
// hold the controller lock while templating.
func (cc *containersController) snapshotSeries(id string) *containerSeries {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	s := cc.hist[id]
	if s == nil {
		return nil
	}
	out := &containerSeries{
		series:    make(map[string][]float64, len(s.series)),
		latest:    make(map[string]float64, len(s.latest)),
		latestRaw: s.latestRaw,
		updatedAt: s.updatedAt,
	}
	for p, vals := range s.series {
		cp := make([]float64, len(vals))
		copy(cp, vals)
		out.series[p] = cp
	}
	for p, v := range s.latest {
		out.latest[p] = v
	}
	return out
}

// -------------------------------------------------------------------------
// Derived stats + stat path resolution
// -------------------------------------------------------------------------

// deriveContainerStats computes the metrics the raw document doesn't carry
// directly. CPU% follows the docker-CLI formula using either the sample's
// own precpu block (when present) or the previous sample this monitor took
// — the consecutive-readings technique lazydocker uses on its stats stream.
// Memory subtracts the page cache (inactive_file) for `docker stats` parity.
func deriveContainerStats(raw map[string]any, s *containerSeries) map[string]float64 {
	d := map[string]float64{}

	cpuTotal, _ := lookupNumberPath(raw, "cpu_stats.cpu_usage.total_usage")
	system, _ := lookupNumberPath(raw, "cpu_stats.system_cpu_usage")
	preTotal, _ := lookupNumberPath(raw, "precpu_stats.cpu_usage.total_usage")
	preSystem, _ := lookupNumberPath(raw, "precpu_stats.system_cpu_usage")
	if preSystem == 0 && s.hasPrev {
		preTotal, preSystem = s.prevCPUTotal, s.prevSystem
	}
	online, _ := lookupNumberPath(raw, "cpu_stats.online_cpus")
	if online == 0 {
		online = 1
	}
	cpuDelta := cpuTotal - preTotal
	sysDelta := system - preSystem
	if sysDelta > 0 && cpuDelta >= 0 && preSystem > 0 {
		d["cpu_percent"] = cpuDelta / sysDelta * online * 100
	}
	s.prevCPUTotal, s.prevSystem, s.hasPrev = cpuTotal, system, true

	usage, hasUsage := lookupNumberPath(raw, "memory_stats.usage")
	if v, ok := lookupNumberPath(raw, "memory_stats.stats.inactive_file"); ok {
		usage -= v // cgroup v2
	} else if v, ok := lookupNumberPath(raw, "memory_stats.stats.total_inactive_file"); ok {
		usage -= v // cgroup v1
	}
	if usage < 0 {
		usage = 0
	}
	limit, _ := lookupNumberPath(raw, "memory_stats.limit")
	if hasUsage {
		d["memory_bytes"] = usage
	}
	if limit > 0 {
		d["memory_limit_bytes"] = limit
		if hasUsage {
			d["memory_percent"] = usage / limit * 100
		}
	}

	// Sum across every interface rather than hardcoding eth0 so containers
	// on multiple compose networks report full traffic.
	if nets, ok := raw["networks"].(map[string]any); ok {
		var rx, tx float64
		for _, v := range nets {
			iface, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if n, ok := asNumber(iface["rx_bytes"]); ok {
				rx += n
			}
			if n, ok := asNumber(iface["tx_bytes"]); ok {
				tx += n
			}
		}
		d["net_rx_bytes"] = rx
		d["net_tx_bytes"] = tx
	}
	if v, ok := lookupNumberPath(raw, "pids_stats.current"); ok {
		d["pids"] = v
	}
	return d
}

// resolveStatPath resolves a stat path against a sample: "derived.*" hits
// the computed metrics; anything else walks the raw Engine stats document
// by dotted keys ("memory_stats.stats.pgmajfault").
func resolveStatPath(raw map[string]any, derived map[string]float64, path string) (float64, bool) {
	if rest, ok := strings.CutPrefix(path, derivedStatPrefix); ok {
		v, ok := derived[rest]
		return v, ok
	}
	return lookupNumberPath(raw, path)
}

// lookupNumberPath walks nested JSON maps by dotted path to a numeric leaf.
func lookupNumberPath(raw map[string]any, path string) (float64, bool) {
	cur := any(raw)
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return 0, false
		}
		cur, ok = m[seg]
		if !ok {
			return 0, false
		}
	}
	return asNumber(cur)
}

func asNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// statPathValue pairs a discoverable stat path with its current value —
// the path browser in the container drawer is built from these.
type statPathValue struct {
	Path  string  `json:"path"`
	Value float64 `json:"value"`
}

// flattenNumericPaths lists every numeric leaf of a stats document as a
// dotted path. This is the discoverability surface: lazydocker tells users
// to read the stats JSON and PascalCase a path; here the dashboard lists
// the exact strings ready to click. Arrays are skipped (no stable path).
func flattenNumericPaths(raw map[string]any) []statPathValue {
	var out []statPathValue
	var walk func(prefix string, m map[string]any)
	walk = func(prefix string, m map[string]any) {
		for k, v := range m {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			switch tv := v.(type) {
			case map[string]any:
				walk(p, tv)
			default:
				if n, ok := asNumber(v); ok {
					out = append(out, statPathValue{Path: p, Value: n})
				}
			}
		}
	}
	walk("", raw)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// validateStatPath enforces shape on operator-supplied stat paths before
// they reach the monitor or templates: bounded length, dotted
// [a-z0-9_-] segments only.
func validateStatPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("empty stat path")
	}
	if len(p) > maxStatPathLen {
		return "", fmt.Errorf("stat path longer than %d characters", maxStatPathLen)
	}
	for _, seg := range strings.Split(p, ".") {
		if seg == "" {
			return "", fmt.Errorf("stat path %q has an empty segment", p)
		}
		for _, r := range seg {
			ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '_' || r == '-'
			if !ok {
				return "", fmt.Errorf("stat path %q contains unsupported character %q", p, r)
			}
		}
	}
	return p, nil
}

// -------------------------------------------------------------------------
// SVG graphs
// -------------------------------------------------------------------------

// metricSparkSVG renders a float64 series as an inline SVG polyline, the
// same no-JS approach as the probe sparklines but min–max normalized so
// cumulative counters (network bytes) show their slope instead of a flat
// line hugging the top. Safe by construction: numeric inputs plus escaped
// label strings.
func metricSparkSVG(values []float64, label string, width, height int) template.HTML {
	if len(values) == 0 {
		return template.HTML(`<span class="muted small" title="collecting samples">&hellip;</span>`)
	}
	minV, maxV := values[0], values[0]
	for _, v := range values {
		if v > maxV {
			maxV = v
		}
		if v < minV {
			minV = v
		}
	}
	tooltip := fmt.Sprintf("min %s · max %s · latest %s (n=%d)",
		formatMetricValue(minV, label), formatMetricValue(maxV, label),
		formatMetricValue(values[len(values)-1], label), len(values))

	var b strings.Builder
	fmt.Fprintf(&b,
		`<svg role="img" aria-label="%s trend, oldest left newest right" class="spark-line metric-spark" viewBox="0 0 %d %d" preserveAspectRatio="none">`,
		template.HTMLEscapeString(label), width, height)
	fmt.Fprintf(&b, `<title>%s</title>`, template.HTMLEscapeString(tooltip))
	b.WriteString(`<polyline fill="none" stroke="currentColor" stroke-width="1.5" points="`)
	span := maxV - minV
	for i, v := range values {
		var x float64
		if len(values) == 1 {
			x = float64(width) / 2
		} else {
			x = float64(i) * float64(width) / float64(len(values)-1)
		}
		norm := 0.5 // flat series renders as a mid-height line
		if span > 0 {
			norm = (v - minV) / span
		}
		y := float64(height) - norm*float64(height-2) - 1
		fmt.Fprintf(&b, "%.1f,%.1f ", x, y)
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String()) //#nosec G203 -- numeric inputs; label strings HTML-escaped above
}

// formatMetricValue humanizes a metric by its stat path/caption: percents
// get one decimal + %, byte-ish paths get KB/MB/GB, everything else prints
// as a plain number.
func formatMetricValue(v float64, pathOrCaption string) string {
	lc := strings.ToLower(pathOrCaption)
	switch {
	case strings.Contains(lc, "percent") || strings.Contains(lc, "%"):
		return fmt.Sprintf("%.1f%%", v)
	case strings.Contains(lc, "bytes"):
		return humanizeBytes(int64(v))
	case v == math.Trunc(v) && math.Abs(v) < 1e15:
		return humanizeCount(int64(v))
	default:
		return fmt.Sprintf("%.2f", v)
	}
}

// -------------------------------------------------------------------------
// View models
// -------------------------------------------------------------------------

// containerMetricCell is one metric column value for one container row.
type containerMetricCell struct {
	Display string        `json:"display"` // humanized current value or "—"
	Value   float64       `json:"value"`
	Spark   template.HTML `json:"-"`
	Has     bool          `json:"has"`
}

// containerRowView is one at-a-glance container row.
type containerRowView struct {
	ID             string                `json:"id"`
	ShortID        string                `json:"short_id"`
	Name           string                `json:"name"`
	Image          string                `json:"image"`
	ImageID        string                `json:"image_id"`
	LayersImageID  string                `json:"-"` // hex form used in the layers URL
	State          string                `json:"state"`
	Health         string                `json:"health,omitempty"`
	StatusText     string                `json:"status"`
	Icon           string                `json:"-"`
	BadgeClass     string                `json:"-"`
	StateLabel     string                `json:"state_label"`
	ComposeService string                `json:"compose_service,omitempty"`
	Ports          string                `json:"ports,omitempty"`
	CreatedAgo     string                `json:"created_ago"`
	Metrics        []containerMetricCell `json:"metrics"`
}

// composeGroupView groups rows by compose project ("" = standalone).
type composeGroupView struct {
	Project string             `json:"project"`
	Rows    []containerRowView `json:"containers"`
}

// imageRowView is one image inventory row.
type imageRowView struct {
	ID       string `json:"id"`
	ShortID  string `json:"short_id"`
	HexID    string `json:"-"`
	Tags     string `json:"tags"`
	Size     string `json:"size"`
	Created  string `json:"created_ago"`
	SizeRaw  int64  `json:"size_bytes"`
	Untagged bool   `json:"untagged"`
}

// graphColumnView describes one metric column: caption, path, and the URL
// that removes it (custom columns only).
type graphColumnView struct {
	Caption   string `json:"caption"`
	StatPath  string `json:"stat_path"`
	RemoveURL string `json:"-"`
	Custom    bool   `json:"custom"`
}

// containersView is the whole page model — HTML fragment and JSON snapshot
// share it so the two can never disagree.
type containersView struct {
	GeneratedAt   string                 `json:"generated_at"`
	DockerHost    string                 `json:"docker_host,omitempty"`
	Available     bool                   `json:"available"`
	Error         string                 `json:"error,omitempty"`
	MonitorNote   string                 `json:"monitor_note,omitempty"`
	Total         int                    `json:"total"`
	RunningCount  int                    `json:"running"`
	UnhealthyN    int                    `json:"unhealthy"`
	ExitedCount   int                    `json:"exited"`
	ProjectCount  int                    `json:"compose_projects"`
	Columns       []graphColumnView      `json:"columns"`
	Groups        []composeGroupView     `json:"groups"`
	Images        []imageRowView         `json:"images,omitempty"`
	ImagesError   string                 `json:"images_error,omitempty"`
	Freshness     observabilityFreshness `json:"-"`
	DetailQuery   string                 `json:"-"` // "?graph=a&graph=b" carried into drawer links
	SnapshotURL   string                 `json:"-"`
	InvalidGraphs []string               `json:"-"` // rejected stat paths, echoed as a warning
}

// containerDetailView is the row-drawer model for one container: full-size
// graphs for every active metric plus the browsable list of every numeric
// stat path in the latest raw sample.
type containerDetailView struct {
	Row        containerRowView
	Graphs     []containerDetailGraph
	Paths      []statPathValueView
	HasSample  bool
	SampledAgo string
	AddBaseURL string // /containers with current graphs preserved
}

type containerDetailGraph struct {
	Caption  string
	StatPath string
	Current  string
	Custom   bool
	Spark    template.HTML
}

type statPathValueView struct {
	Path    string
	Display string
	AddURL  string // page URL with this path appended as a graph column
}

// imageLayersView is the row-drawer model for image ancestor layers.
type imageLayersView struct {
	Ref        string
	ShortID    string
	LayerCount int
	TotalSize  string
	Layers     []imageLayerRowView
	Error      string
}

type imageLayerRowView struct {
	ShortID    string
	CreatedAgo string
	Size       string
	CreatedBy  string // trimmed instruction
	FullCmd    string // untrimmed, for the title tooltip
	Tags       string
	Missing    bool
}

// -------------------------------------------------------------------------
// View building
// -------------------------------------------------------------------------

// containerStateIcon maps state+health to the at-a-glance icon, badge
// class, and accessible label — the lazydocker "icon" status style.
func containerStateIcon(state, health string) (icon, badgeClass, label string) {
	switch strings.ToLower(state) {
	case "running":
		switch health {
		case "healthy":
			return "✔", "badge-green", "running · healthy"
		case "unhealthy":
			return "✖", "badge-red", "running · unhealthy"
		case "starting":
			return "◐", "badge-yellow", "running · health starting"
		}
		return "▶", "badge-green", "running"
	case "paused":
		return "⏸", "badge-yellow", "paused"
	case "restarting":
		return "↻", "badge-orange", "restarting"
	case "exited":
		return "■", "badge-gray", "exited"
	case "dead":
		return "✖", "badge-red", "dead"
	case "created":
		return "+", "badge-blue", "created"
	}
	return "?", "badge-gray", state
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func agoString(t time.Time, now time.Time) string {
	if t.IsZero() || t.After(now) {
		return "—"
	}
	return humanizeDuration(now.Sub(t)) + " ago"
}

// activeGraphColumns is the ordered column set: defaults first, then the
// request's custom paths in the order given.
func activeGraphColumns(customPaths []string, paused bool) []graphColumnView {
	cols := make([]graphColumnView, 0, len(defaultContainerGraphs)+len(customPaths))
	for _, g := range defaultContainerGraphs {
		cols = append(cols, graphColumnView{Caption: g.Caption, StatPath: g.StatPath})
	}
	for i, p := range customPaths {
		remaining := make([]string, 0, len(customPaths)-1)
		remaining = append(remaining, customPaths[:i]...)
		remaining = append(remaining, customPaths[i+1:]...)
		cols = append(cols, graphColumnView{
			Caption:   p,
			StatPath:  p,
			Custom:    true,
			RemoveURL: containersPageURL(remaining, paused),
		})
	}
	return cols
}

// containersPageURL builds the canonical page URL carrying the custom
// graph set — this is what makes a customised view bookmarkable.
func containersPageURL(customPaths []string, paused bool) string {
	q := url.Values{}
	for _, p := range customPaths {
		q.Add("graph", p)
	}
	if paused {
		q.Set("paused", "1")
	}
	if enc := q.Encode(); enc != "" {
		return "/containers?" + enc
	}
	return "/containers"
}

func containersFragmentURL(customPaths []string, paused bool) string {
	page := containersPageURL(customPaths, paused)
	return "/fragments/containers" + strings.TrimPrefix(page, "/containers")
}

// parseContainerGraphParams extracts, validates, dedupes, and caps the
// ?graph= params. Invalid paths are returned separately so the page can
// explain rather than silently drop them.
func parseContainerGraphParams(r *http.Request) (valid []string, invalid []string) {
	seen := map[string]bool{}
	for _, rawPath := range r.URL.Query()["graph"] {
		p, err := validateStatPath(rawPath)
		if err != nil {
			invalid = append(invalid, rawPath)
			continue
		}
		if seen[p] || len(valid) >= maxCustomGraphs {
			continue
		}
		seen[p] = true
		valid = append(valid, p)
	}
	return valid, invalid
}

// buildContainersView assembles the page model: fresh container list from
// the engine (state is always render-accurate), metric cells from the
// monitor's ring buffers.
func (cc *containersController) buildContainersView(ctx context.Context, customPaths []string, paused bool) containersView {
	now := cc.now()
	view := containersView{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Columns:     activeGraphColumns(customPaths, paused),
		DetailQuery: graphQueryOnly(customPaths),
		SnapshotURL: "/api/v1/containers/snapshot.json" + graphQueryOnly(customPaths),
	}

	client, host := cc.client()
	view.DockerHost = host
	if client == nil {
		view.Error = "No Docker or Podman engine found. Set KITE_DOCKER_HOST or start the engine, then reload."
		return view
	}
	live, err := client.ListLive(ctx)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	view.Available = true

	cc.mu.Lock()
	if cc.lastTickErr != "" {
		view.MonitorNote = cc.lastTickErr
	}
	cc.mu.Unlock()

	groups := map[string][]containerRowView{}
	projects := map[string]bool{}
	for _, c := range live {
		icon, badge, label := containerStateIcon(c.State, c.Health)
		row := containerRowView{
			ID:             c.ID,
			ShortID:        shortID(c.ID),
			Name:           c.Name,
			Image:          c.Image,
			ImageID:        c.ImageID,
			LayersImageID:  shortIDForURL(c.ImageID),
			State:          c.State,
			Health:         c.Health,
			StatusText:     c.Status,
			Icon:           icon,
			BadgeClass:     badge,
			StateLabel:     label,
			ComposeService: c.ComposeService,
			Ports:          c.Ports,
			CreatedAgo:     agoString(c.Created, now),
		}
		series := cc.snapshotSeries(c.ID)
		for _, col := range view.Columns {
			row.Metrics = append(row.Metrics, buildMetricCell(series, col))
		}
		view.Total++
		switch strings.ToLower(c.State) {
		case "running":
			view.RunningCount++
		case "exited", "dead":
			view.ExitedCount++
		}
		if c.Health == "unhealthy" {
			view.UnhealthyN++
		}
		if c.ComposeProject != "" {
			projects[c.ComposeProject] = true
		}
		groups[c.ComposeProject] = append(groups[c.ComposeProject], row)
	}
	view.ProjectCount = len(projects)

	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	// Compose projects alphabetically, standalone containers last.
	sort.Slice(names, func(i, j int) bool {
		if (names[i] == "") != (names[j] == "") {
			return names[j] == ""
		}
		return names[i] < names[j]
	})
	for _, name := range names {
		rows := groups[name]
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
		label := name
		if label == "" {
			label = "standalone containers"
		}
		view.Groups = append(view.Groups, composeGroupView{Project: label, Rows: rows})
	}

	images, imgErr := client.ListImagesLive(ctx)
	if imgErr != nil {
		view.ImagesError = imgErr.Error()
	} else {
		sort.Slice(images, func(i, j int) bool { return images[i].Size > images[j].Size })
		for _, img := range images {
			tags := strings.Join(img.RepoTags, ", ")
			untagged := tags == "" || tags == "<none>:<none>"
			if untagged {
				tags = "<untagged>"
			}
			view.Images = append(view.Images, imageRowView{
				ID:       img.ID,
				ShortID:  shortID(img.ID),
				HexID:    shortIDForURL(img.ID),
				Tags:     tags,
				Size:     humanizeBytes(img.Size),
				SizeRaw:  img.Size,
				Created:  agoString(img.Created, now),
				Untagged: untagged,
			})
		}
	}
	return view
}

// shortIDForURL strips the sha256: prefix so the ID is a safe path segment.
func shortIDForURL(id string) string {
	return strings.TrimPrefix(id, "sha256:")
}

// graphQueryOnly renders "?graph=..&graph=.." or "" for URLs with no other params.
func graphQueryOnly(customPaths []string) string {
	if len(customPaths) == 0 {
		return ""
	}
	q := url.Values{}
	for _, p := range customPaths {
		q.Add("graph", p)
	}
	return "?" + q.Encode()
}

func buildMetricCell(series *containerSeries, col graphColumnView) containerMetricCell {
	if series == nil {
		return containerMetricCell{Display: "—"}
	}
	v, ok := series.latest[col.StatPath]
	if !ok {
		return containerMetricCell{Display: "—"}
	}
	return containerMetricCell{
		Display: formatMetricValue(v, col.StatPath),
		Value:   v,
		Has:     true,
		Spark:   metricSparkSVG(series.series[col.StatPath], col.Caption, 120, 24),
	}
}

// buildContainerDetailView assembles the row-drawer model for one container.
func (cc *containersController) buildContainerDetailView(ctx context.Context, id string, customPaths []string, paused bool) (containerDetailView, error) {
	client, _ := cc.client()
	if client == nil {
		return containerDetailView{}, fmt.Errorf("no Docker/Podman engine found")
	}
	live, err := client.ListLive(ctx)
	if err != nil {
		return containerDetailView{}, fmt.Errorf("list containers: %w", err)
	}
	now := cc.now()
	detail := containerDetailView{AddBaseURL: containersPageURL(customPaths, paused)}
	found := false
	for _, c := range live {
		if c.ID != id {
			continue
		}
		icon, badge, label := containerStateIcon(c.State, c.Health)
		detail.Row = containerRowView{
			ID: c.ID, ShortID: shortID(c.ID), Name: c.Name, Image: c.Image,
			ImageID: c.ImageID, LayersImageID: shortIDForURL(c.ImageID),
			State: c.State, Health: c.Health, StatusText: c.Status,
			Icon: icon, BadgeClass: badge, StateLabel: label,
			ComposeService: c.ComposeService, Ports: c.Ports,
			CreatedAgo: agoString(c.Created, now),
		}
		found = true
		break
	}
	if !found {
		return containerDetailView{}, fmt.Errorf("container %s not found", shortID(id))
	}

	series := cc.snapshotSeries(id)
	for _, col := range activeGraphColumns(customPaths, paused) {
		g := containerDetailGraph{Caption: col.Caption, StatPath: col.StatPath, Custom: col.Custom, Current: "—"}
		if series != nil {
			if v, ok := series.latest[col.StatPath]; ok {
				g.Current = formatMetricValue(v, col.StatPath)
			}
			g.Spark = metricSparkSVG(series.series[col.StatPath], col.Caption, 240, 48)
		} else {
			g.Spark = metricSparkSVG(nil, col.Caption, 240, 48)
		}
		detail.Graphs = append(detail.Graphs, g)
	}

	if series != nil && series.latestRaw != nil {
		detail.HasSample = true
		detail.SampledAgo = agoString(series.updatedAt, now)
		for _, pv := range flattenNumericPaths(series.latestRaw) {
			detail.Paths = append(detail.Paths, statPathValueView{
				Path:    pv.Path,
				Display: formatMetricValue(pv.Value, pv.Path),
				AddURL:  containersPageURL(append(append([]string{}, customPaths...), pv.Path), paused),
			})
		}
	}
	return detail, nil
}

// buildImageLayersView fetches and shapes an image's ancestor layers.
func (cc *containersController) buildImageLayersView(ctx context.Context, imageID string) imageLayersView {
	view := imageLayersView{Ref: imageID, ShortID: shortID(imageID)}
	client, _ := cc.client()
	if client == nil {
		view.Error = "no Docker/Podman engine found"
		return view
	}
	layers, err := client.ImageHistory(ctx, imageID)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	now := cc.now()
	var total int64
	for _, l := range layers {
		total += l.Size
		row := imageLayerRowView{
			ShortID:    shortID(l.ID),
			CreatedAgo: agoString(l.Created, now),
			Size:       humanizeBytes(l.Size),
			CreatedBy:  trimLayerInstruction(l.CreatedBy),
			FullCmd:    l.CreatedBy,
			Tags:       strings.Join(l.Tags, ", "),
			Missing:    l.ID == "<missing>",
		}
		if row.Missing {
			row.ShortID = "<missing>"
		}
		view.Layers = append(view.Layers, row)
	}
	view.LayerCount = len(layers)
	view.TotalSize = humanizeBytes(total)
	return view
}

// trimLayerInstruction strips the shell-wrapper noise Docker records around
// Dockerfile instructions so the layer table reads like the Dockerfile
// (same cleanup `docker history` viewers apply).
func trimLayerInstruction(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if rest, ok := strings.CutPrefix(cmd, "/bin/sh -c #(nop)"); ok {
		return strings.TrimSpace(rest)
	}
	if rest, ok := strings.CutPrefix(cmd, "/bin/sh -c "); ok {
		return "RUN " + strings.TrimSpace(rest)
	}
	return cmd
}

// newContainersFreshness mirrors the observability page's live/paused chip
// for the containers fragment, preserving the custom graph set in every URL.
func newContainersFreshness(customPaths []string, paused bool) observabilityFreshness {
	fr := observabilityFreshness{
		Paused:          paused,
		UpdatedAtUTC:    time.Now().UTC().Format(time.RFC3339),
		AutoRefreshSecs: containersRefreshSecs,
		WrapperGetURL:   containersFragmentURL(customPaths, paused),
	}
	if paused {
		fr.ToggleURL = containersFragmentURL(customPaths, false)
		fr.ToggleLabel = "Resume"
		fr.ToggleAriaLabel = "Resume container auto-refresh"
	} else {
		fr.ToggleURL = containersFragmentURL(customPaths, true)
		fr.ToggleLabel = "Pause"
		fr.ToggleAriaLabel = "Pause container auto-refresh"
	}
	return fr
}

// -------------------------------------------------------------------------
// Rendering + routes
// -------------------------------------------------------------------------

func (cc *containersController) renderContainersFragment(w io.Writer, ctx context.Context, customPaths []string, invalid []string, paused bool) error {
	cc.markViewed(customPaths)
	view := cc.buildContainersView(ctx, customPaths, paused)
	view.Freshness = newContainersFreshness(customPaths, paused)
	view.InvalidGraphs = invalid
	if err := containersTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render containers fragment: %w", err)
	}
	return nil
}

func (cc *containersController) renderContainerDetail(w io.Writer, ctx context.Context, id string, customPaths []string, paused bool) error {
	cc.markViewed(customPaths)
	detail, err := cc.buildContainerDetailView(ctx, id, customPaths, paused)
	if err != nil {
		if execErr := containerDrawerErrTmpl.Execute(w, err.Error()); execErr != nil {
			return fmt.Errorf("render container drawer error: %w", execErr)
		}
		return nil
	}
	if err := containerDetailTmpl.Execute(w, detail); err != nil {
		return fmt.Errorf("render container detail: %w", err)
	}
	return nil
}

func (cc *containersController) renderImageLayers(w io.Writer, ctx context.Context, imageID string) error {
	view := cc.buildImageLayersView(ctx, imageID)
	if err := imageLayersTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render image layers: %w", err)
	}
	return nil
}

// registerContainerRoutes wires the containers tab, fragments, drawers, and
// JSON snapshot into the dashboard mux.
func registerContainerRoutes(mux *http.ServeMux, cc *containersController, logger *slog.Logger) {
	mux.HandleFunc("GET /containers", func(w http.ResponseWriter, r *http.Request) {
		customPaths, invalid := parseContainerGraphParams(r)
		paused := r.URL.Query().Get("paused") == "1"
		render := func(buf io.Writer, ctx context.Context) error {
			return cc.renderContainersFragment(buf, ctx, customPaths, invalid, paused)
		}
		if r.Header.Get("HX-Request") == "true" {
			renderBufferedFragment(w, logger, "containers", func(buf io.Writer) error {
				return render(buf, r.Context())
			})
			return
		}
		var buf strings.Builder
		if err := renderIndexPage(&buf, "containers", func(fragBuf io.Writer) error {
			return render(fragBuf, r.Context())
		}); err != nil {
			logger.Error("dashboard: render page containers",
				"code", string(LogCodeContainersRender), "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, buf.String())
	})

	mux.HandleFunc("GET /fragments/containers", func(w http.ResponseWriter, r *http.Request) {
		customPaths, invalid := parseContainerGraphParams(r)
		paused := r.URL.Query().Get("paused") == "1"
		renderBufferedFragment(w, logger, "containers", func(buf io.Writer) error {
			return cc.renderContainersFragment(buf, r.Context(), customPaths, invalid, paused)
		})
	})

	mux.HandleFunc("GET /fragments/containers/{id}", func(w http.ResponseWriter, r *http.Request) {
		customPaths, _ := parseContainerGraphParams(r)
		paused := r.URL.Query().Get("paused") == "1"
		renderBufferedFragment(w, logger, "container-detail", func(buf io.Writer) error {
			return cc.renderContainerDetail(buf, r.Context(), r.PathValue("id"), customPaths, paused)
		})
	})

	mux.HandleFunc("GET /fragments/images/{id}/layers", func(w http.ResponseWriter, r *http.Request) {
		renderBufferedFragment(w, logger, "image-layers", func(buf io.Writer) error {
			return cc.renderImageLayers(buf, r.Context(), r.PathValue("id"))
		})
	})

	mux.HandleFunc("GET /api/v1/containers/snapshot.json", func(w http.ResponseWriter, r *http.Request) {
		customPaths, _ := parseContainerGraphParams(r)
		cc.markViewed(customPaths)
		view := cc.buildContainersView(r.Context(), customPaths, false)
		body, err := json.MarshalIndent(view, "", "  ")
		if err != nil {
			logger.Error("dashboard: containers snapshot marshal failed",
				"code", string(LogCodeContainersSnapshotMarshal), "error", err)
			http.Error(w, "internal encode error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}

// renderBufferedFragment mirrors dashboard.go's renderFragment (buffer
// first, then write) for handlers registered outside Serve's closure.
func renderBufferedFragment(w http.ResponseWriter, logger *slog.Logger, name string, render func(io.Writer) error) {
	var buf strings.Builder
	if err := render(&buf); err != nil {
		if logger != nil {
			logger.Error("dashboard: render "+name,
				"code", string(LogCodeContainersRender), "error", err)
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, buf.String())
}
