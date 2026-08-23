package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

const (
	// machineMemoryWindow is how far back the machine page charts memory.
	machineMemoryWindow = 24 * time.Hour
	// machineMemorySampleCap bounds how many points the sparkline plots.
	machineMemorySampleCap = 1000
)

// The machine resource page: a machine is a page, not a drawer. Breadcrumb,
// identity header with state badges, and related resources as counted tabs
// (Overview, Software, Findings, Interfaces, Events). The Overview keeps only
// identity, open findings, and a software preview; each preview links into
// its tab.

// machinePagePreviewLimit caps the Overview's related-resource previews.
const machinePagePreviewLimit = 5

// machineTabs is the closed set of tabs the page serves. Anything else in
// ?tab= falls back to overview.
var machineTabs = map[string]bool{
	"overview": true, "software": true, "findings": true,
	"interfaces": true, "events": true,
}

// machinePageView is the data model for machinePageTemplate.
type machinePageView struct {
	Machine model.Machine
	Tab     string

	SoftwareCount   int
	FindingsCount   int
	InterfacesCount int64
	EventsCount     int

	// Memory summary. HasMemory is set when total RAM is known (from the
	// osquery physical_memory_bytes tag, available before the first sample) or
	// when the durable time series has points. MemorySpark is the used-percent
	// sparkline over the last day; empty when there are no samples yet.
	HasMemory         bool
	MemoryTotalHuman  string
	MemoryUsedHuman   string
	MemoryUsedPercent float64
	MemorySpark       template.HTML

	// Overview previews (capped at machinePagePreviewLimit).
	FindingsPreview []model.ConfigFinding
	SoftwarePreview []model.InstalledSoftware

	// Tab contents — only the active tab's slice is populated.
	Software   []model.InstalledSoftware
	Findings   []model.ConfigFinding
	Events     []model.MachineEvent
	Interfaces []store.Row
	IfaceCols  []store.ColumnSchema
}

var machinePageTmpl = template.Must(
	template.New("machinePage").Funcs(templateFuncs).Parse(machinePageTemplate))

// renderMachinePageFragment renders /machines/{id}. Returns
// store.ErrNotFound when no machine has that id, so the route can 404.
func renderMachinePageFragment(w io.Writer, ctx context.Context, st store.Store, id uuid.UUID, tab string) error {
	if !machineTabs[tab] {
		tab = "overview"
	}
	machine, err := st.GetMachineByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get machine %s: %w", id, err)
	}

	view := machinePageView{Machine: *machine, Tab: tab}

	software, err := st.ListSoftware(ctx, id)
	if err != nil {
		return fmt.Errorf("list software for %s: %w", id, err)
	}
	view.SoftwareCount = len(software)

	findings, err := st.ListFindings(ctx, store.FindingFilter{MachineID: &id})
	if err != nil {
		return fmt.Errorf("list findings for %s: %w", id, err)
	}
	view.FindingsCount = len(findings)

	events, err := st.ListEvents(ctx, store.EventFilter{MachineID: &id})
	if err != nil {
		return fmt.Errorf("list events for %s: %w", id, err)
	}
	view.EventsCount = len(events)

	// Interfaces have no typed store accessor; the introspection layer's
	// validated WHERE filter serves them like any table grid would.
	ifaceRows, ifaceTotal, err := st.ListRows(ctx, store.RowsFilter{
		Table:       "network_interfaces",
		WhereColumn: "machine_id",
		WhereValue:  id.String(),
		Limit:       store.IntrospectionDefaultPageSize,
	})
	if err != nil {
		// A schema without the table (or column) must not take the page
		// down — interfaces simply don't render.
		if !errors.Is(err, store.ErrUnknownTable) && !errors.Is(err, store.ErrUnknownColumn) {
			return fmt.Errorf("list interfaces for %s: %w", id, err)
		}
		ifaceRows, ifaceTotal = nil, 0
	}
	view.InterfacesCount = ifaceTotal

	switch tab {
	case "software":
		view.Software = software
	case "findings":
		view.Findings = findings
	case "events":
		view.Events = events
	case "interfaces":
		view.Interfaces = ifaceRows
		if schema, describeErr := st.DescribeTable(ctx, "network_interfaces"); describeErr == nil {
			view.IfaceCols = schema.Columns
		}
	default: // overview
		if len(findings) > machinePagePreviewLimit {
			findings = findings[:machinePagePreviewLimit]
		}
		view.FindingsPreview = findings
		if len(software) > machinePagePreviewLimit {
			software = software[:machinePagePreviewLimit]
		}
		view.SoftwarePreview = software
	}

	loadMachineMemory(ctx, st, id, machine, &view)

	if err := machinePageTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render machine page template: %w", err)
	}
	return nil
}

// loadMachineMemory fills the view's memory summary: total RAM (human-readable)
// and, when the durable time series has points, the current usage plus a
// used-percent sparkline over the last day. Best-effort — a store without the
// memory table, or a machine with no samples yet, simply shows less.
func loadMachineMemory(ctx context.Context, st store.Store, id uuid.UUID, machine *model.Machine, view *machinePageView) {
	// Total RAM from the osquery inventory tag is known before the first
	// sample, so seed it first.
	if total, ok := physicalMemoryBytesFromTags(machine.Tags); ok && total > 0 {
		view.HasMemory = true
		view.MemoryTotalHuman = humanizeBytes(total)
	}

	ms, ok := st.(store.MemorySampleStore)
	if !ok {
		return
	}
	samples, err := ms.ListMemorySamples(ctx, id, time.Now().Add(-machineMemoryWindow), machineMemorySampleCap)
	if err != nil || len(samples) == 0 {
		return
	}

	latest := samples[len(samples)-1]
	view.HasMemory = true
	view.MemoryTotalHuman = humanizeBytes(int64(latest.TotalBytes)) // #nosec G115 -- RAM sizes fit int64
	view.MemoryUsedHuman = humanizeBytes(int64(latest.UsedBytes))   // #nosec G115
	view.MemoryUsedPercent = latest.UsedPercent

	pcts := make([]float64, len(samples))
	for i, s := range samples {
		pcts[i] = s.UsedPercent
	}
	view.MemorySpark = metricSparkSVG(pcts, "memory %", 200, 40)
}

// physicalMemoryBytesFromTags reads the osquery-collected total RAM out of a
// machine's tags JSON. The value may be a JSON number or a stringified integer
// depending on how the tag was written.
func physicalMemoryBytesFromTags(tagsJSON string) (int64, bool) {
	if strings.TrimSpace(tagsJSON) == "" {
		return 0, false
	}
	var tags map[string]any
	if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
		return 0, false
	}
	switch v := tags["physical_memory_bytes"].(type) {
	case float64:
		return int64(v), true
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

const machinePageTemplate = `<div class="machine-breadcrumb">
  <a href="/machines" hx-get="/machines" hx-target="#content" hx-push-url="true">Machines</a>
  <span class="machine-breadcrumb-sep">/</span>
  <span>{{.Machine.Hostname}}</span>
</div>

<div class="machine-head">
  <div>
    <div class="machine-head-title">
      <h2>{{.Machine.Hostname}}</h2>
      <span class="badge badge-gray">{{.Machine.MachineType}}</span>
      <span class="badge {{authClass .Machine.IsAuthorized}}">{{.Machine.IsAuthorized}}</span>
      <span class="badge badge-gray">{{.Machine.IsManaged}}</span>
    </div>
    <p class="muted machine-head-meta">{{.Machine.OSFamily}}{{if .Machine.OSVersion}} {{.Machine.OSVersion}}{{end}}{{if .Machine.KernelVersion}} &middot; kernel {{.Machine.KernelVersion}}{{end}}{{if .Machine.Architecture}} &middot; {{.Machine.Architecture}}{{end}} &middot; discovered by {{.Machine.DiscoverySource}} &middot; first seen {{formatTime .Machine.FirstSeenAt}} &middot; last seen {{formatTime .Machine.LastSeenAt}}</p>
  </div>
</div>

{{$id := .Machine.ID}}
<div class="machine-tabs">
  <a class="machine-tab {{if eq .Tab "overview"}}machine-tab-active{{end}}" href="/machines/{{$id}}" hx-get="/machines/{{$id}}" hx-target="#content" hx-push-url="true">Overview</a>
  <a class="machine-tab {{if eq .Tab "software"}}machine-tab-active{{end}}" href="/machines/{{$id}}?tab=software" hx-get="/machines/{{$id}}?tab=software" hx-target="#content" hx-push-url="true">Software <span class="machine-tab-count">{{.SoftwareCount}}</span></a>
  <a class="machine-tab {{if eq .Tab "findings"}}machine-tab-active{{end}}" href="/machines/{{$id}}?tab=findings" hx-get="/machines/{{$id}}?tab=findings" hx-target="#content" hx-push-url="true">Findings <span class="machine-tab-count{{if .FindingsCount}} machine-tab-count-warn{{end}}">{{.FindingsCount}}</span></a>
  <a class="machine-tab {{if eq .Tab "interfaces"}}machine-tab-active{{end}}" href="/machines/{{$id}}?tab=interfaces" hx-get="/machines/{{$id}}?tab=interfaces" hx-target="#content" hx-push-url="true">Interfaces <span class="machine-tab-count">{{.InterfacesCount}}</span></a>
  <a class="machine-tab {{if eq .Tab "events"}}machine-tab-active{{end}}" href="/machines/{{$id}}?tab=events" hx-get="/machines/{{$id}}?tab=events" hx-target="#content" hx-push-url="true">Events <span class="machine-tab-count">{{.EventsCount}}</span></a>
</div>

{{if eq .Tab "overview"}}
<div class="machine-overview-grid">
  <section class="card machine-card">
    <h3>Identity</h3>
    <table class="kv">
      <tbody>
        <tr><th>id</th><td><code>{{.Machine.ID}}</code></td></tr>
        <tr><th>natural key</th><td><code>{{.Machine.NaturalKey}}</code></td></tr>
        <tr><th>discovery source</th><td>{{.Machine.DiscoverySource}}</td></tr>
        <tr><th>environment</th><td>{{if .Machine.Environment}}{{.Machine.Environment}}{{else}}&mdash;{{end}}</td></tr>
        <tr><th>owner</th><td>{{if .Machine.Owner}}{{.Machine.Owner}}{{else}}&mdash;{{end}}</td></tr>
        <tr><th>criticality</th><td>{{if .Machine.Criticality}}{{.Machine.Criticality}}{{else}}&mdash;{{end}}</td></tr>
        <tr><th>tags</th><td>{{if .Machine.Tags}}<code>{{.Machine.Tags}}</code>{{else}}&mdash;{{end}}</td></tr>
      </tbody>
    </table>
  </section>

  {{if .HasMemory}}
  <section class="card machine-card">
    <h3>Memory</h3>
    <div class="machine-mem">
      <div class="machine-mem-figures">
        {{if .MemoryUsedHuman}}<div class="machine-mem-primary">{{.MemoryUsedHuman}} <span class="muted">/ {{.MemoryTotalHuman}}</span></div>
        <div class="muted small">{{printf "%.0f%%" .MemoryUsedPercent}} used &middot; last 24h</div>
        {{else}}<div class="machine-mem-primary">{{.MemoryTotalHuman}}</div>
        <div class="muted small">total RAM &middot; collecting usage&hellip;</div>{{end}}
      </div>
      {{if .MemorySpark}}<div class="machine-mem-spark" title="memory usage, last 24h">{{.MemorySpark}}</div>{{end}}
    </div>
  </section>
  {{end}}

  <section class="card machine-card">
    <div class="machine-card-head">
      <h3>Open findings</h3>
      <a href="/machines/{{$id}}?tab=findings" hx-get="/machines/{{$id}}?tab=findings" hx-target="#content" hx-push-url="true">View all {{.FindingsCount}} &rarr;</a>
    </div>
    {{if .FindingsPreview}}
    <ul class="machine-finding-list">
      {{range .FindingsPreview}}
      <li>
        <span class="badge {{severityClass .Severity}}">{{.Severity}}</span>
        <div>
          <div class="machine-finding-title">{{.Title}}</div>
          <div class="muted small"><code>{{.CheckID}}</code>{{if .CWEID}} &middot; {{.CWEID}}{{end}}</div>
        </div>
      </li>
      {{end}}
    </ul>
    {{else}}
    <p class="muted">No findings for this machine.</p>
    {{end}}
  </section>
</div>

<section class="card machine-card">
  <div class="machine-card-head">
    <h3>Software</h3>
    <a href="/machines/{{$id}}?tab=software" hx-get="/machines/{{$id}}?tab=software" hx-target="#content" hx-push-url="true">View all {{.SoftwareCount}} &rarr;</a>
  </div>
  {{if .SoftwarePreview}}
  <table>
    <thead><tr><th>Name</th><th>Vendor</th><th>Version</th><th>License</th><th>CPE 2.3</th><th>Manager</th></tr></thead>
    <tbody>
    {{range .SoftwarePreview}}
      <tr><td>{{.SoftwareName}}</td><td>{{.Vendor}}</td><td><code>{{.Version}}</code></td><td>{{if .License}}{{.License}}{{else}}unknown{{end}}</td><td><code>{{.CPE23}}</code></td><td>{{.PackageManager}}</td></tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <p class="muted">No software inventory for this machine.</p>
  {{end}}
</section>
{{end}}

{{if eq .Tab "software"}}
<div class="data-grid">
<table>
  <thead><tr><th>Name</th><th>Vendor</th><th>Version</th><th>License</th><th>CPE 2.3</th><th>Manager</th><th>Architecture</th></tr></thead>
  <tbody>
  {{range .Software}}
    <tr><td>{{.SoftwareName}}</td><td>{{.Vendor}}</td><td><code>{{.Version}}</code></td><td>{{if .License}}{{.License}}{{else}}unknown{{end}}</td><td><code>{{.CPE23}}</code></td><td>{{.PackageManager}}</td><td>{{.Architecture}}</td></tr>
  {{end}}
  </tbody>
</table>
</div>
{{end}}

{{if eq .Tab "findings"}}
<div class="data-grid">
<table>
  <thead><tr><th>Severity</th><th>Title</th><th>Check</th><th>CWE</th><th>Auditor</th><th>Remediation</th></tr></thead>
  <tbody>
  {{range .Findings}}
    <tr>
      <td><span class="badge {{severityClass .Severity}}">{{.Severity}}</span></td>
      <td>{{.Title}}</td>
      <td><code>{{.CheckID}}</code></td>
      <td>{{.CWEID}}</td>
      <td>{{.Auditor}}</td>
      <td>{{.Remediation}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>
{{end}}

{{if eq .Tab "interfaces"}}
{{if .Interfaces}}
<div class="data-grid">
<table>
  <thead><tr>{{range .IfaceCols}}<th>{{.Name}}</th>{{end}}</tr></thead>
  <tbody>
  {{range .Interfaces}}
    <tr>{{range .Columns}}<td>{{renderCell .Value}}</td>{{end}}</tr>
  {{end}}
  </tbody>
</table>
</div>
{{else}}
<p class="muted">No network interfaces recorded for this machine.</p>
{{end}}
{{end}}

{{if eq .Tab "events"}}
{{if .Events}}
<div class="data-grid">
<table>
  <thead><tr><th>Time</th><th>Event</th><th>Severity</th><th>Details</th></tr></thead>
  <tbody>
  {{range .Events}}
    <tr>
      <td>{{formatTime .Timestamp}}</td>
      <td><code>{{.EventType}}</code></td>
      <td><span class="badge {{severityClass .Severity}}">{{.Severity}}</span></td>
      <td>{{.Details}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>
{{else}}
<p class="muted">No lifecycle events recorded for this machine.</p>
{{end}}
{{end}}`
