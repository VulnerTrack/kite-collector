package dashboard

import "html/template"

// containersTmpl renders the Containers tab fragment: summary chips, the
// add-metric form, one table per compose project with icon status + metric
// sparkline columns, and the image inventory. Auto-refreshes like the
// observability page, with the same pause/resume chip.
var containersTmpl = template.Must(template.New("containers").Parse(`
<div id="containers-root"
     class="containers-page"
     hx-get="{{.Freshness.WrapperGetURL}}"
     {{if not .Freshness.Paused}}hx-trigger="every {{.Freshness.AutoRefreshSecs}}s"{{end}}
     hx-swap="outerHTML">
<header class="onboarding-header">
  <div class="onboarding-header-row">
    <div class="onboarding-title">
      <h2>Containers</h2>
      <p class="muted small">
        Live view of the local Docker / Podman / docker-compose environment:
        state and health at a glance, metric graphs per container, and image
        ancestor layers. Add a column for any numeric field of the Engine
        stats document by dotted stat path — the customised view lives in the
        URL, so bookmark it to keep it.
      </p>
      <div class="observability-actions" aria-label="Containers exports">
        <a href="{{.SnapshotURL}}" download>JSON snapshot</a>
      </div>
    </div>
    <div class="onboarding-mode containers-summary" aria-label="Container environment summary">
      <span class="badge badge-gray">{{.Total}} total</span>
      <span class="badge badge-green">{{.RunningCount}} running</span>
      {{if .UnhealthyN}}<span class="badge badge-red">{{.UnhealthyN}} unhealthy</span>{{end}}
      {{if .ExitedCount}}<span class="badge badge-gray">{{.ExitedCount}} exited</span>{{end}}
      {{if .ProjectCount}}<span class="badge badge-blue">{{.ProjectCount}} compose {{if eq .ProjectCount 1}}project{{else}}projects{{end}}</span>{{end}}
    </div>
  </div>
  <div class="freshness-chip {{if .Freshness.Paused}}freshness-chip--paused{{else}}freshness-chip--live{{end}}"
       aria-live="polite" role="status">
    <span class="freshness-chip-dot {{if .Freshness.Paused}}freshness-chip-dot--paused{{else}}freshness-chip-dot--live{{end}}" aria-hidden="true"></span>
    {{if .Freshness.Paused}}
      <span>Paused &middot; last update <code>{{.Freshness.UpdatedAtUTC}}</code></span>
    {{else}}
      <span>Live &middot; refreshes every {{.Freshness.AutoRefreshSecs}}s &middot; last update <code>{{.Freshness.UpdatedAtUTC}}</code></span>
    {{end}}
    <a class="freshness-chip-toggle"
       href="{{.Freshness.ToggleURL}}"
       hx-get="{{.Freshness.ToggleURL}}"
       hx-target="#containers-root"
       hx-swap="outerHTML"
       aria-label="{{.Freshness.ToggleAriaLabel}}">{{.Freshness.ToggleLabel}}</a>
  </div>
</header>

{{if not .Available}}
<section class="card containers-card">
  <h3>Docker unavailable</h3>
  <p class="muted">{{.Error}}</p>
  <p class="muted small">The dashboard looks for an engine at the configured
  discovery host, then <code>KITE_DOCKER_HOST</code>, then the standard
  Docker/Podman sockets. Start the engine or point the agent at one, then
  reload this page.</p>
</section>
{{else}}

{{if .MonitorNote}}<p class="muted small containers-monitor-note">Stats monitor: {{.MonitorNote}}</p>{{end}}
{{if .InvalidGraphs}}
<p class="containers-invalid-graphs">Ignored invalid stat {{if eq (len .InvalidGraphs) 1}}path{{else}}paths{{end}}:
  {{range .InvalidGraphs}}<code>{{.}}</code> {{end}}
  &mdash; use dotted lowercase segments, e.g. <code>memory_stats.stats.pgmajfault</code>.</p>
{{end}}

<form class="containers-graph-form"
      hx-get="/containers" hx-target="#content" hx-push-url="true"
      aria-label="Add a custom metric column">
  {{range .Columns}}{{if .Custom}}<input type="hidden" name="graph" value="{{.StatPath}}">{{end}}{{end}}
  {{if .Freshness.Paused}}<input type="hidden" name="paused" value="1">{{end}}
  <input type="text" name="graph" class="containers-graph-input"
         placeholder="Graph any stat path, e.g. pids_stats.current or memory_stats.stats.pgmajfault"
         title="Dotted path into the Engine stats document, or derived.cpu_percent / derived.memory_percent / derived.memory_bytes / derived.net_rx_bytes / derived.net_tx_bytes / derived.pids">
  <button class="btn btn-ghost" type="submit">Add metric column</button>
  <span class="muted small">Open a container&rsquo;s <em>Graphs</em> drawer to browse every available path.</span>
</form>

{{range .Groups}}
<section class="card containers-card">
  <h3 class="containers-group-title">{{.Project}}</h3>
  <div class="observability-table-wrap">
  <table class="observability-table containers-table">
    <thead>
      <tr>
        <th aria-label="State"></th>
        <th>Name</th>
        <th>Status</th>
        <th>Image</th>
        <th>Ports</th>
        <th>Created</th>
        {{range $.Columns}}
          <th class="metric-col"><code>{{.Caption}}</code>{{if .Custom}} <a class="metric-col-remove" href="{{.RemoveURL}}" hx-get="{{.RemoveURL}}" hx-target="#content" hx-push-url="true" title="Remove this metric column" aria-label="Remove {{.Caption}} column">&times;</a>{{end}}</th>
        {{end}}
        <th aria-label="Details"></th>
      </tr>
    </thead>
    <tbody>
    {{range .Rows}}
      <tr>
        <td><span class="badge {{.BadgeClass}} state-icon" title="{{.StateLabel}}" aria-label="{{.StateLabel}}">{{.Icon}}</span></td>
        <td><strong>{{.Name}}</strong>{{if .ComposeService}}<br><span class="muted small">{{.ComposeService}}</span>{{end}}</td>
        <td class="muted small">{{.StatusText}}</td>
        <td><a class="fk-link" href="#" hx-get="/fragments/images/{{.LayersImageID}}/layers" hx-target="#row-drawer" hx-swap="innerHTML" onclick="openRowDrawer()" title="View ancestor layers of {{.Image}}">{{.Image}}</a></td>
        <td class="muted small">{{.Ports}}</td>
        <td class="muted small">{{.CreatedAgo}}</td>
        {{range .Metrics}}
          <td class="metric-cell">{{if .Has}}<span class="metric-value">{{.Display}}</span> {{.Spark}}{{else}}<span class="muted small" title="collecting samples">&hellip;</span>{{end}}</td>
        {{end}}
        <td><button class="btn btn-ghost btn-graphs" type="button" hx-get="/fragments/containers/{{.ID}}{{$.DetailQuery}}" hx-target="#row-drawer" hx-swap="innerHTML" onclick="openRowDrawer()">Graphs</button></td>
      </tr>
    {{end}}
    </tbody>
  </table>
  </div>
</section>
{{end}}

<section class="card containers-card" id="section-images">
  <h3>Images</h3>
  {{if .ImagesError}}
    <p class="muted">Could not list images: {{.ImagesError}}</p>
  {{else}}
    <p class="muted">Local image inventory, largest first. Open <em>Layers</em> to walk an image&rsquo;s ancestor layers &mdash; every instruction that built it, with per-layer sizes.</p>
    <div class="observability-table-wrap">
    <table class="observability-table containers-table">
      <thead><tr><th>Tags</th><th>ID</th><th>Size</th><th>Created</th><th aria-label="Layers"></th></tr></thead>
      <tbody>
      {{range .Images}}
        <tr>
          <td>{{if .Untagged}}<span class="muted">&lt;untagged&gt;</span>{{else}}{{.Tags}}{{end}}</td>
          <td><code>{{.ShortID}}</code></td>
          <td>{{.Size}}</td>
          <td class="muted small">{{.Created}}</td>
          <td><button class="btn btn-ghost" type="button" hx-get="/fragments/images/{{.HexID}}/layers" hx-target="#row-drawer" hx-swap="innerHTML" onclick="openRowDrawer()">Layers</button></td>
        </tr>
      {{end}}
      </tbody>
    </table>
    </div>
  {{end}}
</section>

{{end}}
</div>`))

// containerDetailTmpl renders the row-drawer for one container: full-size
// graphs for every active metric plus the browsable list of every numeric
// stat path in the latest sample (click one to graph it).
var containerDetailTmpl = template.Must(template.New("containerDetail").Parse(`
<div class="row-drawer-head">
  <h3>{{.Row.Name}}</h3>
  <button class="btn btn-outline" onclick="closeRowDrawer()">Close</button>
</div>
<p class="container-detail-meta">
  <span class="badge {{.Row.BadgeClass}}">{{.Row.Icon}} {{.Row.StateLabel}}</span>
  <code>{{.Row.ShortID}}</code>
  &middot; {{.Row.Image}}
  {{if .Row.Ports}}&middot; <span class="muted small">{{.Row.Ports}}</span>{{end}}
</p>
<p class="muted small">{{.Row.StatusText}} &middot; created {{.Row.CreatedAgo}}</p>

<h4>Metric graphs</h4>
<div class="container-graphs">
{{range .Graphs}}
  <div class="container-graph">
    <div class="container-graph-head">
      <strong>{{.Caption}}</strong>
      {{if .Custom}}<code class="muted small">{{.StatPath}}</code>{{end}}
      <span class="container-graph-current">{{.Current}}</span>
    </div>
    {{.Spark}}
  </div>
{{end}}
</div>

<h4>All stat paths{{if .HasSample}} <span class="muted small">&middot; sampled {{.SampledAgo}}</span>{{end}}</h4>
{{if .HasSample}}
  <p class="muted small">Every numeric field the engine reports for this container. <em>Graph</em> adds it as a column for all containers.</p>
  <details class="container-paths">
    <summary>Browse {{len .Paths}} metrics</summary>
    <table class="kv">
      <tbody>
      {{range .Paths}}
        <tr>
          <th><code>{{.Path}}</code></th>
          <td>{{.Display}}</td>
          <td><a class="fk-link" href="{{.AddURL}}" hx-get="{{.AddURL}}" hx-target="#content" hx-push-url="true">Graph</a></td>
        </tr>
      {{end}}
      </tbody>
    </table>
  </details>
{{else}}
  <p class="muted">Collecting the first stats sample&hellip; reopen this drawer in a few seconds.</p>
{{end}}`))

// imageLayersTmpl renders the row-drawer with an image's ancestor layers —
// newest instruction first, as the Engine API returns them.
var imageLayersTmpl = template.Must(template.New("imageLayers").Parse(`
<div class="row-drawer-head">
  <h3>Image layers</h3>
  <button class="btn btn-outline" onclick="closeRowDrawer()">Close</button>
</div>
{{if .Error}}
  <p class="muted">Could not load layer history for <code>{{.ShortID}}</code>: {{.Error}}</p>
{{else}}
  <p class="muted small"><code>{{.ShortID}}</code> &middot; {{.LayerCount}} ancestor layers &middot; {{.TotalSize}} total &middot; newest first</p>
  <div class="observability-table-wrap">
  <table class="observability-table layers-table">
    <thead><tr><th>Layer</th><th>Created</th><th>Size</th><th>Instruction</th></tr></thead>
    <tbody>
    {{range .Layers}}
      <tr{{if .Missing}} class="layer-missing"{{end}}>
        <td><code>{{.ShortID}}</code>{{if .Tags}}<br><span class="muted small">{{.Tags}}</span>{{end}}</td>
        <td class="muted small">{{.CreatedAgo}}</td>
        <td>{{.Size}}</td>
        <td><code class="layer-cmd" title="{{.FullCmd}}">{{.CreatedBy}}</code></td>
      </tr>
    {{end}}
    </tbody>
  </table>
  </div>
{{end}}`))

// containerDrawerErrTmpl renders a drawer-shaped error (container gone,
// engine down) so the drawer still gets a Close button.
var containerDrawerErrTmpl = template.Must(template.New("containerDrawerErr").Parse(`
<div class="row-drawer-head">
  <h3>Container</h3>
  <button class="btn btn-outline" onclick="closeRowDrawer()">Close</button>
</div>
<p class="muted">{{.}}</p>`))
