package dashboard

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"runtime"
	"sort"
	"strings"

	osquerydisc "github.com/vulnertrack/kite-collector/internal/discovery/osquery"
	"github.com/vulnertrack/kite-collector/internal/discovery/osquery/schema"
)

// The osquery explorer makes kite understand and interpret ALL osquery data:
// the full published table catalog (descriptions, platforms, evented flags,
// per-column docs) fused with the live daemon's registry, and a bounded
// SELECT * against any served table. Tables whose virtual implementation
// requires a WHERE constraint (curl, file, hash…) are explained instead of
// silently returning nothing — osquery's error contract makes bare queries
// against them useless, and pretending otherwise would misinform.

// osqueryExplorer is the slice of the osquery Explorer the dashboard needs;
// a package-level constructor var keeps it fake-able in tests.
type osqueryExplorer interface {
	Ping(ctx context.Context) error
	LiveTables(ctx context.Context) ([]string, error)
	TableRows(ctx context.Context, table string, limit int) ([]map[string]string, error)
}

// newOsqueryExplorer returns the explorer and the socket it targets, or
// (nil, "") when no osqueryd socket is resolvable on this host.
var newOsqueryExplorer = func() (osqueryExplorer, string) {
	socket := osquerydisc.ResolveSocketPath()
	if socket == "" {
		return nil, ""
	}
	return osquerydisc.NewExplorer(socket), socket
}

// --- Catalog page ------------------------------------------------------------

type osqueryCatalogRow struct {
	Name        string
	Description string
	Platforms   string
	Evented     bool
	ThisOS      bool
	Live        bool
	Columns     int
}

type osqueryCatalogView struct {
	CatalogVersion string
	Socket         string
	DaemonUp       bool
	LiveCount      int
	Rows           []osqueryCatalogRow
}

var osqueryCatalogTmpl = template.Must(
	template.New("osqueryCatalog").Funcs(templateFuncs).Parse(osqueryCatalogTemplate))

// renderOsqueryCatalogFragment renders /osquery: every cataloged table plus
// any live-only tables the daemon serves (extensions, newer builds), each
// marked live / not loaded / other-platform.
func renderOsqueryCatalogFragment(w io.Writer, ctx context.Context) error {
	view := osqueryCatalogView{CatalogVersion: schema.CatalogVersion}

	live := map[string]bool{}
	explorer, socket := newOsqueryExplorer()
	view.Socket = socket
	if explorer != nil {
		if names, err := explorer.LiveTables(ctx); err == nil {
			view.DaemonUp = true
			view.LiveCount = len(names)
			for _, name := range names {
				live[name] = true
			}
		}
	}

	seen := map[string]bool{}
	for _, t := range schema.Tables() {
		seen[t.Name] = true
		view.Rows = append(view.Rows, osqueryCatalogRow{
			Name:        t.Name,
			Description: t.Description,
			Platforms:   strings.Join(t.Platforms, ", "),
			Evented:     t.Evented,
			ThisOS:      t.SupportsOS(runtime.GOOS),
			Live:        live[t.Name],
			Columns:     len(t.Columns),
		})
	}
	// Live tables the catalog does not know (extensions, version drift).
	var extras []osqueryCatalogRow
	for name := range live {
		if !seen[name] {
			extras = append(extras, osqueryCatalogRow{
				Name: name, Description: "Served by this daemon; not in the embedded catalog.",
				ThisOS: true, Live: true,
			})
		}
	}
	sort.Slice(extras, func(i, j int) bool { return extras[i].Name < extras[j].Name })
	view.Rows = append(view.Rows, extras...)

	if err := osqueryCatalogTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render osquery catalog template: %w", err)
	}
	return nil
}

const osqueryCatalogTemplate = `<h2>Osquery <span class="muted">({{len .Rows}} tables)</span></h2>
<p class="muted osq-intro">Every table osquery can answer, annotated from the published schema (catalog v{{.CatalogVersion}}).
{{if .DaemonUp}}Connected to osqueryd at <code>{{.Socket}}</code> &mdash; {{.LiveCount}} tables served live; click one to see its schema and rows.{{else}}{{if .Socket}}No osqueryd answered at <code>{{.Socket}}</code>{{else}}No osqueryd socket found on this host{{end}} &mdash; the catalog below still documents every table; live queries need a running daemon.{{end}}</p>
<div class="data-grid">
<table>
  <thead>
    <tr><th>Table</th><th>Availability</th><th>Platforms</th><th>Evented</th><th>Columns</th><th>Description</th></tr>
  </thead>
  <tbody>
  {{range .Rows}}
    <tr>
      <td><a class="fk-link" href="/osquery/{{.Name}}" hx-get="/osquery/{{.Name}}" hx-target="#content" hx-push-url="true">{{.Name}}</a></td>
      <td>{{if .Live}}<span class="badge badge-green">live</span>{{else if .ThisOS}}<span class="badge badge-yellow">not loaded</span>{{else}}<span class="badge badge-gray">other platform</span>{{end}}</td>
      <td>{{.Platforms}}</td>
      <td>{{if .Evented}}<span class="badge badge-blue">evented</span>{{end}}</td>
      <td>{{.Columns}}</td>
      <td class="osq-desc">{{.Description}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>`

// --- Table page --------------------------------------------------------------

type osqueryTableView struct {
	Name     string
	Catalog  *schema.Table
	Required []string

	Socket   string
	DaemonUp bool
	Live     bool

	Queried   bool
	QueryErr  string
	SQLText   string
	Columns   []string
	Rows      []map[string]string
	RowsLimit int
}

var osqueryTableTmpl = template.Must(
	template.New("osqueryTable").
		Funcs(templateFuncs).
		Funcs(template.FuncMap{
			"osqThisOS": func(t *schema.Table) bool { return t != nil && t.SupportsOS(runtime.GOOS) },
		}).
		Parse(osqueryTableTemplate))

// renderOsqueryTableFragment renders /osquery/{table}: the catalog schema
// (columns, types, descriptions) plus live rows when the daemon serves the
// table and it needs no WHERE constraint. Unknown table names are only an
// error when neither the catalog nor the live daemon knows them.
func renderOsqueryTableFragment(w io.Writer, ctx context.Context, name string, limit int) error {
	if limit <= 0 {
		limit = 100
	}
	view := osqueryTableView{Name: name, RowsLimit: limit}
	if cat, ok := schema.Lookup(name); ok {
		view.Catalog = cat
		view.Required = cat.RequiredColumns()
	}

	explorer, socket := newOsqueryExplorer()
	view.Socket = socket
	if explorer != nil {
		if names, err := explorer.LiveTables(ctx); err == nil {
			view.DaemonUp = true
			for _, n := range names {
				if n == name {
					view.Live = true
					break
				}
			}
		}
	}

	if view.Catalog == nil && !view.Live {
		return fmt.Errorf("osquery table %q: %w", name, errOsqueryTableUnknown)
	}

	// Query only when it can mean something: daemon serves the table and the
	// virtual table does not demand a WHERE constraint we cannot supply.
	if view.Live && len(view.Required) == 0 {
		view.Queried = true
		view.SQLText = fmt.Sprintf("SELECT * FROM %s LIMIT %d;", name, limit)
		rows, err := explorer.TableRows(ctx, name, limit)
		if err != nil {
			view.QueryErr = err.Error()
		} else {
			view.Rows = rows
			view.Columns = osquerydisc.ColumnOrder(name, rows)
		}
	} else if len(view.Required) > 0 {
		view.SQLText = fmt.Sprintf("SELECT * FROM %s WHERE %s = '…';", name, view.Required[0])
	}

	if err := osqueryTableTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render osquery table template: %w", err)
	}
	return nil
}

// errOsqueryTableUnknown marks a table name neither the catalog nor the live
// daemon recognizes, so the route can 404 instead of 500.
var errOsqueryTableUnknown = fmt.Errorf("unknown osquery table")

const osqueryTableTemplate = `<div class="machine-breadcrumb">
  <a href="/osquery" hx-get="/osquery" hx-target="#content" hx-push-url="true">Osquery</a>
  <span class="machine-breadcrumb-sep">/</span>
  <span>{{.Name}}</span>
</div>
<div class="machine-head-title">
  <h2>{{.Name}}</h2>
  {{if .Live}}<span class="badge badge-green">live</span>{{else if .DaemonUp}}<span class="badge badge-yellow">not loaded</span>{{else}}<span class="badge badge-gray">no daemon</span>{{end}}
  {{if .Catalog}}{{if .Catalog.Evented}}<span class="badge badge-blue">evented</span>{{end}}{{end}}
</div>
{{if .Catalog}}
<p class="muted osq-intro">{{.Catalog.Description}} <span class="osq-platforms">Platforms: {{range $i, $p := .Catalog.Platforms}}{{if $i}}, {{end}}{{$p}}{{end}}.</span></p>
{{else}}
<p class="muted osq-intro">Served by this daemon but not in the embedded catalog (an extension table, or from a different osquery version).</p>
{{end}}

{{if .Required}}
<div class="osq-notice">
  <strong>This table requires a WHERE constraint.</strong>
  A bare <code>SELECT *</code> cannot produce rows: osquery's <code>{{.Name}}</code> virtual table only materializes when you constrain
  {{range $i, $c := .Required}}{{if $i}}, {{end}}<code>{{$c}}</code>{{end}}.
  Query it through osqueryi, e.g.:
  <span class="sql-strip osq-example"><span class="sql-strip-label">SQL</span><code class="sql-strip-text" id="osq-example-sql">{{.SQLText}}</code><button type="button" class="sql-strip-copy" data-copy-target="osq-example-sql" onclick="copyText(this)">Copy</button></span>
</div>
{{end}}

{{if .Catalog}}
<h3 class="osq-h3">Schema <span class="muted small">({{len .Catalog.Columns}} columns)</span></h3>
<table class="osq-schema">
  <thead><tr><th>Column</th><th>Type</th><th>Description</th></tr></thead>
  <tbody>
  {{range .Catalog.Columns}}
    <tr{{if .Hidden}} class="osq-hidden-col"{{end}}>
      <td><code>{{.Name}}</code>{{if .Required}} <span class="badge badge-orange">required</span>{{end}}{{if .Hidden}} <span class="badge badge-gray">hidden</span>{{end}}</td>
      <td class="muted">{{.Type}}</td>
      <td>{{.Description}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
{{end}}

{{if .Queried}}
<h3 class="osq-h3">Live rows <span class="muted small">({{len .Rows}}{{if eq (len .Rows) .RowsLimit}} &mdash; limited{{end}})</span></h3>
<div class="sql-strip">
  <span class="sql-strip-label">SQL</span>
  <code class="sql-strip-text" id="osq-live-sql">{{.SQLText}}</code>
  <button type="button" class="sql-strip-copy" data-copy-target="osq-live-sql" onclick="copyText(this)">Copy</button>
</div>
{{if .QueryErr}}
<div class="osq-error"><strong>The daemon rejected the query:</strong> {{.QueryErr}}</div>
{{else if .Rows}}
<div class="osq-scroll">
<table>
  <thead><tr>{{range .Columns}}<th>{{.}}</th>{{end}}</tr></thead>
  <tbody>
  {{$cols := .Columns}}
  {{range .Rows}}
    {{$row := .}}
    <tr>{{range $cols}}<td>{{index $row .}}</td>{{end}}</tr>
  {{end}}
  </tbody>
</table>
</div>
{{else}}
<p class="muted">The daemon returned zero rows.{{if .Catalog}}{{if .Catalog.Evented}} This is an evented table: rows appear only while its event publisher (audit, EndpointSecurity, ETW…) is active and events have fired.{{end}}{{end}}</p>
{{end}}
{{else if and .DaemonUp (not .Live)}}
<p class="muted">This osqueryd does not serve <code>{{.Name}}</code>{{if .Catalog}}{{if not (osqThisOS .Catalog)}} &mdash; it is a {{range $i, $p := .Catalog.Platforms}}{{if $i}}/{{end}}{{$p}}{{end}} table{{end}}{{end}}.</p>
{{else if not .DaemonUp}}
<p class="muted">No running osqueryd to query{{if .Socket}} (socket <code>{{.Socket}}</code> did not answer){{end}}. The schema above still documents the table.</p>
{{end}}`
