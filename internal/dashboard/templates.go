package dashboard

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// templateFuncs provides helper functions for HTML templates.
var templateFuncs = template.FuncMap{
	"upper": strings.ToUpper,
	"formatTime": func(t time.Time) string {
		return t.Format("2006-01-02 15:04:05")
	},
	"severityClass": func(s model.Severity) string {
		switch s {
		case model.SeverityCritical:
			return "badge-red"
		case model.SeverityHigh:
			return "badge-orange"
		case model.SeverityMedium:
			return "badge-yellow"
		case model.SeverityLow:
			return "badge-blue"
		default:
			return "badge-gray"
		}
	},
	"authClass": func(a model.AuthorizationState) string {
		switch a {
		case model.AuthorizationAuthorized:
			return "badge-green"
		case model.AuthorizationUnauthorized:
			return "badge-red"
		case model.AuthorizationUnknown:
			return "badge-yellow"
		}
		return "badge-yellow"
	},
	"renderCell":  renderCell,
	"rowKeyQuery": rowKeyQuery,
	"cellFK":      findFK,
	"add":         func(a, b int) int { return a + b },
}

// renderCell stringifies a column value for display. Byte slices are rendered
// as hex-shortened placeholders so binary blobs do not bloat tables.
func renderCell(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		if len(x) == 0 {
			return ""
		}
		if len(x) > 64 {
			return fmt.Sprintf("<%d bytes>", len(x))
		}
		return fmt.Sprintf("%x", x)
	case time.Time:
		return x.Format("2006-01-02 15:04:05")
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", x)
	}
}

// rowKeyQuery encodes primary-key values as a URL query string so a row can be
// round-tripped into the row-report endpoint without extra lookups.
func rowKeyQuery(pk map[string]string) string {
	if len(pk) == 0 {
		return ""
	}
	vals := url.Values{}
	for k, v := range pk {
		vals.Set("pk."+k, v)
	}
	return vals.Encode()
}

// findFK returns the ForeignKey whose FromColumn matches col, or nil if no FK
// covers that column. Templates use this to render FK cells as clickable links.
func findFK(fks []store.ForeignKey, col string) *store.ForeignKey {
	for i := range fks {
		if fks[i].FromColumn == col {
			return &fks[i]
		}
	}
	return nil
}

// renderAssetsFragment renders the assets table as an HTML fragment.
func renderAssetsFragment(w io.Writer, ctx context.Context, st store.Store, rc ReportContext) error {
	assets, err := st.ListAssets(ctx, store.AssetFilter{Limit: 500})
	if err != nil {
		return fmt.Errorf("list assets: %w", err)
	}

	tmpl := template.Must(template.New("assets").Funcs(templateFuncs).Parse(assetsTemplate))
	if err := tmpl.Execute(w, map[string]any{
		"Assets":  assets,
		"Context": rc,
	}); err != nil {
		return fmt.Errorf("render assets template: %w", err)
	}
	return nil
}

// renderSoftwareFragment renders the software table as an HTML fragment.
func renderSoftwareFragment(w io.Writer, ctx context.Context, st store.Store, rc ReportContext) error {
	// Collect software across all assets.
	assets, err := st.ListAssets(ctx, store.AssetFilter{Limit: 100})
	if err != nil {
		return fmt.Errorf("list assets: %w", err)
	}

	type softwareRow struct {
		Hostname       string
		SoftwareName   string
		Version        string
		PackageManager string
		CPE23          string
	}

	var rows []softwareRow
	for _, a := range assets {
		sw, swErr := st.ListSoftware(ctx, a.ID)
		if swErr != nil {
			continue
		}
		for _, s := range sw {
			rows = append(rows, softwareRow{
				Hostname:       a.Hostname,
				SoftwareName:   s.SoftwareName,
				Version:        s.Version,
				PackageManager: s.PackageManager,
				CPE23:          s.CPE23,
			})
			if len(rows) >= 500 {
				break
			}
		}
		if len(rows) >= 500 {
			break
		}
	}

	tmpl := template.Must(template.New("software").Funcs(templateFuncs).Parse(softwareTemplate))
	if err := tmpl.Execute(w, map[string]any{
		"Software": rows,
		"Context":  rc,
	}); err != nil {
		return fmt.Errorf("render software template: %w", err)
	}
	return nil
}

// renderFindingsFragment renders the findings table as an HTML fragment.
func renderFindingsFragment(w io.Writer, ctx context.Context, st store.Store, rc ReportContext) error {
	findings, err := st.ListFindings(ctx, store.FindingFilter{Limit: 500})
	if err != nil {
		return fmt.Errorf("list findings: %w", err)
	}

	tmpl := template.Must(template.New("findings").Funcs(templateFuncs).Parse(findingsTemplate))
	if err := tmpl.Execute(w, map[string]any{
		"Findings": findings,
		"Context":  rc,
	}); err != nil {
		return fmt.Errorf("render findings template: %w", err)
	}
	return nil
}

// renderScansFragment renders the scan history table as an HTML fragment.
func renderScansFragment(w io.Writer, ctx context.Context, st store.Store, rc ReportContext) error {
	// Get latest scan for now — in a full implementation this would list all.
	run, err := st.GetLatestScanRun(ctx)
	if err != nil {
		return fmt.Errorf("get latest scan: %w", err)
	}

	var runs []model.ScanRun
	if run != nil {
		runs = append(runs, *run)
	}

	tmpl := template.Must(template.New("scans").Funcs(templateFuncs).Parse(scansTemplate))
	if err := tmpl.Execute(w, map[string]any{
		"Scans":   runs,
		"Context": rc,
	}); err != nil {
		return fmt.Errorf("render scans template: %w", err)
	}
	return nil
}

// HTML fragment templates — returned by HTMX endpoints.

const assetsTemplate = `<h2>Assets ({{len .Assets}})</h2>
<div class="table-actions">
  <a href="/api/v1/assets/export.csv" class="btn">Export CSV</a>
</div>
<table>
  <thead>
    <tr>
      <th>Hostname</th>
      <th>Type</th>
      <th>OS</th>
      <th>Authorized</th>
      <th>Managed</th>
      <th>Source</th>
      <th>Last Seen</th>
    </tr>
  </thead>
  <tbody>
  {{range .Assets}}
    <tr>
      <td>{{.Hostname}}</td>
      <td>{{.AssetType}}</td>
      <td>{{.OSFamily}}{{if .OSVersion}} {{.OSVersion}}{{end}}</td>
      <td><span class="badge {{authClass .IsAuthorized}}">{{.IsAuthorized}}</span></td>
      <td>{{.IsManaged}}</td>
      <td>{{.DiscoverySource}}</td>
      <td>{{formatTime .LastSeenAt}}</td>
    </tr>
  {{end}}
  </tbody>
</table>`

const softwareTemplate = `<h2>Software ({{len .Software}})</h2>
<div class="table-actions">
  <a href="/api/v1/software/export.csv" class="btn">Export CSV</a>
</div>
<table>
  <thead>
    <tr>
      <th>Host</th>
      <th>Package</th>
      <th>Version</th>
      <th>Manager</th>
      <th>CPE 2.3</th>
    </tr>
  </thead>
  <tbody>
  {{range .Software}}
    <tr>
      <td>{{.Hostname}}</td>
      <td>{{.SoftwareName}}</td>
      <td>{{.Version}}</td>
      <td>{{.PackageManager}}</td>
      <td><code>{{.CPE23}}</code></td>
    </tr>
  {{end}}
  </tbody>
</table>`

const findingsTemplate = `<h2>Findings ({{len .Findings}})</h2>
<div class="table-actions">
  <a href="/api/v1/findings/export.csv" class="btn">Export CSV</a>
</div>
<table>
  <thead>
    <tr>
      <th>Check</th>
      <th>Severity</th>
      <th>CWE</th>
      <th>Title</th>
      <th>Auditor</th>
    </tr>
  </thead>
  <tbody>
  {{range .Findings}}
    <tr>
      <td>{{.CheckID}}</td>
      <td><span class="badge {{severityClass .Severity}}">{{.Severity}}</span></td>
      <td>{{.CWEID}}</td>
      <td>{{.Title}}</td>
      <td>{{.Auditor}}</td>
    </tr>
  {{end}}
  </tbody>
</table>`

const scansTemplate = `<h2>Scan History</h2>
<table>
  <thead>
    <tr>
      <th>Started</th>
      <th>Status</th>
      <th>Total Assets</th>
      <th>New</th>
      <th>Updated</th>
      <th>Stale</th>
      <th>Coverage</th>
    </tr>
  </thead>
  <tbody>
  {{range .Scans}}
    <tr>
      <td>{{formatTime .StartedAt}}</td>
      <td>{{.Status}}</td>
      <td>{{.TotalAssets}}</td>
      <td>{{.NewAssets}}</td>
      <td>{{.UpdatedAssets}}</td>
      <td>{{.StaleAssets}}</td>
      <td>{{printf "%.0f" .CoveragePercent}}%</td>
    </tr>
  {{end}}
  </tbody>
</table>`

// renderTablesFragment lists every content table discovered via introspection.
func renderTablesFragment(w io.Writer, ctx context.Context, st store.Store, rc ReportContext) error {
	tables, err := st.ListContentTables(ctx)
	if err != nil {
		return fmt.Errorf("list content tables: %w", err)
	}

	tmpl := template.Must(template.New("tables").Funcs(templateFuncs).Parse(tablesTemplate))
	if err := tmpl.Execute(w, map[string]any{
		"Tables":  tables,
		"Context": rc,
	}); err != nil {
		return fmt.Errorf("render tables template: %w", err)
	}
	return nil
}

// renderTableFragment renders a paginated grid of rows for a single table.
func renderTableFragment(w io.Writer, ctx context.Context, st store.Store, rc ReportContext, name string, limit, offset int) error {
	schema, err := st.DescribeTable(ctx, name)
	if err != nil {
		return fmt.Errorf("describe table %q: %w", name, err)
	}
	rows, total, err := st.ListRows(ctx, store.RowsFilter{
		Table:  name,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return fmt.Errorf("list rows %q: %w", name, err)
	}

	nextOffset := offset + limit
	if int64(nextOffset) >= total {
		nextOffset = -1
	}
	prevOffset := offset - limit
	if prevOffset < 0 {
		prevOffset = -1
	}

	tmpl := template.Must(template.New("table").Funcs(templateFuncs).Parse(tableTemplate))
	if err := tmpl.Execute(w, map[string]any{
		"Schema":     schema,
		"Rows":       rows,
		"Total":      total,
		"Limit":      limit,
		"Offset":     offset,
		"NextOffset": nextOffset,
		"PrevOffset": prevOffset,
		"Context":    rc,
	}); err != nil {
		return fmt.Errorf("render table template: %w", err)
	}
	return nil
}

// renderRowReportFragment renders the sidebar for a single primary row.
func renderRowReportFragment(w io.Writer, ctx context.Context, st store.Store, name string, pk map[string]string) error {
	report, err := st.GetRowReport(ctx, name, pk)
	if err != nil {
		return fmt.Errorf("row report %q: %w", name, err)
	}
	schema, err := st.DescribeTable(ctx, name)
	if err != nil {
		return fmt.Errorf("describe table %q: %w", name, err)
	}

	tmpl := template.Must(template.New("rowReport").Funcs(templateFuncs).Parse(rowReportTemplate))
	if err := tmpl.Execute(w, map[string]any{
		"Report": report,
		"Schema": schema,
	}); err != nil {
		return fmt.Errorf("render row report template: %w", err)
	}
	return nil
}

const tablesTemplate = `<h2>Tables ({{len .Tables}})</h2>
<p class="muted">Every non-system content table in the live database.</p>
<table>
  <thead>
    <tr>
      <th>Name</th>
      <th>Columns</th>
      <th>Rows</th>
      <th>Primary Key</th>
    </tr>
  </thead>
  <tbody>
  {{range .Tables}}
    <tr>
      <td><a hx-get="/fragments/tables/{{.Name}}" hx-target="#content" hx-push-url="false" class="fk-link">{{.Name}}</a></td>
      <td>{{len .Columns}}</td>
      <td>{{if lt .RowCount 0}}<span class="muted">unknown</span>{{else}}{{.RowCount}}{{end}}</td>
      <td>{{range $i, $c := .PrimaryKey}}{{if $i}}, {{end}}{{$c}}{{end}}</td>
    </tr>
  {{end}}
  </tbody>
</table>`

const tableTemplate = `<h2>{{.Schema.Name}} <span class="muted">({{.Total}} rows)</span></h2>
<div class="table-actions">
  <a href="/api/v1/tables/{{.Schema.Name}}/export.csv" class="btn">Export CSV</a>
  <a hx-get="/fragments/tables" hx-target="#content" hx-push-url="false" class="btn btn-outline">Back to tables</a>
</div>
<table>
  <thead>
    <tr>
    {{range .Schema.Columns}}
      <th>{{.Name}}<br><span class="muted small">{{.Type}}</span></th>
    {{end}}
    </tr>
  </thead>
  <tbody>
  {{$schema := .Schema}}
  {{range .Rows}}
    {{$pk := .PrimaryKey}}
    <tr class="row-click" hx-get="/fragments/tables/{{$schema.Name}}/row?{{rowKeyQuery $pk}}" hx-target="#sidebar" hx-swap="innerHTML" onclick="openSidebar()">
    {{range .Columns}}
      {{$fk := cellFK $schema.ForeignKeys .Name}}
      <td>{{if $fk}}<a class="fk-link" hx-get="/fragments/tables/{{$fk.ToTable}}" hx-target="#content" hx-push-url="false" onclick="event.stopPropagation();">{{renderCell .Value}}</a>{{else}}{{renderCell .Value}}{{end}}</td>
    {{end}}
    </tr>
  {{end}}
  </tbody>
</table>
<div class="pager">
  {{if ge .PrevOffset 0}}
    <a class="btn btn-outline" hx-get="/fragments/tables/{{.Schema.Name}}?limit={{.Limit}}&offset={{.PrevOffset}}" hx-target="#content" hx-push-url="false">Previous</a>
  {{end}}
  <span class="muted">rows {{.Offset}}&ndash;{{add .Offset (len .Rows)}}</span>
  {{if ge .NextOffset 0}}
    <a class="btn btn-outline" hx-get="/fragments/tables/{{.Schema.Name}}?limit={{.Limit}}&offset={{.NextOffset}}" hx-target="#content" hx-push-url="false">Next</a>
  {{end}}
</div>`

const rowReportTemplate = `<div class="sidebar-head">
  <h3>{{.Report.Table}}</h3>
  <button class="btn btn-outline" onclick="closeSidebar()">Close</button>
</div>
<h4>Row</h4>
<table class="kv">
  <tbody>
  {{$fks := .Schema.ForeignKeys}}
  {{range .Report.Row.Columns}}
    {{$fk := cellFK $fks .Name}}
    <tr>
      <th>{{.Name}}</th>
      <td>{{if $fk}}<a class="fk-link" hx-get="/fragments/tables/{{$fk.ToTable}}" hx-target="#content" hx-push-url="false" onclick="closeSidebar();">{{renderCell .Value}}</a>{{else}}{{renderCell .Value}}{{end}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
{{if .Report.Outbound}}
  <h4>Parents (outbound FK)</h4>
  {{range .Report.Outbound}}
    <div class="related">
      <div class="related-head"><strong>{{.Table}}</strong> via <code>{{.ViaColumn}}</code></div>
      <table class="kv">
        <tbody>
        {{range .Row.Columns}}
          <tr><th>{{.Name}}</th><td>{{renderCell .Value}}</td></tr>
        {{end}}
        </tbody>
      </table>
    </div>
  {{end}}
{{end}}
{{if .Report.Inbound}}
  <h4>Children (inbound FK)</h4>
  {{range .Report.Inbound}}
    <div class="related">
      <div class="related-head"><strong>{{.Table}}</strong> via <code>{{.ViaColumn}}</code>{{if .Truncated}} <span class="badge badge-yellow">truncated</span>{{end}}</div>
      <table>
        <thead><tr>{{range (index .Rows 0).Columns}}<th>{{.Name}}</th>{{end}}</tr></thead>
        <tbody>
        {{range .Rows}}
          <tr>{{range .Columns}}<td>{{renderCell .Value}}</td>{{end}}</tr>
        {{end}}
        </tbody>
      </table>
    </div>
  {{end}}
{{end}}`
