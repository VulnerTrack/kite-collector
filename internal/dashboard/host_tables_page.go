package dashboard

import (
	"context"
	"fmt"
	"html/template"
	"io"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// Curated, asset-joined pages for host-scoped inventory tables (listeners,
// volumes). The generic /tables/{name} view can already facet and filter these
// raw tables, but it shows only the table's own columns — and a listener or a
// volume is only meaningful next to the asset it belongs to: a port open on an
// UNAUTHORIZED host is the finding, not the port itself.
//
// So these pages join each host row to its owning asset (via machine_id) and
// render the asset's hostname plus its authorization/managed status alongside
// the row, with the same in-place facet rail the machines/software tabs use —
// including facets on the asset status itself.

// hostTableColumn is one displayed column: the raw table column to read and
// the header to show it under.
type hostTableColumn struct {
	Name  string
	Label string
}

// hostTableSpec configures one curated host-scoped page.
type hostTableSpec struct {
	Table     string // underlying store table, e.g. "host_listeners"
	Title     string // page heading
	BasePath  string // canonical URL the facet rail links back to, e.g. "/listeners"
	Display   []hostTableColumn
	FacetCols []string // raw columns offered as facets, on top of asset status
}

var (
	listenersPageSpec = hostTableSpec{
		Table: "host_listeners", Title: "Listeners", BasePath: "/listeners",
		Display: []hostTableColumn{
			{"protocol", "Protocol"}, {"bind_address", "Bind address"}, {"port", "Port"},
			{"exposure", "Exposure"}, {"process_name", "Process"}, {"username", "User"},
			{"last_seen_at", "Last Seen"},
		},
		FacetCols: []string{"protocol", "exposure", "process_name", "username"},
	}
	volumesPageSpec = hostTableSpec{
		Table: "host_volumes", Title: "Volumes", BasePath: "/volumes",
		Display: []hostTableColumn{
			{"mount_point", "Mount"}, {"device", "Device"}, {"filesystem", "FS"},
			{"size_bytes", "Size"}, {"read_only", "Read-only"}, {"removable", "Removable"},
			{"encryption_state", "Encryption"}, {"last_seen_at", "Last Seen"},
		},
		FacetCols: []string{"filesystem", "read_only", "removable", "bootable", "encryption_state"},
	}
)

// hostScopedRow is one host inventory row joined to its owning asset.
type hostScopedRow struct {
	Host       string
	Authorized model.AuthorizationState
	Managed    model.ManagedState
	Cells      []template.HTML // one per spec.Display column, pre-rendered
}

// renderHostScopedFragment renders a curated host-scoped table: asset columns
// (host + status) followed by the configured display columns, with an in-place
// facet rail over the asset status and the configured facet columns.
func renderHostScopedFragment(w io.Writer, ctx context.Context, st store.Store, ts store.TableSource, rc ReportContext, spec hostTableSpec, filterCol, filterVal string, filtered bool) error {
	rows, _, err := ts.ListRows(ctx, store.RowsFilter{Table: spec.Table, Limit: 500})
	if err != nil {
		return fmt.Errorf("list rows %q: %w", spec.Table, err)
	}

	// machine_id -> owning asset, so each host row can show who it belongs to.
	machines, err := st.ListMachines(ctx, store.MachineFilter{Limit: 5000})
	if err != nil {
		return fmt.Errorf("list machines: %w", err)
	}
	byAsset := make(map[string]model.Machine, len(machines))
	for _, m := range machines {
		byAsset[m.ID.String()] = m
	}

	display := make([]hostScopedRow, 0, len(rows))
	// Facet columns are built index-aligned with display rows: asset status
	// first, then the configured raw columns.
	authVals := make([]string, 0, len(rows))
	managedVals := make([]string, 0, len(rows))
	hostVals := make([]string, 0, len(rows))
	rawVals := make(map[string][]string, len(spec.FacetCols))
	for _, c := range spec.FacetCols {
		rawVals[c] = make([]string, 0, len(rows))
	}

	for _, row := range rows {
		cells := make(map[string]string, len(row.Columns))
		for _, cv := range row.Columns {
			cells[cv.Name] = renderCell(cv.Value)
		}
		owner := byAsset[cells["machine_id"]]
		host := owner.Hostname
		if host == "" {
			host = "(unknown asset)"
		}
		dr := hostScopedRow{Host: host, Authorized: owner.IsAuthorized, Managed: owner.IsManaged}
		for _, dc := range spec.Display {
			dr.Cells = append(dr.Cells, template.HTML(template.HTMLEscapeString(cells[dc.Name]))) // #nosec G203 -- escaped
		}
		display = append(display, dr)

		authVals = append(authVals, string(owner.IsAuthorized))
		managedVals = append(managedVals, string(owner.IsManaged))
		hostVals = append(hostVals, host)
		for _, c := range spec.FacetCols {
			rawVals[c] = append(rawVals[c], cells[c])
		}
	}

	cols := []pageFacetColumn{
		{Name: "is_authorized", Values: authVals},
		{Name: "is_managed", Values: managedVals},
		{Name: "host", Values: hostVals},
	}
	for _, c := range spec.FacetCols {
		cols = append(cols, pageFacetColumn{Name: c, Values: rawVals[c]})
	}

	facets := buildPageFacets(cols, tableFacetMaxDistinct, tableFacetTopValues, filterCol, filterVal, filtered)
	shown := pickByIndex(display, pageFacetKeep(cols, filterCol, filterVal, filtered))
	rail, railErr := renderFacetRail(facetRailView{
		BasePath: spec.BasePath, Facets: facets, Filtered: filtered,
		FilterCol: filterCol, FilterVal: filterVal, Shown: len(shown), Total: len(display),
	})
	if railErr != nil {
		return fmt.Errorf("render %s facets: %w", spec.Table, railErr)
	}

	if err := hostTableTmpl.Execute(w, map[string]any{
		"Spec":      spec,
		"Rows":      shown,
		"Total":     len(display),
		"FacetRail": rail,
		"Context":   rc,
	}); err != nil {
		return fmt.Errorf("render host table %q: %w", spec.Table, err)
	}
	return nil
}

var hostTableTmpl = template.Must(
	template.New("host-table").Funcs(templateFuncs).Parse(hostTableTemplate))

const hostTableTemplate = `<h2>{{.Spec.Title}} ({{len .Rows}}{{if lt (len .Rows) .Total}} of {{.Total}}{{end}})</h2>
<div class="table-actions">
  <a href="/api/v1/tables/{{.Spec.Table}}/export.csv" class="btn">Export CSV</a>
</div>
{{.FacetRail}}
<div class="data-grid">
<table>
  <thead>
    <tr>
      <th>Host</th>
      <th>Authorized</th>
      <th>Managed</th>
      {{range .Spec.Display}}<th>{{.Label}}</th>{{end}}
    </tr>
  </thead>
  <tbody>
  {{range .Rows}}
    <tr>
      <td>{{.Host}}</td>
      <td><span class="badge {{authClass .Authorized}}">{{.Authorized}}</span></td>
      <td>{{.Managed}}</td>
      {{range .Cells}}<td>{{.}}</td>{{end}}
    </tr>
  {{end}}
  </tbody>
</table>
</div>`
