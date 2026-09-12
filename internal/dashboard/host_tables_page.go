package dashboard

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"

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

// cellFormat selects how a raw column value is rendered. The zero value shows
// the stored text verbatim, which is right for identifiers and enums; capacity
// columns are integers whose stored form ("999501094912") is unreadable.
type cellFormat string

const (
	cellVerbatim cellFormat = ""
	// cellBytes renders an integer byte count as "931.51 GB".
	cellBytes cellFormat = "bytes"
	// cellRatioBytes renders Name/Of as a percentage plus a fill bar, with the
	// two byte counts in the tooltip. Used for "how full is this volume", the
	// one storage question an operator asks that a pair of raw counters
	// answers badly.
	cellRatioBytes cellFormat = "ratio-bytes"
	// cellRatioCount is cellRatioBytes for dimensionless counters: same bar,
	// tooltip in units rather than bytes. Inodes exhaust independently of
	// capacity — a volume can be 3% full and completely unwritable.
	cellRatioCount cellFormat = "ratio-count"
)

// hostTableColumn is one displayed column: the raw table column to read and
// the header to show it under.
type hostTableColumn struct {
	Name   string
	Label  string
	Format cellFormat
	// Of names the denominator column for the cellRatio* formats.
	Of string
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
			{Name: "protocol", Label: "Protocol"},
			{Name: "bind_address", Label: "Bind address"},
			{Name: "port", Label: "Port"},
			{Name: "exposure", Label: "Exposure"},
			{Name: "process_name", Label: "Process"},
			{Name: "username", Label: "User"},
			{Name: "last_seen_at", Label: "Last Seen"},
		},
		FacetCols: []string{"protocol", "exposure", "process_name", "username"},
	}
	volumesPageSpec = hostTableSpec{
		Table: "host_volumes", Title: "Volumes", BasePath: "/volumes",
		Display: []hostTableColumn{
			{Name: "mount_point", Label: "Mount"},
			{Name: "device", Label: "Device"},
			{Name: "filesystem", Label: "FS"},
			{Name: "size_bytes", Label: "Size", Format: cellBytes},
			{Name: "used_bytes", Label: "Used", Format: cellBytes},
			{Name: "used_bytes", Of: "size_bytes", Label: "Usage", Format: cellRatioBytes},
			{Name: "inodes_used", Of: "inodes_total", Label: "Inodes", Format: cellRatioCount},
			{Name: "read_only", Label: "Read-only"},
			{Name: "removable", Label: "Removable"},
			{Name: "encryption_state", Label: "Encryption"},
			{Name: "last_seen_at", Label: "Last Seen"},
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
			dr.Cells = append(dr.Cells, formatHostCell(dc, cells))
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

// formatHostCell renders one display column for one row. Every branch either
// HTML-escapes the stored text or builds markup out of numbers it parsed
// itself, so no untrusted byte reaches the page unescaped.
func formatHostCell(col hostTableColumn, cells map[string]string) template.HTML {
	raw := cells[col.Name]
	switch col.Format {
	case cellBytes:
		n, ok := parseCellInt(raw)
		if !ok {
			// An unstattable mount stores NULL. "—" says "not measured",
			// where a literal 0 would read as "empty disk".
			return template.HTML(`<span class="muted">&mdash;</span>`)
		}
		return template.HTML(template.HTMLEscapeString(humanizeBytes(n))) // #nosec G203 -- escaped
	case cellRatioBytes, cellRatioCount:
		used, okUsed := parseCellInt(raw)
		total, okTotal := parseCellInt(cells[col.Of])
		if !okUsed || !okTotal || total <= 0 {
			return template.HTML(`<span class="muted">&mdash;</span>`)
		}
		unit := humanizeCount
		if col.Format == cellRatioBytes {
			unit = humanizeBytes
		}
		return ratioBar(used, total, unit)
	case cellVerbatim:
	}
	return template.HTML(template.HTMLEscapeString(raw)) // #nosec G203 -- escaped
}

// parseCellInt reads a stored integer column. Empty, NULL and non-numeric all
// mean "no measurement" rather than zero.
func parseCellInt(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// ratioBar renders used/total as a percentage and a proportional fill, tinted
// once it crosses the thresholds where a full disk stops being trivia and
// starts being an incident. unit formats the two absolute values shown in the
// tooltip (bytes for capacity, plain counts for inodes).
func ratioBar(used, total int64, unit func(int64) string) template.HTML {
	pct := float64(used) / float64(total) * 100
	// A filesystem can report used past total (root-reserved blocks); clamp so
	// the bar never overflows its track.
	if pct > 100 {
		pct = 100
	}
	if pct < 0 {
		pct = 0
	}
	level := "ok"
	switch {
	case pct >= 90:
		level = "crit"
	case pct >= 75:
		level = "warn"
	}
	// Every value interpolated below is a number this function computed, so
	// the markup cannot carry injected content.
	return template.HTML(fmt.Sprintf( // #nosec G203 -- numeric-only interpolation
		`<span class="usage-cell" title="%s of %s used">`+
			`<span class="usage-track"><span class="usage-fill usage-%s" style="width:%.1f%%"></span></span>`+
			`<span class="usage-pct">%.0f%%</span></span>`,
		template.HTMLEscapeString(unit(used)),
		template.HTMLEscapeString(unit(total)),
		level, pct, pct))
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
