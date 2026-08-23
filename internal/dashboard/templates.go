package dashboard

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// templateFuncs provides helper functions for HTML templates.
var templateFuncs = template.FuncMap{
	"upper": strings.ToUpper,
	"formatTime": func(t time.Time) string {
		return t.Local().Format("2006-01-02 15:04:05 MST")
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
	"renderCell":     renderCell,
	"rowKeyQuery":    rowKeyQuery,
	"cellFK":         findFK,
	"add":            func(a, b int) int { return a + b },
	"rowCountBucket": rowCountBucket,
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
		return x.Local().Format("2006-01-02 15:04:05 MST")
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

// renderMachinesFragment renders the machines table as an HTML fragment.
func renderMachinesFragment(w io.Writer, ctx context.Context, st store.Store, rc ReportContext, filterCol, filterVal string, filtered bool) error {
	machines, err := st.ListMachines(ctx, store.MachineFilter{Limit: 500})
	if err != nil {
		return fmt.Errorf("list machines: %w", err)
	}

	localHostname, _ := os.Hostname()
	localIP := ""
	if network, networkErr := detectFleetLocalNetwork(); networkErr == nil {
		localIP = network.LocalIP
	}
	rows := machineDisplayRows(machines, localHostname, localIP)

	// Facets are computed over every loaded row (so all values stay visible),
	// then the grid narrows to the selected value. is_authorized / is_managed
	// are the asset-status columns, so faceting on them is also how an
	// operator slices the fleet by "unauthorized" or "unmanaged".
	cols := machineFacetColumns(rows)
	facets := buildPageFacets(cols, tableFacetMaxDistinct, tableFacetTopValues, filterCol, filterVal, filtered)
	shown := pickByIndex(rows, pageFacetKeep(cols, filterCol, filterVal, filtered))
	rail, railErr := renderFacetRail(facetRailView{
		BasePath: "/machines", Facets: facets, Filtered: filtered,
		FilterCol: filterCol, FilterVal: filterVal, Shown: len(shown), Total: len(rows),
	})
	if railErr != nil {
		return fmt.Errorf("render machines facets: %w", railErr)
	}

	tmpl := template.Must(template.New("machines").Funcs(templateFuncs).Parse(machinesTemplate))
	if err := tmpl.Execute(w, map[string]any{
		"Machines":         shown,
		"Total":            len(rows),
		"FacetRail":        rail,
		"Context":          rc,
		"AgentInstallPath": agentInstallPath(),
	}); err != nil {
		return fmt.Errorf("render machines template: %w", err)
	}
	return nil
}

// machineFacetColumns projects the low-cardinality machine attributes an
// operator filters by — classification plus the two asset-status columns —
// into index-aligned facet columns. High-cardinality fields (hostname, IP)
// are deliberately omitted: buildPageFacets would drop them anyway, and
// listing them wastes a probe.
func machineFacetColumns(rows []machineDisplayRow) []pageFacetColumn {
	machineType := make([]string, len(rows))
	osFamily := make([]string, len(rows))
	authorized := make([]string, len(rows))
	managed := make([]string, len(rows))
	source := make([]string, len(rows))
	for i, r := range rows {
		machineType[i] = string(r.MachineType)
		osFamily[i] = r.OSFamily
		authorized[i] = string(r.IsAuthorized)
		managed[i] = string(r.IsManaged)
		source[i] = r.DiscoverySource
	}
	return []pageFacetColumn{
		{Name: "machine_type", Values: machineType},
		{Name: "os_family", Values: osFamily},
		{Name: "is_authorized", Values: authorized},
		{Name: "is_managed", Values: managed},
		{Name: "discovery_source", Values: source},
	}
}

// agentInstallPath resolves where this agent's binary currently lives,
// so the machines list can show the install location on the row the
// agent source discovered (this host). Best-effort: empty when the
// executable cannot be resolved, and the template omits the detail.
func agentInstallPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	return exe
}

type machineDisplayRow struct {
	model.Machine
	IPAddress string
	IPLabel   string
}

// machineDisplayRows adds address information for the UI without changing the
// persisted machine model. Remote computers keep their hostname as the label;
// the computer serving this dashboard is identified explicitly as local.
func machineDisplayRows(machines []model.Machine, localHostname, localIP string) []machineDisplayRow {
	rows := make([]machineDisplayRow, 0, len(machines))
	for _, machine := range machines {
		hostname := strings.TrimSpace(machine.Hostname)
		isLocal := strings.EqualFold(strings.TrimSpace(machine.DiscoverySource), "local_controller") ||
			(localHostname != "" && strings.EqualFold(hostname, strings.TrimSpace(localHostname)))
		ip := fleetMachineIP(machine)
		if parsedLocalIP := net.ParseIP(strings.TrimSpace(localIP)); isLocal && parsedLocalIP != nil {
			ip = parsedLocalIP.String()
		}
		label := hostname
		if isLocal {
			label = "Local IP"
		} else if net.ParseIP(hostname) != nil {
			label = "IP"
		}
		rows = append(rows, machineDisplayRow{Machine: machine, IPAddress: ip, IPLabel: label})
	}
	return rows
}

// softwareRow is one installed-package row joined to its owning asset. The
// Authorized/Managed fields carry the asset status through so an operator can
// see (and facet on) whether a package sits on an authorized, managed host —
// a package inventory is only actionable next to that context.
// Dependencies/Dependents are only populated for directory services, whose
// relationships are listed on the directory_software_relationships view.
type softwareRow struct {
	Hostname       string
	SoftwareName   string
	Version        string
	PackageManager string
	CPE23          string
	License        string
	Authorized     model.AuthorizationState
	Managed        model.ManagedState
	Dependencies   string
	Dependents     string
}

// renderSoftwareFragment renders the software table as an HTML fragment.
func renderSoftwareFragment(w io.Writer, ctx context.Context, st store.Store, rc ReportContext, filterCol, filterVal string, filtered bool) error {
	// Collect software across all machines. Iterating machines gives us the
	// owning asset (and its status) for free — no second lookup per package.
	machines, err := st.ListMachines(ctx, store.MachineFilter{Limit: 100})
	if err != nil {
		return fmt.Errorf("list machines: %w", err)
	}

	var rows []softwareRow
	for _, a := range machines {
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
				License:        s.License,
				Authorized:     a.IsAuthorized,
				Managed:        a.IsManaged,
			})
			if len(rows) >= 500 {
				break
			}
		}
		if len(rows) >= 500 {
			break
		}
	}
	if directoryStore, ok := st.(store.DirectorySoftwareStore); ok {
		directorySoftware, listErr := directoryStore.ListDirectorySoftware(ctx)
		if listErr == nil {
			byMachineID := make(map[string]model.Machine, len(machines))
			for _, machine := range machines {
				byMachineID[machine.ID.String()] = machine
			}
			for _, service := range directorySoftware {
				machine, exists := byMachineID[service.MachineID.String()]
				if !exists {
					continue
				}
				rows = append(rows, softwareRow{
					Hostname:       machine.Hostname,
					SoftwareName:   "Active Directory Domain Services",
					Version:        service.Version,
					PackageManager: "ldap",
					License:        service.DomainDNSName,
					Authorized:     machine.IsAuthorized,
					Managed:        machine.IsManaged,
					Dependencies:   service.Dependencies,
					Dependents:     service.Dependents,
				})
			}
		}
	}

	cols := softwareFacetColumns(rows)
	facets := buildPageFacets(cols, tableFacetMaxDistinct, tableFacetTopValues, filterCol, filterVal, filtered)
	shown := pickByIndex(rows, pageFacetKeep(cols, filterCol, filterVal, filtered))
	rail, railErr := renderFacetRail(facetRailView{
		BasePath: "/software", Facets: facets, Filtered: filtered,
		FilterCol: filterCol, FilterVal: filterVal, Shown: len(shown), Total: len(rows),
	})
	if railErr != nil {
		return fmt.Errorf("render software facets: %w", railErr)
	}

	tmpl := template.Must(template.New("software").Funcs(templateFuncs).Parse(softwareTemplate))
	if err := tmpl.Execute(w, map[string]any{
		"Software":  shown,
		"Total":     len(rows),
		"FacetRail": rail,
		"Context":   rc,
	}); err != nil {
		return fmt.Errorf("render software template: %w", err)
	}
	return nil
}

// softwareFacetColumns exposes the low-cardinality slices of the software
// inventory: the package manager and license, plus the owning asset's
// authorization and managed status. Package name / version / CPE are
// high-cardinality and left out.
func softwareFacetColumns(rows []softwareRow) []pageFacetColumn {
	pkgMgr := make([]string, len(rows))
	license := make([]string, len(rows))
	authorized := make([]string, len(rows))
	managed := make([]string, len(rows))
	for i, r := range rows {
		pkgMgr[i] = r.PackageManager
		license[i] = r.License
		authorized[i] = string(r.Authorized)
		managed[i] = string(r.Managed)
	}
	return []pageFacetColumn{
		{Name: "package_manager", Values: pkgMgr},
		{Name: "license", Values: license},
		{Name: "is_authorized", Values: authorized},
		{Name: "is_managed", Values: managed},
	}
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
	runs, err := st.ListScanRuns(ctx, 50)
	if err != nil {
		return fmt.Errorf("list scan runs: %w", err)
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

const machinesTemplate = `<h2>Machines ({{len .Machines}}{{if lt (len .Machines) .Total}} of {{.Total}}{{end}})</h2>
<div class="table-actions">
  <a href="/api/v1/machines/export.csv" class="btn">Export CSV</a>
</div>
{{.FacetRail}}
<div class="data-grid">
<table>
  <thead>
    <tr>
      <th>Hostname</th>
      <th>IP address</th>
      <th>Type</th>
      <th>OS</th>
      <th>Authorized</th>
      <th>Managed</th>
      <th>Source</th>
      <th>Last Seen</th>
    </tr>
  </thead>
  <tbody>
  {{range .Machines}}
    <tr>
      <td><a class="fk-link" href="/machines/{{.ID}}" hx-get="/machines/{{.ID}}" hx-target="#content" hx-push-url="true" onclick="event.stopPropagation();">{{.Hostname}}</a></td>
      <td>{{if .IPAddress}}<span class="machine-address"><strong>{{.IPLabel}}:</strong> <code>{{.IPAddress}}</code></span>{{else}}—{{end}}</td>
      <td>{{.MachineType}}</td>
      <td>{{.OSFamily}}{{if .OSVersion}} {{.OSVersion}}{{end}}</td>
      <td><span class="badge {{authClass .IsAuthorized}}">{{.IsAuthorized}}</span></td>
      <td>{{.IsManaged}}</td>
      <td>{{if and (eq .DiscoverySource "agent") $.AgentInstallPath}}<span class="badge badge-blue" title="kite-collector agent installed at {{$.AgentInstallPath}}">agent</span> <code class="small muted">{{$.AgentInstallPath}}</code>{{else}}{{.DiscoverySource}}{{end}}</td>
      <td>{{formatTime .LastSeenAt}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>`

const softwareTemplate = `<h2>Software ({{len .Software}}{{if lt (len .Software) .Total}} of {{.Total}}{{end}})</h2>
<div class="table-actions">
  <a href="/api/v1/software/export.csv" class="btn">Export CSV</a>
  <a href="/tables/directory_software_relationships" class="btn btn-outline">Directory service relationships</a>
</div>
{{.FacetRail}}
<div class="data-grid">
<table>
  <thead>
    <tr>
      <th>Host</th>
      <th>Authorized</th>
      <th>Managed</th>
      <th>Package</th>
      <th>Version</th>
      <th>License</th>
      <th>Manager</th>
      <th>CPE 2.3</th>
    </tr>
  </thead>
  <tbody>
  {{range .Software}}
    <tr>
      <td>{{.Hostname}}</td>
      <td><span class="badge {{authClass .Authorized}}">{{.Authorized}}</span></td>
      <td>{{.Managed}}</td>
      <td>{{.SoftwareName}}</td>
      <td>{{.Version}}</td>
      <td>{{if .License}}{{.License}}{{else}}unknown{{end}}</td>
      <td>{{.PackageManager}}</td>
      <td><code>{{.CPE23}}</code></td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>`

const findingsTemplate = `<h2>Findings ({{len .Findings}})</h2>
<div class="table-actions">
  <a href="/api/v1/findings/export.csv" class="btn">Export CSV</a>
</div>
<div class="data-grid">
<table>
  <thead>
    <tr>
      <th>Check</th>
      <th>Severity</th>
      <th>Title</th>
      <th>Auditor</th>
    </tr>
  </thead>
  <tbody>
  {{range .Findings}}
    <tr>
      <td>{{.CheckID}}</td>
      <td><span class="badge {{severityClass .Severity}}">{{.Severity}}</span></td>
      <td>{{.Title}}</td>
      <td>{{.Auditor}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>`

const scansTemplate = `<h2>Scan History ({{len .Scans}})</h2>
{{if .Scans}}
<div class="data-grid">
<table>
  <thead>
    <tr>
      <th>Started</th>
      <th>Status</th>
      <th>Total Machines</th>
      <th title="First-time sightings (MachineDiscovered events)">New</th>
      <th title="Existing machines with material state changes (MachineUpdated events)">Updated</th>
      <th title="Existing machines with no material change since last scan (MachineAnalyzed events)">Analyzed</th>
      <th title="Machines older than the stale threshold (MachineNotSeen events)">Stale</th>
      <th>Coverage</th>
    </tr>
  </thead>
  <tbody>
  {{range .Scans}}
    <tr>
      <td>{{formatTime .StartedAt}}</td>
      <td>{{.Status}}</td>
      <td>{{.TotalMachines}}</td>
      <td>{{.NewMachines}}</td>
      <td>{{.UpdatedMachines}}</td>
      <td>{{.AnalyzedMachines}}</td>
      <td>{{.StaleMachines}}</td>
      <td>{{printf "%.0f" .CoveragePercent}}%</td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>
{{else}}
<p>No scans recorded yet.</p>
{{end}}`

// rowCountBucket maps a row count into a coarse badge color bucket so the
// sidebar can highlight tables with notable amounts of data at a glance.
// Unknown counts (-1) render as gray.
func rowCountBucket(n int64) string {
	switch {
	case n < 0:
		return "badge-gray"
	case n == 0:
		return "badge-gray"
	case n < 100:
		return "badge-blue"
	case n < 10000:
		return "badge-green"
	default:
		return "badge-yellow"
	}
}

// renderTablesFragment lists every content table discovered via introspection.
func renderTablesFragment(w io.Writer, ctx context.Context, ts store.TableSource, rc ReportContext) error {
	tables, err := ts.ListContentTables(ctx)
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

// tableFacetMaxDistinct is the facet threshold: columns with at most this
// many distinct values get a facet card (most common values, selectable to
// filter). tableFacetTopValues caps the values listed per card.
const (
	tableFacetMaxDistinct = 20
	tableFacetTopValues   = 5
)

// renderTableFragment renders a paginated grid of rows for a single table:
// a facet rail for pattern spotting, the exact SQL the grid runs (copyable),
// and an optional single-column equality filter selected from a facet.
// filterCol/filterVal apply that filter; filtered distinguishes "filter on
// the empty bucket" from "no filter".
func renderTableFragment(w io.Writer, ctx context.Context, ts store.TableSource, rc ReportContext, name string, limit, offset int, filterCol, filterVal string, filtered bool) error {
	schema, err := ts.DescribeTable(ctx, name)
	if err != nil {
		return fmt.Errorf("describe table %q: %w", name, err)
	}

	rf := store.RowsFilter{
		Table:  name,
		Limit:  limit,
		Offset: offset,
	}
	if filtered {
		rf.WhereColumn = filterCol
		rf.WhereValue = filterVal
	}
	rows, total, err := ts.ListRows(ctx, rf)
	if err != nil {
		return fmt.Errorf("list rows %q: %w", name, err)
	}

	// Facets are decoration: a probe failure must not take the grid down.
	facets, facetErr := ts.FacetTable(ctx, name, tableFacetMaxDistinct, tableFacetTopValues)
	if facetErr != nil {
		facets = nil
	}

	nextOffset := offset + limit
	if int64(nextOffset) >= total {
		nextOffset = -1
	}
	prevOffset := offset - limit
	if prevOffset < 0 {
		prevOffset = -1
	}

	// FilterQS rides pager links so paging keeps the active filter. It is
	// built from query-escaped parts and marked template.URL so the template
	// can append it verbatim.
	filterQS := ""
	if filtered {
		filterQS = "&fcol=" + url.QueryEscape(filterCol) + "&fval=" + url.QueryEscape(filterVal)
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
		"Facets":     facets,
		"Filtered":   filtered,
		"FilterCol":  filterCol,
		"FilterVal":  filterVal,
		"FilterQS":   template.URL(filterQS), // #nosec G203 -- built from QueryEscape'd parts above
		"SQLText":    tableSQLText(schema, filterCol, filterVal, filtered, limit, offset),
	}); err != nil {
		return fmt.Errorf("render table template: %w", err)
	}
	return nil
}

// tableSQLText reconstructs the query behind the grid — the same statement
// the store executes — so the page can show and copy it. Values are inlined
// with doubled quotes purely for display; the executed query always binds
// them as parameters.
func tableSQLText(schema *store.TableSchema, filterCol, filterVal string, filtered bool, limit, offset int) string {
	var b strings.Builder
	b.WriteString("SELECT * FROM ")
	b.WriteString(schema.Name)
	if filtered {
		if filterVal == "" {
			b.WriteString(" WHERE (" + filterCol + " IS NULL OR " + filterCol + " = '')")
		} else {
			b.WriteString(" WHERE " + filterCol + " = '" + strings.ReplaceAll(filterVal, "'", "''") + "'")
		}
	}
	orderCol := ""
	if len(schema.PrimaryKey) > 0 {
		orderCol = schema.PrimaryKey[0]
	} else if len(schema.Columns) > 0 {
		orderCol = schema.Columns[0].Name
	}
	if orderCol != "" {
		b.WriteString(" ORDER BY " + orderCol)
	}
	fmt.Fprintf(&b, " LIMIT %d OFFSET %d;", limit, offset)
	return b.String()
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
<div class="data-grid">
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
      <td><a href="/tables/{{.Name}}" hx-get="/tables/{{.Name}}" hx-target="#content" hx-push-url="true" class="fk-link">{{.Name}}</a></td>
      <td>{{len .Columns}}</td>
      <td>{{if lt .RowCount 0}}<span class="muted">unknown</span>{{else}}{{.RowCount}}{{end}}</td>
      <td>{{range $i, $c := .PrimaryKey}}{{if $i}}, {{end}}{{$c}}{{end}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>`

const tableTemplate = `<h2>{{.Schema.Name}} <span class="muted">({{.Total}} rows{{if .Filtered}} matching{{end}})</span></h2>
{{if .Schema.Description}}<p class="muted table-desc">{{.Schema.Description}}</p>{{end}}
{{if .Filtered}}
<div class="facet-active-chip">
  <code>{{.FilterCol}} = {{if .FilterVal}}'{{.FilterVal}}'{{else}}empty{{end}}</code>
  <a href="/tables/{{.Schema.Name}}" hx-get="/tables/{{.Schema.Name}}" hx-target="#content" hx-push-url="true" title="Clear filter">&times;</a>
</div>
{{end}}
<div class="table-actions">
  <a href="/api/v1/tables/{{.Schema.Name}}/export.csv" class="btn">Export CSV</a>
  <a href="/tables" hx-get="/tables" hx-target="#content" hx-push-url="true" class="btn btn-outline">Back to tables</a>
</div>
{{if .Facets}}
<div class="facet-rail">
  <div class="facet-rail-head">Facets <span class="muted small">columns with at most 20 distinct values &mdash; select a value to filter the grid</span></div>
  <div class="facet-cards">
  {{$root := .}}
  {{range .Facets}}
    {{$col := .Column}}
    <div class="facet-card">
      <div class="facet-card-head"><code>{{.Column}}</code><span class="muted small">{{.Distinct}} values</span></div>
      {{range .Values}}
      {{if and $root.Filtered (eq $root.FilterCol $col) (eq $root.FilterVal .Value)}}
      <a class="facet-row facet-selected" href="/tables/{{$root.Schema.Name}}" hx-get="/tables/{{$root.Schema.Name}}" hx-target="#content" hx-push-url="true" title="Clear filter">
        <span class="facet-value">{{if .Value}}{{.Value}}{{else}}&mdash; empty{{end}}</span><span class="facet-count">{{.Count}} &times;</span>
      </a>
      {{else}}
      <a class="facet-row" href="/tables/{{$root.Schema.Name}}?fcol={{$col | urlquery}}&fval={{.Value | urlquery}}" hx-get="/tables/{{$root.Schema.Name}}?fcol={{$col | urlquery}}&fval={{.Value | urlquery}}" hx-target="#content" hx-push-url="true">
        <span class="facet-value">{{if .Value}}{{.Value}}{{else}}&mdash; empty{{end}}</span><span class="facet-count">{{.Count}}</span>
      </a>
      {{end}}
      {{end}}
    </div>
  {{end}}
  </div>
</div>
{{end}}
<div class="sql-strip">
  <span class="sql-strip-label">SQL</span>
  <code class="sql-strip-text" id="table-sql-text">{{.SQLText}}</code>
  <button type="button" class="sql-strip-copy" data-copy-target="table-sql-text" onclick="copyText(this)">Copy</button>
</div>
<table>
  <thead>
    <tr>
    {{if .Schema.Columns}}
    {{range .Schema.Columns}}
      <th{{if .Description}} title="{{.Description}}"{{end}}>{{.Name}}<br><span class="muted small">{{.Type}}</span></th>
    {{end}}
    {{else if .Rows}}
    {{range (index .Rows 0).Columns}}
      <th>{{.Name}}</th>
    {{end}}
    {{end}}
    </tr>
  </thead>
  <tbody>
  {{$schema := .Schema}}
  {{range .Rows}}
    {{$pk := .PrimaryKey}}
    {{if $pk}}<tr class="row-click" hx-get="/fragments/tables/{{$schema.Name}}/row?{{rowKeyQuery $pk}}" hx-target="#row-drawer" hx-swap="innerHTML" onclick="openRowDrawer()">{{else}}<tr>{{end}}
    {{range .Columns}}
      {{$fk := cellFK $schema.ForeignKeys .Name}}
      <td>{{if $fk}}<a class="fk-link" href="/tables/{{$fk.ToTable}}" hx-get="/tables/{{$fk.ToTable}}" hx-target="#content" hx-push-url="true" onclick="event.stopPropagation();">{{renderCell .Value}}</a>{{else}}{{renderCell .Value}}{{end}}</td>
    {{end}}
    </tr>
  {{end}}
  </tbody>
</table>
<div class="pager">
  {{if ge .PrevOffset 0}}
    <a class="btn btn-outline" href="/tables/{{.Schema.Name}}?limit={{.Limit}}&offset={{.PrevOffset}}{{.FilterQS}}" hx-get="/tables/{{.Schema.Name}}?limit={{.Limit}}&offset={{.PrevOffset}}{{.FilterQS}}" hx-target="#content" hx-push-url="true">Previous</a>
  {{end}}
  <span class="muted">rows {{.Offset}}&ndash;{{add .Offset (len .Rows)}}</span>
  {{if ge .NextOffset 0}}
    <a class="btn btn-outline" href="/tables/{{.Schema.Name}}?limit={{.Limit}}&offset={{.NextOffset}}{{.FilterQS}}" hx-get="/tables/{{.Schema.Name}}?limit={{.Limit}}&offset={{.NextOffset}}{{.FilterQS}}" hx-target="#content" hx-push-url="true">Next</a>
  {{end}}
</div>`

const rowReportTemplate = `<div class="row-drawer-head">
  <h3>{{.Report.Table}}</h3>
  <button class="btn btn-outline" onclick="closeRowDrawer()">Close</button>
</div>
<h4>Row</h4>
<table class="kv">
  <tbody>
  {{$fks := .Schema.ForeignKeys}}
  {{range .Report.Row.Columns}}
    {{$fk := cellFK $fks .Name}}
    <tr>
      <th>{{.Name}}</th>
      <td>{{if $fk}}<a class="fk-link" href="/tables/{{$fk.ToTable}}" hx-get="/tables/{{$fk.ToTable}}" hx-target="#content" hx-push-url="true" onclick="closeRowDrawer();">{{renderCell .Value}}</a>{{else}}{{renderCell .Value}}{{end}}</td>
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
