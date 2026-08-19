package dashboard

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/vulnertrack/kite-collector/internal/store"
)

// The sidebar is a single resource tree: domain groups with human names and
// row counts, a Settings group, and a collapsible "All tables" catalog. It
// replaces the former Views + Tables split so users think in resources, not
// storage layout — the backing table name is still one click away (the table
// catalog, and the chip on each grid header).
//
// The tree renders twice per page load: a static, count-less variant baked
// into the shell (usable without JS), then a counted variant HTMX swaps in
// from /fragments/sidebar-tree once the page is up.

// sidebarEntry is one navigable row of the resource tree.
type sidebarEntry struct {
	Label string
	Href  string
	// Tab is the ActiveTab key that marks this entry active on a full-shell
	// render. Table-backed entries leave it empty: the shell cannot know
	// which table page is open, and setActive() handles clicks client-side.
	Tab string
	// Table names the backing content table for the count badge. Entries
	// without one (Observability, Docs, Settings pages) render no badge.
	Table string
	// Count is the row count of Table; -1 renders no badge (static variant
	// or unknown).
	Count int64
	// Warn tints the count badge red — used for Findings, where a non-zero
	// count is a call to action rather than inventory size.
	Warn bool
}

// sidebarGroup is a titled section of the resource tree.
type sidebarGroup struct {
	Title   string
	Entries []sidebarEntry
}

// sidebarGroups returns the curated resource tree. Counts default to -1
// (unknown); the counted variant fills them from the introspection catalog.
func sidebarGroups() []sidebarGroup {
	return []sidebarGroup{
		{Title: "Inventory", Entries: []sidebarEntry{
			{Label: "Machines", Href: "/machines", Tab: "machines", Table: "machines", Count: -1},
			{Label: "Software", Href: "/software", Tab: "software", Table: "installed_software", Count: -1},
			{Label: "Processes", Href: "/tables/host_processes", Table: "host_processes", Count: -1},
			{Label: "Listeners", Href: "/tables/host_listeners", Table: "host_listeners", Count: -1},
			{Label: "Containers", Href: "/containers", Tab: "containers", Table: "host_containers", Count: -1},
			{Label: "Volumes", Href: "/tables/host_volumes", Table: "host_volumes", Count: -1},
		}},
		{Title: "Security", Entries: []sidebarEntry{
			{Label: "Findings", Href: "/findings", Tab: "findings", Table: "config_findings", Count: -1, Warn: true},
			{Label: "Drivers", Href: "/tables/loaded_drivers", Table: "loaded_drivers", Count: -1},
			{Label: "Firewall rules", Href: "/tables/host_firewall_rules", Table: "host_firewall_rules", Count: -1},
		}},
		{Title: "Operations", Entries: []sidebarEntry{
			{Label: "Scans", Href: "/scans", Tab: "scans", Table: "scan_runs", Count: -1},
			{Label: "Events", Href: "/tables/events", Table: "events", Count: -1},
			{Label: "Observability", Href: "/observability", Tab: "observability"},
			{Label: "Docs", Href: "/docs", Tab: "docs"},
		}},
		{Title: "Views", Entries: viewSidebarEntries()},
		{Title: "Settings", Entries: []sidebarEntry{
			{Label: "Onboarding", Href: "/onboarding", Tab: "onboarding"},
			{Label: "Mass deployment", Href: "/fleet", Tab: "fleet"},
			{Label: "Certificates", Href: "/certificates", Tab: "certificates"},
		}},
	}
}


// viewSidebarEntries lists the built-in views plus the builder link. The
// counted sidebar variant splices saved views in after the built-ins.
func viewSidebarEntries() []sidebarEntry {
	entries := make([]sidebarEntry, 0, 4)
	for _, v := range builtinViews() {
		entries = append(entries, sidebarEntry{
			Label: v.Name, Href: "/views/" + v.Slug, Tab: "views:" + v.Slug, Count: -1,
		})
	}
	entries = append(entries, sidebarEntry{Label: "New view", Href: "/views/new", Tab: "views-new", Count: -1})
	return entries
}

// sidebarTreeView is the data model for sidebarTreeTemplate.
type sidebarTreeView struct {
	Groups []sidebarGroup
	// Tables is the full content-table catalog for the collapsible
	// "All tables" group; nil in the static variant.
	Tables       []store.TableSchema
	TablesActive bool
}

// sidebarTreeTemplate renders the resource tree. The <a> attribute order
// (href, hx-get, hx-target, hx-push-url, class) is load-bearing: tests and
// the HTMX history integration match on it.
const sidebarTreeTemplate = `{{ range .Groups -}}
<div class="sidenav-section">
  <h4>{{.Title}}</h4>
  {{- range .Entries }}
  <a href="{{.Href}}" hx-get="{{.Href}}" hx-target="#content" hx-push-url="true" class="{{if .Active}}active sidenav-resource{{else}}sidenav-resource{{end}}" onclick="setActive(this)"><span class="sidenav-label">{{.Label}}</span>{{if ge .Count 0}}<span class="badge sidenav-count{{if and .Warn (gt .Count 0)}} sidenav-count-warn{{end}}">{{.Count}}</span>{{end}}</a>
  {{- end }}
</div>
{{ end -}}
<div class="sidenav-section">
  <h4>Data</h4>
{{- if .Tables }}
  <details class="sidenav-alltables">
    <summary><span class="sidenav-label">All tables</span><span class="badge sidenav-count">{{len .Tables}}</span></summary>
    <ul class="sidenav-tables">
    {{- range .Tables }}
      <li>
        <a href="/tables/{{.Name}}" hx-get="/tables/{{.Name}}" hx-target="#content" hx-push-url="true" onclick="setActive(this)">
          <span class="sidenav-table-name">{{.Name}}</span>
          <span class="badge {{rowCountBucket .RowCount}}">{{ if lt .RowCount 0 }}?{{ else }}{{.RowCount}}{{ end }}</span>
        </a>
      </li>
    {{- end }}
    </ul>
  </details>
{{- end }}
  <a href="/tables" hx-get="/tables" hx-target="#content" hx-push-url="true" class="{{if .TablesActive}}active sidenav-resource{{else}}sidenav-resource{{end}}" onclick="setActive(this)"><span class="sidenav-label">Table catalog</span></a>
</div>`

// sidebarEntryView decorates a sidebarEntry with its active state for the
// template.
type sidebarEntryView struct {
	sidebarEntry
	Active bool
}

// sidebarGroupView mirrors sidebarGroup with decorated entries.
type sidebarGroupView struct {
	Title   string
	Entries []sidebarEntryView
}

var sidebarTreeTmpl = template.Must(
	template.New("sidebarTree").Funcs(templateFuncs).Parse(sidebarTreeTemplate))

// renderSidebarTree writes the resource tree. groups carry counts already
// filled (or -1); tables is nil for the static variant.
func renderSidebarTree(w io.Writer, activeTab string, groups []sidebarGroup, tables []store.TableSchema) error {
	viewGroups := make([]sidebarGroupView, 0, len(groups))
	for _, g := range groups {
		gv := sidebarGroupView{Title: g.Title}
		for _, e := range g.Entries {
			gv.Entries = append(gv.Entries, sidebarEntryView{
				sidebarEntry: e,
				Active:       e.Tab != "" && e.Tab == activeTab,
			})
		}
		viewGroups = append(viewGroups, gv)
	}
	view := struct {
		Groups       []sidebarGroupView
		Tables       []store.TableSchema
		TablesActive bool
	}{
		Groups:       viewGroups,
		Tables:       tables,
		TablesActive: activeTab == "tables",
	}
	if err := sidebarTreeTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render sidebar tree: %w", err)
	}
	return nil
}

// renderSidebarTreeStatic renders the count-less tree for the page shell.
// It cannot fail at runtime short of a programmer error in the template, so
// it returns the HTML directly; renderIndexPage embeds it as-is.
func renderSidebarTreeStatic(activeTab string) template.HTML {
	var buf strings.Builder
	if err := renderSidebarTree(&buf, activeTab, sidebarGroups(), nil); err != nil {
		// Template exec over static data — unreachable short of a template
		// bug, which the counted-variant tests would catch. Degrade to an
		// empty sidebar rather than panicking the page render.
		return ""
	}
	// The tree is produced by our own template over static data.
	return template.HTML(buf.String()) // #nosec G203 -- trusted in-process render
}

// renderSidebarTreeFragment renders the counted tree for the HTMX swap:
// resource counts from the introspection catalog plus the full table list.
func renderSidebarTreeFragment(w io.Writer, ctx context.Context, st store.Store, activeTab string) error {
	tables, err := st.ListContentTables(ctx)
	if err != nil {
		return fmt.Errorf("list content tables: %w", err)
	}
	counts := make(map[string]int64, len(tables))
	for _, t := range tables {
		counts[t.Name] = t.RowCount
	}
	groups := sidebarGroups()
	for gi := range groups {
		for ei := range groups[gi].Entries {
			e := &groups[gi].Entries[ei]
			if e.Table == "" {
				continue
			}
			if n, ok := counts[e.Table]; ok {
				e.Count = n
			}
		}
	}

	// Saved views join the Views group between the built-ins and "New view".
	if svs, ok := st.(store.SavedViewStore); ok {
		if saved, listErr := svs.ListSavedViews(ctx); listErr == nil && len(saved) > 0 {
			for gi := range groups {
				if groups[gi].Title != "Views" {
					continue
				}
				entries := groups[gi].Entries
				tail := entries[len(entries)-1] // "New view"
				entries = entries[:len(entries)-1]
				for _, sv := range saved {
					entries = append(entries, sidebarEntry{
						Label: sv.Name, Href: "/views/" + sv.Slug, Tab: "views:" + sv.Slug, Count: -1,
					})
				}
				groups[gi].Entries = append(entries, tail)
			}
		}
	}
	return renderSidebarTree(w, activeTab, groups, tables)
}
