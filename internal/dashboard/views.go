package dashboard

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/vulnertrack/kite-collector/internal/store"
)

// Views are saved two-table joins that live in the sidebar and render as
// ordinary grids: a plain-language join type (Inner — only matches / Left —
// keep every base row), an ON clause pre-filled from foreign keys, and the
// generated SQL always visible so nothing is magic.
//
// Three views ship built in; the store's optional SavedViewStore persists
// user-defined ones from the builder at /views/new.

// dashView is a renderable view: a named, described JoinFilter.
type dashView struct {
	Slug        string
	Name        string
	Description string
	Join        store.JoinFilter
	BuiltIn     bool
}

// builtinViews returns the shipped views. Slugs are stable — they are URLs.
func builtinViews() []dashView {
	return []dashView{
		{
			Slug:        "machine-findings-coverage",
			Name:        "Machine findings coverage",
			Description: "Every machine with its findings — machines with none stay in the result, so clean hosts are visible too.",
			BuiltIn:     true,
			Join: store.JoinFilter{
				Base: "machines", Join: "config_findings", Type: store.JoinLeft,
				OnBase: "id", OnJoin: "machine_id",
				Columns: []store.JoinColumn{
					{Table: "machines", Column: "hostname"},
					{Table: "machines", Column: "os_family"},
					{Table: "config_findings", Column: "severity"},
					{Table: "config_findings", Column: "title"},
				},
			},
		},
		{
			Slug:        "software-by-machine",
			Name:        "Software by machine",
			Description: "What runs where: each package joined to the machine it was found on, with CPE and package manager.",
			BuiltIn:     true,
			Join: store.JoinFilter{
				Base: "installed_software", Join: "machines", Type: store.JoinInner,
				OnBase: "machine_id", OnJoin: "id",
				Columns: []store.JoinColumn{
					{Table: "machines", Column: "hostname"},
					{Table: "installed_software", Column: "software_name"},
					{Table: "installed_software", Column: "version"},
					{Table: "installed_software", Column: "cpe23"},
					{Table: "installed_software", Column: "package_manager"},
				},
			},
		},
		{
			Slug:        "listeners-by-machine",
			Name:        "Listeners by machine",
			Description: "Open ports joined to the machine that exposes them, with process and exposure class.",
			BuiltIn:     true,
			Join: store.JoinFilter{
				Base: "host_listeners", Join: "machines", Type: store.JoinInner,
				OnBase: "machine_id", OnJoin: "id",
				Columns: []store.JoinColumn{
					{Table: "machines", Column: "hostname"},
					{Table: "host_listeners", Column: "protocol"},
					{Table: "host_listeners", Column: "port"},
					{Table: "host_listeners", Column: "process_name"},
					{Table: "host_listeners", Column: "exposure"},
				},
			},
		},
	}
}

// resolveView finds a view by slug: built-ins first, then the saved-view
// store when the backing store supports one. Returns store.ErrNotFound for
// unknown slugs.
func resolveView(ctx context.Context, st store.Store, slug string) (*dashView, error) {
	for _, v := range builtinViews() {
		if v.Slug == slug {
			return &v, nil
		}
	}
	svs, ok := st.(store.SavedViewStore)
	if !ok {
		return nil, store.ErrNotFound
	}
	saved, err := svs.GetSavedViewBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	return &dashView{
		Slug: saved.Slug,
		Name: saved.Name,
		Join: saved.Join,
	}, nil
}

// viewSQLText reconstructs the join SQL for display — the same statement the
// store executes, with identifiers only (no values ever enter it).
func viewSQLText(v dashView, orderCol string, limit, offset int) string {
	var b strings.Builder
	b.WriteString("SELECT ")
	parts := make([]string, 0, len(v.Join.Columns))
	for _, c := range v.Join.Columns {
		alias := "b"
		if c.Table == v.Join.Join {
			alias = "j"
		}
		parts = append(parts, alias+"."+c.Column)
	}
	b.WriteString(strings.Join(parts, ", "))
	b.WriteString("\nFROM " + v.Join.Base + " b\n")
	if v.Join.Type == store.JoinLeft {
		b.WriteString("LEFT JOIN ")
	} else {
		b.WriteString("JOIN ")
	}
	b.WriteString(v.Join.Join + " j ON j." + v.Join.OnJoin + " = b." + v.Join.OnBase)
	if orderCol != "" {
		b.WriteString("\nORDER BY b." + orderCol)
	}
	fmt.Fprintf(&b, "\nLIMIT %d OFFSET %d;", limit, offset)
	return b.String()
}

// viewPageView is the data model for viewPageTemplate.
type viewPageView struct {
	View       dashView
	Rows       []store.Row
	Columns    []store.JoinColumn
	SQLText    string
	Limit      int
	Offset     int
	NextOffset int
	PrevOffset int
	CanDelete  bool
}

var viewPageTmpl = template.Must(
	template.New("viewPage").Funcs(templateFuncs).Parse(viewPageTemplate))

// renderViewFragment renders /views/{slug}: description, join formula, the
// SQL behind the grid, and the joined rows.
func renderViewFragment(w io.Writer, ctx context.Context, st store.Store, slug string, limit, offset int) error {
	v, err := resolveView(ctx, st, slug)
	if err != nil {
		return err
	}
	if limit <= 0 {
		limit = 50
	}
	jf := v.Join
	jf.Limit = limit
	jf.Offset = offset
	rows, err := st.ListJoinedRows(ctx, jf)
	if err != nil {
		return fmt.Errorf("run view %q: %w", slug, err)
	}

	orderCol := ""
	if schema, describeErr := st.DescribeTable(ctx, v.Join.Base); describeErr == nil && len(schema.PrimaryKey) > 0 {
		orderCol = schema.PrimaryKey[0]
	}

	nextOffset := -1
	if len(rows) == limit {
		nextOffset = offset + limit
	}
	prevOffset := offset - limit
	if prevOffset < 0 && offset > 0 {
		prevOffset = 0
	} else if offset == 0 {
		prevOffset = -1
	}

	_, canDelete := st.(store.SavedViewStore)
	view := viewPageView{
		View:       *v,
		Rows:       rows,
		Columns:    v.Join.Columns,
		SQLText:    viewSQLText(*v, orderCol, limit, offset),
		Limit:      limit,
		Offset:     offset,
		NextOffset: nextOffset,
		PrevOffset: prevOffset,
		CanDelete:  canDelete && !v.BuiltIn,
	}
	if err := viewPageTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render view template: %w", err)
	}
	return nil
}

const viewPageTemplate = `<h2>{{.View.Name}}</h2>
<p class="muted view-desc">{{if .View.Description}}{{.View.Description}} {{end}}<code class="view-formula">{{.View.Join.Base}} {{if eq (printf "%s" .View.Join.Type) "left"}}&#10197;{{else}}&#8904;{{end}} {{.View.Join.Join}}</code></p>
<div class="sql-strip sql-strip-multiline">
  <span class="sql-strip-label">SQL</span>
  <code class="sql-strip-text" id="view-sql-text">{{.SQLText}}</code>
  <button type="button" class="sql-strip-copy" data-copy-target="view-sql-text" onclick="copyText(this)">Copy</button>
</div>
{{if .Rows}}
<table>
  <thead><tr>{{range .Columns}}<th>{{.Table}}.{{.Column}}</th>{{end}}</tr></thead>
  <tbody>
  {{range .Rows}}
    <tr>{{range .Columns}}<td>{{with renderCell .Value}}{{.}}{{else}}<span class="muted">&mdash;</span>{{end}}</td>{{end}}</tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p class="muted">The join produced no rows.</p>
{{end}}
<div class="pager">
  {{if ge .PrevOffset 0}}
    <a class="btn btn-outline" href="/views/{{.View.Slug}}?limit={{.Limit}}&offset={{.PrevOffset}}" hx-get="/views/{{.View.Slug}}?limit={{.Limit}}&offset={{.PrevOffset}}" hx-target="#content" hx-push-url="true">Previous</a>
  {{end}}
  <span class="muted">rows {{.Offset}}&ndash;{{add .Offset (len .Rows)}}</span>
  {{if ge .NextOffset 0}}
    <a class="btn btn-outline" href="/views/{{.View.Slug}}?limit={{.Limit}}&offset={{.NextOffset}}" hx-get="/views/{{.View.Slug}}?limit={{.Limit}}&offset={{.NextOffset}}" hx-target="#content" hx-push-url="true">Next</a>
  {{end}}
</div>`

// --- View builder ----------------------------------------------------------

// builderSelection is the parsed state of the builder form.
type builderSelection struct {
	Base     string
	Join     string
	JoinType store.JoinType
	OnBase   string
	OnJoin   string
	Columns  []store.JoinColumn
	Name     string
}

// parseBuilderForm reads the builder's form fields. Unknown values are kept
// as-is here; normalization against the catalog happens in
// normalizeBuilderSelection.
func parseBuilderForm(values url.Values) builderSelection {
	sel := builderSelection{
		Base:   values.Get("base"),
		Join:   values.Get("join"),
		OnBase: values.Get("onbase"),
		OnJoin: values.Get("onjoin"),
		Name:   strings.TrimSpace(values.Get("name")),
	}
	if values.Get("jointype") == string(store.JoinInner) {
		sel.JoinType = store.JoinInner
	} else {
		sel.JoinType = store.JoinLeft
	}
	for _, raw := range values["cols"] {
		table, column, ok := strings.Cut(raw, ".")
		if !ok || table == "" || column == "" {
			continue
		}
		sel.Columns = append(sel.Columns, store.JoinColumn{Table: table, Column: column})
	}
	return sel
}

// builderView is the data model for the builder template.
type builderView struct {
	Tables      []store.TableSchema
	Sel         builderSelection
	BaseSchema  *store.TableSchema
	JoinSchema  *store.TableSchema
	Selected    map[string]bool // "table.column" -> checked
	FKSuggested bool
	CanSave     bool
	Error       string
	PreviewRows []store.Row
	PreviewSQL  string
}

var viewBuilderTmpl = template.Must(
	template.New("viewBuilder").Funcs(templateFuncs).Parse(viewBuilderTemplate))

// normalizeBuilderSelection validates the selection against the catalog and
// fills gaps with sensible defaults: FK-suggested ON columns and a small
// default projection. It never fails — an unknown table falls back to the
// first tables in the catalog.
func normalizeBuilderSelection(tables []store.TableSchema, sel builderSelection) builderSelection {
	byName := make(map[string]*store.TableSchema, len(tables))
	for i := range tables {
		byName[tables[i].Name] = &tables[i]
	}
	if _, ok := byName[sel.Base]; !ok {
		if _, machines := byName["machines"]; machines {
			sel.Base = "machines"
		} else if len(tables) > 0 {
			sel.Base = tables[0].Name
		}
	}
	if _, ok := byName[sel.Join]; !ok || sel.Join == sel.Base {
		if _, findings := byName["config_findings"]; findings && sel.Base != "config_findings" {
			sel.Join = "config_findings"
		} else {
			for _, t := range tables {
				if t.Name != sel.Base {
					sel.Join = t.Name
					break
				}
			}
		}
	}
	base := byName[sel.Base]
	join := byName[sel.Join]
	if base == nil || join == nil {
		return sel
	}

	if !schemaHasColumn(base, sel.OnBase) || !schemaHasColumn(join, sel.OnJoin) {
		sel.OnBase, sel.OnJoin = suggestJoinColumns(base, join)
	}

	valid := sel.Columns[:0]
	for _, c := range sel.Columns {
		switch c.Table {
		case base.Name:
			if schemaHasColumn(base, c.Column) {
				valid = append(valid, c)
			}
		case join.Name:
			if schemaHasColumn(join, c.Column) {
				valid = append(valid, c)
			}
		}
	}
	sel.Columns = valid
	if len(sel.Columns) == 0 {
		sel.Columns = defaultProjection(base, join)
	}
	return sel
}

func schemaHasColumn(schema *store.TableSchema, name string) bool {
	if name == "" {
		return false
	}
	for _, c := range schema.Columns {
		if c.Name == name {
			return true
		}
	}
	return false
}

// suggestJoinColumns picks the ON pair from declared foreign keys — the join
// table pointing at the base first, then the reverse — falling back to the
// machine_id/id convention, then to primary keys.
func suggestJoinColumns(base, join *store.TableSchema) (onBase, onJoin string) {
	for _, fk := range join.ForeignKeys {
		if fk.ToTable == base.Name {
			return fk.ToColumn, fk.FromColumn
		}
	}
	for _, fk := range base.ForeignKeys {
		if fk.ToTable == join.Name {
			return fk.FromColumn, fk.ToColumn
		}
	}
	if schemaHasColumn(base, "id") && schemaHasColumn(join, "machine_id") {
		return "id", "machine_id"
	}
	if schemaHasColumn(base, "machine_id") && schemaHasColumn(join, "id") {
		return "machine_id", "id"
	}
	onBase = ""
	if len(base.PrimaryKey) > 0 {
		onBase = base.PrimaryKey[0]
	} else if len(base.Columns) > 0 {
		onBase = base.Columns[0].Name
	}
	onJoin = ""
	if len(join.PrimaryKey) > 0 {
		onJoin = join.PrimaryKey[0]
	} else if len(join.Columns) > 0 {
		onJoin = join.Columns[0].Name
	}
	return onBase, onJoin
}

// defaultProjection picks up to two non-key columns from each table so a
// fresh builder shows something meaningful immediately.
func defaultProjection(base, join *store.TableSchema) []store.JoinColumn {
	var cols []store.JoinColumn
	cols = append(cols, pickDefaultColumns(base, 2)...)
	cols = append(cols, pickDefaultColumns(join, 2)...)
	return cols
}

func pickDefaultColumns(schema *store.TableSchema, n int) []store.JoinColumn {
	pk := make(map[string]bool, len(schema.PrimaryKey))
	for _, c := range schema.PrimaryKey {
		pk[c] = true
	}
	fk := make(map[string]bool, len(schema.ForeignKeys))
	for _, f := range schema.ForeignKeys {
		fk[f.FromColumn] = true
	}
	preferred := map[string]bool{"hostname": true, "name": true, "title": true, "severity": true, "software_name": true}
	var cols []store.JoinColumn
	for _, c := range schema.Columns {
		if len(cols) >= n {
			return cols
		}
		if preferred[c.Name] {
			cols = append(cols, store.JoinColumn{Table: schema.Name, Column: c.Name})
		}
	}
	for _, c := range schema.Columns {
		if len(cols) >= n {
			break
		}
		if pk[c.Name] || fk[c.Name] {
			continue
		}
		dup := false
		for _, existing := range cols {
			if existing.Column == c.Name {
				dup = true
				break
			}
		}
		if !dup {
			cols = append(cols, store.JoinColumn{Table: schema.Name, Column: c.Name})
		}
	}
	return cols
}

// renderViewBuilderFragment renders the builder form (and, when the current
// selection is runnable, a live preview). It is the target of every form
// change, so the whole thing re-renders server-side.
func renderViewBuilderFragment(w io.Writer, ctx context.Context, st store.Store, sel builderSelection, saveError string) error {
	tables, err := st.ListContentTables(ctx)
	if err != nil {
		return fmt.Errorf("list content tables: %w", err)
	}
	sel = normalizeBuilderSelection(tables, sel)

	view := builderView{
		Tables:   tables,
		Sel:      sel,
		Selected: map[string]bool{},
		Error:    saveError,
	}
	_, view.CanSave = st.(store.SavedViewStore)
	for _, c := range sel.Columns {
		view.Selected[c.Table+"."+c.Column] = true
	}
	for i := range tables {
		if tables[i].Name == sel.Base {
			view.BaseSchema = &tables[i]
		}
		if tables[i].Name == sel.Join {
			view.JoinSchema = &tables[i]
		}
	}

	if view.BaseSchema != nil && view.JoinSchema != nil && len(sel.Columns) > 0 && sel.OnBase != "" && sel.OnJoin != "" {
		preview := dashView{Slug: "preview", Name: "preview", Join: store.JoinFilter{
			Base: sel.Base, Join: sel.Join, Type: sel.JoinType,
			OnBase: sel.OnBase, OnJoin: sel.OnJoin, Columns: sel.Columns,
			Limit: 10,
		}}
		rows, previewErr := st.ListJoinedRows(ctx, preview.Join)
		if previewErr != nil {
			if view.Error == "" {
				view.Error = previewErr.Error()
			}
		} else {
			view.PreviewRows = rows
			orderCol := ""
			if len(view.BaseSchema.PrimaryKey) > 0 {
				orderCol = view.BaseSchema.PrimaryKey[0]
			}
			view.PreviewSQL = viewSQLText(preview, orderCol, 10, 0)
		}
	}

	if err := viewBuilderTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render view builder template: %w", err)
	}
	return nil
}

// slugPattern reduces a view name to its URL slug.
var slugNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func slugifyViewName(name string) string {
	slug := strings.ToLower(strings.TrimSpace(name))
	slug = slugNonAlnum.ReplaceAllString(slug, "-")
	return strings.Trim(slug, "-")
}

// errViewValidation marks user-fixable builder errors so the save handler
// can render them inline instead of a 500.
var errViewValidation = errors.New("view validation")

// saveViewFromSelection validates and persists a builder selection.
func saveViewFromSelection(ctx context.Context, st store.Store, sel builderSelection) (slug string, err error) {
	svs, ok := st.(store.SavedViewStore)
	if !ok {
		return "", fmt.Errorf("%w: this store cannot persist views", errViewValidation)
	}
	if sel.Name == "" {
		return "", fmt.Errorf("%w: name this view before saving", errViewValidation)
	}
	slug = slugifyViewName(sel.Name)
	if slug == "" {
		return "", fmt.Errorf("%w: the name must contain letters or digits", errViewValidation)
	}
	for _, b := range builtinViews() {
		if b.Slug == slug {
			return "", fmt.Errorf("%w: %q is a built-in view", errViewValidation, sel.Name)
		}
	}
	if len(sel.Columns) == 0 {
		return "", fmt.Errorf("%w: pick at least one column", errViewValidation)
	}
	view := store.SavedView{
		Name: sel.Name,
		Slug: slug,
		Join: store.JoinFilter{
			Base: sel.Base, Join: sel.Join, Type: sel.JoinType,
			OnBase: sel.OnBase, OnJoin: sel.OnJoin, Columns: sel.Columns,
		},
	}
	// Dry-run the join so a broken definition is rejected at save time with
	// the store's validation error, not discovered on first render.
	dry := view.Join
	dry.Limit = 1
	if _, dryErr := st.ListJoinedRows(ctx, dry); dryErr != nil {
		return "", fmt.Errorf("%w: %v", errViewValidation, dryErr)
	}
	if saveErr := svs.SaveView(ctx, view); saveErr != nil {
		return "", saveErr
	}
	return slug, nil
}

const viewBuilderTemplate = `<h2>New view</h2>
<p class="muted view-desc">Views are saved joins across resources. They live in the sidebar and render as regular grids &mdash; the generated SQL stays visible, so nothing is magic.</p>
{{if .Error}}<div class="view-builder-error">{{.Error}}</div>{{end}}
<form id="view-builder" hx-post="/fragments/views/builder" hx-trigger="change" hx-target="this" hx-swap="outerHTML">
  <div class="view-builder-row">
    <label class="form-label" for="vb-base">From</label>
    <select id="vb-base" name="base">
      {{$sel := .Sel}}
      {{range .Tables}}<option value="{{.Name}}" {{if eq .Name $sel.Base}}selected{{end}}>{{.Name}}</option>{{end}}
    </select>
    <label class="form-label">Join</label>
    <span class="view-jointype">
      <label><input type="radio" name="jointype" value="left" {{if eq (printf "%s" $sel.JoinType) "left"}}checked{{end}}> &#10197; Left &mdash; keep all {{$sel.Base}} rows</label>
      <label><input type="radio" name="jointype" value="inner" {{if eq (printf "%s" $sel.JoinType) "inner"}}checked{{end}}> &#8904; Inner &mdash; only matches</label>
    </span>
    <select name="join" aria-label="Joined table">
      {{range .Tables}}{{if ne .Name $sel.Base}}<option value="{{.Name}}" {{if eq .Name $sel.Join}}selected{{end}}>{{.Name}}</option>{{end}}{{end}}
    </select>
  </div>
  <div class="view-builder-row">
    <label class="form-label">On</label>
    {{if .JoinSchema}}
    <select name="onjoin" aria-label="Join column">
      {{range .JoinSchema.Columns}}<option value="{{.Name}}" {{if eq .Name $sel.OnJoin}}selected{{end}}>{{$sel.Join}}.{{.Name}}</option>{{end}}
    </select>
    {{end}}
    <span class="muted">=</span>
    {{if .BaseSchema}}
    <select name="onbase" aria-label="Base column">
      {{range .BaseSchema.Columns}}<option value="{{.Name}}" {{if eq .Name $sel.OnBase}}selected{{end}}>{{$sel.Base}}.{{.Name}}</option>{{end}}
    </select>
    {{end}}
    <span class="muted small">suggested from foreign keys</span>
  </div>
  <div class="view-builder-row view-builder-cols">
    <label class="form-label">Columns</label>
    <div class="view-col-groups">
      {{$checked := .Selected}}
      {{if .BaseSchema}}
      <fieldset>
        <legend><code>{{.BaseSchema.Name}}</code></legend>
        {{$t := .BaseSchema.Name}}
        {{range .BaseSchema.Columns}}
        <label class="view-col-choice"><input type="checkbox" name="cols" value="{{$t}}.{{.Name}}" {{if index $checked (printf "%s.%s" $t .Name)}}checked{{end}}> {{.Name}}</label>
        {{end}}
      </fieldset>
      {{end}}
      {{if .JoinSchema}}
      <fieldset>
        <legend><code>{{.JoinSchema.Name}}</code></legend>
        {{$t := .JoinSchema.Name}}
        {{range .JoinSchema.Columns}}
        <label class="view-col-choice"><input type="checkbox" name="cols" value="{{$t}}.{{.Name}}" {{if index $checked (printf "%s.%s" $t .Name)}}checked{{end}}> {{.Name}}</label>
        {{end}}
      </fieldset>
      {{end}}
    </div>
  </div>

  {{if .PreviewSQL}}
  <div class="sql-strip sql-strip-multiline">
    <span class="sql-strip-label">SQL</span>
    <code class="sql-strip-text" id="builder-sql-text">{{.PreviewSQL}}</code>
    <button type="button" class="sql-strip-copy" data-copy-target="builder-sql-text" onclick="copyText(this)">Copy</button>
  </div>
  {{end}}
  {{if .PreviewRows}}
  <div class="view-preview-head">Preview <span class="muted small">first 10 rows{{if eq (printf "%s" $sel.JoinType) "left"}} &mdash; left join keeps base rows with no match; their joined columns render as &ldquo;&mdash;&rdquo;{{end}}</span></div>
  <table>
    <thead><tr>{{range $sel.Columns}}<th>{{.Table}}.{{.Column}}</th>{{end}}</tr></thead>
    <tbody>
    {{range .PreviewRows}}
      <tr>{{range .Columns}}<td>{{with renderCell .Value}}{{.}}{{else}}<span class="muted">&mdash;</span>{{end}}</td>{{end}}</tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  <div class="view-builder-save">
    <label class="form-label" for="vb-name">Name</label>
    <input id="vb-name" type="text" name="name" value="{{$sel.Name}}" placeholder="Name this view&hellip;" hx-trigger="none">
    {{if .CanSave}}
    <button class="btn" hx-post="/api/v1/views" hx-include="closest form" hx-target="#view-builder" hx-swap="outerHTML">Save view</button>
    <span class="muted small">appears in the sidebar under Views</span>
    {{else}}
    <span class="muted small">this dashboard mode cannot persist views &mdash; preview only</span>
    {{end}}
  </div>
</form>`
