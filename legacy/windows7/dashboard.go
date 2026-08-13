package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var inventoryScanMu sync.Mutex

func scanAndSaveInventory(ctx context.Context, dir string) error {
	inventoryScanMu.Lock()
	defer inventoryScanMu.Unlock()
	return saveInventory(dir, collectInventory(ctx))
}

type legacyDashboard struct {
	dir    string
	server *http.Server
}

func startLegacyDashboard(dir, addr string) (*legacyDashboard, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	d := &legacyDashboard{dir: dir}
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.serveHome)
	mux.HandleFunc("/api/v1/inventory", d.serveInventoryJSON)
	mux.HandleFunc("/api/v1/export.csv", d.serveExportCSV)
	mux.HandleFunc("/api/v1/database", d.serveDatabase)
	mux.HandleFunc("/api/v1/scan", d.serveScan)
	d.server = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	go func() { _ = d.server.Serve(listener) }()
	return d, nil
}

func (d *legacyDashboard) shutdown(ctx context.Context) error {
	if d == nil || d.server == nil {
		return nil
	}
	return d.server.Shutdown(ctx)
}

type legacyDashboardPage struct {
	Hostname    string
	CollectedAt string
	DBPath      string
	Sections    []legacyDashboardSection
	Selected    string
	Columns     []string
	Rows        []map[string]string
	Summary     inventorySummary
	Findings    []securityFinding
	Changes     []categoryChange
	History     []inventoryHistoryItem
	Errors      []inventoryErrorItem
	Error       string
}

type legacyDashboardSection struct {
	Name       string
	Categories []legacyCategorySummary
}
type legacyCategorySummary struct {
	Name, Label string
	Count       int
}
type inventoryHistoryItem struct {
	CollectedAt      string
	Categories, Rows int
}
type inventoryErrorItem struct{ Category, Error string }

func (d *legacyDashboard) serveHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	page := legacyDashboardPage{DBPath: inventoryDBPath(d.dir)}
	snapshot, err := loadLatestInventory(d.dir)
	if err != nil {
		page.Error = err.Error()
	} else {
		page.Hostname = snapshot.Hostname
		page.CollectedAt = snapshot.CollectedAt.Local().Format("2006-01-02 15:04:05 MST")
		page.Summary = summarizeInventory(snapshot)
		page.Findings = buildSecurityFindings(snapshot)
		page.Sections = buildDashboardSections(snapshot)
		page.Selected = strings.TrimSpace(r.URL.Query().Get("category"))
		if _, exists := snapshot.Categories[page.Selected]; !exists {
			page.Selected = "system"
		}
		if _, exists := snapshot.Categories[page.Selected]; !exists {
			names := inventoryCategoryNames(snapshot)
			if len(names) > 0 {
				page.Selected = names[0]
			}
		}
		page.Rows = snapshot.Categories[page.Selected]
		page.Columns = rowColumns(page.Rows)
		for category, errorText := range snapshot.Errors {
			page.Errors = append(page.Errors, inventoryErrorItem{category, errorText})
		}
		sort.Slice(page.Errors, func(i, j int) bool { return page.Errors[i].Category < page.Errors[j].Category })
		history, historyErr := loadInventoryHistory(d.dir, 30)
		if historyErr == nil {
			for _, item := range history {
				rows := 0
				for _, values := range item.Categories {
					rows += len(values)
				}
				page.History = append(page.History, inventoryHistoryItem{item.CollectedAt.Local().Format("2006-01-02 15:04:05"), len(item.Categories), rows})
			}
			if len(history) > 1 {
				page.Changes = compareSnapshots(&history[0], &history[1])
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := legacyDashboardTemplate.Execute(w, page); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func buildDashboardSections(snapshot *inventorySnapshot) []legacyDashboardSection {
	seen := make(map[string]bool)
	var sections []legacyDashboardSection
	for _, definition := range categorySections {
		section := legacyDashboardSection{Name: definition.Name}
		for _, name := range definition.Categories {
			if rows, exists := snapshot.Categories[name]; exists {
				section.Categories = append(section.Categories, legacyCategorySummary{name, categoryLabel(name), len(rows)})
				seen[name] = true
			}
		}
		if len(section.Categories) > 0 {
			sections = append(sections, section)
		}
	}
	other := legacyDashboardSection{Name: "Other"}
	for _, name := range inventoryCategoryNames(snapshot) {
		if !seen[name] {
			other.Categories = append(other.Categories, legacyCategorySummary{name, categoryLabel(name), len(snapshot.Categories[name])})
		}
	}
	if len(other.Categories) > 0 {
		sections = append(sections, other)
	}
	return sections
}

func categoryLabel(name string) string {
	label := strings.ReplaceAll(name, "_", " ")
	if label == "installed software native" {
		return "Installed software"
	}
	if label == "installed software wow64" {
		return "Installed software (Wow64)"
	}
	return strings.Title(label) //nolint:staticcheck -- Go 1.17 compatibility module
}

func rowColumns(rows []map[string]string) []string {
	set := make(map[string]bool)
	for _, row := range rows {
		for column := range row {
			set[column] = true
		}
	}
	columns := make([]string, 0, len(set))
	for column := range set {
		columns = append(columns, column)
	}
	sort.Strings(columns)
	for _, preferred := range []string{"name", "displayName", "Name", "version", "publisher", "State", "Status", "line"} {
		for i, column := range columns {
			if column == preferred {
				columns[0], columns[i] = columns[i], columns[0]
				return columns
			}
		}
	}
	return columns
}

func (d *legacyDashboard) serveInventoryJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="kite-inventory.json"`)
	category := strings.TrimSpace(r.URL.Query().Get("category"))
	if category != "" {
		rows, err := loadInventoryCategory(d.dir, category)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(rows)
		return
	}
	snapshot, err := loadLatestInventory(d.dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(snapshot)
}

func (d *legacyDashboard) serveExportCSV(w http.ResponseWriter, r *http.Request) {
	category := strings.TrimSpace(r.URL.Query().Get("category"))
	rows, err := loadInventoryCategory(d.dir, category)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	columns := rowColumns(rows)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="kite-`+safeFilename(category)+`.csv"`)
	_, _ = w.Write([]byte{0xef, 0xbb, 0xbf})
	writer := csv.NewWriter(w)
	_ = writer.Write(columns)
	for _, row := range rows {
		record := make([]string, len(columns))
		for i, column := range columns {
			record[i] = row[column]
		}
		_ = writer.Write(record)
	}
	writer.Flush()
}

func safeFilename(value string) string {
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "inventory"
	}
	return b.String()
}

func (d *legacyDashboard) serveDatabase(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Disposition", `attachment; filename="kite.db"`)
	http.ServeFile(w, r, filepath.Clean(inventoryDBPath(d.dir)))
}

func (d *legacyDashboard) serveScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Minute)
	defer cancel()
	if err := scanAndSaveInventory(ctx, d.dir); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func openLegacyDashboard(addr string) {
	target := "http://" + addr + "/"
	if host, port, err := net.SplitHostPort(addr); err == nil && (host == "0.0.0.0" || host == "::") {
		target = "http://127.0.0.1:" + port + "/"
	}
	_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", target).Start()
}

var legacyDashboardTemplate = template.Must(template.New("dashboard").Funcs(template.FuncMap{
	"cell":     func(row map[string]string, column string) string { return row[column] },
	"link":     func(category string) string { return "/?category=" + url.QueryEscape(category) },
	"csvlink":  func(category string) string { return "/api/v1/export.csv?category=" + url.QueryEscape(category) },
	"jsonlink": func(category string) string { return "/api/v1/inventory?category=" + url.QueryEscape(category) },
	"lower":    strings.ToLower,
	"delta": func(value int) string {
		if value > 0 {
			return "+" + strconv.Itoa(value)
		}
		return strconv.Itoa(value)
	},
}).Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Kite Windows Inventory</title>
<style>
*{box-sizing:border-box}body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f3f5f8;color:#20252b}header{background:#141922;color:#fff;padding:17px 24px;display:flex;justify-content:space-between;align-items:center}main{padding:20px;max-width:1800px;margin:auto}h1{margin:0 0 6px}.meta,.muted{color:#667085;font-size:13px}.actions{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}.btn,button{display:inline-block;background:#d71942;color:#fff;border:0;border-radius:5px;padding:9px 14px;text-decoration:none;cursor:pointer;font-size:13px}.btn.secondary{background:#344054}.summary{display:grid;grid-template-columns:repeat(4,minmax(170px,1fr));gap:10px;margin:14px 0}.stat,.card{background:#fff;border:1px solid #dfe3e8;border-radius:8px;padding:14px}.stat strong{display:block;font-size:18px;margin-top:4px}.grid{display:grid;grid-template-columns:280px minmax(0,1fr);gap:16px}.categories h3{font-size:12px;text-transform:uppercase;color:#667085;margin:16px 8px 5px}.categories a{display:flex;justify-content:space-between;padding:7px 9px;text-decoration:none;color:#253858;border-radius:4px}.categories a:hover,.categories a.active{background:#e9f2ff}.badge{background:#e7eef8;border-radius:12px;padding:2px 8px;font-size:12px}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px}.toolbar input{padding:8px;width:280px;border:1px solid #cfd4dc;border-radius:4px}.table-wrap{max-height:650px;overflow:auto}table{border-collapse:collapse;width:100%;font-size:12px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #e8eaed;padding:7px;max-width:440px;word-break:break-word}th{position:sticky;top:0;background:#f8fafc;cursor:pointer;z-index:1}.error{background:#fff1f1;color:#9b1c1c;padding:12px;border-radius:5px}.panels{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}.finding{border-left:4px solid #98a2b3;padding:8px 10px;margin:7px 0;background:#f8fafc}.finding.high{border-color:#d92d20}.finding.medium{border-color:#f79009}.finding.info{border-color:#2e90fa}.pager{display:flex;gap:8px;align-items:center;justify-content:flex-end;margin-top:10px}.pager button{padding:5px 9px}.errors details{margin:5px 0}.change-up{color:#b42318}.change-down{color:#027a48}@media(max-width:1000px){.summary{grid-template-columns:repeat(2,1fr)}.grid,.panels{grid-template-columns:1fr}}@media(max-width:560px){.summary{grid-template-columns:1fr}}
</style></head><body><header><strong>Kite Collector &mdash; Windows 7</strong><span>Local-only inventory</span></header><main>
<h1>{{if .Hostname}}{{.Hostname}}{{else}}Local inventory{{end}}</h1><p class="meta">Database: <code>{{.DBPath}}</code>{{if .CollectedAt}} &middot; Last scan: {{.CollectedAt}}{{end}}</p>
<div class="actions"><form method="post" action="/api/v1/scan"><button type="submit">Run full scan</button></form><a class="btn secondary" href="/api/v1/inventory">Export all JSON</a><a class="btn secondary" href="/api/v1/database">Download kite.db</a></div>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<section class="summary"><div class="stat"><span>Operating system</span><strong>{{.Summary.OS}}</strong></div><div class="stat"><span>Model</span><strong>{{.Summary.Model}}</strong></div><div class="stat"><span>CPU</span><strong>{{.Summary.CPU}}</strong></div><div class="stat"><span>Memory</span><strong>{{.Summary.Memory}}</strong></div><div class="stat"><span>Disk</span><strong>{{.Summary.Disk}}</strong></div><div class="stat"><span>IP addresses</span><strong>{{.Summary.IP}}</strong></div><div class="stat"><span>Software</span><strong>{{.Summary.Software}}</strong></div><div class="stat"><span>Services / ports</span><strong>{{.Summary.Services}} / {{.Summary.Ports}}</strong></div></section>
<div class="grid"><aside class="card categories">{{range .Sections}}<h3>{{.Name}}</h3>{{range .Categories}}<a href="{{link .Name}}" class="{{if eq $.Selected .Name}}active{{end}}"><span>{{.Label}}</span><span class="badge">{{.Count}}</span></a>{{end}}{{end}}</aside>
<section class="card"><h2>{{.Selected}}</h2><div class="toolbar"><input id="search" placeholder="Search this category..." onkeyup="filterRows()"><a class="btn secondary" href="{{csvlink .Selected}}">CSV</a><a class="btn secondary" href="{{jsonlink .Selected}}">JSON</a><span id="resultCount" class="muted"></span></div><div class="table-wrap"><table id="inventoryTable"><thead><tr>{{range .Columns}}<th onclick="sortTable(this.cellIndex)">{{.}}</th>{{end}}</tr></thead><tbody>{{range .Rows}}{{$row := .}}<tr>{{range $.Columns}}<td>{{cell $row .}}</td>{{end}}</tr>{{end}}</tbody></table></div><div class="pager"><button type="button" onclick="changePage(-1)">Previous</button><span id="pageInfo"></span><button type="button" onclick="changePage(1)">Next</button></div></section></div>
<div class="panels"><section class="card"><h2>Security findings</h2>{{if .Findings}}{{range .Findings}}<div class="finding {{lower .Severity}}"><strong>{{.Severity}} &middot; {{.Title}}</strong><div>{{.Detail}}</div><a href="{{link .Category}}">Open evidence</a></div>{{end}}{{else}}<p>No heuristic findings in the latest scan.</p>{{end}}</section>
<section class="card"><h2>Changes since previous scan</h2>{{if .Changes}}<table><tr><th>Category</th><th>Before</th><th>Now</th><th>Delta</th></tr>{{range .Changes}}<tr><td>{{.Category}}</td><td>{{.Before}}</td><td>{{.After}}</td><td class="{{if gt .Delta 0}}change-up{{else}}change-down{{end}}">{{delta .Delta}}</td></tr>{{end}}</table>{{else}}<p>No count changes, or this is the first snapshot.</p>{{end}}<h3>Snapshot history</h3>{{range .History}}<div class="muted">{{.CollectedAt}} &middot; {{.Categories}} categories &middot; {{.Rows}} rows</div>{{end}}</section></div>
{{if .Errors}}<section class="card errors" style="margin-top:16px"><h2>Collector diagnostics ({{len .Errors}})</h2><p class="muted">Unsupported or failed Windows interfaces are visible here instead of silently disappearing.</p>{{range .Errors}}<details><summary>{{.Category}}</summary><pre>{{.Error}}</pre></details>{{end}}</section>{{end}}
</main><script>
var page=1,pageSize=50,visible=[];function rows(){return Array.prototype.slice.call(document.querySelectorAll('#inventoryTable tbody tr'));}function filterRows(){var q=document.getElementById('search').value.toLowerCase();visible=[];rows().forEach(function(r){if(r.innerText.toLowerCase().indexOf(q)>=0)visible.push(r);});page=1;renderPage();}function renderPage(){rows().forEach(function(r){r.style.display='none';});var pages=Math.max(1,Math.ceil(visible.length/pageSize));if(page>pages)page=pages;visible.slice((page-1)*pageSize,page*pageSize).forEach(function(r){r.style.display='table-row';});document.getElementById('pageInfo').innerText='Page '+page+' / '+pages;document.getElementById('resultCount').innerText=visible.length+' rows';}function changePage(d){page+=d;if(page<1)page=1;renderPage();}function sortTable(n){visible.sort(function(a,b){return a.cells[n].innerText.localeCompare(b.cells[n].innerText);});var body=document.querySelector('#inventoryTable tbody');visible.forEach(function(r){body.appendChild(r);});renderPage();}window.onload=function(){visible=rows();renderPage();};
</script></body></html>`))

func dashboardURL(addr string) string { return fmt.Sprintf("http://%s/", addr) }
