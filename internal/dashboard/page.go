package dashboard

import (
	"fmt"
	"html/template"
	"io"
	"strings"
)

// indexPageView is the data model for the dashboard shell.
//
// ActiveTab drives the `class="active"` decoration on the matching sidebar
// link and (indirectly via InitialContent) the body of the #content div.
//
// InitialContent is the pre-rendered HTML for the active link's fragment. It
// is embedded directly into #content so the page is fully usable on first
// paint without a follow-up XHR.
type indexPageView struct {
	ActiveTab      string
	InitialContent template.HTML
}

// indexPageTemplate is the dashboard shell. The layout is a CSS grid with a
// top header (title + global controls), a left sidebar (views + tables list),
// and a central content pane that HTMX swaps fragments into.
//
// Each sidebar link uses canonical pretty URLs (e.g. /assets) for both
// `hx-get` and `href`:
//   - hx-get drives in-app HTMX swaps (HX-Request header → fragment-only)
//   - href is the no-JS / right-click / accessibility fallback
//
// hx-push-url="true" tells HTMX to push the canonical URL into history so
// browser back/forward replay correctly. hx-history-elt on #content marks
// the swap target as the element HTMX should snapshot for the cache.
const indexPageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="htmx-config" content='{"historyCacheSize": 20}'>
<title>kite-collector dashboard</title>
<link rel="stylesheet" href="/static/tabulator.min.css">
<link rel="stylesheet" href="/static/style.css">
<script src="/static/htmx.min.js"></script>
<script src="/static/tabulator.min.js"></script>
</head>
<body>
<div class="layout">

<header class="topbar">
  <a class="brand" href="https://vulnertrack.com" target="_blank" rel="noopener" aria-label="Vulnertrack">
    <img class="brand-logo"
         src="/static/img/vulnertrack_banner_dark.png"
         alt="Vulnertrack"
         width="160" height="40">
    <span class="brand-sub">kite-collector &middot; Cybersecurity Asset Discovery Agent</span>
  </a>
  <div class="topbar-actions">
    <a href="/onboarding" hx-get="/onboarding" hx-target="#content" hx-push-url="true"
       class="btn btn-ghost {{ if eq .ActiveTab "onboarding" }}active{{ end }}"
       onclick="setActive(this)">Onboarding</a>
    <span hx-get="/fragments/scan-controls" hx-trigger="load" hx-swap="innerHTML"></span>
    <div id="scan-status"
         hx-get="/fragments/scan-status"
         hx-trigger="load, every 3s"
         hx-swap="innerHTML">
      <span class="badge badge-gray">Loading scan status&hellip;</span>
    </div>
  </div>
</header>

<aside class="sidenav" aria-label="Primary navigation">
  <nav>
    <div class="sidenav-section">
      <h4>Views</h4>
      <a href="/assets" hx-get="/assets" hx-target="#content" hx-push-url="true" class="{{ if eq .ActiveTab "assets" }}active{{ end }}"
         onclick="setActive(this)">Assets</a>
      <a href="/software" hx-get="/software" hx-target="#content" hx-push-url="true" class="{{ if eq .ActiveTab "software" }}active{{ end }}"
         onclick="setActive(this)">Software</a>
      <a href="/findings" hx-get="/findings" hx-target="#content" hx-push-url="true" class="{{ if eq .ActiveTab "findings" }}active{{ end }}"
         onclick="setActive(this)">Findings</a>
      <a href="/scans" hx-get="/scans" hx-target="#content" hx-push-url="true" class="{{ if eq .ActiveTab "scans" }}active{{ end }}"
         onclick="setActive(this)">Scans</a>
      <a href="/tables" hx-get="/tables" hx-target="#content" hx-push-url="true" class="{{ if eq .ActiveTab "tables" }}active{{ end }}"
         onclick="setActive(this)">All Tables</a>
    </div>
    <div class="sidenav-section">
      <h4>Tables</h4>
      <div id="sidebar-tables"
           hx-get="/fragments/sidebar-tables"
           hx-trigger="load"
           hx-swap="innerHTML">
        <span class="muted small">Loading&hellip;</span>
      </div>
    </div>
  </nav>
</aside>

<main class="content-pane">
  <div id="content" hx-history-elt="true">
{{ .InitialContent }}
  </div>
</main>

<aside id="row-drawer" class="row-drawer" aria-hidden="true"></aside>

<footer class="vt-footer">
  <div class="vt-footer-meta">kite-collector dashboard &mdash; all data from local SQLite, no external connections</div>
  <div class="vt-powered">
    Powered by
    <a href="https://vulnertrack.com" target="_blank" rel="noopener" class="vt-brand">Vulnertrack</a>
  </div>
</footer>

</div>

<script>
function setActive(el) {
  document.querySelectorAll('.sidenav a, .topbar a.btn-ghost').forEach(function(a) { a.classList.remove('active'); });
  el.classList.add('active');
  closeRowDrawer();
}
function openRowDrawer() {
  var s = document.getElementById('row-drawer');
  if (s) { s.classList.add('row-drawer-open'); s.setAttribute('aria-hidden', 'false'); }
}
function closeRowDrawer() {
  var s = document.getElementById('row-drawer');
  if (s) { s.classList.remove('row-drawer-open'); s.setAttribute('aria-hidden', 'true'); s.innerHTML = ''; }
}
// Back-compat shims — older fragment HTML still calls openSidebar/closeSidebar.
function openSidebar() { openRowDrawer(); }
function closeSidebar() { closeRowDrawer(); }
// Tabulator integration — every server-rendered <table> wrapped in a
// .data-grid container is upgraded into a Tabulator instance with sort,
// per-column filter, pagination, and resizable/movable columns. The init
// is idempotent (data-grid-ready guard) and re-runs after each HTMX swap
// so fragments loaded into #content get the same treatment.
function initDataGrids(root) {
  if (typeof Tabulator === 'undefined') return;
  var scope = root || document;
  if (!scope.querySelectorAll) return;
  scope.querySelectorAll('.data-grid:not([data-grid-ready])').forEach(function(host) {
    var tbl = host.querySelector('table');
    if (!tbl) return;
    host.setAttribute('data-grid-ready', '1');
    var instance = new Tabulator(tbl, {
      layout: 'fitDataStretch',
      pagination: true,
      paginationSize: 25,
      paginationSizeSelector: [10, 25, 50, 100, 250, true],
      paginationCounter: 'rows',
      movableColumns: true,
      resizableColumns: true,
      placeholder: 'No rows',
      autoColumnsDefinitions: function(defs) {
        defs.forEach(function(d) {
          d.headerFilter = 'input';
          d.headerFilterLiveFilter = true;
          d.headerSort = true;
          // Preserve <span class="badge">, <code>, <a class="fk-link">,
          // and other cell HTML that Go templates emitted server-side.
          d.formatter = 'html';
        });
        return defs;
      },
    });
    // Re-scan the rebuilt DOM so HTMX picks up hx-get links Tabulator
    // re-rendered into its cell elements (e.g. table-name links on the
    // /tables overview).
    instance.on('renderComplete', function() {
      if (window.htmx && typeof htmx.process === 'function') {
        htmx.process(host);
      }
    });
  });
}
document.addEventListener('DOMContentLoaded', function() { initDataGrids(); });
document.body.addEventListener('htmx:afterSwap', function(evt) {
  initDataGrids(evt.detail && evt.detail.target);
});
</script>
</body>
</html>`

// indexPageTmpl is parsed once at package init. Parse panics on a malformed
// template — that would be a programmer error, not a runtime condition.
var indexPageTmpl = template.Must(template.New("indexPage").Parse(indexPageTemplate))

// renderIndexPage writes the full dashboard shell with the named tab marked
// active and `initialFragment` embedded inside #content. The fragment is
// rendered into an in-memory buffer first so a fragment error does not leak
// partial HTML into the response.
func renderIndexPage(w io.Writer, activeTab string, initialFragment func(io.Writer) error) error {
	var buf strings.Builder
	if err := initialFragment(&buf); err != nil {
		return fmt.Errorf("render initial fragment for %q: %w", activeTab, err)
	}
	// fragment HTML is produced by trusted in-process html/template renders
	// (renderAssetsFragment, renderTableFragment, etc.) that already escape
	// every user-controlled value via {{ .Field }} interpolation. We hand it
	// to the shell as template.HTML to avoid double-escaping the inner
	// <table>/<tr>/<td> markup into &lt;table&gt; soup.
	initialHTML := template.HTML(buf.String()) // #nosec G203 -- see comment above
	view := indexPageView{
		ActiveTab:      activeTab,
		InitialContent: initialHTML,
	}
	if err := indexPageTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("execute index page template: %w", err)
	}
	return nil
}
