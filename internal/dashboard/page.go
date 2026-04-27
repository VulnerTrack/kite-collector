package dashboard

import (
	"fmt"
	"html/template"
	"io"
	"strings"
)

// indexPageView is the data model for the dashboard shell.
//
// ActiveTab drives both the `class="active"` decoration on the matching nav
// link and (indirectly via InitialContent) the body of the #content div.
//
// InitialContent is the pre-rendered HTML for the active tab's fragment. It
// is embedded directly into #content so the page is fully usable on first
// paint without a follow-up XHR — this also avoids the original race where
// the auto-loading #content's `hx-trigger="load"` would fire concurrently
// with whatever the user actually navigated to.
type indexPageView struct {
	ActiveTab      string
	InitialContent template.HTML
}

// indexPageTemplate is the dashboard shell. Each nav link uses canonical
// pretty URLs (e.g. /assets) for both `hx-get` and `href`:
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
<link rel="stylesheet" href="/static/style.css">
<script src="/static/htmx.min.js"></script>
</head>
<body>
<div class="container">

<header>
  <h1>kite-collector</h1>
  <div class="meta">
    <span>Cybersecurity Asset Discovery Agent</span>
  </div>
</header>

<nav>
  <a href="/assets" hx-get="/assets" hx-target="#content" hx-push-url="true" class="{{ if eq .ActiveTab "assets" }}active{{ end }}"
     onclick="setActive(this)">Assets</a>
  <a href="/software" hx-get="/software" hx-target="#content" hx-push-url="true" class="{{ if eq .ActiveTab "software" }}active{{ end }}"
     onclick="setActive(this)">Software</a>
  <a href="/findings" hx-get="/findings" hx-target="#content" hx-push-url="true" class="{{ if eq .ActiveTab "findings" }}active{{ end }}"
     onclick="setActive(this)">Findings</a>
  <a href="/scans" hx-get="/scans" hx-target="#content" hx-push-url="true" class="{{ if eq .ActiveTab "scans" }}active{{ end }}"
     onclick="setActive(this)">Scans</a>
  <a href="/tables" hx-get="/tables" hx-target="#content" hx-push-url="true" class="{{ if eq .ActiveTab "tables" }}active{{ end }}"
     onclick="setActive(this)">Tables</a>
  <a href="/onboarding">Onboarding</a>
  <div style="flex:1"></div>
  <span hx-get="/fragments/scan-controls" hx-trigger="load" hx-swap="innerHTML"></span>
</nav>

<div id="scan-status"
     hx-get="/fragments/scan-status"
     hx-trigger="load, every 3s"
     hx-swap="innerHTML">
  <span class="badge badge-gray">Loading scan status…</span>
</div>

<div id="content" hx-history-elt="true">
{{ .InitialContent }}
</div>

<aside id="sidebar" class="sidebar" aria-hidden="true"></aside>

<footer>
  kite-collector dashboard &mdash; all data from local SQLite, no external connections
</footer>

</div>

<script>
function setActive(el) {
  document.querySelectorAll('nav a').forEach(function(a) { a.classList.remove('active'); });
  el.classList.add('active');
  closeSidebar();
}
function openSidebar() {
  var s = document.getElementById('sidebar');
  if (s) { s.classList.add('sidebar-open'); s.setAttribute('aria-hidden', 'false'); }
}
function closeSidebar() {
  var s = document.getElementById('sidebar');
  if (s) { s.classList.remove('sidebar-open'); s.setAttribute('aria-hidden', 'true'); s.innerHTML = ''; }
}
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
