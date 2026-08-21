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
	// SidebarTree is the static (count-less) resource tree, pre-rendered so
	// navigation works before — and without — JS. Once the page is up, HTMX
	// swaps in the counted variant from /fragments/sidebar-tree.
	SidebarTree template.HTML
}

// indexPageTemplate is the dashboard shell. The layout is a CSS grid with a
// top header (title + global controls), a left sidebar (views + tables list),
// and a central content pane that HTMX swaps fragments into.
//
// Each sidebar link uses canonical pretty URLs (e.g. /machines) for both
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
<link rel="icon" type="image/png" sizes="32x32" href="/static/img/favicon-32.png">
<link rel="icon" href="/favicon.ico" sizes="48x48 32x32 16x16">
<link rel="apple-touch-icon" href="/static/img/apple-touch-icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap">
<link rel="stylesheet" href="/static/tabulator.min.css">
<link rel="stylesheet" href="/static/style.css?v=1.0.6">
<script src="/static/htmx.min.js"></script>
<script src="/static/tabulator.min.js"></script>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body>
<a class="skip-link" href="#content">Skip to main content</a>
<div class="layout">

<header class="topbar">
  <a class="brand" href="https://vulnertrack.com" target="_blank" rel="noopener" aria-label="Vulnertrack">
    <img class="brand-logo"
         src="/static/img/vulnertrack_banner_dark.png"
         alt="Vulnertrack"
         width="160" height="40">
    <span class="brand-sub">kite-collector &middot; Cybersecurity Machine Discovery Agent</span>
  </a>
  <div class="topbar-nav">
    <span id="onboarding-status-badge"
          hx-get="/fragments/onboarding-status-badge"
          hx-trigger="load, every 30s, refresh-agent-state from:body"
          hx-swap="innerHTML"
          title="Agent onboarding health — drill in via Settings &rarr; Onboarding"
          aria-label="Agent health summary"></span>
  </div>
  <div class="topbar-actions">
    <div class="topbar-scan-group">
      <span hx-get="/fragments/scan-controls" hx-trigger="load" hx-swap="innerHTML"></span>
      <div id="scan-status"
           hx-get="/fragments/scan-status"
           hx-trigger="load, every 3s"
           hx-swap="innerHTML">
        <span class="badge badge-gray">Loading scan status&hellip;</span>
      </div>
    </div>
  </div>
</header>

<aside class="sidenav" aria-label="Primary navigation">
  <div class="sidenav-filter">
    <input type="search" id="sidenav-filter" placeholder="Filter resources, views, tables"
           aria-label="Filter navigation" oninput="filterSidenav(this.value)" autocomplete="off">
  </div>
  <nav id="sidenav-tree"
       hx-get="/fragments/sidebar-tree?active={{.ActiveTab}}"
       hx-trigger="load"
       hx-swap="innerHTML">
{{ .SidebarTree }}
  </nav>
</aside>

<main class="content-pane" id="main-content">
  <div id="content" hx-history-elt="true" tabindex="-1">
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
// Sidebar filter — hides non-matching links and any section left empty. A
// match inside the collapsed "All tables" group pops it open so hits are
// visible; clearing the query re-collapses it.
function filterSidenav(q) {
  q = (q || '').trim().toLowerCase();
  document.querySelectorAll('#sidenav-tree .sidenav-section').forEach(function(section) {
    var any = false;
    section.querySelectorAll('a').forEach(function(a) {
      var hit = !q || a.textContent.toLowerCase().indexOf(q) !== -1;
      a.style.display = hit ? '' : 'none';
      if (a.parentElement && a.parentElement.tagName === 'LI') {
        a.parentElement.style.display = hit ? '' : 'none';
      }
      if (hit) any = true;
    });
    section.style.display = any ? '' : 'none';
    var det = section.querySelector('details');
    if (det) { det.open = !!q && any; }
  });
}
// Clipboard helper for docs snippets and SQL strips: copies the text content
// of the element named by data-copy-target (or the data-copy attribute) and
// flashes the button label as feedback.
function copyText(btn) {
  var targetID = btn.getAttribute('data-copy-target');
  var text = '';
  if (targetID) {
    var el = document.getElementById(targetID);
    if (el) text = el.textContent;
  } else {
    text = btn.getAttribute('data-copy') || '';
  }
  if (!text || !navigator.clipboard) return;
  navigator.clipboard.writeText(text).then(function() {
    var prev = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(function() { btn.textContent = prev; }, 1200);
  });
}
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
      selectableRows: true,
      selectableRowsPersistence: false,
      placeholder: 'No rows',
      // columnDefaults applies to every column, including those parsed
      // from <thead> on HTML-table init. autoColumnsDefinitions only
      // fires when autoColumns:true, which is not the case here, so the
      // html formatter must be set as a default to keep server-emitted
      // <span class="badge">, <code>, <a class="fk-link"> rendering.
      columnDefaults: {
        formatter: 'html',
        headerFilter: 'input',
        headerFilterLiveFilter: true,
        headerSort: true,
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
    attachCopyBar(host, instance);
  });
}

// --- Grid copy affordances -------------------------------------------------
// Selected rows (or the visible grid) copy to the clipboard as CSV, TSV,
// Markdown, or JSON; a single column copies as one value per line. The bar
// appears above a grid once rows are selected.
function gridPlainText(value) {
  if (value === null || value === undefined) return '';
  var div = document.createElement('div');
  div.innerHTML = String(value);
  return div.textContent || '';
}
function gridColumnDefs(instance) {
  return instance.getColumnDefinitions().filter(function(def) { return !!def.field; });
}
function gridRowsToText(defs, rows, format) {
  var headers = defs.map(function(def) { return gridPlainText(def.title || def.field); });
  var table = rows.map(function(row) {
    return defs.map(function(def) { return gridPlainText(row[def.field]); });
  });
  if (format === 'json') {
    return JSON.stringify(table.map(function(vals) {
      var obj = {};
      headers.forEach(function(h, i) { obj[h] = vals[i]; });
      return obj;
    }), null, 2);
  }
  if (format === 'tsv') {
    return [headers.join('\t')].concat(table.map(function(vals) { return vals.join('\t'); })).join('\n');
  }
  if (format === 'markdown') {
    var lines = ['| ' + headers.join(' | ') + ' |',
                 '| ' + headers.map(function() { return '---'; }).join(' | ') + ' |'];
    table.forEach(function(vals) {
      lines.push('| ' + vals.map(function(v) { return v.replace(/\|/g, '\\|'); }).join(' | ') + ' |');
    });
    return lines.join('\n');
  }
  var esc = function(v) { return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  return [headers.map(esc).join(',')].concat(table.map(function(vals) {
    return vals.map(esc).join(',');
  })).join('\n');
}
function gridCopy(text, btn) {
  if (!navigator.clipboard) return;
  navigator.clipboard.writeText(text).then(function() {
    var prev = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(function() { btn.textContent = prev; }, 1200);
  });
}
function attachCopyBar(host, instance) {
  if (host.previousElementSibling && host.previousElementSibling.classList &&
      host.previousElementSibling.classList.contains('grid-copy-bar')) {
    return;
  }
  var bar = document.createElement('div');
  bar.className = 'grid-copy-bar';
  bar.style.display = 'none';
  host.parentNode.insertBefore(bar, host);

  function copyButton(label, getText) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'grid-copy-btn';
    btn.textContent = label;
    btn.addEventListener('click', function() { gridCopy(getText(), btn); });
    return btn;
  }

  function render() {
    var selected = instance.getSelectedData();
    if (!selected.length) { bar.style.display = 'none'; bar.innerHTML = ''; return; }
    var defs = gridColumnDefs(instance);
    bar.innerHTML = '';
    bar.style.display = '';

    var count = document.createElement('span');
    count.className = 'grid-copy-count';
    count.textContent = selected.length + ' row' + (selected.length === 1 ? '' : 's') + ' selected';
    bar.appendChild(count);

    var label = document.createElement('span');
    label.className = 'grid-copy-label';
    label.textContent = 'copy as';
    bar.appendChild(label);

    ['csv', 'tsv', 'markdown', 'json'].forEach(function(format) {
      bar.appendChild(copyButton(format.toUpperCase().replace('MARKDOWN', 'Markdown'), function() {
        return gridRowsToText(defs, instance.getSelectedData(), format);
      }));
    });

    var colSelect = document.createElement('select');
    colSelect.className = 'grid-copy-select';
    defs.forEach(function(def) {
      var opt = document.createElement('option');
      opt.value = def.field;
      opt.textContent = def.title || def.field;
      colSelect.appendChild(opt);
    });
    bar.appendChild(colSelect);
    bar.appendChild(copyButton('Copy column', function() {
      return instance.getSelectedData().map(function(row) {
        return gridPlainText(row[colSelect.value]);
      }).join('\n');
    }));

    bar.appendChild(copyButton('Copy visible grid', function() {
      return gridRowsToText(defs, instance.getData('active'), 'csv');
    }));

    var clear = document.createElement('button');
    clear.type = 'button';
    clear.className = 'grid-copy-clear';
    clear.textContent = 'Clear';
    clear.addEventListener('click', function() { instance.deselectRow(); });
    bar.appendChild(clear);
  }

  instance.on('rowSelectionChanged', render);
}
function renderTurnstileWidgets(root) {
  if (!window.turnstile) {
    return;
  }
  if (typeof turnstile.implicitRender === 'function') {
    turnstile.implicitRender();
    return;
  }
  if (typeof turnstile.render !== 'function') {
    return;
  }
  var scope = root || document;
  scope.querySelectorAll('.cf-turnstile').forEach(function(el) {
    if (el.dataset.turnstileRendered === '1' || el.querySelector('iframe')) {
      return;
    }
    try {
      turnstile.render(el);
      el.dataset.turnstileRendered = '1';
    } catch (_) {}
  });
}
document.addEventListener('DOMContentLoaded', function() {
  initDataGrids();
  renderTurnstileWidgets();
});
document.body.addEventListener('htmx:afterSwap', function(evt) {
  initDataGrids(evt.detail && evt.detail.target);
  renderTurnstileWidgets(evt.detail && evt.detail.target);
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
	// (renderMachinesFragment, renderTableFragment, etc.) that already escape
	// every user-controlled value via {{ .Field }} interpolation. We hand it
	// to the shell as template.HTML to avoid double-escaping the inner
	// <table>/<tr>/<td> markup into &lt;table&gt; soup.
	initialHTML := template.HTML(buf.String()) // #nosec G203 -- see comment above
	view := indexPageView{
		ActiveTab:      activeTab,
		InitialContent: initialHTML,
		SidebarTree:    renderSidebarTreeStatic(activeTab),
	}
	if err := indexPageTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("execute index page template: %w", err)
	}
	return nil
}
