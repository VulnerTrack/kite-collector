package dashboard

import (
	"fmt"
	"html/template"
	"io"
	"strings"
)

// The Docs page hands the user's own AI agent — or any script — read-only
// access to kite's data. Kite ships no assistant: the page is copy-paste
// snippets for the SQLite database, the dashboard's CSV endpoints, and a
// ready-made tool description for an agent config or MCP manifest.

// docsView parameterizes the snippets with the address this dashboard is
// actually being served on, so the curl examples work as pasted.
type docsView struct {
	Host string
}

var docsTmpl = template.Must(template.New("docs").Parse(docsTemplate))

// renderDocsFragment renders the Docs fragment. host is the request's Host
// header; empty falls back to the documented example address.
func renderDocsFragment(w io.Writer, host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		host = "127.0.0.1:9090"
	}
	if err := docsTmpl.Execute(w, docsView{Host: host}); err != nil {
		return fmt.Errorf("render docs template: %w", err)
	}
	return nil
}

const docsTemplate = `<h2>Docs</h2>
<p class="muted docs-intro">Everything below is copy-paste: the database, the API, and a ready-made tool description for the agent you already use &mdash; Claude Code, a script, any tool-calling model. All of it is read-only.</p>

<div class="docs-grid">
  <section class="card docs-card">
    <div class="docs-card-head">
      <h3>Query the database</h3>
      <button class="btn btn-outline btn-sm" data-copy-target="docs-snippet-db" onclick="copyText(this)">Copy</button>
    </div>
    <p class="muted small">Everything kite knows lives in one SQLite file. Point any agent at it read-only.</p>
    <pre class="docs-snippet" id="docs-snippet-db">sqlite3 -readonly ./kite.db \
  "SELECT hostname, os_family, is_authorized
   FROM machines ORDER BY last_seen_at DESC"</pre>
    <p class="muted small docs-footnote">Default path <code>./kite.db</code> &mdash; override with <code>--db</code>. The full schema is browsable under All tables.</p>
  </section>

  <section class="card docs-card">
    <div class="docs-card-head">
      <h3>Use the HTTP API</h3>
      <button class="btn btn-outline btn-sm" data-copy-target="docs-snippet-api" onclick="copyText(this)">Copy</button>
    </div>
    <p class="muted small">The dashboard serves CSV exports on localhost &mdash; same data as every grid.</p>
    <pre class="docs-snippet" id="docs-snippet-api">curl http://{{.Host}}/api/v1/machines/export.csv
curl http://{{.Host}}/api/v1/findings/export.csv
curl http://{{.Host}}/api/v1/tables/host_listeners/export.csv</pre>
    <p class="muted small docs-footnote">The dashboard is off by default &mdash; enable with <code>--dashboard-addr {{.Host}}</code>. It binds localhost only.</p>
  </section>
</div>

<section class="card docs-card docs-card-wide">
  <div class="docs-card-head">
    <h3>Hand these docs to your agent</h3>
    <button class="btn btn-outline btn-sm" data-copy-target="docs-snippet-agent" onclick="copyText(this)">Copy as Markdown</button>
  </div>
  <p class="muted small">A ready-made tool description &mdash; paste it into an agent&rsquo;s config, an MCP manifest, or a plain system prompt.</p>
  <pre class="docs-snippet" id="docs-snippet-agent">## kite-collector (local, read-only)
Machine inventory, software, and posture findings for this host and its
network. Data is collected by the local kite-collector agent.

- SQLite: ./kite.db (open read-only). Key tables: machines,
  installed_software, config_findings, host_listeners, scan_runs.
  Join on machine_id -&gt; machines.id.
- CSV API: http://{{.Host}}/api/v1/machines/export.csv
  (also /software, /findings, /tables/{name}/export.csv)
- Read-only: there is no write endpoint. Do not modify kite.db.</pre>
</section>

<div class="docs-rules">
  <div class="docs-rule">
    <h4>Read-only by construction</h4>
    <p class="muted small">The database opens read-only and the export endpoints are GET-only. A connected agent can look, never touch.</p>
  </div>
  <div class="docs-rule">
    <h4>Local by default</h4>
    <p class="muted small">The dashboard binds 127.0.0.1. Data leaves this machine only if the agent you connect sends it somewhere.</p>
  </div>
  <div class="docs-rule">
    <h4>Reproducible</h4>
    <p class="muted small">Every grid shows the SQL behind it, so anything an agent reports can be re-run and checked by hand.</p>
  </div>
</div>`
