package dashboard

import "html/template"

// certificatesFragmentTmpl renders the whole certificates page body in every
// page mode. The "This computer" card renders in every mode — it comes from
// local disk and never needs the platform session.
var certificatesFragmentTmpl = template.Must(template.New("certificates").Parse(`
{{define "certLocalCard"}}
<section class="card cert-card">
  <h4 class="cert-card-label{{if eq .Local.PKIMatch "drift"}} cert-label-drift{{end}}">This computer{{if eq .Local.PKIMatch "drift"}} · identity drift{{end}}</h4>
  {{if .Local.HasCert}}
    <div class="cert-idcard">
      <div class="cert-gauge" role="img" aria-label="{{.Local.DaysLeft}} days of certificate validity remaining">
        <svg viewBox="0 0 72 72" width="72" height="72">
          <circle cx="36" cy="36" r="30" fill="none" stroke="currentColor" stroke-opacity="0.12" stroke-width="7"/>
          <circle cx="36" cy="36" r="30" fill="none" stroke="{{if .Local.Expired}}#dc2626{{else if lt .Local.DaysLeft 30}}#e8a13d{{else}}#22c55e{{end}}" stroke-width="7"
                  stroke-dasharray="{{.Local.GaugePct}} 100" pathLength="100" stroke-linecap="round" transform="rotate(-90 36 36)"/>
        </svg>
        <div class="cert-gauge-num">{{if .Local.Expired}}0d{{else}}{{.Local.DaysLeft}}d{{end}}<small>left</small></div>
      </div>
      <div class="cert-idmeta">
        <div class="cert-idrow"><span class="cert-k">Agent code</span><code>{{.Local.AgentCode}}</code></div>
        <div class="cert-idrow"><span class="cert-k">Certificate</span>
          {{if .Local.Expired}}<span class="badge badge-expired">expired</span>{{else if lt .Local.DaysLeft 30}}<span class="badge badge-yellow">expiring</span>{{else}}<span class="badge badge-green">active</span>{{end}}
          <span class="muted small">expires {{.Local.NotAfter}}{{if .Local.SubjectCN}} · CN {{.Local.SubjectCN}}{{end}}</span></div>
        <div class="cert-idrow"><span class="cert-k">Fingerprint</span><code class="cert-fp" title="{{.Local.FingerprintFull}}">{{.Local.Fingerprint}}</code>
          {{if eq .Local.PKIMatch "match"}}<span class="cert-match ok">&#10003; disk matches the PKI-active record</span>
          {{else if eq .Local.PKIMatch "drift"}}<span class="cert-match bad">&#9888; not the certificate PKI considers active ({{.Local.PKIActiveShort}}) — re-enroll to converge</span>
          {{else if eq .Local.PKIMatch "absent"}}<span class="cert-match bad">&#9888; no active PKI record for this agent code</span>
          {{else if eq .Local.PKIMatch "unverified"}}<span class="cert-match dim">&#9675; not verified against PKI</span>{{end}}</div>
        {{if eq .Local.PKIMatch "drift"}}
          <div class="cert-idrow"><span class="cert-k"></span><a class="btn btn-ghost" href="/onboarding?step=enroll">Re-enroll now</a></div>
        {{end}}
      </div>
    </div>
  {{else if .Local.ReadError}}
    <p class="muted small">Could not read <code>agent.pem</code> in <code>{{.Local.CertsDir}}</code>: {{.Local.ReadError}}</p>
  {{else}}
    <p class="muted small">No enrollment certificate on this machine (<code>{{.Local.CertsDir}}</code>).
       <a href="/onboarding?step=enroll">Enroll this computer</a> to issue one.</p>
  {{end}}
</section>
{{end}}

<div id="certificates-root"
     hx-get="{{.WrapperURL}}"
     {{if not .Paused}}hx-trigger="every 60s"{{end}}
     hx-swap="outerHTML">

<div class="cert-head">
  <div>
    <h2>Certificates</h2>
    <p class="muted small cert-tenant">{{if .Tenant}}Tenant <code>{{.Tenant}}</code> · {{end}}VulnerTrack PKI · fleet identity</p>
  </div>
  <span class="freshness-chip {{if .Paused}}freshness-chip--paused{{else}}freshness-chip--live{{end}}" role="status">
    <span class="freshness-chip-dot {{if .Paused}}freshness-chip-dot--paused{{else}}freshness-chip-dot--live{{end}}" aria-hidden="true"></span>
    {{if .Paused}}<span>Paused</span>{{else}}<span>Live · 60s</span>{{end}}
    <a class="freshness-chip-toggle" href="{{.ToggleURL}}" hx-get="{{.ToggleURL}}" hx-target="#certificates-root" hx-swap="outerHTML">{{if .Paused}}Resume{{else}}Pause{{end}}</a>
  </span>
</div>

{{template "certLocalCard" .}}

{{if eq .Mode "signin"}}
  <section class="cert-hero">
    <div class="cert-hero-icon" aria-hidden="true">&#128272;</div>
    <div>
      <h5>Sign in to see your fleet&rsquo;s certificates</h5>
      <p class="muted">{{if .Error}}{{.Error}}{{else}}This computer&rsquo;s certificate above is read from local disk. The tenant
         inventory — every certificate your enrollments have issued, with expiries and
         revocations — lives in VulnerTrack PKI and needs your operator session.{{end}}</p>
      <a class="btn btn-primary cert-signin" href="{{.SignInURL}}">Sign in with VulnerTrack</a>
      <p class="muted small">Opens your browser and returns to this page. The dashboard keeps a
         read-only operator token; certificate private keys never leave their machines.</p>
    </div>
  </section>

{{else if eq .Mode "unavailable"}}
  <section class="cert-hero">
    <div class="cert-hero-icon" aria-hidden="true">&#128683;</div>
    <div>
      <h5>Tenant inventory unavailable in this dashboard mode</h5>
      <p class="muted">This dashboard was started without a PKI connection (inspector mode).
         The local certificate above still works; start the installed service&rsquo;s dashboard
         to browse the tenant inventory.</p>
    </div>
  </section>

{{else if eq .Mode "error"}}
  <section class="cert-hero">
    <div class="cert-hero-icon" aria-hidden="true">&#9940;</div>
    <div>
      <h5>VulnerTrack PKI is unreachable</h5>
      <p class="muted">The inventory request failed: <code>{{.Error}}</code>.
         Your session is fine — this is network or service.</p>
      <a class="btn btn-primary cert-signin" href="{{.WrapperURL}}" hx-get="{{.WrapperURL}}" hx-target="#certificates-root" hx-swap="outerHTML">Retry</a>
      <span class="muted small cert-hero-side">or run <code>kite-collector doctor</code></span>
    </div>
  </section>

{{else if eq .Mode "empty"}}
  <section class="cert-hero">
    <div class="cert-hero-icon" aria-hidden="true">&#129714;</div>
    <div>
      <h5>No certificates issued for this tenant yet</h5>
      <p class="muted">You&rsquo;re signed in and the PKI answered: zero certificates. Each enrollment
         issues one certificate per computer — rows appear here within seconds of each computer
         completing enrollment.</p>
      <a class="btn btn-primary cert-signin" href="/onboarding?step=enroll">Enroll this computer</a>
      <a class="btn btn-ghost" href="/fleet" hx-get="/fleet" hx-target="#content" hx-push-url="true">Mass deployment &rarr;</a>
    </div>
  </section>

{{else}}
  {{if eq .Mode "session-expired"}}
    <div class="cert-stale-ribbon">&#9888; Your VulnerTrack session expired. Showing the inventory
      fetched at <strong>{{.StaleAt}}</strong> · <a href="{{.SignInURL}}">Sign in again</a> to refresh.</div>
  {{end}}

  <div class="cert-chips" aria-label="Certificate counts and filters">
    <a class="cert-chip c-green{{if eq .Filter "active"}} on{{end}}" href="{{call .ChipURL "active"}}" hx-get="{{call .ChipURL "active"}}" hx-target="#content" hx-push-url="true"><b>{{.Counts.Active}}</b> active</a>
    <a class="cert-chip c-amber{{if eq .Filter "expiring"}} on{{end}}" href="{{call .ChipURL "expiring"}}" hx-get="{{call .ChipURL "expiring"}}" hx-target="#content" hx-push-url="true"><b>{{.Counts.Expiring}}</b> expiring &le;30d</a>
    <a class="cert-chip c-red{{if eq .Filter "expired"}} on{{end}}" href="{{call .ChipURL "expired"}}" hx-get="{{call .ChipURL "expired"}}" hx-target="#content" hx-push-url="true"><b>{{.Counts.Expired}}</b> expired</a>
    <a class="cert-chip c-red{{if eq .Filter "revoked"}} on{{end}}" href="{{call .ChipURL "revoked"}}" hx-get="{{call .ChipURL "revoked"}}" hx-target="#content" hx-push-url="true"><b>{{.Counts.Revoked}}</b> revoked</a>
    <a class="cert-chip c-gray{{if eq .Filter "history"}} on{{end}}" href="{{call .ChipURL "history"}}" hx-get="{{call .ChipURL "history"}}" hx-target="#content" hx-push-url="true"><b>{{.Counts.History}}</b> history</a>
  </div>

  {{if .HorizonSVG}}
  <section class="card cert-card">
    <h4 class="cert-card-label">Renewal horizon · next 90 days</h4>
    <div class="cert-horizon">{{.HorizonSVG}}</div>
  </section>
  {{end}}

  <section class="card cert-card{{if eq .Mode "session-expired"}} cert-stale{{end}}">
    <h4 class="cert-card-label">Tenant inventory · attention first{{if eq .Mode "session-expired"}} · stale{{end}}</h4>
    {{if .Rows}}
    <div class="observability-table-wrap">
    <table class="observability-table cert-table">
      <thead><tr><th>Status</th><th>Agent</th><th>Expires</th><th>Issued</th><th>Key</th><th>Fingerprint</th><th aria-label="Details"></th></tr></thead>
      <tbody>
      {{range .Rows}}
        <tr{{if .Attention}} class="cert-attn"{{else if .IsHistory}} class="cert-hist"{{end}}>
          <td><span class="badge {{.BadgeClass}}">{{.BadgeLabel}}</span>{{if .BadgeNote}}<span class="cert-sub">{{.BadgeNote}}</span>{{end}}</td>
          <td><code>{{.AgentCode}}</code>{{if .IsLocal}}<span class="cert-sub">this computer</span>{{else if .SubjectCN}}<span class="cert-sub">{{.SubjectCN}}</span>{{end}}</td>
          <td class="cert-exp{{if eq .StateKey "expiring"}} warn{{end}}{{if .Attention}} bad{{end}}" title="{{.NotAfter}}">{{.ExpiresRel}}</td>
          <td class="muted small">{{.IssuedAbs}}</td>
          <td class="muted small">{{.KeyAlgorithm}}</td>
          <td><code class="cert-fp" title="{{.FingerprintSHA256}}">{{.ShortFP}}</code></td>
          <td><button class="btn btn-ghost" type="button"
                hx-get="/fragments/certificates/{{.ID}}"
                hx-target="#row-drawer" hx-swap="innerHTML"
                onclick="openRowDrawer()">Details</button></td>
        </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    {{else}}
      <p class="muted">No certificates match this filter. <a href="{{call .ChipURL .Filter}}" hx-get="{{call .ChipURL .Filter}}" hx-target="#content" hx-push-url="true">Clear the filter</a>.</p>
    {{end}}
    <p class="muted small cert-tfoot">
      {{if .Hidden}}Rotation history hidden — {{.Hidden}} superseded certificate{{if ne .Hidden 1}}s{{end}}.
        <a href="{{.HistoryURL}}" hx-get="{{.HistoryURL}}" hx-target="#content" hx-push-url="true">Show history</a> ·{{else if .ShowHistory}}
        <a href="{{.HistoryURL}}" hx-get="{{.HistoryURL}}" hx-target="#content" hx-push-url="true">Hide history</a> ·{{end}}
      {{.Total}} certificate{{if ne .Total 1}}s{{end}} total · a row&rsquo;s Details opens every field, PEM and CSR.
    </p>
  </section>
{{end}}
</div>`))

// certDrawerTmpl wraps the shared certificate detail in the app's row-drawer
// chrome.
var certDrawerTmpl = template.Must(template.New("certDrawer").Parse(`
<div class="row-drawer-head">
  <h3>Certificate{{if .Title}} · {{.Title}}{{end}}</h3>
  <button class="btn btn-outline" onclick="closeRowDrawer()">Close</button>
</div>
{{.Body}}`))

// certDrawerErrTmpl is the drawer-shaped error so a failed detail load still
// gets a Close button.
var certDrawerErrTmpl = template.Must(template.New("certDrawerErr").Parse(`
<div class="row-drawer-head">
  <h3>Certificate</h3>
  <button class="btn btn-outline" onclick="closeRowDrawer()">Close</button>
</div>
<p class="muted">{{.}}</p>`))
