package dashboard

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/scan"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// recentCompletionWindow is how long a finished scan reads as "Completed"
// in the topbar before the cluster settles back to "Idle · last run …".
const recentCompletionWindow = 2 * time.Minute

// readOnlyScanTooltip explains the disabled button when the dashboard runs
// without a scan coordinator (inspector mode).
const readOnlyScanTooltip = "Scan trigger unavailable in read-only inspector mode. " +
	"Restart with 'kite-collector agent --dashboard-addr <host:port>' to enable scans."

// scanStatusView is the data shape consumed by scanStatusTemplate: the
// button state plus the fixed two-line status block beside it. Line1 is the
// short state word (Idle, Scanning, Completed, Last run failed) and Line2
// the supporting detail, so the block keeps its shape while the text
// changes and the button beside it holds still.
type scanStatusView struct {
	ActiveSince time.Time
	Latest      *model.ScanRun
	ActiveID    string
	Line1       string
	Line2       string
	Line2Title  string // absolute timestamp behind a relative Line2, when there is one
	Tooltip     string
	ToneClass   string // "" | "scan-meta-running" | "scan-meta-error"
	CanScan     bool   // a coordinator and base config are wired: the button may POST
	Running     bool   // a scan is in flight: the button shows the spinner and is disabled
}

// renderScanStatusFragment writes the #scan-status cluster inner HTML: the
// Run Scan button and the status block. coord is nil when the dashboard is
// running in read-only inspector mode; canScan is false whenever a scan
// cannot be started (no coordinator or no base config), which disables the
// button with a tooltip explaining why.
func renderScanStatusFragment(w io.Writer, ctx context.Context, st store.Store, coord *scan.Coordinator, canScan bool) error {
	view := scanStatusView{CanScan: canScan && coord != nil}

	if coord != nil {
		if active, ok := coord.Active(); ok {
			view.Running = true
			view.ActiveID = active.ID.String()
			view.ActiveSince = active.StartedAt
		}
	}

	latest, err := st.GetLatestScanRun(ctx)
	if err != nil {
		return fmt.Errorf("get latest scan run: %w", err)
	}
	view.Latest = latest
	view.fillLines(time.Now())

	tmpl := template.Must(template.New("scan-status").
		Funcs(templateFuncs).
		Parse(scanStatusTemplate))
	if err := tmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render scan-status template: %w", err)
	}
	return nil
}

// fillLines derives the two status lines from the run state. Kept separate
// from the render so the wording is unit-testable without a template.
func (v *scanStatusView) fillLines(now time.Time) {
	switch {
	case !v.CanScan && !v.Running:
		v.Line1 = "Inspector mode"
		v.Line2 = "read-only, start with --with-agent to scan"
		v.Tooltip = readOnlyScanTooltip
	case v.Running:
		v.Line1 = "Scanning"
		v.Line2 = "started " + humanizeRelativeTime(now.Sub(v.ActiveSince)) + " · id " + shortScanID(v.ActiveID)
		v.Line2Title = v.ActiveSince.Local().Format("2006-01-02 15:04:05 MST")
		v.ToneClass = "scan-meta-running"
	case v.Latest == nil:
		v.Line1 = "Idle"
		v.Line2 = "no scans yet"
	default:
		v.fillFromLatest(now)
	}
}

// fillFromLatest words the idle state after at least one recorded run.
func (v *scanStatusView) fillFromLatest(now time.Time) {
	run := v.Latest
	ago := humanizeRelativeTime(now.Sub(run.StartedAt))
	v.Line2Title = run.StartedAt.Local().Format("2006-01-02 15:04:05 MST")

	switch run.Status {
	case model.ScanStatusCompleted:
		if run.CompletedAt != nil && now.Sub(*run.CompletedAt) < recentCompletionWindow {
			v.Line1 = "Completed"
			v.Line2 = "just now"
			if run.TotalMachines > 0 {
				v.Line2 += fmt.Sprintf(" · %d machines", run.TotalMachines)
			}
			return
		}
		v.Line1 = "Idle"
		v.Line2 = "last run " + ago
	case model.ScanStatusFailed:
		v.Line1 = "Last run failed"
		v.Line2 = ago
		v.ToneClass = "scan-meta-error"
	case model.ScanStatusTimedOut:
		v.Line1 = "Last run timed out"
		v.Line2 = ago
		v.ToneClass = "scan-meta-error"
	case model.ScanStatusRunning:
		// A run the store still calls running with no live coordinator run
		// behind it: the process restarted mid-scan.
		v.Line1 = "Idle"
		v.Line2 = "last run " + ago + " · unfinished"
	default:
		v.Line1 = "Idle"
		v.Line2 = "last run " + ago + " · " + string(run.Status)
	}
}

// shortScanID trims a UUID to its first block so the status line stays one
// line wide; the full id is on the scans page.
func shortScanID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// scanStatusTemplate is the HTML fragment swapped into #scan-status on every
// 3-second HTMX poll and on every Run Scan click. The outer div with
// id=scan-status lives in the page shell and carries the polling triggers;
// this template only renders inner content so swaps do not drop those
// triggers.
//
// The disabled button is wrapped in a <span title> because disabled buttons
// do not fire mouseover in some browsers, which breaks native tooltips.
const scanStatusTemplate = `
{{- if .Running -}}
<button class="btn scan-btn" type="button" disabled aria-disabled="true" aria-live="polite"><svg class="scan-btn-icon spin" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-6.2-8.6"></path></svg>Scanning&hellip;</button>
{{- else if .CanScan -}}
<button class="btn scan-btn" type="button" hx-post="/api/v1/scan" hx-target="#scan-status" hx-swap="innerHTML"><svg class="scan-btn-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 4 12 8-12 8V4Z"></path></svg>Run Scan</button>
{{- else -}}
<span title="{{.Tooltip}}"><button class="btn scan-btn" type="button" disabled aria-disabled="true"><svg class="scan-btn-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"></rect><path d="M8 11V7a4 4 0 0 1 8 0v4"></path></svg>Run Scan</button></span>
{{- end }}
<span class="scan-meta" role="status" aria-live="polite"{{if .ActiveID}} data-scan-id="{{.ActiveID}}"{{end}}><span class="scan-meta-1 {{.ToneClass}}">{{.Line1}}</span><span class="scan-meta-2"{{if .Line2Title}} title="{{.Line2Title}}"{{end}}>{{.Line2}}</span></span>
`
