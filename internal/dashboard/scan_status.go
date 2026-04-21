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

// scanStatusView is the data shape consumed by scanStatusTemplate. It carries
// enough state for the template to render a live status badge without any
// further round-trips: the active run (if one is in flight), and the latest
// ScanRun row so the template can show the most recent terminal state
// between scans.
type scanStatusView struct {
	ActiveSince   time.Time
	Latest        *model.ScanRun
	ActiveID      string
	CoordinatorOK bool
	HasActive     bool
}

// renderScanStatusFragment writes the #scan-status panel inner HTML. Callers
// supply the coordinator (optional — nil when the dashboard is running in
// read-only inspector mode) and the store. The template gracefully handles
// all four states: no coordinator, no scans ever, active scan, last run
// terminal.
func renderScanStatusFragment(w io.Writer, ctx context.Context, st store.Store, coord *scan.Coordinator) error {
	view := scanStatusView{CoordinatorOK: coord != nil}

	if coord != nil {
		if active, ok := coord.Active(); ok {
			view.HasActive = true
			view.ActiveID = active.ID.String()
			view.ActiveSince = active.StartedAt
		}
	}

	latest, err := st.GetLatestScanRun(ctx)
	if err != nil {
		return fmt.Errorf("get latest scan run: %w", err)
	}
	view.Latest = latest

	tmpl := template.Must(template.New("scan-status").
		Funcs(templateFuncs).
		Funcs(template.FuncMap{"scanStatusClass": scanStatusClass}).
		Parse(scanStatusTemplate))
	if err := tmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render scan-status template: %w", err)
	}
	return nil
}

// scanStatusClass maps a ScanStatus to a CSS badge class so the template
// can colour the status chip without a long if-else chain.
func scanStatusClass(s model.ScanStatus) string {
	switch s {
	case model.ScanStatusCompleted:
		return "badge-green"
	case model.ScanStatusRunning:
		return "badge-yellow"
	case model.ScanStatusFailed:
		return "badge-red"
	case model.ScanStatusTimedOut:
		return "badge-orange"
	default:
		return "badge-gray"
	}
}

// scanStatusTemplate is the HTML fragment swapped into #scan-status on every
// 3-second HTMX poll (and on every "Run Scan" button click). The outer div
// with id=scan-status lives in index.html and carries the polling triggers;
// this template only renders inner content so swaps do not drop those
// triggers.
const scanStatusTemplate = `
{{- if not .CoordinatorOK -}}
<span class="badge badge-gray">Scan trigger unavailable in read-only dashboard mode</span>
{{- else if .HasActive -}}
<span class="badge badge-yellow">Scan running</span>
<span class="scan-status-meta">id {{.ActiveID}} · started {{formatTime .ActiveSince}}</span>
{{- else if .Latest -}}
<span class="badge {{scanStatusClass .Latest.Status}}">{{.Latest.Status}}</span>
<span class="scan-status-meta">last scan {{formatTime .Latest.StartedAt}}</span>
{{- else -}}
<span class="badge badge-gray">No scans yet</span>
{{- end -}}
`
