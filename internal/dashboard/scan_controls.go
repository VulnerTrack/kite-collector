package dashboard

import (
	"fmt"
	"html/template"
	"io"
)

type scanControlsView struct {
	Tooltip       string
	CoordinatorOK bool
}

const scanControlsTemplate = `{{ if .CoordinatorOK -}}
<button class="btn" hx-post="/api/v1/scan" hx-target="#scan-status" hx-swap="innerHTML">Run Scan</button>
{{- else -}}
<span title="{{ .Tooltip }}"><button class="btn" disabled aria-disabled="true">Run Scan</button></span>
{{- end }}`

const readOnlyScanTooltip = "Scan trigger unavailable in read-only inspector mode. " +
	"Restart with 'kite-collector agent --dashboard-addr <host:port>' to enable scans."

func renderScanControlsFragment(w io.Writer, coordinatorOK bool) error {
	view := scanControlsView{
		CoordinatorOK: coordinatorOK,
		Tooltip:       readOnlyScanTooltip,
	}
	tmpl := template.Must(template.New("scan-controls").Parse(scanControlsTemplate))
	if err := tmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render scan-controls template: %w", err)
	}
	return nil
}
