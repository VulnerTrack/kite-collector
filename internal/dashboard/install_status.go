package dashboard

import (
	"net/http"
	"time"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// installStatusView is the RFC-0156 R14 wire shape.
//
// The two service-name keys are spelled exactly as the RFC specifies
// (`{"kite-collector": "running", "kite-osqueryd": "running"}`) because that
// literal shape is the contract; everything else is additive context a
// dashboard or a support bundle can use without a second round-trip.
//
// This endpoint is deliberately useful on the plain build too. Before this
// RFC, "is the osquery daemon actually registered and running on this host"
// was answerable only by opening services.msc — and the MSI channel, which is
// how every osquery-bundled Windows host got there until now, has exactly the
// same question. Reporting both services regardless of how they were installed
// is what makes the answer worth asking for.
type installStatusView struct {
	KiteCollector string                 `json:"kite-collector"`
	KiteOsqueryd  string                 `json:"kite-osqueryd"`
	Osquery       installer.OsqueryState `json:"osquery"`
	NextAction    string                 `json:"next_action"`
	GeneratedAt   string                 `json:"generated_at"`
	BinaryPath    string                 `json:"binary_path"`
	CertsDir      string                 `json:"certs_dir"`
}

// handleInstallStatus reports both registered services' state.
func handleInstallStatus(w http.ResponseWriter, deps onboardingDeps) {
	opts := installer.DetectDefaults().Options
	if deps.PlatformEndpoint != "" {
		opts.Endpoint = deps.PlatformEndpoint
	}
	state := installer.Probe(opts)
	osq := installer.ProbeOsquery(opts)

	writeJSON(w, deps.Logger, http.StatusOK, installStatusView{
		KiteCollector: state.ServiceState,
		KiteOsqueryd:  osq.ServiceState,
		Osquery:       osq,
		NextAction:    state.NextAction,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		BinaryPath:    state.BinaryPath,
		CertsDir:      state.CertsDir,
	})
}
