package dashboard

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// TestInstallStatus_ReportsBothServices pins the RFC-0156 R14 wire contract.
// The two hyphenated keys are the contract itself — a struct-tag typo here
// would be invisible in Go and would silently break every consumer.
func TestInstallStatus_ReportsBothServices(t *testing.T) {
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/install/status", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	require.Contains(t, raw, "kite-collector")
	require.Contains(t, raw, "kite-osqueryd")

	var view installStatusView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))

	legal := []string{
		installer.ServiceRunning,
		installer.ServiceStopped,
		installer.ServiceNotInstalled,
		installer.ServiceUnknown,
	}
	assert.Contains(t, legal, view.KiteCollector)
	assert.Contains(t, legal, view.KiteOsqueryd,
		"the sibling daemon must report a legal service state on every "+
			"platform, including hosts that never installed it")
	assert.Equal(t, view.KiteOsqueryd, view.Osquery.ServiceState,
		"the flat key and the detail block must not be able to disagree")
	assert.NotEmpty(t, view.GeneratedAt)
	assert.NotEmpty(t, view.BinaryPath)
	assert.NotEmpty(t, view.CertsDir)
	assert.Equal(t, installer.OsqueryExtensionsEndpoint(), view.Osquery.SocketPath)
}

// TestInstallStatus_PlainBuildReportsNoBundle documents what the default
// (non -tags osquery_bundle) build must say: no embedded payload. R2 makes
// that a build-time property, so a plain binary claiming otherwise would mean
// the tag leaked into the default channel.
func TestInstallStatus_PlainBuildReportsNoBundle(t *testing.T) {
	if installer.BundleAvailable() {
		t.Skip("built with -tags osquery_bundle")
	}
	h := newInstallHarness(t, nil)
	rec := h.do(t, "GET", "/api/v1/install/status", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var view installStatusView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	assert.False(t, view.Osquery.Bundled)
	assert.Empty(t, view.Osquery.Version)
}
