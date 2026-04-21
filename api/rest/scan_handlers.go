package rest

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/api/middleware"
	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/scan"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// SetScanCoordinator wires a coordinator into the REST handler so
// POST /api/v1/scans can trigger real scans. Without a coordinator those
// routes return 503 Service Unavailable.
func (h *Handler) SetScanCoordinator(c *scan.Coordinator) { h.coordinator = c }

// SetBaseConfig wires the operator-declared base config used when POSTers do
// not supply a body. Without a base config the trigger endpoint returns 503.
func (h *Handler) SetBaseConfig(cfg *config.Config) { h.baseConfig = cfg }

// scanAPIKillSwitchEnv, when set to "off", disables the trigger/get endpoints
// unconditionally. Ships in Phase 3 per RFC-0104 §6.3 Rollback Plan.
const scanAPIKillSwitchEnv = "KITE_COLLECTOR_SCAN_API"

// scanAPIDisabled reports whether the kill switch env var is set to "off".
func scanAPIDisabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(scanAPIKillSwitchEnv)), "off")
}

// triggerResponse is the 202 Accepted body returned by POST /api/v1/scans.
type triggerResponse struct {
	ScanRunID string `json:"scan_run_id"`
}

// alreadyRunningBody is the 409 Conflict body returned when a scan is
// already in flight. scan_run_id carries the active scan's ID so the caller
// can poll or subscribe to it instead of retrying blindly.
type alreadyRunningBody struct {
	Error     string `json:"error"`
	ScanRunID string `json:"scan_run_id"`
}

// resolveTriggeredBy returns the caller identity stamped into
// ScanRun.triggered_by. Preference order: mTLS CN, then the tenant field when
// the middleware injected one, else the generic "api-key" label. An empty
// string falls through to NULL in the DB, which is the right choice for
// unauthenticated dashboard stub callers (e.g. local development).
func resolveTriggeredBy(r *http.Request) string {
	if cn := middleware.AgentIDFromContext(r.Context()); cn != "" {
		return cn
	}
	if tid := middleware.TenantIDFromContext(r.Context()); tid != "" {
		return tid
	}
	if r.Header.Get("X-API-Key") != "" {
		return "api-key"
	}
	return ""
}

// handleStartScan implements POST /api/v1/scans. It optionally decodes a
// JSON body carrying source / scope narrowing, asks the coordinator to
// start, and returns 202 Accepted with a Location header pointing at the
// per-scan GET endpoint.
func (h *Handler) handleStartScan(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("request", "method", r.Method, "path", r.URL.Path)

	if scanAPIDisabled() {
		writeError(w, http.StatusServiceUnavailable, "scan API disabled via "+scanAPIKillSwitchEnv)
		return
	}
	if h.coordinator == nil || h.baseConfig == nil {
		writeError(w, http.StatusServiceUnavailable, "scan coordinator not configured")
		return
	}

	var req scan.TriggerRequest
	body, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		writeError(w, http.StatusBadRequest, "read body: "+readErr.Error())
		return
	}
	if len(body) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if decodeErr := dec.Decode(&req); decodeErr != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+decodeErr.Error())
			return
		}
	}

	cfg, err := scan.ApplyOverrides(h.baseConfig, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id, err := h.coordinator.Start(r.Context(), scan.StartRequest{
		Config:        cfg,
		TriggerSource: "api",
		TriggeredBy:   resolveTriggeredBy(r),
	})
	if err != nil {
		var already *scan.AlreadyRunningError
		if errors.As(err, &already) {
			writeJSON(w, http.StatusConflict, alreadyRunningBody{
				Error:     err.Error(),
				ScanRunID: already.ActiveID.String(),
			})
			return
		}
		h.logger.Error("start scan failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Location", "/api/v1/scans/"+id.String())
	writeJSON(w, http.StatusAccepted, triggerResponse{ScanRunID: id.String()})
}

// handleGetScan implements GET /api/v1/scans/{id}. It returns the scan run
// row, or 404 when the id is unknown.
func (h *Handler) handleGetScan(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("request", "method", r.Method, "path", r.URL.Path)

	if scanAPIDisabled() {
		writeError(w, http.StatusServiceUnavailable, "scan API disabled via "+scanAPIKillSwitchEnv)
		return
	}

	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid scan id")
		return
	}

	run, err := h.store.GetScanRun(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "scan run not found")
		return
	}
	if err != nil {
		h.logger.Error("get scan run failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, run)
}
