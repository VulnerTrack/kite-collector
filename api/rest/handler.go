// Package rest provides an HTTP REST API for querying kite-collector assets,
// events, and scan history. It uses the Go 1.22+ stdlib ServeMux with
// method-based routing and requires no external router dependencies.
package rest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vulnertrack/kite-collector/api/middleware"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safety"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// defaultLimit is used when the caller omits or provides an invalid limit.
const defaultLimit = 50

// maxLimit caps the maximum number of items returned in a single request.
const maxLimit = 1000

// Handler holds the dependencies for the REST API and exposes an
// http.Handler via its Mux method. It is safe for concurrent use because
// the underlying store.Store is required to be safe for concurrent use and
// Handler itself carries no mutable state.
type Handler struct {
	store               store.Store
	logger              *slog.Logger
	panicsRecovered     *prometheus.CounterVec
	responseTruncations prometheus.Counter
	circuitBreaker      *safety.CircuitBreaker
	apiKey              string // when non-empty, MTLSOrAPIKey middleware is wired
	maxRequestBytes     int64
	maxResponseBytes    int64
}

// SetPanicsRecovered sets the Prometheus counter used by the recovery
// middleware to track recovered panics.
func (h *Handler) SetPanicsRecovered(c *prometheus.CounterVec) {
	h.panicsRecovered = c
}

// SetMaxRequestBytes configures the maximum allowed request body size.
func (h *Handler) SetMaxRequestBytes(n int64) { h.maxRequestBytes = n }

// SetMaxResponseBytes configures the maximum allowed response body size.
func (h *Handler) SetMaxResponseBytes(n int64) { h.maxResponseBytes = n }

// SetResponseTruncations sets the Prometheus counter incremented when a
// response is truncated due to the size limit.
func (h *Handler) SetResponseTruncations(c prometheus.Counter) { h.responseTruncations = c }

// SetCircuitBreaker sets the circuit breaker used to serve source health.
func (h *Handler) SetCircuitBreaker(cb *safety.CircuitBreaker) { h.circuitBreaker = cb }

// SetAPIKey enables MTLSOrAPIKey authentication on all API routes when
// key is non-empty. This wires the middleware defined in RFC-0063.
func (h *Handler) SetAPIKey(key string) { h.apiKey = key }

// Handler returns an http.Handler that wraps all routes with safety
// middleware. The chain (outermost first) is: recovery → response
// bounding → request body limiting → auth → routes.
func (h *Handler) Handler() http.Handler {
	var handler http.Handler = h.Mux()

	// Auth middleware (RFC-0063): when an API key is configured, require
	// either a valid mTLS client certificate or the API key on every request.
	if h.apiKey != "" {
		handler = middleware.MTLSOrAPIKey(handler, h.apiKey)
	}

	if h.maxRequestBytes > 0 {
		handler = MaxBytesMiddleware(h.maxRequestBytes, handler)
	}
	if h.maxResponseBytes > 0 {
		handler = ResponseBoundingMiddleware(h.maxResponseBytes, h.responseTruncations, handler)
	}
	if h.panicsRecovered != nil {
		handler = RecoveryMiddleware(h.panicsRecovered, handler)
	}

	return handler
}

// New creates a Handler backed by the given store. If logger is nil a
// default slog.Logger is used.
func New(s store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		store:  s,
		logger: logger,
	}
}

// Mux returns an *http.ServeMux with all API routes registered. The caller
// is responsible for starting the HTTP server.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", h.handleHealth)
	mux.HandleFunc("GET /api/v1/assets/{id}", h.handleGetAsset)
	mux.HandleFunc("GET /api/v1/assets", h.handleListAssets)
	mux.HandleFunc("GET /api/v1/events", h.handleListEvents)
	mux.HandleFunc("GET /api/v1/scans/latest", h.handleLatestScan)
	mux.HandleFunc("GET /api/v1/scans", h.handleListScans)
	mux.HandleFunc("GET /api/v1/runtime-incidents", h.handleListIncidents)
	mux.HandleFunc("GET /api/v1/source-health", h.handleListSourceHealth)
	mux.HandleFunc("GET /api/v1/source-health/{name}", h.handleGetSourceHealth)

	return mux
}

// --- response helpers -------------------------------------------------------

// errorBody is the JSON body returned on errors.
type errorBody struct {
	Error string `json:"error"`
}

// writeJSON serialises v as JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Encoding errors at this point are unrecoverable; best-effort write.
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

// emptyArray is a pre-allocated empty slice that serialises as [] in JSON,
// avoiding null output when no results are found.
var emptyArray = []struct{}{}

// --- handlers ---------------------------------------------------------------

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("request", "method", r.Method, "path", r.URL.Path)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("request", "method", r.Method, "path", r.URL.Path)

	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid asset id")
		return
	}

	asset, err := h.store.GetAssetByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if err != nil {
		h.logger.Error("get asset by id failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, asset)
}

func (h *Handler) handleListAssets(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("request", "method", r.Method, "path", r.URL.Path)

	q := r.URL.Query()

	filter := store.AssetFilter{
		AssetType:    q.Get("asset_type"),
		IsAuthorized: q.Get("is_authorized"),
		IsManaged:    q.Get("is_managed"),
		Hostname:     q.Get("hostname"),
		Limit:        clampLimit(parseIntParam(q.Get("limit"), defaultLimit)),
		Offset:       clampOffset(parseIntParam(q.Get("offset"), 0)),
	}

	assets, err := h.store.ListAssets(r.Context(), filter)
	if err != nil {
		h.logger.Error("list assets failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if len(assets) == 0 {
		writeJSON(w, http.StatusOK, emptyArray)
		return
	}

	writeJSON(w, http.StatusOK, assets)
}

func (h *Handler) handleListEvents(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("request", "method", r.Method, "path", r.URL.Path)

	q := r.URL.Query()

	filter := store.EventFilter{
		EventType: q.Get("event_type"),
		Limit:     clampLimit(parseIntParam(q.Get("limit"), defaultLimit)),
		Offset:    clampOffset(parseIntParam(q.Get("offset"), 0)),
	}

	if raw := q.Get("asset_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid asset_id")
			return
		}
		filter.AssetID = &id
	}

	if raw := q.Get("scan_run_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid scan_run_id")
			return
		}
		filter.ScanRunID = &id
	}

	events, err := h.store.ListEvents(r.Context(), filter)
	if err != nil {
		h.logger.Error("list events failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if len(events) == 0 {
		writeJSON(w, http.StatusOK, emptyArray)
		return
	}

	writeJSON(w, http.StatusOK, events)
}

func (h *Handler) handleListScans(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("request", "method", r.Method, "path", r.URL.Path)

	// The Store interface only exposes GetLatestScanRun. When a full
	// ListScanRuns method is added to the store, this handler should be
	// updated to use it. For now we return at most one scan run.
	run, err := h.store.GetLatestScanRun(r.Context())
	if err != nil {
		h.logger.Error("get latest scan run failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if run == nil {
		writeJSON(w, http.StatusOK, emptyArray)
		return
	}

	writeJSON(w, http.StatusOK, []*model.ScanRun{run})
}

func (h *Handler) handleLatestScan(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("request", "method", r.Method, "path", r.URL.Path)

	run, err := h.store.GetLatestScanRun(r.Context())
	if err != nil {
		h.logger.Error("get latest scan run failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if run == nil {
		writeError(w, http.StatusNotFound, "no scan runs found")
		return
	}

	writeJSON(w, http.StatusOK, run)
}

func (h *Handler) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("request", "method", r.Method, "path", r.URL.Path)

	q := r.URL.Query()

	filter := store.IncidentFilter{
		IncidentType: q.Get("type"),
		Limit:        clampLimit(parseIntParam(q.Get("limit"), defaultLimit)),
		Offset:       clampOffset(parseIntParam(q.Get("offset"), 0)),
	}

	if raw := q.Get("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since: expected RFC3339")
			return
		}
		filter.Since = &t
	}

	if raw := q.Get("scan_run_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid scan_run_id")
			return
		}
		filter.ScanRunID = &id
	}

	incidents, err := h.store.ListRuntimeIncidents(r.Context(), filter)
	if err != nil {
		h.logger.Error("list runtime incidents failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if len(incidents) == 0 {
		writeJSON(w, http.StatusOK, emptyArray)
		return
	}

	writeJSON(w, http.StatusOK, incidents)
}

func (h *Handler) handleListSourceHealth(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("request", "method", r.Method, "path", r.URL.Path)

	if h.circuitBreaker == nil {
		writeJSON(w, http.StatusOK, emptyArray)
		return
	}

	writeJSON(w, http.StatusOK, h.circuitBreaker.AllSourceHealth())
}

func (h *Handler) handleGetSourceHealth(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("request", "method", r.Method, "path", r.URL.Path)

	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "missing source name")
		return
	}

	if h.circuitBreaker == nil {
		writeError(w, http.StatusNotFound, "source not found")
		return
	}

	health, err := h.circuitBreaker.GetSourceHealth(name)
	if err != nil || health == nil {
		writeError(w, http.StatusNotFound, "source not found")
		return
	}

	writeJSON(w, http.StatusOK, health)
}

// --- utilities --------------------------------------------------------------

// parseIntParam parses a string to int, returning fallback when the string is
// empty or not a valid integer.
func parseIntParam(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return v
}

// clampLimit ensures limit is within [1, maxLimit], using defaultLimit for
// non-positive values.
func clampLimit(v int) int {
	if v <= 0 {
		return defaultLimit
	}
	if v > maxLimit {
		return maxLimit
	}
	return v
}

// clampOffset ensures offset is non-negative.
func clampOffset(v int) int {
	if v < 0 {
		return 0
	}
	return v
}
