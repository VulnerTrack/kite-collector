//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/api/rest"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// TestAPIEndpoints exercises all REST API endpoints against a real PostgreSQL-
// backed store seeded with test data.
func TestAPIEndpoints(t *testing.T) {
	ctx := context.Background()
	dsn := startPostgresContainer(ctx, t)
	st := newTestStore(t, dsn)

	// ---- Seed test data ----
	now := time.Now().UTC().Truncate(time.Millisecond)
	machines := []model.Machine{
		makeMachine("api-srv-01", model.MachineTypeServer, now),
		makeMachine("api-ws-01", model.MachineTypeWorkstation, now),
		makeMachine("api-cloud-01", model.MachineTypeCloudInstance, now),
	}
	_, _, err := st.UpsertMachines(ctx, machines)
	require.NoError(t, err)

	scanRunID := uuid.Must(uuid.NewV7())
	scanRun := model.ScanRun{
		ID:        scanRunID,
		StartedAt: now,
		Status:    model.ScanStatusRunning,
	}
	require.NoError(t, st.CreateScanRun(ctx, scanRun))

	events := []model.MachineEvent{
		makeEvent(machines[0].ID, scanRunID, model.EventMachineDiscovered, now),
		makeEvent(machines[1].ID, scanRunID, model.EventMachineDiscovered, now),
	}
	require.NoError(t, st.InsertEvents(ctx, events))

	result := model.ScanResult{
		TotalMachines:   3,
		NewMachines:     3,
		CoveragePercent: 100.0,
	}
	require.NoError(t, st.CompleteScanRun(ctx, scanRunID, result))

	// ---- Start API server ----
	handler := rest.New(st, nil)
	srv := httptest.NewServer(handler.Mux())
	t.Cleanup(srv.Close)

	client := srv.Client()

	// ---- GET /api/v1/health ----
	t.Run("Health", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/health")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body map[string]string
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "ok", body["status"])
	})

	// ---- GET /api/v1/machines ----
	t.Run("ListMachines", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/machines")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body []json.RawMessage
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.GreaterOrEqual(t, len(body), 3)
	})

	// ---- GET /api/v1/machines?machine_type=cloud_instance ----
	t.Run("ListMachines_FilterByType", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/machines?machine_type=cloud_instance")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body []map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		for _, a := range body {
			assert.Equal(t, "cloud_instance", a["machine_type"])
		}
	})

	// ---- GET /api/v1/machines/{id} ----
	t.Run("GetMachine_Found", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/machines/" + machines[0].ID.String())
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, machines[0].Hostname, body["hostname"])
	})

	// ---- GET /api/v1/machines/{id} — 404 ----
	t.Run("GetMachine_NotFound", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/machines/" + uuid.Must(uuid.NewV7()).String())
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		var body map[string]string
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "machine not found", body["error"])
	})

	// ---- GET /api/v1/machines/{id} — bad UUID ----
	t.Run("GetMachine_BadID", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/machines/not-a-uuid")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	// ---- GET /api/v1/events ----
	t.Run("ListEvents", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/events")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body []json.RawMessage
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.GreaterOrEqual(t, len(body), 2)
	})

	// ---- GET /api/v1/events?machine_id=... ----
	t.Run("ListEvents_FilterByMachine", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/events?machine_id=" + machines[0].ID.String())
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body []map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		for _, e := range body {
			assert.Equal(t, machines[0].ID.String(), e["machine_id"])
		}
	})

	// ---- GET /api/v1/scans/latest ----
	t.Run("LatestScan", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/scans/latest")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, scanRunID.String(), body["id"])
		assert.Equal(t, "completed", body["status"])
	})

	// ---- GET /api/v1/scans ----
	t.Run("ListScans", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/scans")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body []json.RawMessage
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.NotEmpty(t, body)
	})

	// ---- Pagination ----
	t.Run("ListMachines_Pagination", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/machines?limit=1&offset=0")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		bodyBytes, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var body []json.RawMessage
		require.NoError(t, json.Unmarshal(bodyBytes, &body))
		// The store mock in handler_test.go doesn't enforce limit, but the
		// real PostgreSQL store does. If the store supports it, we should get
		// at most 1 result. The actual ListMachines in the handler does pass
		// the filter with Limit to the store.
		assert.LessOrEqual(t, len(body), 1, "limit=1 should return at most 1 machine")
	})
}

// TestAPIEmptyStore verifies API responses when the database has no data.
func TestAPIEmptyStore(t *testing.T) {
	ctx := context.Background()
	dsn := startPostgresContainer(ctx, t)
	st := newTestStore(t, dsn)

	handler := rest.New(st, nil)
	srv := httptest.NewServer(handler.Mux())
	t.Cleanup(srv.Close)

	client := srv.Client()

	// Empty machines → []
	t.Run("EmptyMachines", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/machines")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var body []any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Empty(t, body)
	})

	// Empty events → []
	t.Run("EmptyEvents", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/events")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var body []any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Empty(t, body)
	})

	// No scans → 404
	t.Run("NoScans", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/scans/latest")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// Ensure store.MachineFilter and store.EventFilter are used (suppress unused import).
var _ = store.MachineFilter{}
