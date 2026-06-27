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
	assets := []model.Asset{
		makeAsset("api-srv-01", model.AssetTypeServer, now),
		makeAsset("api-ws-01", model.AssetTypeWorkstation, now),
		makeAsset("api-cloud-01", model.AssetTypeCloudInstance, now),
	}
	_, _, err := st.UpsertAssets(ctx, assets)
	require.NoError(t, err)

	scanRunID := uuid.Must(uuid.NewV7())
	scanRun := model.ScanRun{
		ID:        scanRunID,
		StartedAt: now,
		Status:    model.ScanStatusRunning,
	}
	require.NoError(t, st.CreateScanRun(ctx, scanRun))

	events := []model.AssetEvent{
		makeEvent(assets[0].ID, scanRunID, model.EventAssetDiscovered, now),
		makeEvent(assets[1].ID, scanRunID, model.EventAssetDiscovered, now),
	}
	require.NoError(t, st.InsertEvents(ctx, events))

	result := model.ScanResult{
		TotalAssets:     3,
		NewAssets:       3,
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

	// ---- GET /api/v1/assets ----
	t.Run("ListAssets", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/assets")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body []json.RawMessage
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.GreaterOrEqual(t, len(body), 3)
	})

	// ---- GET /api/v1/assets?asset_type=cloud_instance ----
	t.Run("ListAssets_FilterByType", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/assets?asset_type=cloud_instance")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body []map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		for _, a := range body {
			assert.Equal(t, "cloud_instance", a["asset_type"])
		}
	})

	// ---- GET /api/v1/assets/{id} ----
	t.Run("GetAsset_Found", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/assets/" + assets[0].ID.String())
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, assets[0].Hostname, body["hostname"])
	})

	// ---- GET /api/v1/assets/{id} — 404 ----
	t.Run("GetAsset_NotFound", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/assets/" + uuid.Must(uuid.NewV7()).String())
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		var body map[string]string
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "asset not found", body["error"])
	})

	// ---- GET /api/v1/assets/{id} — bad UUID ----
	t.Run("GetAsset_BadID", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/assets/not-a-uuid")
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

	// ---- GET /api/v1/events?asset_id=... ----
	t.Run("ListEvents_FilterByAsset", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/events?asset_id=" + assets[0].ID.String())
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body []map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		for _, e := range body {
			assert.Equal(t, assets[0].ID.String(), e["asset_id"])
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
	t.Run("ListAssets_Pagination", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/assets?limit=1&offset=0")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		bodyBytes, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var body []json.RawMessage
		require.NoError(t, json.Unmarshal(bodyBytes, &body))
		// The store mock in handler_test.go doesn't enforce limit, but the
		// real PostgreSQL store does. If the store supports it, we should get
		// at most 1 result. The actual ListAssets in the handler does pass
		// the filter with Limit to the store.
		assert.LessOrEqual(t, len(body), 1, "limit=1 should return at most 1 asset")
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

	// Empty assets → []
	t.Run("EmptyAssets", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/v1/assets")
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

// Ensure store.AssetFilter and store.EventFilter are used (suppress unused import).
var _ = store.AssetFilter{}
