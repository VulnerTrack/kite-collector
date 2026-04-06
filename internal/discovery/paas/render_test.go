package paas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func newMockRenderAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/services", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-render-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		cursor := r.URL.Query().Get("cursor")
		w.Header().Set("Content-Type", "application/json")

		switch cursor {
		case "":
			_ = json.NewEncoder(w).Encode([]renderServiceWrapper{
				{
					Service: renderService{
						ID: "srv-1", Name: "frontend",
						Type:      "web_service",
						Suspended: "not_suspended",
						ServiceDetails: renderServiceDetails{
							Runtime: "node",
							Region:  "oregon",
						},
						CreatedAt: "2024-01-10T08:00:00.000000Z",
						UpdatedAt: "2024-06-15T12:00:00.000000Z",
					},
					Cursor: "cur1",
				},
				{
					Service: renderService{
						ID: "srv-2", Name: "backend",
						Type:      "web_service",
						Suspended: "suspended",
						ServiceDetails: renderServiceDetails{
							Runtime: "python",
							Region:  "ohio",
						},
						CreatedAt: "2024-02-01T10:00:00.000000Z",
						UpdatedAt: "2024-05-01T08:00:00.000000Z",
					},
					Cursor: "cur2",
				},
			})
		case "cur2":
			_ = json.NewEncoder(w).Encode([]renderServiceWrapper{
				{
					Service: renderService{
						ID: "srv-3", Name: "worker",
						Type:      "background_worker",
						Suspended: "not_suspended",
						ServiceDetails: renderServiceDetails{
							Region: "oregon",
						},
						CreatedAt: "2024-03-01T00:00:00.000000Z",
						UpdatedAt: "2024-06-20T18:00:00.000000Z",
					},
					Cursor: "cur3",
				},
			})
		default:
			_ = json.NewEncoder(w).Encode([]renderServiceWrapper{})
		}
	})

	return httptest.NewServer(mux)
}

func TestRender_Name(t *testing.T) {
	assert.Equal(t, "render", NewRender().Name())
}

func TestRender_Discover_Success(t *testing.T) {
	srv := newMockRenderAPI(t)
	defer srv.Close()

	t.Setenv("KITE_RENDER_TOKEN", "test-render-token")

	r := NewRender()
	r.baseURL = srv.URL
	assets, err := r.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, assets, 3)

	frontend := findAssetByHostname(assets, "frontend")
	require.NotNil(t, frontend)
	assert.Equal(t, model.AssetTypeContainer, frontend.AssetType)
	assert.Equal(t, "render", frontend.DiscoverySource)
	assert.Equal(t, "oregon", frontend.Environment)
	assert.NotEmpty(t, frontend.NaturalKey)

	var frontTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(frontend.Tags), &frontTags))
	assert.Equal(t, "node", frontTags["runtime"])
	assert.Equal(t, "web_service", frontTags["type"])
	assert.NotContains(t, frontTags, "warning")

	// Suspended service gets warning.
	backend := findAssetByHostname(assets, "backend")
	require.NotNil(t, backend)
	var backTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(backend.Tags), &backTags))
	assert.Contains(t, backTags, "warning")
	assert.Equal(t, true, backTags["suspended"])

	// Third page item found via cursor pagination.
	worker := findAssetByHostname(assets, "worker")
	require.NotNil(t, worker)
	assert.Equal(t, "background_worker", func() string {
		var tags map[string]any
		_ = json.Unmarshal([]byte(worker.Tags), &tags)
		return tags["type"].(string)
	}())
}

func TestRender_Discover_MissingToken(t *testing.T) {
	t.Setenv("KITE_RENDER_TOKEN", "")

	r := NewRender()

	_, err := r.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_RENDER_TOKEN")

	assets, err := r.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestRender_Discover_AuthFailure(t *testing.T) {
	srv := newMockRenderAPI(t)
	defer srv.Close()

	t.Setenv("KITE_RENDER_TOKEN", "wrong-token")

	r := NewRender()
	r.baseURL = srv.URL
	_, err := r.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
