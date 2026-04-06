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

func newMockFlyIOAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/apps", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-fly-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(flyAppsResponse{
			Apps: []flyApp{
				{ID: "app-1", Name: "my-web-app"},
				{ID: "app-2", Name: "my-api"},
			},
			TotalApps: 2,
		})
	})

	mux.HandleFunc("GET /v1/apps/my-web-app/machines", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-fly-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]flyMachine{
			{
				ID: "mach-1", Name: "green-machine",
				Region: "iad", State: "started",
				Config: flyMachineConfig{
					Image: "registry.fly.io/my-web-app:latest",
					Guest: flyMachineGuest{CPUs: 2, MemoryMB: 512},
				},
				CreatedAt: "2024-01-10T08:00:00Z",
				UpdatedAt: "2024-06-15T12:00:00Z",
			},
			{
				ID: "mach-2", Name: "blue-machine",
				Region: "lhr", State: "stopped",
				Config: flyMachineConfig{
					Image: "registry.fly.io/my-web-app:v2",
					Guest: flyMachineGuest{CPUs: 1, MemoryMB: 256},
				},
				CreatedAt: "2024-02-01T10:00:00Z",
				UpdatedAt: "2024-05-01T08:00:00Z",
			},
		})
	})

	mux.HandleFunc("GET /v1/apps/my-api/machines", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-fly-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]flyMachine{
			{
				ID: "mach-3", Name: "api-machine",
				Region: "sea", State: "started",
				Config: flyMachineConfig{
					Image: "registry.fly.io/my-api:v2",
					Guest: flyMachineGuest{CPUs: 4, MemoryMB: 1024},
				},
				CreatedAt: "2024-03-01T00:00:00Z",
				UpdatedAt: "2024-06-20T18:00:00Z",
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestFlyIO_Name(t *testing.T) {
	assert.Equal(t, "flyio", NewFlyIO().Name())
}

func TestFlyIO_Discover_Success(t *testing.T) {
	srv := newMockFlyIOAPI(t)
	defer srv.Close()

	t.Setenv("KITE_FLY_TOKEN", "test-fly-token")

	f := NewFlyIO()
	f.baseURL = srv.URL
	assets, err := f.Discover(context.Background(), map[string]any{
		"org": "personal",
	})
	require.NoError(t, err)
	assert.Len(t, assets, 3)

	green := findAssetByHostname(assets, "green-machine")
	require.NotNil(t, green)
	assert.Equal(t, model.AssetTypeContainer, green.AssetType)
	assert.Equal(t, "flyio", green.DiscoverySource)
	assert.Equal(t, "iad", green.Environment)
	assert.NotEmpty(t, green.NaturalKey)

	var greenTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(green.Tags), &greenTags))
	assert.Equal(t, "my-web-app", greenTags["app"])
	assert.Equal(t, "started", greenTags["state"])
	assert.Equal(t, "flyio", greenTags["platform"])
	assert.NotContains(t, greenTags, "warning")

	// Stopped machine gets warning.
	blue := findAssetByHostname(assets, "blue-machine")
	require.NotNil(t, blue)
	var blueTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(blue.Tags), &blueTags))
	assert.Contains(t, blueTags, "warning")
	assert.Equal(t, "lhr", blue.Environment)

	// Machine from second app.
	apiMachine := findAssetByHostname(assets, "api-machine")
	require.NotNil(t, apiMachine)
	assert.Equal(t, "sea", apiMachine.Environment)
}

func TestFlyIO_Discover_MissingToken(t *testing.T) {
	t.Setenv("KITE_FLY_TOKEN", "")

	f := NewFlyIO()

	_, err := f.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_FLY_TOKEN")

	assets, err := f.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestFlyIO_Discover_AuthFailure(t *testing.T) {
	srv := newMockFlyIOAPI(t)
	defer srv.Close()

	t.Setenv("KITE_FLY_TOKEN", "wrong-token")

	f := NewFlyIO()
	f.baseURL = srv.URL
	_, err := f.Discover(context.Background(), map[string]any{
		"org": "personal",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
