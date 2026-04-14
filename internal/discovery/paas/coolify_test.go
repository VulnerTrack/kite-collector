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

func newMockCoolifyAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/applications", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-coolify-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]coolifyApplication{
			{
				ID: 1, Name: "webapp",
				FQDN:          "https://app.example.com",
				Status:         "running",
				GitRepository:  "https://github.com/example/webapp",
				CreatedAt:      "2024-01-10T08:00:00Z",
				UpdatedAt:      "2024-06-15T12:00:00Z",
			},
			{
				ID: 2, Name: "api-service",
				FQDN:      "https://api.example.com",
				Status:     "stopped",
				CreatedAt:  "2024-03-01T10:00:00Z",
				UpdatedAt:  "2024-05-01T08:00:00Z",
			},
		})
	})

	mux.HandleFunc("GET /api/v1/servers", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-coolify-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]coolifyServer{
			{
				ID: 10, Name: "prod-server",
				IP:        "10.0.0.1",
				Status:    "reachable",
				CreatedAt: "2024-01-01T00:00:00Z",
				UpdatedAt: "2024-06-20T18:00:00Z",
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestCoolify_Name(t *testing.T) {
	assert.Equal(t, "coolify", NewCoolify().Name())
}

func TestCoolify_Discover_Success(t *testing.T) {
	srv := newMockCoolifyAPI(t)
	defer srv.Close()

	t.Setenv("KITE_COOLIFY_TOKEN", "test-coolify-token")

	c := NewCoolify()
	c.baseURL = srv.URL
	assets, err := c.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	// 2 apps + 1 server = 3
	assert.Len(t, assets, 3)

	webapp := findAssetByHostname(assets, "webapp")
	require.NotNil(t, webapp)
	assert.Equal(t, model.AssetTypeContainer, webapp.AssetType)
	assert.Equal(t, "coolify", webapp.DiscoverySource)

	var wTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(webapp.Tags), &wTags))
	assert.Equal(t, "https://app.example.com", wTags["fqdn"])
	assert.Equal(t, "running", wTags["status"])

	// Server has AssetTypeServer.
	server := findAssetByHostname(assets, "prod-server")
	require.NotNil(t, server)
	assert.Equal(t, model.AssetTypeServer, server.AssetType)
	assert.Equal(t, "coolify", server.DiscoverySource)

	var sTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(server.Tags), &sTags))
	assert.Equal(t, "10.0.0.1", sTags["ip"])
}

func TestCoolify_Discover_MissingCredentials(t *testing.T) {
	t.Setenv("KITE_COOLIFY_TOKEN", "")
	t.Setenv("KITE_COOLIFY_ENDPOINT", "")

	c := NewCoolify()

	// Token missing with explicit config → error.
	_, err := c.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_COOLIFY_TOKEN")

	// No config → silent skip.
	assets, err := c.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestCoolify_Discover_AuthFailure(t *testing.T) {
	srv := newMockCoolifyAPI(t)
	defer srv.Close()

	t.Setenv("KITE_COOLIFY_TOKEN", "wrong-token")

	c := NewCoolify()
	c.baseURL = srv.URL
	_, err := c.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
