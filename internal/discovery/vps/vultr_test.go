package vps

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

func newMockVultrAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /instances", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-vultr-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		cursor := r.URL.Query().Get("cursor")
		w.Header().Set("Content-Type", "application/json")

		if cursor == "" {
			_ = json.NewEncoder(w).Encode(vultrInstancesResponse{
				Instances: []vultrInstance{
					{
						ID: "inst-001", Label: "frontend", OS: "Ubuntu 22.04 x64",
						Plan: "vc2-2c-4gb", Region: "ewr", Status: "active",
						MainIP: "149.28.0.1", Tags: []string{"web"},
						DateCreated: "2024-03-01T10:00:00+00:00",
					},
					{
						ID: "inst-002", Label: "database", OS: "Debian 12 x64",
						Plan: "vc2-4c-8gb", Region: "ams", Status: "stopped",
						MainIP: "149.28.0.2",
						DateCreated: "2024-04-15T14:00:00+00:00",
					},
				},
				Meta: vultrMeta{Total: 3, Links: vultrLinks{Next: "cursor-page2"}},
			})
		} else {
			_ = json.NewEncoder(w).Encode(vultrInstancesResponse{
				Instances: []vultrInstance{
					{
						ID: "inst-003", Label: "worker", OS: "CentOS 9 Stream x64",
						Plan: "vc2-1c-2gb", Region: "sgp", Status: "active",
						MainIP: "149.28.0.3",
						DateCreated: "2024-05-20T09:00:00+00:00",
					},
				},
				Meta: vultrMeta{Total: 3, Links: vultrLinks{Next: ""}},
			})
		}
	})

	return httptest.NewServer(mux)
}

func TestVultr_Name(t *testing.T) {
	assert.Equal(t, "vultr", NewVultr().Name())
}

func TestVultr_Discover_Success(t *testing.T) {
	srv := newMockVultrAPI(t)
	defer srv.Close()

	t.Setenv("KITE_VULTR_TOKEN", "test-vultr-token")

	v := NewVultr()
	v.baseURL = srv.URL
	assets, err := v.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, assets, 3)

	frontend := findAssetByHostname(assets, "frontend")
	require.NotNil(t, frontend)
	assert.Equal(t, model.AssetTypeCloudInstance, frontend.AssetType)
	assert.Equal(t, "vultr", frontend.DiscoverySource)
	assert.Equal(t, "Ubuntu 22.04 x64", frontend.OSFamily)
	assert.Equal(t, "ewr", frontend.Environment)

	var feTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(frontend.Tags), &feTags))
	assert.Equal(t, "149.28.0.1", feTags["ip"])
	assert.NotContains(t, feTags, "warning")

	// Stopped instance gets warning.
	db := findAssetByHostname(assets, "database")
	require.NotNil(t, db)
	var dbTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(db.Tags), &dbTags))
	assert.Contains(t, dbTags, "warning")
}

func TestVultr_Discover_MissingToken(t *testing.T) {
	t.Setenv("KITE_VULTR_TOKEN", "")

	v := NewVultr()

	_, err := v.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_VULTR_TOKEN")

	assets, err := v.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestVultr_Discover_AuthFailure(t *testing.T) {
	srv := newMockVultrAPI(t)
	defer srv.Close()

	t.Setenv("KITE_VULTR_TOKEN", "wrong-token")

	v := NewVultr()
	v.baseURL = srv.URL
	_, err := v.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
