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

func newMockHetznerAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /servers", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-hetzner-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")

		if page == "" || page == "1" {
			_ = json.NewEncoder(w).Encode(hetznerServersResponse{
				Servers: []hetznerServer{
					{
						ID: 1, Name: "web-1", Status: "running",
						PublicNet:  hetznerPublicNet{IPv4: hetznerIPv4{IP: "1.2.3.4"}},
						ServerType: hetznerServerType{Description: "CX21"},
						Datacenter: hetznerDatacenter{Name: "fsn1-dc14"},
						Image:      &hetznerImage{OSFlavor: "ubuntu", Description: "Ubuntu 22.04"},
						Labels:     map[string]string{"env": "prod"},
						Created:    "2024-01-15T10:00:00+00:00",
					},
					{
						ID: 2, Name: "db-1", Status: "off",
						PublicNet:  hetznerPublicNet{IPv4: hetznerIPv4{IP: "5.6.7.8"}},
						ServerType: hetznerServerType{Description: "CX31"},
						Datacenter: hetznerDatacenter{Name: "nbg1-dc3"},
						Created:    "2024-02-20T12:00:00+00:00",
					},
				},
				Meta: hetznerMeta{Pagination: hetznerPagination{NextPage: 2, TotalEntries: 3}},
			})
		} else {
			_ = json.NewEncoder(w).Encode(hetznerServersResponse{
				Servers: []hetznerServer{
					{
						ID: 3, Name: "worker-1", Status: "running",
						PublicNet:  hetznerPublicNet{IPv4: hetznerIPv4{IP: "9.10.11.12"}},
						ServerType: hetznerServerType{Description: "CX41"},
						Datacenter: hetznerDatacenter{Name: "hel1-dc2"},
						Image:      &hetznerImage{OSFlavor: "debian", Description: "Debian 12"},
						Created:    "2024-03-01T08:00:00+00:00",
					},
				},
				Meta: hetznerMeta{Pagination: hetznerPagination{NextPage: 0, TotalEntries: 3}},
			})
		}
	})

	return httptest.NewServer(mux)
}

func TestHetzner_Name(t *testing.T) {
	assert.Equal(t, "hetzner", NewHetzner().Name())
}

func TestHetzner_Discover_Success(t *testing.T) {
	srv := newMockHetznerAPI(t)
	defer srv.Close()

	t.Setenv("KITE_HETZNER_TOKEN", "test-hetzner-token")

	h := NewHetzner()
	h.baseURL = srv.URL
	assets, err := h.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, assets, 3, "expected 2 servers on page 1 + 1 on page 2")

	// Verify running server.
	web := findAssetByHostname(assets, "web-1")
	require.NotNil(t, web)
	assert.Equal(t, model.AssetTypeCloudInstance, web.AssetType)
	assert.Equal(t, "hetzner", web.DiscoverySource)
	assert.Equal(t, "ubuntu", web.OSFamily)
	assert.Equal(t, "Ubuntu 22.04", web.OSVersion)
	assert.Equal(t, "fsn1-dc14", web.Environment)
	assert.NotEmpty(t, web.NaturalKey)

	var webTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(web.Tags), &webTags))
	assert.Equal(t, "1.2.3.4", webTags["ip"])
	assert.Equal(t, "CX21", webTags["server_type"])
	assert.NotContains(t, webTags, "warning")

	// Verify powered-off server gets warning.
	db := findAssetByHostname(assets, "db-1")
	require.NotNil(t, db)
	var dbTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(db.Tags), &dbTags))
	assert.Equal(t, "off", dbTags["status"])
	assert.Contains(t, dbTags, "warning")
}

func TestHetzner_Discover_MissingToken(t *testing.T) {
	t.Setenv("KITE_HETZNER_TOKEN", "")

	h := NewHetzner()

	// With config → error.
	_, err := h.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_HETZNER_TOKEN")

	// Without config → skip silently.
	assets, err := h.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestHetzner_Discover_AuthFailure(t *testing.T) {
	srv := newMockHetznerAPI(t)
	defer srv.Close()

	t.Setenv("KITE_HETZNER_TOKEN", "wrong-token")

	h := NewHetzner()
	h.baseURL = srv.URL
	_, err := h.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}

// findAssetByHostname returns the first asset matching hostname, or nil.
func findAssetByHostname(assets []model.Asset, hostname string) *model.Asset {
	for i := range assets {
		if assets[i].Hostname == hostname {
			return &assets[i]
		}
	}
	return nil
}
