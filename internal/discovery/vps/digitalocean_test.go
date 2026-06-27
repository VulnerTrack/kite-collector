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

func newMockDOAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /droplets", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-do-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")

		if page == "" || page == "1" {
			_ = json.NewEncoder(w).Encode(doDropletsResponse{
				Droplets: []doDroplet{
					{
						ID: 100, Name: "app-1", Status: "active",
						Networks: doNetworks{V4: []doNetworkV4{
							{IPAddress: "10.0.0.1", Type: "private"},
							{IPAddress: "203.0.113.1", Type: "public"},
						}},
						Image:    doImage{Distribution: "Ubuntu", Name: "22.04 (LTS) x64"},
						SizeSlug: "s-2vcpu-4gb",
						Region:   doRegion{Slug: "nyc3"},
						Tags:     []string{"web", "production"},
						Created:  "2024-01-10T08:00:00Z",
					},
					{
						ID: 101, Name: "staging-1", Status: "off",
						Networks: doNetworks{V4: []doNetworkV4{
							{IPAddress: "203.0.113.2", Type: "public"},
						}},
						Image:    doImage{Distribution: "Debian", Name: "12 x64"},
						SizeSlug: "s-1vcpu-1gb",
						Region:   doRegion{Slug: "ams3"},
						Created:  "2024-06-01T12:00:00Z",
					},
				},
				Links: doLinks{Pages: doPages{Next: "page2"}},
			})
		} else {
			_ = json.NewEncoder(w).Encode(doDropletsResponse{
				Droplets: []doDroplet{
					{
						ID: 102, Name: "worker-1", Status: "active",
						Networks: doNetworks{V4: []doNetworkV4{
							{IPAddress: "203.0.113.3", Type: "public"},
						}},
						Image:    doImage{Distribution: "Fedora", Name: "39 x64"},
						SizeSlug: "s-4vcpu-8gb",
						Region:   doRegion{Slug: "fra1"},
						Created:  "2024-09-15T06:00:00Z",
					},
				},
				Links: doLinks{Pages: doPages{Next: ""}},
			})
		}
	})

	return httptest.NewServer(mux)
}

func TestDigitalOcean_Name(t *testing.T) {
	assert.Equal(t, "digitalocean", NewDigitalOcean().Name())
}

func TestDigitalOcean_Discover_Success(t *testing.T) {
	srv := newMockDOAPI(t)
	defer srv.Close()

	t.Setenv("KITE_DIGITALOCEAN_TOKEN", "test-do-token")

	d := NewDigitalOcean()
	d.baseURL = srv.URL
	assets, err := d.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, assets, 3)

	app := findAssetByHostname(assets, "app-1")
	require.NotNil(t, app)
	assert.Equal(t, model.AssetTypeCloudInstance, app.AssetType)
	assert.Equal(t, "digitalocean", app.DiscoverySource)
	assert.Equal(t, "Ubuntu", app.OSFamily)
	assert.Equal(t, "nyc3", app.Environment)

	var appTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(app.Tags), &appTags))
	assert.Equal(t, "203.0.113.1", appTags["ip"])
	assert.NotContains(t, appTags, "warning")

	// Powered-off droplet gets warning.
	staging := findAssetByHostname(assets, "staging-1")
	require.NotNil(t, staging)
	var stagingTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(staging.Tags), &stagingTags))
	assert.Contains(t, stagingTags, "warning")
}

func TestDigitalOcean_Discover_MissingToken(t *testing.T) {
	t.Setenv("KITE_DIGITALOCEAN_TOKEN", "")

	d := NewDigitalOcean()

	_, err := d.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_DIGITALOCEAN_TOKEN")

	assets, err := d.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestDigitalOcean_Discover_AuthFailure(t *testing.T) {
	srv := newMockDOAPI(t)
	defer srv.Close()

	t.Setenv("KITE_DIGITALOCEAN_TOKEN", "wrong-token")

	d := NewDigitalOcean()
	d.baseURL = srv.URL
	_, err := d.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
