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

// findAssetByHostname returns the first asset matching hostname, or nil.
func findAssetByHostname(assets []model.Asset, hostname string) *model.Asset {
	for i := range assets {
		if assets[i].Hostname == hostname {
			return &assets[i]
		}
	}
	return nil
}

func newMockHerokuAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /apps", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-heroku-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		rangeHeader := r.Header.Get("Range")
		w.Header().Set("Content-Type", "application/json")

		if rangeHeader == "" || rangeHeader == "id ..; max=200" {
			w.Header().Set("Next-Range", "id 01234..; max=200")
			_ = json.NewEncoder(w).Encode([]herokuApp{
				{
					ID: "app-1-id", Name: "web-app",
					Stack:                herokuRef{Name: "heroku-24"},
					Region:               herokuRef{Name: "us"},
					BuildpackDescription: "Ruby/Rack",
					WebURL:               "https://web-app.herokuapp.com/",
					CreatedAt:            "2024-01-10T08:00:00Z",
					ReleasedAt:           "2024-06-15T12:00:00Z",
					Maintenance:          false,
				},
				{
					ID: "app-2-id", Name: "api-app",
					Stack:       herokuRef{Name: "heroku-24"},
					Region:      herokuRef{Name: "eu"},
					WebURL:      "https://api-app.herokuapp.com/",
					CreatedAt:   "2024-03-01T10:00:00Z",
					ReleasedAt:  "2024-06-01T08:00:00Z",
					Maintenance: true,
				},
			})
		} else {
			_ = json.NewEncoder(w).Encode([]herokuApp{
				{
					ID: "app-3-id", Name: "worker-app",
					Stack:                herokuRef{Name: "heroku-22"},
					Region:               herokuRef{Name: "us"},
					BuildpackDescription: "Python",
					WebURL:               "https://worker-app.herokuapp.com/",
					CreatedAt:            "2024-05-01T00:00:00Z",
					ReleasedAt:           "2024-06-20T18:00:00Z",
				},
			})
		}
	})

	return httptest.NewServer(mux)
}

func TestHeroku_Name(t *testing.T) {
	assert.Equal(t, "heroku", NewHeroku().Name())
}

func TestHeroku_Discover_Success(t *testing.T) {
	srv := newMockHerokuAPI(t)
	defer srv.Close()

	t.Setenv("KITE_HEROKU_TOKEN", "test-heroku-token")

	h := NewHeroku()
	h.baseURL = srv.URL
	assets, err := h.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, assets, 3)

	web := findAssetByHostname(assets, "web-app")
	require.NotNil(t, web)
	assert.Equal(t, model.AssetTypeContainer, web.AssetType)
	assert.Equal(t, "heroku", web.DiscoverySource)
	assert.Equal(t, "us", web.Environment)
	assert.NotEmpty(t, web.NaturalKey)

	var webTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(web.Tags), &webTags))
	assert.Equal(t, "heroku-24", webTags["stack"])
	assert.Equal(t, "Ruby/Rack", webTags["runtime"])
	assert.Equal(t, "heroku", webTags["platform"])
	assert.NotContains(t, webTags, "warning")

	// Maintenance app gets warning.
	api := findAssetByHostname(assets, "api-app")
	require.NotNil(t, api)
	var apiTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(api.Tags), &apiTags))
	assert.Contains(t, apiTags, "warning")
	assert.Equal(t, true, apiTags["maintenance"])
}

func TestHeroku_Discover_MissingToken(t *testing.T) {
	t.Setenv("KITE_HEROKU_TOKEN", "")

	h := NewHeroku()

	_, err := h.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_HEROKU_TOKEN")

	assets, err := h.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestHeroku_Discover_AuthFailure(t *testing.T) {
	srv := newMockHerokuAPI(t)
	defer srv.Close()

	t.Setenv("KITE_HEROKU_TOKEN", "wrong-token")

	h := NewHeroku()
	h.baseURL = srv.URL
	_, err := h.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
