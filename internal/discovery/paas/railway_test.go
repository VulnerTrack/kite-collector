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

func newMockRailwayAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /graphql/v2", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-railway-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "data": {
    "me": {
      "projects": {
        "edges": [
          {
            "node": {
              "id": "proj-1",
              "name": "my-project",
              "services": {
                "edges": [
                  {"node": {"id": "svc-1", "name": "web", "icon": "globe"}},
                  {"node": {"id": "svc-2", "name": "worker", "icon": ""}}
                ]
              },
              "environments": {
                "edges": [
                  {"node": {"id": "env-1", "name": "production"}},
                  {"node": {"id": "env-2", "name": "staging"}}
                ]
              }
            }
          },
          {
            "node": {
              "id": "proj-2",
              "name": "empty-project",
              "services": {"edges": []},
              "environments": {"edges": []}
            }
          }
        ]
      }
    }
  }
}`))
	})

	return httptest.NewServer(mux)
}

func TestRailway_Name(t *testing.T) {
	assert.Equal(t, "railway", NewRailway().Name())
}

func TestRailway_Discover_Success(t *testing.T) {
	srv := newMockRailwayAPI(t)
	defer srv.Close()

	t.Setenv("KITE_RAILWAY_TOKEN", "test-railway-token")

	ry := NewRailway()
	ry.baseURL = srv.URL
	assets, err := ry.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	// 2 services from my-project + 1 empty-project = 3
	assert.Len(t, assets, 3)

	web := findAssetByHostname(assets, "web")
	require.NotNil(t, web)
	assert.Equal(t, model.AssetTypeContainer, web.AssetType)
	assert.Equal(t, "railway", web.DiscoverySource)
	assert.NotEmpty(t, web.NaturalKey)

	var webTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(web.Tags), &webTags))
	assert.Equal(t, "my-project", webTags["project"])
	assert.Equal(t, "railway", webTags["platform"])
	assert.Equal(t, "globe", webTags["icon"])

	// Empty project gets a warning tag.
	empty := findAssetByHostname(assets, "empty-project")
	require.NotNil(t, empty)
	var emptyTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(empty.Tags), &emptyTags))
	assert.Contains(t, emptyTags, "warning")
}

func TestRailway_Discover_MissingToken(t *testing.T) {
	t.Setenv("KITE_RAILWAY_TOKEN", "")

	ry := NewRailway()

	_, err := ry.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_RAILWAY_TOKEN")

	assets, err := ry.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestRailway_Discover_AuthFailure(t *testing.T) {
	srv := newMockRailwayAPI(t)
	defer srv.Close()

	t.Setenv("KITE_RAILWAY_TOKEN", "wrong-token")

	ry := NewRailway()
	ry.baseURL = srv.URL
	_, err := ry.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
