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

func newMockVercelAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v9/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-vercel-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		until := r.URL.Query().Get("until")
		w.Header().Set("Content-Type", "application/json")

		if until == "" {
			next := int64(1700000000000)
			_ = json.NewEncoder(w).Encode(vercelProjectsResponse{
				Projects: []vercelProject{
					{
						ID: "prj-1", Name: "marketing-site",
						Framework: "nextjs",
						CreatedAt: 1680000000000,
						UpdatedAt: 1700000000000,
					},
					{
						ID: "prj-2", Name: "api-gateway",
						Framework: "remix",
						CreatedAt: 1690000000000,
						UpdatedAt: 1705000000000,
					},
				},
				Pagination: vercelPagination{Count: 2, Next: &next},
			})
		} else {
			_ = json.NewEncoder(w).Encode(vercelProjectsResponse{
				Projects: []vercelProject{
					{
						ID: "prj-3", Name: "docs",
						Framework: "",
						CreatedAt: 1670000000000,
						UpdatedAt: 1695000000000,
					},
				},
				Pagination: vercelPagination{Count: 1, Next: nil},
			})
		}
	})

	return httptest.NewServer(mux)
}

func TestVercel_Name(t *testing.T) {
	assert.Equal(t, "vercel", NewVercel().Name())
}

func TestVercel_Discover_Success(t *testing.T) {
	srv := newMockVercelAPI(t)
	defer srv.Close()

	t.Setenv("KITE_VERCEL_TOKEN", "test-vercel-token")

	v := NewVercel()
	v.baseURL = srv.URL
	assets, err := v.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, assets, 3)

	marketing := findAssetByHostname(assets, "marketing-site")
	require.NotNil(t, marketing)
	assert.Equal(t, model.AssetTypeContainer, marketing.AssetType)
	assert.Equal(t, "vercel", marketing.DiscoverySource)
	assert.NotEmpty(t, marketing.NaturalKey)

	var mTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(marketing.Tags), &mTags))
	assert.Equal(t, "nextjs", mTags["framework"])
	assert.Equal(t, "vercel", mTags["platform"])

	// Third page item found via pagination.
	docs := findAssetByHostname(assets, "docs")
	require.NotNil(t, docs)
	var dTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(docs.Tags), &dTags))
	assert.NotContains(t, dTags, "framework")
}

func TestVercel_Discover_MissingToken(t *testing.T) {
	t.Setenv("KITE_VERCEL_TOKEN", "")

	v := NewVercel()

	_, err := v.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_VERCEL_TOKEN")

	assets, err := v.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestVercel_Discover_AuthFailure(t *testing.T) {
	srv := newMockVercelAPI(t)
	defer srv.Close()

	t.Setenv("KITE_VERCEL_TOKEN", "wrong-token")

	v := NewVercel()
	v.baseURL = srv.URL
	_, err := v.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
