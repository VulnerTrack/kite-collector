package cmdb

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// lansweeperGraphQLPage builds the GraphQL response envelope for a single
// page of asset resources.
func lansweeperGraphQLPage(items []map[string]any, next string) map[string]any {
	return map[string]any{
		"data": map[string]any{
			"site": map[string]any{
				"assetResources": map[string]any{
					"items":      items,
					"pagination": map[string]any{"next": next},
				},
			},
		},
	}
}

// lansweeperItemJSON builds a single asset resource item.
func lansweeperItemJSON(key, name, osCaption, ip, domain string) map[string]any {
	return map[string]any{
		"key": key,
		"assetBasicInfo": map[string]any{
			"name":      name,
			"type":      "Windows",
			"ipAddress": ip,
			"domain":    domain,
		},
		"operatingSystem": map[string]any{"caption": osCaption},
	}
}

func newMockLansweeperAPI(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer ls-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(lansweeperGraphQLPage(
			[]map[string]any{
				lansweeperItemJSON("ls-1", "win-ws-01", "Microsoft Windows 10 Pro", "10.0.0.20", "corp.local"),
			}, "",
		))
	}))
}

func TestLansweeper_Name(t *testing.T) {
	assert.Equal(t, "lansweeper", NewLansweeper().Name())
}

func TestLansweeper_Discover_Success(t *testing.T) {
	srv := newMockLansweeperAPI(t)
	defer srv.Close()

	l := &Lansweeper{baseURL: srv.URL}
	cfg := map[string]any{
		"enabled": true,
		"api_key": "ls-key",
		"site_id": "site-1",
	}

	assets, err := l.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, assets, 1)

	ws := findAssetByHostname(assets, "win-ws-01")
	require.NotNil(t, ws)
	assert.Equal(t, "windows", ws.OSFamily)
	assert.Equal(t, "ls-1", ws.CMDBSysID)
	assert.Equal(t, "lansweeper", ws.DiscoverySource)
	assert.Equal(t, model.AuthorizationAuthorized, ws.IsAuthorized)
	assert.Equal(t, model.ManagedUnknown, ws.IsManaged)
	assert.NotEmpty(t, ws.NaturalKey)

	// ipAddress/domain land in Tags (no Environment/Owner overloading).
	assert.Empty(t, ws.Environment)
	assert.Empty(t, ws.Owner)
	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(ws.Tags), &tags))
	assert.Equal(t, "10.0.0.20", tags["ip_address"])
	assert.Equal(t, "corp.local", tags["domain"])
}

func TestLansweeper_Discover_Pagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Variables struct {
				Cursor string `json:"cursor"`
			} `json:"variables"`
		}
		_ = json.Unmarshal(body, &req)

		w.Header().Set("Content-Type", "application/json")
		if req.Variables.Cursor == "" {
			// First page returns a cursor pointing at page two.
			_ = json.NewEncoder(w).Encode(lansweeperGraphQLPage(
				[]map[string]any{
					lansweeperItemJSON("k1", "host-a", "Windows", "1.1.1.1", "d"),
				}, "cursor-2",
			))
			return
		}
		// Second page terminates pagination (next empty).
		_ = json.NewEncoder(w).Encode(lansweeperGraphQLPage(
			[]map[string]any{
				lansweeperItemJSON("k2", "host-b", "Linux", "2.2.2.2", "d"),
			}, "",
		))
	}))
	defer srv.Close()

	l := &Lansweeper{baseURL: srv.URL}
	cfg := map[string]any{
		"enabled": true,
		"api_key": "k",
		"site_id": "s",
	}

	assets, err := l.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, assets, 2)
	assert.NotNil(t, findAssetByHostname(assets, "host-a"))
	assert.NotNil(t, findAssetByHostname(assets, "host-b"))
}

func TestLansweeper_Discover_Disabled(t *testing.T) {
	srv := newMockLansweeperAPI(t)
	defer srv.Close()

	// F3: creds present but enabled is false → discovery must be skipped.
	l := &Lansweeper{baseURL: srv.URL}
	assets, err := l.Discover(context.Background(), map[string]any{
		"enabled": false,
		"api_key": "ls-key",
		"site_id": "site-1",
	})
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestLansweeper_Discover_MissingCredentials(t *testing.T) {
	l := NewLansweeper()

	// Enabled with an endpoint and site but no api_key → graceful skip.
	assets, err := l.Discover(context.Background(), map[string]any{
		"enabled": true,
		"api_url": "https://api.lansweeper.com/graphql",
		"site_id": "site-1",
	})
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestLansweeper_Discover_AuthFailure(t *testing.T) {
	srv := newMockLansweeperAPI(t)
	defer srv.Close()

	l := &Lansweeper{baseURL: srv.URL}
	cfg := map[string]any{
		"enabled": true,
		"api_key": "wrong-key",
		"site_id": "site-1",
	}

	// Auth failure → returns empty (graceful).
	assets, err := l.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Empty(t, assets)
}

func TestClassifyLansweeperAsset(t *testing.T) {
	assert.Equal(t, model.AssetTypeServer, classifyLansweeperAsset("Windows Server"))
	assert.Equal(t, model.AssetTypeWorkstation, classifyLansweeperAsset("Workstation"))
	assert.Equal(t, model.AssetTypeIOTDevice, classifyLansweeperAsset("Printer"))
	assert.Equal(t, model.AssetTypeServer, classifyLansweeperAsset("Windows"))
}

func TestDeriveLansweeperOSFamily(t *testing.T) {
	assert.Equal(t, "windows", deriveLansweeperOSFamily("Microsoft Windows 11 Pro"))
	assert.Equal(t, "linux", deriveLansweeperOSFamily("Ubuntu 22.04"))
	assert.Equal(t, "darwin", deriveLansweeperOSFamily("macOS Ventura"))
	assert.Equal(t, "", deriveLansweeperOSFamily(""))
}
