package cmdb

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

func newMockDevice42API(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/1.0/devices/", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "d42-user" || pass != "d42-pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total_count": 2,
			"offset":      0,
			"limit":       100,
			"Devices": []map[string]any{
				{
					"device_id":     501,
					"name":          "d42-srv-01",
					"type":          "physical",
					"os":            "Ubuntu",
					"osver":         "22.04",
					"serial_no":     "SN-501",
					"service_level": "production",
					"asset_no":      "D42-ASSET-501",
					"in_service":    true,
					"uuid":          "uuid-501",
				},
				{
					"device_id":     502,
					"name":          "d42-vm-01",
					"type":          "virtual",
					"os":            "Windows Server 2022",
					"osver":         "2022",
					"serial_no":     "SN-502",
					"service_level": "staging",
					"asset_no":      "D42-ASSET-502",
					"in_service":    false,
					"uuid":          "uuid-502",
				},
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestDevice42_Name(t *testing.T) {
	assert.Equal(t, "device42", NewDevice42().Name())
}

func TestDevice42_Discover_Success(t *testing.T) {
	srv := newMockDevice42API(t)
	defer srv.Close()

	d := &Device42{baseURL: srv.URL}
	cfg := map[string]any{
		"enabled":  true,
		"username": "d42-user",
		"password": "d42-pass",
	}

	assets, err := d.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, assets, 2)

	srvAsset := findAssetByHostname(assets, "d42-srv-01")
	require.NotNil(t, srvAsset)
	assert.Equal(t, model.AssetTypeServer, srvAsset.AssetType)
	assert.Equal(t, "linux", srvAsset.OSFamily)
	assert.Equal(t, "22.04", srvAsset.OSVersion)
	assert.Equal(t, "device42", srvAsset.DiscoverySource)
	assert.Equal(t, model.AuthorizationAuthorized, srvAsset.IsAuthorized)
	assert.Equal(t, model.ManagedUnknown, srvAsset.IsManaged)
	assert.NotEmpty(t, srvAsset.NaturalKey)

	// Dedicated CMDB fields (no Environment/Owner overloading).
	assert.Equal(t, "501", srvAsset.CMDBSysID)
	assert.Equal(t, "D42-ASSET-501", srvAsset.AssetTag)
	assert.Equal(t, "operational", srvAsset.OperationalStatus)
	assert.Empty(t, srvAsset.Environment)
	assert.Empty(t, srvAsset.Owner)

	// service_level/serial_no/type land in Tags.
	var srvTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(srvAsset.Tags), &srvTags))
	assert.Equal(t, "production", srvTags["service_level"])
	assert.Equal(t, "SN-501", srvTags["serial_no"])
	assert.Equal(t, "physical", srvTags["type"])

	// Virtual device → non_operational + VirtualMachine.
	vm := findAssetByHostname(assets, "d42-vm-01")
	require.NotNil(t, vm)
	assert.Equal(t, model.AssetTypeVirtualMachine, vm.AssetType)
	assert.Equal(t, "windows", vm.OSFamily)
	assert.Equal(t, "502", vm.CMDBSysID)
	assert.Equal(t, "non_operational", vm.OperationalStatus)
}

func TestDevice42_Discover_Disabled(t *testing.T) {
	srv := newMockDevice42API(t)
	defer srv.Close()

	// F3: creds present but enabled is false → discovery must be skipped.
	d := &Device42{baseURL: srv.URL}
	assets, err := d.Discover(context.Background(), map[string]any{
		"enabled":  false,
		"username": "d42-user",
		"password": "d42-pass",
	})
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestDevice42_Discover_MissingCredentials(t *testing.T) {
	d := NewDevice42()

	// Enabled but no username/password → graceful skip.
	assets, err := d.Discover(context.Background(), map[string]any{
		"enabled": true,
		"api_url": "https://device42.example.com",
	})
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestDevice42_Discover_AuthFailure(t *testing.T) {
	srv := newMockDevice42API(t)
	defer srv.Close()

	d := &Device42{baseURL: srv.URL}
	cfg := map[string]any{
		"enabled":  true,
		"username": "d42-user",
		"password": "wrong",
	}

	// Auth failure → returns empty (graceful).
	assets, err := d.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Empty(t, assets)
}

func TestClassifyDevice42(t *testing.T) {
	assert.Equal(t, model.AssetTypeVirtualMachine, classifyDevice42("virtual"))
	assert.Equal(t, model.AssetTypeServer, classifyDevice42("cluster"))
	assert.Equal(t, model.AssetTypeServer, classifyDevice42("physical"))
	assert.Equal(t, model.AssetTypeServer, classifyDevice42("unknown"))
}

func TestDeriveDevice42OSFamily(t *testing.T) {
	assert.Equal(t, "windows", deriveDevice42OSFamily("Windows Server 2022"))
	assert.Equal(t, "linux", deriveDevice42OSFamily("Ubuntu"))
	assert.Equal(t, "darwin", deriveDevice42OSFamily("macOS Sonoma"))
	assert.Equal(t, "freebsd", deriveDevice42OSFamily("FreeBSD"))
	assert.Equal(t, "", deriveDevice42OSFamily(""))
}
