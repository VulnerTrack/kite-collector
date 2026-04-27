package entra

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

// newMockEntraAPI returns an httptest.Server that fakes the OAuth2 token
// endpoint plus the four Graph list endpoints (users, servicePrincipals,
// groups, devices). All endpoints succeed; the device list returns two
// records — one Windows workstation and one macOS device — so callers can
// assert on the asset slice produced by buildDeviceAssets.
func newMockEntraAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.FormValue("client_secret") != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-bearer-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	mux.HandleFunc("GET /v1.0/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mock-bearer-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "u1", "userPrincipalName": "alice@example.com", "displayName": "Alice", "accountEnabled": true},
				{"id": "u2", "userPrincipalName": "bob@example.com", "displayName": "Bob", "accountEnabled": false},
			},
		})
	})

	mux.HandleFunc("GET /v1.0/servicePrincipals", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "sp1", "appId": "app-1", "displayName": "deploy-bot", "servicePrincipalType": "Application"},
			},
		})
	})

	mux.HandleFunc("GET /v1.0/groups", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "g1", "displayName": "Engineers", "securityEnabled": true},
			},
		})
	})

	mux.HandleFunc("GET /v1.0/devices", func(w http.ResponseWriter, _ *http.Request) {
		isCompliantTrue := true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id":                     "d1",
					"deviceId":               "device-1",
					"displayName":            "LAPTOP-001",
					"operatingSystem":        "Windows",
					"operatingSystemVersion": "10.0.22631",
					"trustType":              "AzureAD",
					"isCompliant":            isCompliantTrue,
					"isManaged":              true,
				},
				{
					"id":                     "d2",
					"deviceId":               "device-2",
					"displayName":            "MAC-002",
					"operatingSystem":        "macOS",
					"operatingSystemVersion": "14.4",
					"trustType":              "Workplace",
				},
			},
		})
	})

	return httptest.NewServer(mux)
}

// newMockEntraPaginatedDevicesAPI returns a server that emits the device list
// across two pages so the @odata.nextLink walker can be exercised.
func newMockEntraPaginatedDevicesAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-bearer-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	// Empty user / SP / group endpoints to keep Discover() flowing.
	for _, path := range []string{"/v1.0/users", "/v1.0/servicePrincipals", "/v1.0/groups"} {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
		})
	}

	var srv *httptest.Server
	calls := 0
	mux.HandleFunc("GET /v1.0/devices", func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"id": "d1", "deviceId": "device-1", "displayName": "DEV-A", "operatingSystem": "Windows", "trustType": "AzureAD"},
				},
				"@odata.nextLink": srv.URL + "/v1.0/devices?page=2",
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"id": "d2", "deviceId": "device-2", "displayName": "DEV-B", "operatingSystem": "Linux", "trustType": "AzureAD"},
				},
			})
		}
	})

	srv = httptest.NewServer(mux)
	return srv
}

func TestEntraID_Name(t *testing.T) {
	assert.Equal(t, "entra", New().Name())
}

func TestEntraID_Discover_Success(t *testing.T) {
	srv := newMockEntraAPI(t)
	defer srv.Close()

	e := New()
	e.tokenBaseURL = srv.URL
	e.graphBaseURL = srv.URL

	cfg := map[string]any{
		"enabled":       true,
		"tenant_id":     "tenant-guid",
		"client_id":     "client-guid",
		"client_secret": "test-secret",
	}

	assets, err := e.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, assets, 2)

	laptop := findEntraAsset(assets, "LAPTOP-001")
	require.NotNil(t, laptop)
	assert.Equal(t, model.AssetTypeWorkstation, laptop.AssetType)
	assert.Equal(t, "windows", laptop.OSFamily)
	assert.Equal(t, "10.0.22631", laptop.OSVersion)
	assert.Equal(t, "entra", laptop.DiscoverySource)
	assert.Equal(t, "tenant-guid", laptop.TenantID)
	assert.Equal(t, model.AuthorizationUnknown, laptop.IsAuthorized)
	assert.Equal(t, model.ManagedManaged, laptop.IsManaged)
	assert.NotEmpty(t, laptop.NaturalKey)

	mac := findEntraAsset(assets, "MAC-002")
	require.NotNil(t, mac)
	assert.Equal(t, "darwin", mac.OSFamily)
	assert.Equal(t, model.ManagedUnknown, mac.IsManaged) // isManaged absent in payload
}

func TestEntraID_Discover_DisabledReturnsNil(t *testing.T) {
	e := New()
	cfg := map[string]any{
		"enabled":       false,
		"tenant_id":     "tenant",
		"client_id":     "client",
		"client_secret": "secret",
	}
	assets, err := e.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestEntraID_Discover_MissingCredentials(t *testing.T) {
	e := New()
	assets, err := e.Discover(context.Background(), map[string]any{"enabled": true})
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestEntraID_Discover_TokenFailure(t *testing.T) {
	srv := newMockEntraAPI(t)
	defer srv.Close()

	e := New()
	e.tokenBaseURL = srv.URL
	e.graphBaseURL = srv.URL

	cfg := map[string]any{
		"enabled":       true,
		"tenant_id":     "tenant",
		"client_id":     "client",
		"client_secret": "wrong-secret",
	}

	assets, err := e.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestEntraID_Discover_Pagination(t *testing.T) {
	srv := newMockEntraPaginatedDevicesAPI(t)
	defer srv.Close()

	e := New()
	e.tokenBaseURL = srv.URL
	e.graphBaseURL = srv.URL

	cfg := map[string]any{
		"enabled":       true,
		"tenant_id":     "tenant",
		"client_id":     "client",
		"client_secret": "test-secret",
	}

	assets, err := e.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, assets, 2)
	assert.NotNil(t, findEntraAsset(assets, "DEV-A"))
	assert.NotNil(t, findEntraAsset(assets, "DEV-B"))
}

func TestEntraID_Discover_InvalidConfigReturnsError(t *testing.T) {
	e := New()
	cfg := map[string]any{
		"enabled":       true,
		"tenant_id":     "tenant",
		"client_id":     "client",
		"client_secret": "secret",
		// page_size has a hard upper bound of 999 — set above the limit so
		// validate() fails on a real positive value (zero / negative would
		// silently fall back to the default per intCfg).
		"page_size": 5000,
	}
	_, err := e.Discover(context.Background(), cfg)
	require.Error(t, err)
}

func TestParseConfig_Defaults(t *testing.T) {
	c, err := parseConfig(map[string]any{
		"tenant_id":     "t",
		"client_id":     "c",
		"client_secret": "s",
	})
	require.NoError(t, err)
	assert.True(t, c.enabled)
	assert.Equal(t, defaultStaleAccountDays, c.staleAccountDays)
	assert.Equal(t, defaultMaxUsers, c.maxUsers)
	assert.Equal(t, defaultMaxServicePrincipal, c.maxServicePrincipal)
	assert.Equal(t, defaultPageSize, c.pageSize)
}

func TestParseConfig_Overrides(t *testing.T) {
	c, err := parseConfig(map[string]any{
		"enabled":                true,
		"tenant_id":              "t",
		"client_id":              "c",
		"client_secret":          "s",
		"stale_account_days":     30,
		"max_users":              500,
		"max_service_principals": 25,
	})
	require.NoError(t, err)
	assert.Equal(t, 30, c.staleAccountDays)
	assert.Equal(t, 500, c.maxUsers)
	assert.Equal(t, 25, c.maxServicePrincipal)
}

func TestPrivilegedRoleTemplateIDs_Stable(t *testing.T) {
	ids := PrivilegedRoleTemplateIDs()
	assert.Equal(t, "Global Administrator", ids["62e90394-69f5-4237-9190-012177145e10"])
	assert.Equal(t, "Privileged Role Administrator", ids["e8611ab8-c189-46e8-94e1-60213ab1f814"])
	// Returned map is a copy: mutating it must not affect future calls.
	ids["00000000-0000-0000-0000-000000000000"] = "tampered"
	again := PrivilegedRoleTemplateIDs()
	_, leaked := again["00000000-0000-0000-0000-000000000000"]
	assert.False(t, leaked, "PrivilegedRoleTemplateIDs must return a defensive copy")
}

func TestClassifyEntraDevice(t *testing.T) {
	tests := []struct {
		os   string
		want model.AssetType
	}{
		{"Windows", model.AssetTypeWorkstation},
		{"macOS", model.AssetTypeWorkstation},
		{"Windows Server 2022", model.AssetTypeServer},
		{"Linux Server", model.AssetTypeServer},
		{"", model.AssetTypeWorkstation},
	}
	for _, tc := range tests {
		t.Run(tc.os, func(t *testing.T) {
			assert.Equal(t, tc.want, classifyEntraDevice(tc.os))
		})
	}
}

func TestNormalizeOS(t *testing.T) {
	cases := map[string]string{
		"Windows":             "windows",
		"Windows Server 2022": "windows",
		"macOS":               "darwin",
		"iOS":                 "darwin",
		"iPadOS":              "darwin",
		"Android":             "linux",
		"Linux":               "linux",
		"":                    "",
		"ChromeOS":            "chromeos",
	}
	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, want, normalizeOS(input))
		})
	}
}

func TestNormalizeTrustType(t *testing.T) {
	cases := map[string]string{
		"AzureAD":                 "AzureAD",
		"azuread":                 "AzureAD",
		"":                        "AzureAD",
		"ServerAD":                "ServerAD",
		"hybrid azure ad joined":  "ServerAD",
		"hybridAzureADJoined":     "ServerAD",
		"Workplace":               "Workplace",
		"workplace":               "Workplace",
		"unknown_value_from_test": "AzureAD",
	}
	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, want, normalizeTrustType(input))
		})
	}
}

func TestManagedStateFromEntraDevice(t *testing.T) {
	managed := true
	unmanaged := false
	assert.Equal(t, model.ManagedManaged, managedStateFromEntraDevice(entraDevice{IsManaged: &managed}))
	assert.Equal(t, model.ManagedUnmanaged, managedStateFromEntraDevice(entraDevice{IsManaged: &unmanaged}))
	assert.Equal(t, model.ManagedUnknown, managedStateFromEntraDevice(entraDevice{}))
}

func TestDeviceTags_OmitsAbsentBooleans(t *testing.T) {
	d := entraDevice{ID: "obj-1", DeviceID: "dev-1", DisplayName: "X"}
	tags := deviceTags(d, "tenant")
	_, hasCompliant := tags[tagIsCompliant]
	_, hasManaged := tags[tagIsManaged]
	assert.False(t, hasCompliant)
	assert.False(t, hasManaged)
	assert.Equal(t, "tenant", tags[tagTenantID])
	assert.Equal(t, "obj-1", tags[tagObjectID])
}

// findEntraAsset returns the first asset matching hostname, or nil.
func findEntraAsset(assets []model.Asset, hostname string) *model.Asset {
	for i := range assets {
		if assets[i].Hostname == hostname {
			return &assets[i]
		}
	}
	return nil
}
