package mdm

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

func newMockWorkspaceOneAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /API/mdm/devices/search", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "wso-user" || pass != "wso-pass" || r.Header.Get("aw-tenant-code") != "tenant-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Devices": []map[string]any{
				{
					"DeviceFriendlyName": "iphone-ceo",
					"Model":              "iPhone 15 Pro",
					"Platform":           "Apple",
					"OperatingSystem":    "iOS 17.4",
					"SerialNumber":       "F2LABC123",
					"Udid":               "udid-aaa-111",
					"DeviceId":           101,
					"UserEmailAddress":   "CEO@Example.com",
					"OwnershipTypeCode":  "C",
					"ComplianceStatus":   "Compliant",
					"LastSeen":           "2026-04-05T09:00:00Z",
				},
				{
					"DeviceFriendlyName": "win-laptop",
					"Model":              "Surface",
					"Platform":           "WinRT",
					"OperatingSystem":    "Windows 10.0.19045",
					"SerialNumber":       "SN-WIN-1",
					"Udid":               "",
					"DeviceId":           202,
					"UserEmailAddress":   "no-at-sign",
					"OwnershipTypeCode":  "E",
					"ComplianceStatus":   "NonCompliant",
					"LastSeen":           "2026-04-04T09:00:00Z",
				},
			},
			"Total":    2,
			"Page":     0,
			"PageSize": wsonePageSize,
		})
	})

	return httptest.NewServer(mux)
}

func TestWorkspaceOne_Name(t *testing.T) {
	assert.Equal(t, "workspace_one", NewWorkspaceOne().Name())
}

func TestWorkspaceOne_Discover_Success(t *testing.T) {
	srv := newMockWorkspaceOneAPI(t)
	defer srv.Close()

	w := &WorkspaceOne{baseURL: srv.URL}
	cfg := map[string]any{
		"enabled":  true,
		"username": "wso-user",
		"password": "wso-pass",
		"api_key":  "tenant-key",
	}

	assets, err := w.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, assets, 2)

	phone := findAsset(assets, "iphone-ceo")
	require.NotNil(t, phone)
	assert.Equal(t, model.AssetTypeWorkstation, phone.AssetType)
	assert.Equal(t, "ios", phone.OSFamily)
	assert.Equal(t, "iOS 17.4", phone.OSVersion)
	assert.Equal(t, "workspace_one", phone.DiscoverySource)
	assert.Equal(t, model.ManagedManaged, phone.IsManaged)
	assert.Equal(t, model.AuthorizationUnknown, phone.IsAuthorized)
	assert.Equal(t, "udid-aaa-111", phone.MDMEnrollmentID)
	assert.Equal(t, "corporate_dedicated", phone.OwnershipType)
	assert.Equal(t, "ceo@example.com", phone.EnrolledUserUPN) // lowercased
	assert.Equal(t, "compliant", phone.ComplianceState)
	assert.NotEmpty(t, phone.NaturalKey)

	var phoneTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(phone.Tags), &phoneTags))
	assert.Equal(t, "F2LABC123", phoneTags["serial_number"])
	assert.Equal(t, "iPhone 15 Pro", phoneTags["model"])

	laptop := findAsset(assets, "win-laptop")
	require.NotNil(t, laptop)
	assert.Equal(t, "windows", laptop.OSFamily)
	assert.Equal(t, "202", laptop.MDMEnrollmentID) // Udid empty → DeviceId fallback
	assert.Equal(t, "employee_owned", laptop.OwnershipType)
	assert.Empty(t, laptop.EnrolledUserUPN) // no "@" → dropped
	assert.Equal(t, "non_compliant", laptop.ComplianceState)
}

func TestWorkspaceOne_Discover_Pagination(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /API/mdm/devices/search", func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")

		if page == "0" {
			// A full page (wsonePageSize devices) forces a second fetch.
			devices := make([]map[string]any, 0, wsonePageSize)
			for n := 0; n < wsonePageSize; n++ {
				devices = append(devices, map[string]any{
					"DeviceFriendlyName": "dev-p0",
					"Platform":           "Apple",
					"OperatingSystem":    "iOS 17",
					"Udid":               "udid-0",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Devices": devices, "Total": wsonePageSize + 2, "Page": 0, "PageSize": wsonePageSize,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Devices": []map[string]any{
				{"DeviceFriendlyName": "dev-p1-a", "Platform": "Android", "OperatingSystem": "Android 14", "Udid": "udid-1a"},
				{"DeviceFriendlyName": "dev-p1-b", "Platform": "Apple", "OperatingSystem": "macOS 14", "Udid": "udid-1b"},
			},
			"Total": wsonePageSize + 2, "Page": 1, "PageSize": wsonePageSize,
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	w := &WorkspaceOne{baseURL: srv.URL}
	cfg := map[string]any{
		"enabled":  true,
		"username": "u",
		"password": "p",
		"api_key":  "k",
	}

	assets, err := w.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Len(t, assets, wsonePageSize+2)
	// macOS device on page 1 normalises to darwin.
	mac := findAsset(assets, "dev-p1-b")
	require.NotNil(t, mac)
	assert.Equal(t, "darwin", mac.OSFamily)
}

func TestWorkspaceOne_Discover_MissingCredentials(t *testing.T) {
	w := NewWorkspaceOne()

	// Enabled but no credentials → skip (nil, nil).
	assets, err := w.Discover(context.Background(), map[string]any{"enabled": true})
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestWorkspaceOne_Discover_DisabledWithCredentials(t *testing.T) {
	srv := newMockWorkspaceOneAPI(t)
	defer srv.Close()

	w := &WorkspaceOne{baseURL: srv.URL}
	cfg := map[string]any{
		"enabled":  false,
		"username": "wso-user",
		"password": "wso-pass",
		"api_key":  "tenant-key",
	}

	assets, err := w.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestWorkspaceOne_Discover_AuthFailure(t *testing.T) {
	srv := newMockWorkspaceOneAPI(t)
	defer srv.Close()

	w := &WorkspaceOne{baseURL: srv.URL}
	cfg := map[string]any{
		"enabled":  true,
		"username": "wso-user",
		"password": "wso-pass",
		"api_key":  "wrong-tenant",
	}

	// 401 surfaces as an error for this connector.
	_, err := w.Discover(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestDeriveWorkspaceOneOSFamily(t *testing.T) {
	assert.Equal(t, "windows", deriveWorkspaceOneOSFamily("WinRT", ""))
	assert.Equal(t, "windows", deriveWorkspaceOneOSFamily("Windows", "Windows 10"))
	assert.Equal(t, "android", deriveWorkspaceOneOSFamily("Android", "Android 14"))
	assert.Equal(t, "darwin", deriveWorkspaceOneOSFamily("AppleOsX", "macOS 14"))
	assert.Equal(t, "darwin", deriveWorkspaceOneOSFamily("Apple", "macOS 14"))
	assert.Equal(t, "ios", deriveWorkspaceOneOSFamily("Apple", "iOS 17.4"))
	assert.Equal(t, "unknown", deriveWorkspaceOneOSFamily("ChromeOS", "Chrome"))
}

func TestMapWorkspaceOneOwnership(t *testing.T) {
	assert.Equal(t, "corporate_dedicated", mapWorkspaceOneOwnership("C"))
	assert.Equal(t, "corporate_shared", mapWorkspaceOneOwnership("s"))
	assert.Equal(t, "employee_owned", mapWorkspaceOneOwnership(" E "))
	assert.Equal(t, "unknown", mapWorkspaceOneOwnership("X"))
	assert.Equal(t, "unknown", mapWorkspaceOneOwnership(""))
}

func TestMapWorkspaceOneCompliance(t *testing.T) {
	assert.Equal(t, "compliant", mapWorkspaceOneCompliance("Compliant"))
	assert.Equal(t, "non_compliant", mapWorkspaceOneCompliance("NonCompliant"))
	assert.Equal(t, "non_compliant", mapWorkspaceOneCompliance("non-compliant"))
	assert.Equal(t, "unknown", mapWorkspaceOneCompliance("Unknown"))
}
