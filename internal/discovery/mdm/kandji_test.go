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

func newMockKandjiAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Top-level JSON array.
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"device_id":      "kandji-dev-1",
				"device_name":    "macbook-air-jane",
				"model":          "MacBook Air",
				"platform":       "Mac",
				"os_version":     "14.4.1",
				"serial_number":  "C02XYZ",
				"blueprint_name": "Corporate Macs",
				"last_check_in":  "2026-04-06T08:00:00Z",
				"user":           map[string]any{"email": "Jane.Doe@Example.com", "name": "Jane Doe"},
			},
			{
				"device_id":      "kandji-dev-2",
				"device_name":    "iphone-bob",
				"model":          "iPhone 14",
				"platform":       "iPhone",
				"os_version":     "17.4",
				"serial_number":  "F1ABC",
				"blueprint_name": "Mobile",
				"last_check_in":  "2026-04-06T07:00:00Z",
				"user":           map[string]any{"email": "", "name": ""},
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestKandji_Name(t *testing.T) {
	assert.Equal(t, "kandji", NewKandji().Name())
}

func TestKandji_Discover_Success(t *testing.T) {
	srv := newMockKandjiAPI(t)
	defer srv.Close()

	k := &Kandji{baseURL: srv.URL}
	cfg := map[string]any{
		"enabled": true,
		"api_key": "tok",
	}

	assets, err := k.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, assets, 2)

	mac := findAsset(assets, "macbook-air-jane")
	require.NotNil(t, mac)
	assert.Equal(t, model.AssetTypeWorkstation, mac.AssetType)
	assert.Equal(t, "darwin", mac.OSFamily)
	assert.Equal(t, "14.4.1", mac.OSVersion)
	assert.Equal(t, "kandji", mac.DiscoverySource)
	assert.Equal(t, model.ManagedManaged, mac.IsManaged)
	assert.Equal(t, model.AuthorizationUnknown, mac.IsAuthorized)
	assert.Equal(t, "kandji-dev-1", mac.MDMEnrollmentID)
	assert.Equal(t, "jane.doe@example.com", mac.EnrolledUserUPN) // lowercased
	assert.Equal(t, "corporate_dedicated", mac.OwnershipType)
	assert.Equal(t, "not_evaluated", mac.ComplianceState)
	assert.NotEmpty(t, mac.NaturalKey)

	var macTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(mac.Tags), &macTags))
	assert.Equal(t, "C02XYZ", macTags["serial_number"])
	assert.Equal(t, "Corporate Macs", macTags["blueprint"])
	assert.Equal(t, "MacBook Air", macTags["model"])

	phone := findAsset(assets, "iphone-bob")
	require.NotNil(t, phone)
	assert.Equal(t, "ios", phone.OSFamily)
	assert.Equal(t, "kandji-dev-2", phone.MDMEnrollmentID)
	assert.Empty(t, phone.EnrolledUserUPN) // no email → dropped
}

func TestKandji_Discover_Pagination(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		offset := r.URL.Query().Get("offset")
		w.Header().Set("Content-Type", "application/json")
		if offset == "0" {
			// A full page (kandjiPageSize) forces a second fetch.
			devices := make([]map[string]any, 0, kandjiPageSize)
			for n := 0; n < kandjiPageSize; n++ {
				devices = append(devices, map[string]any{
					"device_id":   "p0",
					"device_name": "p0-host",
					"platform":    "Mac",
					"os_version":  "14",
				})
			}
			_ = json.NewEncoder(w).Encode(devices)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"device_id": "p1", "device_name": "p1-host", "platform": "iPad", "os_version": "17"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	k := &Kandji{baseURL: srv.URL}
	cfg := map[string]any{"enabled": true, "api_key": "anything"}

	assets, err := k.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Len(t, assets, kandjiPageSize+1)
	ipad := findAsset(assets, "p1-host")
	require.NotNil(t, ipad)
	assert.Equal(t, "ios", ipad.OSFamily)
}

func TestKandji_Discover_MissingCredentials(t *testing.T) {
	k := NewKandji()

	// Enabled and api_url present but api_key absent → skip (nil, nil, no error).
	cfg := map[string]any{
		"enabled": true,
		"api_url": "https://sub.api.kandji.io",
	}
	assets, err := k.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestKandji_Discover_DisabledWithCredentials(t *testing.T) {
	srv := newMockKandjiAPI(t)
	defer srv.Close()

	k := &Kandji{baseURL: srv.URL}
	cfg := map[string]any{
		"enabled": false,
		"api_key": "tok",
	}

	assets, err := k.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestKandji_Discover_AuthFailure(t *testing.T) {
	srv := newMockKandjiAPI(t)
	defer srv.Close()

	k := &Kandji{baseURL: srv.URL}
	cfg := map[string]any{
		"enabled": true,
		"api_key": "wrong",
	}

	_, err := k.Discover(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestDeriveKandjiOSFamily(t *testing.T) {
	assert.Equal(t, "darwin", deriveKandjiOSFamily("Mac", "MacBook Pro"))
	assert.Equal(t, "ios", deriveKandjiOSFamily("iPhone", "iPhone 15"))
	assert.Equal(t, "ios", deriveKandjiOSFamily("iPad", "iPad Air"))
	assert.Equal(t, "unknown", deriveKandjiOSFamily("AppleTV", "Apple TV 4K"))
}
