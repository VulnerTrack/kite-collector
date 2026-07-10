package mdm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/connectorkit"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// kandjiPageSize is the number of devices requested per Kandji list page.
const kandjiPageSize = 300

// Kandji implements discovery.Source by listing enrolled devices from the
// Kandji API (/api/v1/devices). All devices it returns are considered managed.
type Kandji struct {
	baseURL string // test override; when set, endpoint validation is skipped
}

// NewKandji returns a new Kandji discovery source.
func NewKandji() *Kandji {
	return &Kandji{}
}

// Name returns the stable identifier for this source.
func (k *Kandji) Name() string { return "kandji" }

// Discover lists enrolled devices from Kandji and returns them as assets. It
// honours cfg["enabled"] first (F3), loads credentials via connectorkit and
// zeroes them on return (R1), and validates the operator URL via SafeClient
// with allowPrivate=false (SaaS). If any required credential is absent the
// method logs a warning and returns nil (graceful degradation).
//
// Supported config keys:
//
//	api_url – string base URL of the Kandji API (e.g. "https://SUBDOMAIN.api.kandji.io")
//	api_key – string API token (Authorization: Bearer)
func (k *Kandji) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	if !connectorkit.Enabled(cfg) {
		return nil, nil // R2: honour enabled:false even with creds present (F3)
	}

	creds := connectorkit.LoadCredentials(cfg)
	defer creds.Zero() // R1

	apiURL := creds.APIURL
	if k.baseURL != "" {
		apiURL = k.baseURL
	}

	slog.Info("kandji: starting discovery", "api_url_set", apiURL != "")

	if apiURL == "" || creds.APIKey == "" {
		slog.Warn("kandji: api_url or api_key not configured, skipping discovery")
		return nil, nil
	}

	client, base, err := k.httpClient(apiURL)
	if err != nil {
		return nil, err
	}
	baseStr := strings.TrimRight(base.String(), "/")

	now := time.Now().UTC()
	var assets []model.Asset
	guard := connectorkit.NewGuard("kandji")

	for offset := 0; ; offset += kandjiPageSize {
		if err := ctx.Err(); err != nil {
			return assets, fmt.Errorf("kandji discovery cancelled: %w", err)
		}

		devices, bodyLen, err := k.fetchDevicePage(ctx, client, baseStr, creds.APIKey, offset)
		if err != nil {
			return assets, err
		}
		if err := guard.NextPage(int64(bodyLen)); err != nil {
			return assets, fmt.Errorf("kandji pagination guard: %w", err)
		}

		pageAssets := make([]model.Asset, 0, len(devices))
		for _, dev := range devices {
			pageAssets = append(pageAssets, kandjiDeviceToAsset(dev, now))
		}
		assets = append(assets, pageAssets...)

		if len(devices) < kandjiPageSize {
			break
		}
	}

	slog.Info("kandji: discovery complete", "total_assets", len(assets))
	return assets, nil
}

// httpClient returns the validated client + base URL for this source. In tests
// (baseURL set) it skips SafeClient; in production it validates apiURL with
// allowPrivate=false because Kandji is SaaS.
func (k *Kandji) httpClient(apiURL string) (*http.Client, *url.URL, error) {
	return newValidatedClient("kandji", k.baseURL, apiURL, false)
}

// ---------------------------------------------------------------------------
// Kandji API types
// ---------------------------------------------------------------------------

// kandjiDevice holds the fields extracted from a single /api/v1/devices entry.
type kandjiDevice struct {
	DeviceID      string     `json:"device_id"`
	DeviceName    string     `json:"device_name"`
	Model         string     `json:"model"`
	Platform      string     `json:"platform"`
	OSVersion     string     `json:"os_version"`
	SerialNumber  string     `json:"serial_number"`
	BlueprintName string     `json:"blueprint_name"`
	LastCheckIn   string     `json:"last_check_in"`
	User          kandjiUser `json:"user"`
}

// kandjiUser is the embedded primary-user object on a Kandji device.
type kandjiUser struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

// fetchDevicePage retrieves a single offset page of the device list, returning
// the decoded devices and the raw body length (for the pagination guard). The
// Kandji list endpoint returns a top-level JSON array.
func (k *Kandji) fetchDevicePage(ctx context.Context, client *http.Client, baseURL, apiKey string, offset int) ([]kandjiDevice, int, error) {
	endpoint := fmt.Sprintf("%s/api/v1/devices?limit=%d&offset=%d", baseURL, kandjiPageSize, offset)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("kandji: creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req) //#nosec G107 -- URL from user-configured, safenet-validated endpoint
	if err != nil {
		return nil, 0, fmt.Errorf("kandji: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, 0, fmt.Errorf("kandji: reading response: %w", readErr)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, len(body), fmt.Errorf("kandji: API returned %d: %s", resp.StatusCode, truncateBytes(body, 500))
	}

	var devices []kandjiDevice
	if err := json.Unmarshal(body, &devices); err != nil {
		return nil, len(body), fmt.Errorf("kandji: parsing response: %w", err)
	}

	return devices, len(body), nil
}

// ---------------------------------------------------------------------------
// Asset mapping
// ---------------------------------------------------------------------------

// kandjiDeviceToAsset converts a single Kandji device into an asset, populating
// the MDM dedicated fields.
func kandjiDeviceToAsset(dev kandjiDevice, now time.Time) model.Asset {
	tags := map[string]any{}
	if dev.SerialNumber != "" {
		tags["serial_number"] = dev.SerialNumber
	}
	if dev.BlueprintName != "" {
		tags["blueprint"] = dev.BlueprintName
	}
	if dev.Model != "" {
		tags["model"] = dev.Model
	}
	var tagsJSON string
	if len(tags) > 0 {
		encoded, _ := json.Marshal(tags)
		tagsJSON = string(encoded)
	}

	asset := model.Asset{
		ID: uuid.Must(uuid.NewV7()),
		// The model has no dedicated mobile asset type, so Mac, iPhone and
		// iPad all map to Workstation.
		AssetType:       model.AssetTypeWorkstation,
		Hostname:        dev.DeviceName,
		OSFamily:        deriveKandjiOSFamily(dev.Platform, dev.Model),
		OSVersion:       dev.OSVersion,
		DiscoverySource: "kandji",
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedManaged,
		MDMEnrollmentID: dev.DeviceID,
		OwnershipType:   "corporate_dedicated",
		EnrolledUserUPN: normalizeUPN(dev.User.Email),
		ComplianceState: "not_evaluated",
		Tags:            tagsJSON,
	}
	asset.ComputeNaturalKey()
	return asset
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// deriveKandjiOSFamily normalises the Kandji platform (with model as a
// tie-breaker) to a standard OS family string.
func deriveKandjiOSFamily(platform, model string) string {
	p := strings.ToLower(platform)
	m := strings.ToLower(model)
	switch {
	case strings.Contains(p, "mac"):
		return "darwin"
	case strings.Contains(p, "iphone"), strings.Contains(p, "ipad"),
		strings.Contains(m, "iphone"), strings.Contains(m, "ipad"):
		return "ios"
	default:
		return "unknown"
	}
}

// ensure Kandji satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*Kandji)(nil)
