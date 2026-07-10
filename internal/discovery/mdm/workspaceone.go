package mdm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/connectorkit"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// wsonePageSize is the number of devices requested per Workspace ONE search
// page. The upstream cap is 500.
const wsonePageSize = 500

// WorkspaceOne implements discovery.Source by listing managed devices from the
// VMware Workspace ONE UEM REST API (/API/mdm/devices/search). All devices it
// returns are considered managed.
type WorkspaceOne struct {
	baseURL string // test override; when set, endpoint validation is skipped
}

// NewWorkspaceOne returns a new Workspace ONE UEM discovery source.
func NewWorkspaceOne() *WorkspaceOne {
	return &WorkspaceOne{}
}

// Name returns the stable identifier for this source.
func (w *WorkspaceOne) Name() string { return "workspace_one" }

// Discover lists managed devices from Workspace ONE UEM and returns them as
// assets. It honours cfg["enabled"] first (F3), loads credentials via
// connectorkit and zeroes them on return (R1), and validates the operator URL
// via SafeClient with allowPrivate=false (SaaS). If any required credential is
// absent the method logs a warning and returns nil (graceful degradation).
//
// Supported config keys:
//
//	api_url  – string base URL of the Workspace ONE UEM API
//	username – string API account username (HTTP Basic)
//	password – string API account password (HTTP Basic)
//	api_key  – string REST API tenant code (aw-tenant-code header)
func (w *WorkspaceOne) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	if !connectorkit.Enabled(cfg) {
		return nil, nil // R2: honour enabled:false even with creds present (F3)
	}

	creds := connectorkit.LoadCredentials(cfg)
	defer creds.Zero() // R1

	apiURL := creds.APIURL
	if w.baseURL != "" {
		apiURL = w.baseURL
	}

	slog.Info("workspace_one: starting discovery", "api_url_set", apiURL != "")

	if apiURL == "" || creds.Username == "" || creds.Password == "" || creds.APIKey == "" {
		slog.Warn("workspace_one: api_url, username, password, or api_key not configured, skipping discovery")
		return nil, nil
	}

	client, base, err := w.httpClient(apiURL)
	if err != nil {
		return nil, err
	}
	baseStr := strings.TrimRight(base.String(), "/")

	now := time.Now().UTC()
	var assets []model.Asset
	guard := connectorkit.NewGuard("workspace_one")

	for page := 0; ; page++ {
		if err := ctx.Err(); err != nil {
			return assets, fmt.Errorf("workspace_one discovery cancelled: %w", err)
		}

		resp, bodyLen, err := w.fetchDevicePage(ctx, client, baseStr, creds, page)
		if err != nil {
			return assets, err
		}
		if err := guard.NextPage(int64(bodyLen)); err != nil {
			return assets, fmt.Errorf("workspace_one pagination guard: %w", err)
		}

		pageAssets := make([]model.Asset, 0, len(resp.Devices))
		for _, dev := range resp.Devices {
			pageAssets = append(pageAssets, workspaceOneDeviceToAsset(dev, now))
		}
		assets = append(assets, pageAssets...)

		fetched := len(resp.Devices)
		if fetched < wsonePageSize {
			break
		}
		if resp.Total > 0 && int64(page+1)*int64(wsonePageSize) >= int64(resp.Total) {
			break
		}
	}

	slog.Info("workspace_one: discovery complete", "total_assets", len(assets))
	return assets, nil
}

// httpClient returns the validated client + base URL for this source. In tests
// (baseURL set) it skips SafeClient; in production it validates apiURL with
// allowPrivate=false because Workspace ONE UEM is SaaS.
func (w *WorkspaceOne) httpClient(apiURL string) (*http.Client, *url.URL, error) {
	return newValidatedClient("workspace_one", w.baseURL, apiURL, false)
}

// ---------------------------------------------------------------------------
// Workspace ONE UEM API types
// ---------------------------------------------------------------------------

// wsoneSearchResponse is the /API/mdm/devices/search envelope.
type wsoneSearchResponse struct {
	Devices  []wsoneDevice `json:"Devices"`
	Total    int           `json:"Total"`
	Page     int           `json:"Page"`
	PageSize int           `json:"PageSize"`
}

// wsoneDevice holds the fields extracted from a single search result.
type wsoneDevice struct {
	DeviceFriendlyName string `json:"DeviceFriendlyName"`
	Model              string `json:"Model"`
	Platform           string `json:"Platform"`
	OperatingSystem    string `json:"OperatingSystem"`
	SerialNumber       string `json:"SerialNumber"`
	Udid               string `json:"Udid"`
	UserEmailAddress   string `json:"UserEmailAddress"`
	OwnershipTypeCode  string `json:"OwnershipTypeCode"`
	ComplianceStatus   string `json:"ComplianceStatus"`
	LastSeen           string `json:"LastSeen"`
	DeviceID           int64  `json:"DeviceId"`
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

// fetchDevicePage retrieves a single page of the device search, returning the
// decoded envelope and the raw body length (for the pagination guard).
func (w *WorkspaceOne) fetchDevicePage(ctx context.Context, client *http.Client, baseURL string, creds connectorkit.Credentials, page int) (wsoneSearchResponse, int, error) {
	endpoint := fmt.Sprintf("%s/API/mdm/devices/search?pagesize=%d&page=%d", baseURL, wsonePageSize, page)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return wsoneSearchResponse{}, 0, fmt.Errorf("workspace_one: creating request: %w", err)
	}
	req.SetBasicAuth(creds.Username, creds.Password)
	req.Header.Set("aw-tenant-code", creds.APIKey)
	req.Header.Set("Accept", "application/json;version=2")

	resp, err := client.Do(req) //#nosec G107 -- URL from user-configured, safenet-validated endpoint
	if err != nil {
		return wsoneSearchResponse{}, 0, fmt.Errorf("workspace_one: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	_ = resp.Body.Close()
	if readErr != nil {
		return wsoneSearchResponse{}, 0, fmt.Errorf("workspace_one: reading response: %w", readErr)
	}

	if resp.StatusCode != http.StatusOK {
		return wsoneSearchResponse{}, len(body), fmt.Errorf("workspace_one: API returned %d: %s", resp.StatusCode, truncateBytes(body, 500))
	}

	var out wsoneSearchResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return wsoneSearchResponse{}, len(body), fmt.Errorf("workspace_one: parsing response: %w", err)
	}

	return out, len(body), nil
}

// ---------------------------------------------------------------------------
// Asset mapping
// ---------------------------------------------------------------------------

// workspaceOneDeviceToAsset converts a single Workspace ONE device into an
// asset, populating the MDM dedicated fields.
func workspaceOneDeviceToAsset(dev wsoneDevice, now time.Time) model.Asset {
	enrollID := dev.Udid
	if enrollID == "" && dev.DeviceID != 0 {
		enrollID = strconv.FormatInt(dev.DeviceID, 10)
	}

	tags := map[string]any{}
	if dev.SerialNumber != "" {
		tags["serial_number"] = dev.SerialNumber
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
		ID:              uuid.Must(uuid.NewV7()),
		AssetType:       model.AssetTypeWorkstation,
		Hostname:        dev.DeviceFriendlyName,
		OSFamily:        deriveWorkspaceOneOSFamily(dev.Platform, dev.OperatingSystem),
		OSVersion:       dev.OperatingSystem,
		DiscoverySource: "workspace_one",
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedManaged,
		MDMEnrollmentID: enrollID,
		OwnershipType:   mapWorkspaceOneOwnership(dev.OwnershipTypeCode),
		EnrolledUserUPN: normalizeUPN(dev.UserEmailAddress),
		ComplianceState: mapWorkspaceOneCompliance(dev.ComplianceStatus),
		Tags:            tagsJSON,
	}
	asset.ComputeNaturalKey()
	return asset
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// deriveWorkspaceOneOSFamily normalises the Workspace ONE Platform (with the
// OperatingSystem string as a tie-breaker for Apple) to a standard OS family.
func deriveWorkspaceOneOSFamily(platform, os string) string {
	p := strings.ToLower(platform)
	o := strings.ToLower(os)
	switch {
	case strings.Contains(p, "winrt"), strings.Contains(p, "windows"):
		return "windows"
	case strings.Contains(p, "android"):
		return "android"
	case strings.Contains(p, "osx"), strings.Contains(o, "mac"):
		return "darwin"
	case strings.Contains(p, "apple"), strings.Contains(p, "ios"), strings.Contains(o, "ios"):
		return "ios"
	default:
		return "unknown"
	}
}

// mapWorkspaceOneOwnership maps the single-letter OwnershipTypeCode to the
// OwnershipType enum.
func mapWorkspaceOneOwnership(code string) string {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "C":
		return "corporate_dedicated"
	case "S":
		return "corporate_shared"
	case "E":
		return "employee_owned"
	default:
		return "unknown"
	}
}

// mapWorkspaceOneCompliance maps the ComplianceStatus string to the
// ComplianceState enum.
func mapWorkspaceOneCompliance(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "compliant":
		return "compliant"
	case "noncompliant", "non-compliant", "not compliant":
		return "non_compliant"
	default:
		return "unknown"
	}
}

// ensure WorkspaceOne satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*WorkspaceOne)(nil)
