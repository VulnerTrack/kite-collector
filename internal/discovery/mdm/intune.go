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

// Intune implements discovery.Source by listing managed devices from
// Microsoft Intune via the Microsoft Graph API. All devices present in
// Intune are considered managed.
//
// Intune talks only to fixed Microsoft endpoints (login.microsoftonline.com
// and graph.microsoft.com); there is no operator-supplied base URL, so it does
// NOT call connectorkit.SafeClient. The tokenBaseURL/graphBaseURL fields exist
// solely so tests can point it at an httptest server.
type Intune struct {
	tokenBaseURL string // override for testing; empty = production
	graphBaseURL string // override for testing; empty = production
}

// NewIntune returns a new Microsoft Intune discovery source.
func NewIntune() *Intune {
	return &Intune{ //#nosec G101 -- base URLs, not credentials
		tokenBaseURL: "https://login.microsoftonline.com",
		graphBaseURL: "https://graph.microsoft.com",
	}
}

// Name returns the stable identifier for this source.
func (i *Intune) Name() string { return "intune" }

// Discover lists managed devices from Microsoft Intune and returns them as
// assets. It honours cfg["enabled"] first (F3), loads credentials via
// connectorkit and zeroes them on return (R1). Authentication uses OAuth2
// client credentials (service principal). If credentials are absent the method
// logs a warning and returns nil (graceful degradation).
//
// Supported config keys:
//
//	tenant_id     – string Azure AD tenant ID
//	client_id     – string Application (client) ID
//	client_secret – string Client secret value
func (i *Intune) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	if !connectorkit.Enabled(cfg) {
		return nil, nil // R2: honour enabled:false even with creds present (F3)
	}

	creds := connectorkit.LoadCredentials(cfg)
	defer creds.Zero() // R1

	tenantID := creds.TenantID
	clientID := creds.ClientID
	clientSecret := creds.ClientSecret

	slog.Info(
		"Starting Intune managed device discovery",
		"code", string(LogCodeIntuneStarting),
		"tenant_id_set", tenantID != "",
		"client_id_set", clientID != "",
		"client_secret_set", clientSecret != "",
	)

	if tenantID == "" || clientID == "" || clientSecret == "" {
		slog.Warn(
			"Skipping Intune discovery: tenant_id, client_id, or client_secret not configured",
			"code", string(LogCodeIntuneCredsMissing),
			"tenant_id_set", tenantID != "",
			"client_id_set", clientID != "",
			"client_secret_set", clientSecret != "",
		)
		return nil, nil
	}

	client := &http.Client{Timeout: clientTimeout}

	token, err := i.acquireToken(ctx, client, tenantID, clientID, clientSecret)
	if err != nil {
		slog.Warn(
			"Failed to acquire OAuth2 token from Microsoft identity platform, skipping Intune discovery",
			"code", string(LogCodeIntuneTokenAcquireFailed),
			"token_base_url", i.tokenBaseURL,
			"tenant_id_set", tenantID != "",
			"error", err,
		)
		return nil, nil //nolint:nilerr // graceful degradation: a token failure skips this source, not the whole run
	}

	devices, err := i.listManagedDevices(ctx, client, token)
	if err != nil {
		return nil, fmt.Errorf("intune: listing managed devices: %w", err)
	}

	now := time.Now().UTC()
	assets := make([]model.Asset, 0, len(devices))

	for _, dev := range devices {
		asset := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			AssetType:       classifyIntuneDevice(dev.operatingSystem),
			Hostname:        dev.deviceName,
			OSFamily:        deriveIntuneOSFamily(dev.operatingSystem),
			OSVersion:       dev.osVersion,
			DiscoverySource: "intune",
			FirstSeenAt:     now,
			LastSeenAt:      now,
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       model.ManagedManaged,
			MDMEnrollmentID: dev.id,
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}

	slog.Info(
		"Completed Intune managed device discovery",
		"code", string(LogCodeIntuneComplete),
		"total_assets", len(assets),
		"total_devices", len(devices),
		"graph_base_url", i.graphBaseURL,
	)
	return assets, nil
}

// ---------------------------------------------------------------------------
// OAuth2 token acquisition
// ---------------------------------------------------------------------------

// acquireToken exchanges client credentials for an OAuth2 bearer token from
// the Microsoft identity platform for the Graph API scope.
func (i *Intune) acquireToken(ctx context.Context, client *http.Client, tenantID, clientID, clientSecret string) (string, error) {
	tokenURL := fmt.Sprintf(
		"%s/%s/oauth2/v2.0/token",
		i.tokenBaseURL, url.PathEscape(tenantID),
	)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("intune: creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req) //#nosec G107 -- fixed Microsoft identity platform endpoint
	if err != nil {
		return "", fmt.Errorf("intune: executing token request: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	_ = resp.Body.Close()
	if readErr != nil {
		return "", fmt.Errorf("intune: reading token response: %w", readErr)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("intune: token endpoint returned %d: %s",
			resp.StatusCode, truncateBytes(body, 300))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("intune: decoding token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("intune: empty access_token in response")
	}

	return tokenResp.AccessToken, nil
}

// ---------------------------------------------------------------------------
// Graph API
// ---------------------------------------------------------------------------

// intuneDevice holds the fields extracted from the Graph managedDevices
// response.
type intuneDevice struct {
	id              string
	deviceName      string
	operatingSystem string
	osVersion       string
}

// listManagedDevices calls the Microsoft Graph API to enumerate all Intune
// managed devices, handling pagination via @odata.nextLink under a labelled
// guard.
func (i *Intune) listManagedDevices(ctx context.Context, client *http.Client, token string) ([]intuneDevice, error) {
	apiURL := i.graphBaseURL + "/v1.0/deviceManagement/managedDevices"

	var allDevices []intuneDevice
	guard := connectorkit.NewGuard("intune")

	for apiURL != "" {
		if err := ctx.Err(); err != nil {
			return allDevices, fmt.Errorf("intune list cancelled: %w", err)
		}

		devices, nextLink, bodyLen, err := i.fetchDevicePage(ctx, client, apiURL, token)
		if err != nil {
			return allDevices, err
		}
		if err := guard.NextPage(int64(bodyLen)); err != nil {
			return allDevices, fmt.Errorf("intune pagination guard: %w", err)
		}
		allDevices = append(allDevices, devices...)
		apiURL = nextLink
	}

	return allDevices, nil
}

// fetchDevicePage fetches a single page of the managed devices response and
// returns parsed devices, the next page URL (empty if no more pages), and the
// raw body length (for the pagination guard).
func (i *Intune) fetchDevicePage(ctx context.Context, client *http.Client, apiURL, token string) ([]intuneDevice, string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, "", 0, fmt.Errorf("intune: creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req) //#nosec G107 -- fixed Microsoft Graph endpoint (and @odata.nextLink returned by it)
	if err != nil {
		return nil, "", 0, fmt.Errorf("intune: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, "", 0, fmt.Errorf("intune: reading response: %w", readErr)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", 0, fmt.Errorf("intune: graph API returned %d: %s",
			resp.StatusCode, truncateBytes(body, 500))
	}

	var result struct {
		NextLink string            `json:"@odata.nextLink"`
		Value    []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, "", 0, fmt.Errorf("intune: parsing response: %w", err)
	}

	devices := make([]intuneDevice, 0, len(result.Value))
	for _, raw := range result.Value {
		dev, err := parseIntuneDevice(raw)
		if err != nil {
			slog.Debug("intune: skipping unparseable device entry", "code", string(LogCodeIntuneSkipUnparseable), "error", err)
			continue
		}
		devices = append(devices, dev)
	}

	return devices, result.NextLink, len(body), nil
}

// parseIntuneDevice extracts the fields we need from a single managed device
// JSON object.
func parseIntuneDevice(data json.RawMessage) (intuneDevice, error) {
	var raw struct {
		ID              string `json:"id"`
		DeviceName      string `json:"deviceName"`
		OperatingSystem string `json:"operatingSystem"`
		OSVersion       string `json:"osVersion"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return intuneDevice{}, fmt.Errorf("intune: unmarshal device: %w", err)
	}

	return intuneDevice{
		id:              raw.ID,
		deviceName:      raw.DeviceName,
		operatingSystem: raw.OperatingSystem,
		osVersion:       raw.OSVersion,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// deriveIntuneOSFamily normalises the Intune operatingSystem field to a
// standard OS family string.
func deriveIntuneOSFamily(os string) string {
	lower := strings.ToLower(os)
	switch {
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "macos"),
		strings.Contains(lower, "ios"),
		strings.Contains(lower, "ipados"):
		return "darwin"
	case strings.Contains(lower, "android"):
		return "linux"
	case strings.Contains(lower, "linux"):
		return "linux"
	default:
		return strings.ToLower(os)
	}
}

// classifyIntuneDevice maps the Intune operatingSystem to an asset type.
func classifyIntuneDevice(os string) model.AssetType {
	lower := strings.ToLower(os)
	switch {
	case strings.Contains(lower, "windows server"):
		return model.AssetTypeServer
	case strings.Contains(lower, "windows"),
		strings.Contains(lower, "macos"):
		return model.AssetTypeWorkstation
	default:
		return model.AssetTypeWorkstation
	}
}

// ensure Intune satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*Intune)(nil)
