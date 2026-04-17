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
	"github.com/vulnertrack/kite-collector/internal/model"
)

// Intune implements discovery.Source by listing managed devices from
// Microsoft Intune via the Microsoft Graph API. All devices present in
// Intune are considered managed.
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
// assets. Authentication uses OAuth2 client credentials (service principal).
// If credentials are not available the method logs a warning and returns nil
// (graceful degradation).
//
// Supported config keys:
//
//	tenant_id     – string Azure AD tenant ID
//	client_id     – string Application (client) ID
//	client_secret – string Client secret value
func (i *Intune) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	tenantID := toString(cfg["tenant_id"])
	clientID := toString(cfg["client_id"])
	clientSecret := toString(cfg["client_secret"])

	slog.Info("intune: starting discovery",
		"tenant_id_set", tenantID != "",
		"client_id_set", clientID != "",
	)

	if tenantID == "" || clientID == "" || clientSecret == "" {
		slog.Warn("intune: tenant_id, client_id, or client_secret not configured, skipping discovery")
		return nil, nil
	}

	token, err := i.acquireToken(ctx, tenantID, clientID, clientSecret)
	if err != nil {
		slog.Warn("intune: failed to acquire OAuth2 token, skipping discovery",
			"error", err,
		)
		return nil, nil
	}

	devices, err := i.listManagedDevices(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("intune: listing managed devices: %w", err)
	}

	now := time.Now().UTC()
	var assets []model.Asset

	for _, dev := range devices {
		osFamily := deriveIntuneOSFamily(dev.operatingSystem)

		asset := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			AssetType:       classifyIntuneDevice(dev.operatingSystem),
			Hostname:        dev.deviceName,
			OSFamily:        osFamily,
			OSVersion:       dev.osVersion,
			DiscoverySource: "intune",
			FirstSeenAt:     now,
			LastSeenAt:      now,
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       model.ManagedManaged,
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}

	slog.Info("intune: discovery complete", "total_assets", len(assets))
	return assets, nil
}

// ---------------------------------------------------------------------------
// OAuth2 token acquisition
// ---------------------------------------------------------------------------

// acquireToken exchanges client credentials for an OAuth2 bearer token from
// the Microsoft identity platform for the Graph API scope.
func (i *Intune) acquireToken(ctx context.Context, tenantID, clientID, clientSecret string) (string, error) {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, //#nosec G107 -- URL from operator-configured Intune tenant
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req) //#nosec G107
	if err != nil {
		return "", fmt.Errorf("executing token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s",
			resp.StatusCode, truncateBytes(body, 300))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access_token in response")
	}

	return tokenResp.AccessToken, nil
}

// ---------------------------------------------------------------------------
// Graph API
// ---------------------------------------------------------------------------

// intuneDevice holds the fields extracted from the Graph managedDevices
// response.
type intuneDevice struct {
	deviceName      string
	operatingSystem string
	osVersion       string
}

// listManagedDevices calls the Microsoft Graph API to enumerate all Intune
// managed devices, handling pagination via @odata.nextLink.
func (i *Intune) listManagedDevices(ctx context.Context, token string) ([]intuneDevice, error) {
	apiURL := i.graphBaseURL + "/v1.0/deviceManagement/managedDevices"

	var allDevices []intuneDevice

	for apiURL != "" {
		if err := ctx.Err(); err != nil {
			return allDevices, fmt.Errorf("intune list cancelled: %w", err)
		}

		devices, nextLink, err := i.fetchDevicePage(ctx, apiURL, token)
		if err != nil {
			return allDevices, err
		}
		allDevices = append(allDevices, devices...)
		apiURL = nextLink
	}

	return allDevices, nil
}

// fetchDevicePage fetches a single page of the managed devices response and
// returns parsed devices plus the next page URL (empty if no more pages).
func (i *Intune) fetchDevicePage(ctx context.Context, apiURL, token string) ([]intuneDevice, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil) //#nosec G107 -- URL from operator-configured Intune/Graph API
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req) //#nosec G107
	if err != nil {
		return nil, "", fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("graph API returned %d: %s",
			resp.StatusCode, truncateBytes(body, 500))
	}

	var result struct {
		NextLink string            `json:"@odata.nextLink"`
		Value    []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, "", fmt.Errorf("parsing response: %w", err)
	}

	var devices []intuneDevice
	for _, raw := range result.Value {
		dev, err := parseIntuneDevice(raw)
		if err != nil {
			slog.Debug("intune: skipping unparseable device entry", "error", err)
			continue
		}
		devices = append(devices, dev)
	}

	return devices, result.NextLink, nil
}

// parseIntuneDevice extracts the fields we need from a single managed device
// JSON object.
func parseIntuneDevice(data json.RawMessage) (intuneDevice, error) {
	var raw struct {
		DeviceName      string `json:"deviceName"`
		OperatingSystem string `json:"operatingSystem"`
		OSVersion       string `json:"osVersion"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return intuneDevice{}, fmt.Errorf("unmarshal intune device: %w", err)
	}

	return intuneDevice{
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
	case strings.Contains(lower, "windows"),
		strings.Contains(lower, "macos"):
		return model.AssetTypeWorkstation
	case strings.Contains(lower, "windows server"):
		return model.AssetTypeServer
	default:
		return model.AssetTypeWorkstation
	}
}

// ensure Intune satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*Intune)(nil)
