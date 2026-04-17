package cmdb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// NetBox implements discovery.Source by listing devices from a NetBox
// instance via its REST API. All devices present in NetBox are considered
// authorised since their presence in the DCIM/CMDB implies organisational
// awareness.
type NetBox struct{}

// NewNetBox returns a new NetBox discovery source.
func NewNetBox() *NetBox {
	return &NetBox{}
}

// Name returns the stable identifier for this source.
func (n *NetBox) Name() string { return "netbox" }

// Discover lists devices from NetBox and returns them as assets. If
// credentials are not available the method logs a warning and returns nil
// (graceful degradation).
//
// Supported config keys:
//
//	api_url – string base URL of the NetBox instance (e.g. "https://netbox.corp.local")
//	token   – string API authentication token
func (n *NetBox) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	apiURL := strings.TrimRight(toString(cfg["api_url"]), "/")
	token := toString(cfg["token"])

	slog.Info("netbox: starting discovery", "api_url_set", apiURL != "")

	if apiURL == "" || token == "" {
		slog.Warn("netbox: api_url or token not configured, skipping discovery")
		return nil, nil
	}

	devices, err := n.listDevices(ctx, apiURL, token)
	if err != nil {
		return nil, fmt.Errorf("netbox: listing devices: %w", err)
	}

	now := time.Now().UTC()
	var assets []model.Asset

	for _, dev := range devices {
		assetType := classifyNetBoxDevice(dev.deviceRole)
		osFamily := ""
		if dev.platform != "" {
			osFamily = deriveNetBoxOSFamily(dev.platform)
		}

		asset := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			AssetType:       assetType,
			Hostname:        dev.name,
			OSFamily:        osFamily,
			Environment:     dev.site,
			Owner:           dev.tenant,
			DiscoverySource: "netbox",
			FirstSeenAt:     now,
			LastSeenAt:      now,
			IsAuthorized:    model.AuthorizationAuthorized,
			IsManaged:       model.ManagedUnknown,
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}

	slog.Info("netbox: discovery complete", "total_assets", len(assets))
	return assets, nil
}

// ---------------------------------------------------------------------------
// NetBox API types
// ---------------------------------------------------------------------------

// netboxDevice holds the fields extracted from the NetBox devices API
// response.
type netboxDevice struct {
	name       string
	deviceRole string
	platform   string
	site       string
	tenant     string
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

const netboxPageSize = 1000

// listDevices calls the NetBox REST API to enumerate all DCIM devices,
// handling pagination via the "next" URL field.
func (n *NetBox) listDevices(ctx context.Context, apiURL, token string) ([]netboxDevice, error) {
	nextURL := fmt.Sprintf("%s/api/dcim/devices/?limit=%d", apiURL, netboxPageSize)

	var allDevices []netboxDevice

	for nextURL != "" {
		if ctx.Err() != nil {
			return allDevices, fmt.Errorf("netbox: context cancelled: %w", ctx.Err())
		}

		devices, next, err := n.fetchDevicePage(ctx, nextURL, token)
		if err != nil {
			return allDevices, err
		}
		allDevices = append(allDevices, devices...)
		nextURL = next
	}

	return allDevices, nil
}

// fetchDevicePage fetches a single page of the devices response and returns
// parsed devices plus the next page URL (empty if no more pages).
func (n *NetBox) fetchDevicePage(ctx context.Context, apiURL, token string) ([]netboxDevice, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil) //#nosec G107 -- URL from operator-configured NetBox instance
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Token "+token)
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

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		slog.Warn("netbox: authentication failed", "status", resp.StatusCode)
		return nil, "", nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("NetBox API returned %d: %s",
			resp.StatusCode, truncateBytes(body, 500))
	}

	var result struct {
		Next    *string           `json:"next"`
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, "", fmt.Errorf("parsing response: %w", err)
	}

	var devices []netboxDevice
	for _, raw := range result.Results {
		dev, err := parseNetBoxDevice(raw)
		if err != nil {
			slog.Debug("netbox: skipping unparseable device entry", "error", err)
			continue
		}
		devices = append(devices, dev)
	}

	nextLink := ""
	if result.Next != nil {
		nextLink = *result.Next
	}

	return devices, nextLink, nil
}

// parseNetBoxDevice extracts the fields we need from a single device JSON
// object returned by the NetBox API. Nested objects (device_role, platform,
// site, tenant) use only their display/name/slug field.
func parseNetBoxDevice(data json.RawMessage) (netboxDevice, error) {
	var raw struct {
		DeviceRole *struct {
			Name string `json:"name"`
			Slug string `json:"slug"`
		} `json:"device_role"`
		Platform *struct {
			Name string `json:"name"`
			Slug string `json:"slug"`
		} `json:"platform"`
		Site *struct {
			Name string `json:"name"`
			Slug string `json:"slug"`
		} `json:"site"`
		Tenant *struct {
			Name string `json:"name"`
			Slug string `json:"slug"`
		} `json:"tenant"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return netboxDevice{}, fmt.Errorf("unmarshal netbox device: %w", err)
	}

	dev := netboxDevice{
		name: raw.Name,
	}
	if raw.DeviceRole != nil {
		dev.deviceRole = raw.DeviceRole.Slug
	}
	if raw.Platform != nil {
		dev.platform = raw.Platform.Name
	}
	if raw.Site != nil {
		dev.site = raw.Site.Name
	}
	if raw.Tenant != nil {
		dev.tenant = raw.Tenant.Name
	}

	return dev, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// classifyNetBoxDevice maps the NetBox device_role slug to an asset type.
func classifyNetBoxDevice(role string) model.AssetType {
	lower := strings.ToLower(role)
	switch {
	case strings.Contains(lower, "server"):
		return model.AssetTypeServer
	case strings.Contains(lower, "router"),
		strings.Contains(lower, "switch"),
		strings.Contains(lower, "firewall"),
		strings.Contains(lower, "load-balancer"),
		strings.Contains(lower, "network"):
		return model.AssetTypeNetworkDevice
	case strings.Contains(lower, "workstation"),
		strings.Contains(lower, "desktop"),
		strings.Contains(lower, "laptop"):
		return model.AssetTypeWorkstation
	case strings.Contains(lower, "appliance"):
		return model.AssetTypeAppliance
	default:
		return model.AssetTypeServer
	}
}

// deriveNetBoxOSFamily normalises the NetBox platform name to a standard OS
// family string.
func deriveNetBoxOSFamily(platform string) string {
	lower := strings.ToLower(platform)
	switch {
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "linux"),
		strings.Contains(lower, "ubuntu"),
		strings.Contains(lower, "centos"),
		strings.Contains(lower, "debian"),
		strings.Contains(lower, "rhel"),
		strings.Contains(lower, "red hat"),
		strings.Contains(lower, "fedora"),
		strings.Contains(lower, "rocky"),
		strings.Contains(lower, "alma"):
		return "linux"
	case strings.Contains(lower, "junos"),
		strings.Contains(lower, "juniper"):
		return "junos"
	case strings.Contains(lower, "ios"),
		strings.Contains(lower, "cisco"):
		return "ios"
	case strings.Contains(lower, "eos"),
		strings.Contains(lower, "arista"):
		return "eos"
	case strings.Contains(lower, "nxos"):
		return "nxos"
	case strings.Contains(lower, "freebsd"):
		return "freebsd"
	case strings.Contains(lower, "macos"),
		strings.Contains(lower, "darwin"):
		return "darwin"
	default:
		return strings.ToLower(platform)
	}
}

// ensure NetBox satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*NetBox)(nil)
