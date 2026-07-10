package cmdb

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

// NetBox implements discovery.Source by listing devices from a NetBox
// instance via its REST API. All devices present in NetBox are considered
// authorised since their presence in the DCIM/CMDB implies organisational
// awareness.
type NetBox struct {
	// baseURL is a test override. When set, endpoint validation
	// (connectorkit.SafeClient) is skipped and a plain client is built so an
	// httptest server on 127.0.0.1 is reachable.
	baseURL string
}

// NewNetBox returns a new NetBox discovery source.
func NewNetBox() *NetBox {
	return &NetBox{}
}

// Name returns the stable identifier for this source.
func (n *NetBox) Name() string { return "netbox" }

// Discover lists devices from NetBox and returns them as assets. If discovery
// is not enabled, or credentials are not available, the method returns nil
// (graceful degradation).
//
// Supported config keys:
//
//	enabled  – bool; discovery is skipped unless explicitly true (F3)
//	api_url  – string base URL of the NetBox instance (e.g. "https://netbox.corp.local")
//	token    – string API authentication token
func (n *NetBox) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	if !connectorkit.Enabled(cfg) {
		return nil, nil // R2/F3: honour enabled:false even when creds are present.
	}

	creds := connectorkit.LoadCredentials(cfg)
	defer creds.Zero() // R1: never let plaintext secrets linger past discovery.

	apiURL := strings.TrimRight(creds.APIURL, "/")
	if n.baseURL != "" {
		apiURL = strings.TrimRight(n.baseURL, "/")
	}
	token := creds.Token

	slog.Info(
		"NetBox discovery starting",
		"code", string(LogCodeNetBoxStarting),
		"api_url_set", apiURL != "",
		"token_set", token != "",
	)

	if apiURL == "" || token == "" {
		slog.Warn(
			"NetBox api_url or token not configured, skipping discovery",
			"code", string(LogCodeNetBoxNotConfigured),
			"api_url_set", apiURL != "",
			"token_set", token != "",
		)
		return nil, nil
	}

	client, base, err := n.httpClient(apiURL)
	if err != nil {
		return nil, err
	}
	baseStr := strings.TrimRight(base.String(), "/")

	devices, err := n.listDevices(ctx, client, baseStr, token)
	if err != nil {
		return nil, fmt.Errorf("netbox: listing devices: %w", err)
	}

	now := time.Now().UTC()
	assets := make([]model.Asset, 0, len(devices))

	for _, dev := range devices {
		assetType := classifyNetBoxDevice(dev.deviceRole)
		osFamily := ""
		if dev.platform != "" {
			osFamily = deriveNetBoxOSFamily(dev.platform)
		}

		// R6: device_role/platform are supplementary context, not identity —
		// they belong in Tags, not in a dedicated column.
		tags := map[string]any{}
		if dev.deviceRole != "" {
			tags["device_role"] = dev.deviceRole
		}
		if dev.platform != "" {
			tags["platform"] = dev.platform
		}

		// R6: stop overloading Environment/Owner — NetBox site and tenant have
		// dedicated columns now, and the device id is the CMDB sys id.
		asset := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			AssetType:       assetType,
			Hostname:        dev.name,
			OSFamily:        osFamily,
			Site:            dev.site,
			Tenant:          dev.tenant,
			CMDBSysID:       dev.id,
			DiscoverySource: "netbox",
			FirstSeenAt:     now,
			LastSeenAt:      now,
			IsAuthorized:    model.AuthorizationAuthorized,
			IsManaged:       model.ManagedUnknown,
		}
		if len(tags) > 0 {
			b, _ := json.Marshal(tags)
			asset.Tags = string(b)
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}

	slog.Info(
		"NetBox discovery completed",
		"code", string(LogCodeNetBoxComplete),
		"api_url_set", apiURL != "",
		"total_assets", len(assets),
		"raw_devices", len(devices),
	)
	return assets, nil
}

// httpClient returns the outbound client and validated base URL. When baseURL
// is set (tests) SafeClient is skipped so an httptest server is reachable;
// otherwise connectorkit.SafeClient enforces HTTPS + SSRF validation. NetBox
// is commonly self-hosted, so private addresses are allowed (allowPrivate).
func (n *NetBox) httpClient(apiURL string) (*http.Client, *url.URL, error) {
	if n.baseURL != "" {
		u, err := url.Parse(n.baseURL)
		if err != nil {
			return nil, nil, fmt.Errorf("netbox: %w", err)
		}
		return &http.Client{Timeout: cmdbClientTimeout}, u, nil
	}
	client, u, err := connectorkit.SafeClient("netbox", apiURL, true)
	if err != nil {
		return nil, nil, fmt.Errorf("netbox: %w", err)
	}
	return client, u, nil
}

// ---------------------------------------------------------------------------
// NetBox API types
// ---------------------------------------------------------------------------

// netboxDevice holds the fields extracted from the NetBox devices API
// response.
type netboxDevice struct {
	id         string
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
// handling pagination via the "next" URL field and bounding the loop with a
// pagination guard.
func (n *NetBox) listDevices(ctx context.Context, client *http.Client, baseURL, token string) ([]netboxDevice, error) {
	nextURL := fmt.Sprintf("%s/api/dcim/devices/?limit=%d", baseURL, netboxPageSize)

	var allDevices []netboxDevice
	guard := connectorkit.NewGuard("netbox")

	for nextURL != "" {
		if ctx.Err() != nil {
			return allDevices, fmt.Errorf("netbox: context cancelled: %w", ctx.Err())
		}

		devices, next, nBytes, err := n.fetchDevicePage(ctx, client, nextURL, token)
		if err != nil {
			return allDevices, err
		}
		if err := guard.NextPage(nBytes); err != nil {
			return allDevices, fmt.Errorf("netbox: %w", err)
		}
		allDevices = append(allDevices, devices...)
		nextURL = next
	}

	return allDevices, nil
}

// fetchDevicePage fetches a single page of the devices response and returns
// parsed devices, the next page URL (empty if no more pages), and the raw
// page byte count for the pagination guard.
func (n *NetBox) fetchDevicePage(ctx context.Context, client *http.Client, pageURL, token string) ([]netboxDevice, string, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil) //#nosec G107 -- URL from operator-configured, safenet-validated NetBox instance
	if err != nil {
		return nil, "", 0, fmt.Errorf("netbox: creating request: %w", err)
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req) //#nosec G107 -- URL from user-configured, safenet-validated endpoint
	if err != nil {
		return nil, "", 0, fmt.Errorf("netbox: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, "", 0, fmt.Errorf("netbox: reading response: %w", readErr)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		slog.Warn("netbox: authentication failed", "code", string(LogCodeNetBoxAuthFailed), "status", resp.StatusCode)
		return nil, "", int64(len(body)), nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", 0, fmt.Errorf("netbox: API returned %d: %s",
			resp.StatusCode, truncateBytes(body, 500))
	}

	var result struct {
		Next    *string           `json:"next"`
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, "", 0, fmt.Errorf("netbox: parsing response: %w", err)
	}

	devices := make([]netboxDevice, 0, len(result.Results))
	for _, raw := range result.Results {
		dev, err := parseNetBoxDevice(raw)
		if err != nil {
			slog.Debug("netbox: skipping unparseable device entry",
				"code", string(LogCodeNetBoxSkipUnparseable), "error", err)
			continue
		}
		devices = append(devices, dev)
	}

	nextLink := ""
	if result.Next != nil {
		nextLink = *result.Next
	}

	return devices, nextLink, int64(len(body)), nil
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
		ID   int    `json:"id"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return netboxDevice{}, fmt.Errorf("unmarshal netbox device: %w", err)
	}

	dev := netboxDevice{
		name: raw.Name,
	}
	if raw.ID != 0 {
		dev.id = strconv.Itoa(raw.ID)
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
