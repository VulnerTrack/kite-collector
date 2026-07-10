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

// Device42 implements discovery.Source by listing devices from a Device42
// instance via its REST API. All devices present in Device42 are considered
// authorised since their presence in the CMDB implies organisational
// awareness.
type Device42 struct {
	// baseURL is a test override. When set, endpoint validation
	// (connectorkit.SafeClient) is skipped and a plain client is built so an
	// httptest server on 127.0.0.1 is reachable.
	baseURL string
}

// NewDevice42 returns a new Device42 discovery source.
func NewDevice42() *Device42 {
	return &Device42{}
}

// Name returns the stable identifier for this source.
func (d *Device42) Name() string { return "device42" }

const device42PageSize = 100

// Discover lists devices from Device42 and returns them as assets. If
// discovery is not enabled, or credentials are not available, the method
// returns nil (graceful degradation).
//
// Supported config keys:
//
//	enabled  – bool; discovery is skipped unless explicitly true (F3)
//	api_url  – string base URL of the Device42 instance (e.g. "https://device42.corp.local")
//	username – string API account username
//	password – string API account password
func (d *Device42) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	if !connectorkit.Enabled(cfg) {
		return nil, nil // R2/F3: honour enabled:false even when creds are present.
	}

	creds := connectorkit.LoadCredentials(cfg)
	defer creds.Zero() // R1: never let plaintext secrets linger past discovery.

	apiURL := strings.TrimRight(creds.APIURL, "/")
	if d.baseURL != "" {
		apiURL = strings.TrimRight(d.baseURL, "/")
	}
	username := creds.Username
	password := creds.Password

	slog.Info(
		"device42: starting discovery",
		"code", string(LogCodeDevice42Starting),
		"api_url_set", apiURL != "",
	)

	if apiURL == "" || username == "" || password == "" {
		slog.Warn("device42: api_url, username, or password not configured, skipping discovery",
			"code", string(LogCodeDevice42NotConfigured))
		return nil, nil
	}

	client, base, err := d.httpClient(apiURL)
	if err != nil {
		return nil, err
	}
	baseStr := strings.TrimRight(base.String(), "/")

	devices, err := d.listDevices(ctx, client, baseStr, username, password)
	if err != nil {
		return nil, fmt.Errorf("device42: listing devices: %w", err)
	}

	now := time.Now().UTC()
	assets := make([]model.Asset, 0, len(devices))

	for _, dev := range devices {
		osFamily := deriveDevice42OSFamily(dev.OS)

		opStatus := "operational"
		if !dev.InService {
			opStatus = "non_operational"
		}

		// R6: service_level/serial_no/type/uuid have no dedicated column —
		// keep them in Tags rather than overloading a scalar field.
		tags := map[string]any{}
		if dev.ServiceLevel != "" {
			tags["service_level"] = dev.ServiceLevel
		}
		if dev.SerialNo != "" {
			tags["serial_no"] = dev.SerialNo
		}
		if dev.Type != "" {
			tags["type"] = dev.Type
		}
		if dev.UUID != "" {
			tags["uuid"] = dev.UUID
		}

		asset := model.Asset{
			ID:                uuid.Must(uuid.NewV7()),
			AssetType:         classifyDevice42(dev.Type),
			Hostname:          dev.Name,
			OSFamily:          osFamily,
			OSVersion:         dev.OSVer,
			AssetTag:          dev.AssetNo,
			OperationalStatus: opStatus,
			DiscoverySource:   "device42",
			FirstSeenAt:       now,
			LastSeenAt:        now,
			IsAuthorized:      model.AuthorizationAuthorized,
			IsManaged:         model.ManagedUnknown,
		}
		if dev.DeviceID != 0 {
			asset.CMDBSysID = strconv.Itoa(dev.DeviceID)
		}
		if len(tags) > 0 {
			b, _ := json.Marshal(tags)
			asset.Tags = string(b)
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}

	slog.Info("device42: discovery complete", "code", string(LogCodeDevice42Complete), "total_assets", len(assets))
	return assets, nil
}

// httpClient returns the outbound client and validated base URL. When baseURL
// is set (tests) SafeClient is skipped; otherwise connectorkit.SafeClient
// enforces HTTPS + SSRF validation. Device42 is commonly self-hosted, so
// private addresses are allowed (allowPrivate).
func (d *Device42) httpClient(apiURL string) (*http.Client, *url.URL, error) {
	if d.baseURL != "" {
		u, err := url.Parse(d.baseURL)
		if err != nil {
			return nil, nil, fmt.Errorf("device42: %w", err)
		}
		return &http.Client{Timeout: cmdbClientTimeout}, u, nil
	}
	client, u, err := connectorkit.SafeClient("device42", apiURL, true)
	if err != nil {
		return nil, nil, fmt.Errorf("device42: %w", err)
	}
	return client, u, nil
}

// ---------------------------------------------------------------------------
// Device42 API types
// ---------------------------------------------------------------------------

// device42Response is the devices list envelope returned by the Device42
// REST API (GET /api/1.0/devices/).
type device42Response struct {
	Devices    []device42Device `json:"Devices"`
	TotalCount int              `json:"total_count"`
	Offset     int              `json:"offset"`
	Limit      int              `json:"limit"`
}

// device42Device holds the fields extracted from a single device entry.
type device42Device struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	OS           string `json:"os"`
	OSVer        string `json:"osver"`
	SerialNo     string `json:"serial_no"`
	ServiceLevel string `json:"service_level"`
	AssetNo      string `json:"asset_no"`
	UUID         string `json:"uuid"`
	DeviceID     int    `json:"device_id"`
	InService    bool   `json:"in_service"`
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

// listDevices enumerates all devices using offset pagination, bounding the
// loop with a pagination guard.
func (d *Device42) listDevices(ctx context.Context, client *http.Client, baseURL, username, password string) ([]device42Device, error) {
	var all []device42Device
	offset := 0
	guard := connectorkit.NewGuard("device42")

	for {
		if ctx.Err() != nil {
			return all, fmt.Errorf("device42: context cancelled: %w", ctx.Err())
		}

		page, nBytes, err := d.fetchDevicePage(ctx, client, baseURL, username, password, offset)
		if err != nil {
			return all, err
		}
		if err := guard.NextPage(nBytes); err != nil {
			return all, fmt.Errorf("device42: %w", err)
		}

		all = append(all, page.Devices...)

		n := len(page.Devices)
		offset += n
		if n < device42PageSize || offset >= page.TotalCount {
			break
		}
	}

	return all, nil
}

// fetchDevicePage fetches a single page of devices and returns the parsed
// envelope plus the raw page byte count for the pagination guard.
func (d *Device42) fetchDevicePage(ctx context.Context, client *http.Client, baseURL, username, password string, offset int) (device42Response, int64, error) {
	endpoint := fmt.Sprintf("%s/api/1.0/devices/?limit=%d&offset=%d", baseURL, device42PageSize, offset)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) //#nosec G107 -- URL from operator-configured, safenet-validated Device42 instance
	if err != nil {
		return device42Response{}, 0, fmt.Errorf("device42: creating request: %w", err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req) //#nosec G107 -- URL from user-configured, safenet-validated endpoint
	if err != nil {
		return device42Response{}, 0, fmt.Errorf("device42: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	_ = resp.Body.Close()
	if readErr != nil {
		return device42Response{}, 0, fmt.Errorf("device42: reading response: %w", readErr)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		slog.Warn("device42: authentication failed", "code", string(LogCodeDevice42AuthFailed), "status", resp.StatusCode)
		return device42Response{}, int64(len(body)), nil
	}

	if resp.StatusCode != http.StatusOK {
		return device42Response{}, 0, fmt.Errorf("device42: API returned %d: %s",
			resp.StatusCode, truncateBytes(body, 500))
	}

	var out device42Response
	if err := json.Unmarshal(body, &out); err != nil {
		return device42Response{}, 0, fmt.Errorf("device42: parsing response: %w", err)
	}

	return out, int64(len(body)), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// classifyDevice42 maps the Device42 device type to an asset type.
func classifyDevice42(deviceType string) model.AssetType {
	switch strings.ToLower(deviceType) {
	case "virtual":
		return model.AssetTypeVirtualMachine
	case "cluster":
		return model.AssetTypeServer
	default:
		return model.AssetTypeServer
	}
}

// deriveDevice42OSFamily normalises the Device42 os field to a standard OS
// family string.
func deriveDevice42OSFamily(os string) string {
	lower := strings.ToLower(os)
	switch {
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "linux"),
		strings.Contains(lower, "ubuntu"),
		strings.Contains(lower, "centos"),
		strings.Contains(lower, "debian"),
		strings.Contains(lower, "red hat"),
		strings.Contains(lower, "rhel"),
		strings.Contains(lower, "suse"):
		return "linux"
	case strings.Contains(lower, "mac"),
		strings.Contains(lower, "darwin"):
		return "darwin"
	case strings.Contains(lower, "freebsd"):
		return "freebsd"
	default:
		if os == "" {
			return ""
		}
		return lower
	}
}

// ensure Device42 satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*Device42)(nil)
