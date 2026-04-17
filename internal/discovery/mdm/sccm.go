package mdm

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

// SCCM implements discovery.Source by listing managed devices from Microsoft
// SCCM (ConfigMgr) via the AdminService REST API. Devices with IsClient set
// to true are considered managed.
type SCCM struct{}

// NewSCCM returns a new SCCM/ConfigMgr discovery source.
func NewSCCM() *SCCM {
	return &SCCM{}
}

// Name returns the stable identifier for this source.
func (s *SCCM) Name() string { return "sccm" }

// Discover lists devices from SCCM AdminService REST API and returns them
// as assets. Authentication uses HTTP Basic auth. If credentials are not
// available the method logs a warning and returns nil (graceful degradation).
//
// Supported config keys:
//
//	api_url  – string base URL of the SCCM AdminService (e.g. "https://sccm.corp.local")
//	username – string account username
//	password – string account password
func (s *SCCM) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	apiURL := strings.TrimRight(toString(cfg["api_url"]), "/")
	username := toString(cfg["username"])
	password := toString(cfg["password"])

	slog.Info("sccm: starting discovery", "api_url_set", apiURL != "")

	if apiURL == "" || username == "" || password == "" {
		slog.Warn("sccm: api_url, username, or password not configured, skipping discovery")
		return nil, nil
	}

	devices, err := s.listDevices(ctx, apiURL, username, password)
	if err != nil {
		return nil, fmt.Errorf("sccm: listing devices: %w", err)
	}

	now := time.Now().UTC()
	var assets []model.Asset

	for _, dev := range devices {
		osFamily := deriveSCCMOSFamily(dev.osNameAndVersion)

		managed := model.ManagedUnknown
		if dev.isClient {
			managed = model.ManagedManaged
		}

		asset := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			AssetType:       classifySCCMDevice(dev.osNameAndVersion),
			Hostname:        dev.name,
			OSFamily:        osFamily,
			OSVersion:       dev.osNameAndVersion,
			DiscoverySource: "sccm",
			FirstSeenAt:     now,
			LastSeenAt:      now,
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       managed,
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}

	slog.Info("sccm: discovery complete", "total_assets", len(assets))
	return assets, nil
}

// ---------------------------------------------------------------------------
// AdminService API types
// ---------------------------------------------------------------------------

// sccmDevice holds the fields extracted from the AdminService Device
// response.
type sccmDevice struct {
	name             string
	osNameAndVersion string
	isClient         bool
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

// listDevices calls the SCCM AdminService REST API to enumerate all devices.
func (s *SCCM) listDevices(ctx context.Context, apiURL, username, password string) ([]sccmDevice, error) {
	endpoint := apiURL + "/AdminService/v1.0/Device"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) //#nosec G107 -- URL from operator-configured SCCM endpoint
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req) //#nosec G107
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		slog.Warn("sccm: authentication failed (HTTP 401)")
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AdminService API returned %d: %s", resp.StatusCode, truncateBytes(body, 500))
	}

	var result struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	var devices []sccmDevice
	for _, raw := range result.Value {
		dev, err := parseSCCMDevice(raw)
		if err != nil {
			slog.Debug("sccm: skipping unparseable device entry", "error", err)
			continue
		}
		devices = append(devices, dev)
	}

	return devices, nil
}

// parseSCCMDevice extracts the fields we need from a single device JSON
// object returned by the AdminService.
func parseSCCMDevice(data json.RawMessage) (sccmDevice, error) {
	var raw struct {
		Name                          string `json:"Name"`
		OperatingSystemNameAndVersion string `json:"OperatingSystemNameandVersion"`
		IsClient                      bool   `json:"IsClient"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return sccmDevice{}, fmt.Errorf("unmarshal sccm device: %w", err)
	}

	return sccmDevice{
		name:             raw.Name,
		osNameAndVersion: raw.OperatingSystemNameAndVersion,
		isClient:         raw.IsClient,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// deriveSCCMOSFamily normalises the SCCM OperatingSystemNameandVersion field
// to a standard OS family string.
func deriveSCCMOSFamily(osNameAndVersion string) string {
	lower := strings.ToLower(osNameAndVersion)
	switch {
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "linux"),
		strings.Contains(lower, "ubuntu"),
		strings.Contains(lower, "centos"),
		strings.Contains(lower, "red hat"),
		strings.Contains(lower, "rhel"):
		return "linux"
	case strings.Contains(lower, "mac os"),
		strings.Contains(lower, "macos"):
		return "darwin"
	default:
		return "windows" // SCCM is predominantly Windows
	}
}

// classifySCCMDevice maps the SCCM OS name to an asset type.
func classifySCCMDevice(osNameAndVersion string) model.AssetType {
	lower := strings.ToLower(osNameAndVersion)
	if strings.Contains(lower, "server") {
		return model.AssetTypeServer
	}
	return model.AssetTypeWorkstation
}

// ensure SCCM satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*SCCM)(nil)
