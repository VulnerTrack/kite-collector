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

// SCCM implements discovery.Source by listing managed devices from Microsoft
// SCCM (ConfigMgr) via the AdminService REST API. Devices with IsClient set
// to true are considered managed.
type SCCM struct {
	baseURL string // test override; when set, endpoint validation is skipped
}

// NewSCCM returns a new SCCM/ConfigMgr discovery source.
func NewSCCM() *SCCM {
	return &SCCM{}
}

// Name returns the stable identifier for this source.
func (s *SCCM) Name() string { return "sccm" }

// Discover lists devices from SCCM AdminService REST API and returns them
// as assets. It honours cfg["enabled"] first (F3), loads credentials via
// connectorkit and zeroes them on return (R1), and validates the operator URL
// via SafeClient with allowPrivate=true because ConfigMgr is self-hosted.
// Authentication uses HTTP Basic auth. If credentials are absent the method
// logs a warning and returns nil (graceful degradation).
//
// Supported config keys:
//
//	api_url  – string base URL of the SCCM AdminService (e.g. "https://sccm.corp.local")
//	username – string account username
//	password – string account password
func (s *SCCM) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	if !connectorkit.Enabled(cfg) {
		return nil, nil // R2: honour enabled:false even with creds present (F3)
	}

	creds := connectorkit.LoadCredentials(cfg)
	defer creds.Zero() // R1

	apiURL := creds.APIURL
	if s.baseURL != "" {
		apiURL = s.baseURL
	}

	slog.Info("sccm: starting discovery", "api_url_set", apiURL != "")

	if apiURL == "" || creds.Username == "" || creds.Password == "" {
		slog.Warn("sccm: api_url, username, or password not configured, skipping discovery", "code", string(LogCodeSCCMCredsMissing))
		return nil, nil
	}

	client, base, err := s.httpClient(apiURL)
	if err != nil {
		return nil, err
	}
	baseStr := strings.TrimRight(base.String(), "/")

	devices, err := s.listDevices(ctx, client, baseStr, creds.Username, creds.Password)
	if err != nil {
		return nil, fmt.Errorf("sccm: listing devices: %w", err)
	}

	now := time.Now().UTC()
	assets := make([]model.Asset, 0, len(devices))

	for _, dev := range devices {
		managed := model.ManagedUnknown
		if dev.isClient {
			managed = model.ManagedManaged
		}

		asset := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			AssetType:       classifySCCMDevice(dev.osNameAndVersion),
			Hostname:        dev.name,
			OSFamily:        deriveSCCMOSFamily(dev.osNameAndVersion),
			OSVersion:       dev.osNameAndVersion,
			DiscoverySource: "sccm",
			FirstSeenAt:     now,
			LastSeenAt:      now,
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       managed,
		}
		if dev.resourceID != 0 {
			asset.MDMEnrollmentID = strconv.FormatInt(dev.resourceID, 10)
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}

	slog.Info("sccm: discovery complete", "total_assets", len(assets))
	return assets, nil
}

// httpClient returns the validated client + base URL for this source. In tests
// (baseURL set) it skips SafeClient; in production it validates apiURL with
// allowPrivate=true because ConfigMgr is commonly self-hosted on RFC-1918
// addresses.
func (s *SCCM) httpClient(apiURL string) (*http.Client, *url.URL, error) {
	return newValidatedClient("sccm", s.baseURL, apiURL, true)
}

// ---------------------------------------------------------------------------
// AdminService API types
// ---------------------------------------------------------------------------

// sccmDevice holds the fields extracted from the AdminService Device
// response.
type sccmDevice struct {
	name             string
	osNameAndVersion string
	resourceID       int64
	isClient         bool
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

// listDevices calls the SCCM AdminService REST API to enumerate all devices.
func (s *SCCM) listDevices(ctx context.Context, client *http.Client, baseURL, username, password string) ([]sccmDevice, error) {
	endpoint := baseURL + "/AdminService/v1.0/Device"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("sccm: creating request: %w", err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req) //#nosec G107 -- URL from user-configured, safenet-validated endpoint
	if err != nil {
		return nil, fmt.Errorf("sccm: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("sccm: reading response: %w", readErr)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		slog.Warn("sccm: authentication failed (HTTP 401)", "code", string(LogCodeSCCMAuthFailed))
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sccm: AdminService API returned %d: %s", resp.StatusCode, truncateBytes(body, 500))
	}

	// Single-page GET: record the fetched body against the guard so an
	// oversized response is capped like any paginated connector.
	guard := connectorkit.NewGuard("sccm")
	if err := guard.NextPage(int64(len(body))); err != nil {
		return nil, fmt.Errorf("sccm pagination guard: %w", err)
	}

	var result struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("sccm: parsing response: %w", err)
	}

	devices := make([]sccmDevice, 0, len(result.Value))
	for _, raw := range result.Value {
		dev, err := parseSCCMDevice(raw)
		if err != nil {
			slog.Debug("sccm: skipping unparseable device entry", "code", string(LogCodeSCCMSkipUnparseable), "error", err)
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
		ResourceID                    int64  `json:"ResourceID"`
		IsClient                      bool   `json:"IsClient"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return sccmDevice{}, fmt.Errorf("sccm: unmarshal device: %w", err)
	}

	return sccmDevice{
		name:             raw.Name,
		osNameAndVersion: raw.OperatingSystemNameAndVersion,
		resourceID:       raw.ResourceID,
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
