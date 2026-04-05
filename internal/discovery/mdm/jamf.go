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

// Jamf implements discovery.Source by listing managed computers from the
// Jamf Pro Classic API. All devices present in Jamf are considered managed.
type Jamf struct{}

// NewJamf returns a new Jamf Pro discovery source.
func NewJamf() *Jamf {
	return &Jamf{}
}

// Name returns the stable identifier for this source.
func (j *Jamf) Name() string { return "jamf" }

// Discover lists managed computers from Jamf Pro and returns them as assets.
// If credentials are not available the method logs a warning and returns nil
// (graceful degradation).
//
// Supported config keys:
//
//	api_url  – string base URL of the Jamf Pro instance (e.g. "https://myorg.jamfcloud.com")
//	username – string API account username
//	password – string API account password
func (j *Jamf) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	apiURL := strings.TrimRight(toString(cfg["api_url"]), "/")
	username := toString(cfg["username"])
	password := toString(cfg["password"])

	slog.Info("jamf: starting discovery", "api_url_set", apiURL != "")

	if apiURL == "" || username == "" || password == "" {
		slog.Warn("jamf: api_url, username, or password not configured, skipping discovery")
		return nil, nil
	}

	computers, err := j.listComputers(ctx, apiURL, username, password)
	if err != nil {
		return nil, fmt.Errorf("jamf: listing computers: %w", err)
	}

	slog.Info("jamf: fetched computer list", "count", len(computers))

	now := time.Now().UTC()
	var assets []model.Asset

	for _, comp := range computers {
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		detail, err := j.getComputerDetail(ctx, apiURL, username, password, comp.ID)
		if err != nil {
			slog.Warn("jamf: failed to fetch computer detail, skipping",
				"computer_id", comp.ID,
				"error", err,
			)
			continue
		}

		hostname := detail.General.Name
		if hostname == "" {
			hostname = comp.Name
		}

		osFamily := deriveJamfOSFamily(detail.Hardware.OSName)

		asset := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			AssetType:       model.AssetTypeWorkstation,
			Hostname:        hostname,
			OSFamily:        osFamily,
			OSVersion:       detail.Hardware.OSVersion,
			DiscoverySource: "jamf",
			FirstSeenAt:     now,
			LastSeenAt:      now,
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       model.ManagedManaged,
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}

	slog.Info("jamf: discovery complete", "total_assets", len(assets))
	return assets, nil
}

// ---------------------------------------------------------------------------
// Jamf Pro Classic API types
// ---------------------------------------------------------------------------

// jamfComputerListEntry represents a single computer in the list response.
type jamfComputerListEntry struct {
	Name string `json:"name"`
	ID   int    `json:"id"`
}

// jamfComputerDetail holds the fields extracted from the computer detail
// response.
type jamfComputerDetail struct {
	Hardware struct {
		OSName    string `json:"os_name"`
		OSVersion string `json:"os_version"`
		OSBuild   string `json:"os_build"`
	} `json:"hardware"`
	General struct {
		Name         string `json:"name"`
		SerialNumber string `json:"serial_number"`
		ID           int    `json:"id"`
	} `json:"general"`
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

// listComputers calls the Jamf Pro Classic API to enumerate all computers.
func (j *Jamf) listComputers(ctx context.Context, apiURL, username, password string) ([]jamfComputerListEntry, error) {
	endpoint := apiURL + "/JSSResource/computers"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		slog.Warn("jamf: authentication failed (HTTP 401)")
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Jamf API returned %d: %s", resp.StatusCode, truncateBytes(body, 500))
	}

	var result struct {
		Computers []jamfComputerListEntry `json:"computers"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return result.Computers, nil
}

// getComputerDetail fetches the full detail record for a single computer.
func (j *Jamf) getComputerDetail(ctx context.Context, apiURL, username, password string, computerID int) (jamfComputerDetail, error) {
	endpoint := fmt.Sprintf("%s/JSSResource/computers/id/%d", apiURL, computerID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return jamfComputerDetail{}, fmt.Errorf("creating request: %w", err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return jamfComputerDetail{}, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return jamfComputerDetail{}, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return jamfComputerDetail{}, fmt.Errorf("Jamf API returned %d: %s", resp.StatusCode, truncateBytes(body, 500))
	}

	var wrapper struct {
		Computer jamfComputerDetail `json:"computer"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return jamfComputerDetail{}, fmt.Errorf("parsing response: %w", err)
	}

	return wrapper.Computer, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// deriveJamfOSFamily normalises the Jamf os_name field to a standard OS family
// string.
func deriveJamfOSFamily(osName string) string {
	lower := strings.ToLower(osName)
	switch {
	case strings.Contains(lower, "mac os"),
		strings.Contains(lower, "macos"),
		strings.Contains(lower, "os x"):
		return "darwin"
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "linux"):
		return "linux"
	default:
		return "darwin" // Jamf is predominantly macOS
	}
}

// ensure Jamf satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*Jamf)(nil)
