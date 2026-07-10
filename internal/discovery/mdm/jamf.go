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

// Jamf implements discovery.Source by listing managed computers from the
// Jamf Pro Classic API. All devices present in Jamf are considered managed.
type Jamf struct {
	baseURL string // test override; when set, endpoint validation is skipped
}

// NewJamf returns a new Jamf Pro discovery source.
func NewJamf() *Jamf {
	return &Jamf{}
}

// Name returns the stable identifier for this source.
func (j *Jamf) Name() string { return "jamf" }

// Discover lists managed computers from Jamf Pro and returns them as assets.
// It honours cfg["enabled"] first (F3), loads credentials via connectorkit and
// zeroes them on return (R1), and validates the operator URL via SafeClient
// (SaaS: private targets rejected). If credentials are absent the method logs a
// warning and returns nil (graceful degradation).
//
// Supported config keys:
//
//	api_url  – string base URL of the Jamf Pro instance (e.g. "https://myorg.jamfcloud.com")
//	username – string API account username
//	password – string API account password
func (j *Jamf) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	if !connectorkit.Enabled(cfg) {
		return nil, nil // R2: honour enabled:false even with creds present (F3)
	}

	creds := connectorkit.LoadCredentials(cfg)
	defer creds.Zero() // R1

	apiURL := creds.APIURL
	if j.baseURL != "" {
		apiURL = j.baseURL
	}

	slog.Info("jamf: starting discovery", "api_url_set", apiURL != "")

	if apiURL == "" || creds.Username == "" || creds.Password == "" {
		slog.Warn("jamf: api_url, username, or password not configured, skipping discovery", "code", string(LogCodeJamfCredsMissing))
		return nil, nil
	}

	client, base, err := j.httpClient(apiURL)
	if err != nil {
		return nil, err
	}
	baseStr := strings.TrimRight(base.String(), "/")

	computers, err := j.listComputers(ctx, client, baseStr, creds.Username, creds.Password)
	if err != nil {
		return nil, fmt.Errorf("jamf: listing computers: %w", err)
	}

	slog.Info("jamf: fetched computer list", "count", len(computers))

	now := time.Now().UTC()
	assets := make([]model.Asset, 0, len(computers))
	guard := connectorkit.NewGuard("jamf")

	for _, comp := range computers {
		if err := ctx.Err(); err != nil {
			return assets, fmt.Errorf("jamf discovery cancelled: %w", err)
		}
		// N+1 detail fetch: bound the per-computer loop with the guard.
		if err := guard.Next(); err != nil {
			return assets, fmt.Errorf("jamf pagination guard: %w", err)
		}

		detail, err := j.getComputerDetail(ctx, client, baseStr, creds.Username, creds.Password, comp.ID)
		if err != nil {
			slog.Warn(
				"jamf: failed to fetch computer detail, skipping",
				"code", string(LogCodeJamfDetailFetchFailed),
				"computer_id", comp.ID,
				"error", err,
			)
			continue
		}

		hostname := detail.General.Name
		if hostname == "" {
			hostname = comp.Name
		}

		asset := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			AssetType:       model.AssetTypeWorkstation,
			Hostname:        hostname,
			OSFamily:        deriveJamfOSFamily(detail.Hardware.OSName),
			OSVersion:       detail.Hardware.OSVersion,
			DiscoverySource: "jamf",
			FirstSeenAt:     now,
			LastSeenAt:      now,
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       model.ManagedManaged,
			// Jamf computer id is an integer, so %d/Itoa is injection-safe
			// (no SanitizePathSegment needed).
			MDMEnrollmentID: strconv.Itoa(comp.ID),
		}
		if detail.General.SerialNumber != "" {
			tagsJSON, _ := json.Marshal(map[string]any{"serial_number": detail.General.SerialNumber})
			asset.Tags = string(tagsJSON)
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}

	slog.Info("jamf: discovery complete", "total_assets", len(assets))
	return assets, nil
}

// httpClient returns the validated client + base URL for this source. In tests
// (baseURL set) it skips SafeClient; in production it validates apiURL with
// allowPrivate=false because Jamf Pro is SaaS.
func (j *Jamf) httpClient(apiURL string) (*http.Client, *url.URL, error) {
	return newValidatedClient("jamf", j.baseURL, apiURL, false)
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
func (j *Jamf) listComputers(ctx context.Context, client *http.Client, baseURL, username, password string) ([]jamfComputerListEntry, error) {
	endpoint := baseURL + "/JSSResource/computers"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("jamf: creating request: %w", err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req) //#nosec G107 -- URL from user-configured, safenet-validated endpoint
	if err != nil {
		return nil, fmt.Errorf("jamf: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("jamf: reading response: %w", readErr)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		slog.Warn("jamf: authentication failed (HTTP 401)", "code", string(LogCodeJamfAuthFailed))
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jamf: API returned %d: %s", resp.StatusCode, truncateBytes(body, 500))
	}

	var result struct {
		Computers []jamfComputerListEntry `json:"computers"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("jamf: parsing response: %w", err)
	}

	return result.Computers, nil
}

// getComputerDetail fetches the full detail record for a single computer.
func (j *Jamf) getComputerDetail(ctx context.Context, client *http.Client, baseURL, username, password string, computerID int) (jamfComputerDetail, error) {
	endpoint := fmt.Sprintf("%s/JSSResource/computers/id/%d", baseURL, computerID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return jamfComputerDetail{}, fmt.Errorf("jamf: creating request: %w", err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req) //#nosec G107 -- URL from user-configured, safenet-validated endpoint
	if err != nil {
		return jamfComputerDetail{}, fmt.Errorf("jamf: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	_ = resp.Body.Close()
	if readErr != nil {
		return jamfComputerDetail{}, fmt.Errorf("jamf: reading response: %w", readErr)
	}

	if resp.StatusCode != http.StatusOK {
		return jamfComputerDetail{}, fmt.Errorf("jamf: API returned %d: %s", resp.StatusCode, truncateBytes(body, 500))
	}

	var wrapper struct {
		Computer jamfComputerDetail `json:"computer"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return jamfComputerDetail{}, fmt.Errorf("jamf: parsing response: %w", err)
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
