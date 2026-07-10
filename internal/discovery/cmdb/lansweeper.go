package cmdb

import (
	"bytes"
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
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// Lansweeper implements discovery.Source by listing asset resources from the
// Lansweeper GraphQL API. All assets present in Lansweeper are considered
// authorised since their presence in the CMDB implies organisational
// awareness.
type Lansweeper struct {
	// baseURL is a test override. When set, endpoint validation
	// (connectorkit.SafeClient) is skipped and a plain client is built so an
	// httptest server on 127.0.0.1 is reachable.
	baseURL string
}

// NewLansweeper returns a new Lansweeper discovery source.
func NewLansweeper() *Lansweeper {
	return &Lansweeper{}
}

// Name returns the stable identifier for this source.
func (l *Lansweeper) Name() string { return "lansweeper" }

// lansweeperQuery is the GraphQL query used to page asset resources for a
// site. The cursor variable is empty on the first page and carries
// pagination.next on subsequent pages.
const lansweeperQuery = `query($siteId: ID!, $cursor: String) {` +
	` site(id: $siteId) {` +
	` assetResources(fields: ["assetBasicInfo.name","assetBasicInfo.type","assetBasicInfo.ipAddress","assetBasicInfo.domain","operatingSystem.caption"], pagination: { limit: 100, page: NEXT, cursor: $cursor }) {` +
	` items { key assetBasicInfo { name type ipAddress domain } operatingSystem { caption } }` +
	` pagination { next }` +
	` } } }`

// Discover lists asset resources from Lansweeper and returns them as assets.
// If discovery is not enabled, or credentials are not available, the method
// returns nil (graceful degradation).
//
// Supported config keys:
//
//	enabled – bool; discovery is skipped unless explicitly true (F3)
//	api_url – string GraphQL endpoint (e.g. "https://api.lansweeper.com/api/v2/graphql")
//	api_key – string personal application API key (Bearer token)
//	site_id – string Lansweeper site identifier to enumerate
func (l *Lansweeper) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	if !connectorkit.Enabled(cfg) {
		return nil, nil // R2/F3: honour enabled:false even when creds are present.
	}

	creds := connectorkit.LoadCredentials(cfg)
	defer creds.Zero() // R1: never let plaintext secrets linger past discovery.

	apiURL := strings.TrimRight(creds.APIURL, "/")
	if l.baseURL != "" {
		apiURL = strings.TrimRight(l.baseURL, "/")
	}
	apiKey := creds.APIKey
	siteID := creds.SiteID

	slog.Info(
		"lansweeper: starting discovery",
		"code", string(LogCodeLansweeperStarting),
		"api_url_set", apiURL != "",
		"api_key_set", apiKey != "",
		"site_id_set", siteID != "",
	)

	if apiURL == "" || apiKey == "" || siteID == "" {
		slog.Warn("lansweeper: api_url, api_key, or site_id not configured, skipping discovery",
			"code", string(LogCodeLansweeperNotConfigured))
		return nil, nil
	}

	client, base, err := l.httpClient(apiURL)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(base.String(), "/")

	items, err := l.listAssets(ctx, client, endpoint, apiKey, siteID)
	if err != nil {
		return nil, fmt.Errorf("lansweeper: listing assets: %w", err)
	}

	now := time.Now().UTC()
	assets := make([]model.Asset, 0, len(items))

	for _, it := range items {
		osFamily := deriveLansweeperOSFamily(it.OperatingSystem.Caption)

		// R6: ip_address/domain have no dedicated column — keep them in Tags.
		tags := map[string]any{}
		if it.AssetBasicInfo.IPAddress != "" {
			tags["ip_address"] = it.AssetBasicInfo.IPAddress
		}
		if it.AssetBasicInfo.Domain != "" {
			tags["domain"] = it.AssetBasicInfo.Domain
		}

		asset := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			AssetType:       classifyLansweeperAsset(it.AssetBasicInfo.Type),
			Hostname:        it.AssetBasicInfo.Name,
			OSFamily:        osFamily,
			CMDBSysID:       it.Key,
			DiscoverySource: "lansweeper",
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

	slog.Info("lansweeper: discovery complete", "code", string(LogCodeLansweeperComplete), "total_assets", len(assets))
	return assets, nil
}

// httpClient returns the outbound client and validated base URL. When baseURL
// is set (tests) SafeClient is skipped; otherwise connectorkit.SafeClient
// enforces HTTPS + SSRF validation. Lansweeper is SaaS-only, so an
// operator-supplied URL resolving to a private/loopback address is rejected
// (allowPrivate=false).
func (l *Lansweeper) httpClient(apiURL string) (*http.Client, *url.URL, error) {
	if l.baseURL != "" {
		u, err := url.Parse(l.baseURL)
		if err != nil {
			return nil, nil, fmt.Errorf("lansweeper: %w", err)
		}
		return &http.Client{Timeout: cmdbClientTimeout}, u, nil
	}
	client, u, err := connectorkit.SafeClient("lansweeper", apiURL, false)
	if err != nil {
		return nil, nil, fmt.Errorf("lansweeper: %w", err)
	}
	return client, u, nil
}

// ---------------------------------------------------------------------------
// Lansweeper GraphQL types
// ---------------------------------------------------------------------------

// lansweeperResponse is the GraphQL response envelope for the assetResources
// query.
type lansweeperResponse struct {
	Data struct {
		Site struct {
			AssetResources struct {
				Pagination struct {
					Next string `json:"next"`
				} `json:"pagination"`
				Items []lansweeperItem `json:"items"`
			} `json:"assetResources"`
		} `json:"site"`
	} `json:"data"`
}

// lansweeperItem holds the fields extracted from a single asset resource.
type lansweeperItem struct {
	Key            string `json:"key"`
	AssetBasicInfo struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		IPAddress string `json:"ipAddress"`
		Domain    string `json:"domain"`
	} `json:"assetBasicInfo"`
	OperatingSystem struct {
		Caption string `json:"caption"`
	} `json:"operatingSystem"`
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

// listAssets enumerates all asset resources using cursor pagination, bounding
// the loop with a pagination guard and sanitising each upstream cursor before
// reuse.
func (l *Lansweeper) listAssets(ctx context.Context, client *http.Client, endpoint, apiKey, siteID string) ([]lansweeperItem, error) {
	var all []lansweeperItem
	cursor := ""
	guard := connectorkit.NewGuard("lansweeper")

	for {
		if ctx.Err() != nil {
			return all, fmt.Errorf("lansweeper: context cancelled: %w", ctx.Err())
		}

		page, nBytes, err := l.fetchPage(ctx, client, endpoint, apiKey, siteID, cursor)
		if err != nil {
			return all, err
		}
		if gErr := guard.NextPage(nBytes); gErr != nil {
			return all, fmt.Errorf("lansweeper: %w", gErr)
		}

		all = append(all, page.Data.Site.AssetResources.Items...)

		next := page.Data.Site.AssetResources.Pagination.Next
		if next == "" {
			break
		}
		safeCursor, err := safenet.SanitizeCursorWithSource("lansweeper", next)
		if err != nil {
			return all, fmt.Errorf("lansweeper: %w", err)
		}
		cursor = safeCursor
	}

	return all, nil
}

// fetchPage performs a single GraphQL POST and returns the parsed response
// plus the raw page byte count for the pagination guard.
func (l *Lansweeper) fetchPage(ctx context.Context, client *http.Client, endpoint, apiKey, siteID, cursor string) (lansweeperResponse, int64, error) {
	reqBody := map[string]any{
		"query": lansweeperQuery,
		"variables": map[string]any{
			"siteId": siteID,
			"cursor": cursor,
		},
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return lansweeperResponse{}, 0, fmt.Errorf("lansweeper: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload)) //#nosec G107 -- URL from operator-configured, safenet-validated Lansweeper endpoint
	if err != nil {
		return lansweeperResponse{}, 0, fmt.Errorf("lansweeper: creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req) //#nosec G107 -- URL from user-configured, safenet-validated endpoint
	if err != nil {
		return lansweeperResponse{}, 0, fmt.Errorf("lansweeper: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	_ = resp.Body.Close()
	if readErr != nil {
		return lansweeperResponse{}, 0, fmt.Errorf("lansweeper: reading response: %w", readErr)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		slog.Warn("lansweeper: authentication failed", "code", string(LogCodeLansweeperAuthFailed), "status", resp.StatusCode)
		return lansweeperResponse{}, int64(len(body)), nil
	}

	if resp.StatusCode != http.StatusOK {
		return lansweeperResponse{}, 0, fmt.Errorf("lansweeper: API returned %d: %s",
			resp.StatusCode, truncateBytes(body, 500))
	}

	var out lansweeperResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return lansweeperResponse{}, 0, fmt.Errorf("lansweeper: parsing response: %w", err)
	}

	return out, int64(len(body)), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// classifyLansweeperAsset maps the Lansweeper asset type to an asset type.
func classifyLansweeperAsset(assetType string) model.AssetType {
	lower := strings.ToLower(assetType)
	switch {
	case strings.Contains(lower, "server"):
		return model.AssetTypeServer
	case strings.Contains(lower, "workstation"),
		strings.Contains(lower, "desktop"),
		strings.Contains(lower, "laptop"):
		return model.AssetTypeWorkstation
	case strings.Contains(lower, "printer"),
		strings.Contains(lower, "monitor"):
		return model.AssetTypeIOTDevice
	default:
		return model.AssetTypeServer
	}
}

// deriveLansweeperOSFamily normalises the Lansweeper operatingSystem.caption
// field to a standard OS family string.
func deriveLansweeperOSFamily(caption string) string {
	lower := strings.ToLower(caption)
	switch {
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "linux"),
		strings.Contains(lower, "ubuntu"),
		strings.Contains(lower, "centos"),
		strings.Contains(lower, "debian"),
		strings.Contains(lower, "red hat"),
		strings.Contains(lower, "rhel"):
		return "linux"
	case strings.Contains(lower, "mac"),
		strings.Contains(lower, "darwin"):
		return "darwin"
	case strings.Contains(lower, "ios"):
		return "ios"
	case strings.Contains(lower, "android"):
		return "android"
	default:
		if caption == "" {
			return ""
		}
		return lower
	}
}

// ensure Lansweeper satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*Lansweeper)(nil)
