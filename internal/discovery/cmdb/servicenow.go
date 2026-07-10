package cmdb

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

// ServiceNow implements discovery.Source by listing configuration items from
// a ServiceNow CMDB instance via the Table API. All CIs present in the CMDB
// are considered authorised.
type ServiceNow struct {
	// baseURL is a test override. When set, endpoint validation
	// (connectorkit.SafeClient) is skipped and a plain client is built so an
	// httptest server on 127.0.0.1 is reachable.
	baseURL string
}

// NewServiceNow returns a new ServiceNow CMDB discovery source.
func NewServiceNow() *ServiceNow {
	return &ServiceNow{}
}

// Name returns the stable identifier for this source.
func (s *ServiceNow) Name() string { return "servicenow" }

// Discover lists configuration items from ServiceNow CMDB and returns them
// as assets. If discovery is not enabled, or credentials are not available,
// the method returns nil (graceful degradation).
//
// Supported config keys:
//
//	enabled      – bool; discovery is skipped unless explicitly true (F3)
//	instance_url – string base URL of the instance (e.g. "https://myorg.service-now.com")
//	username     – string API account username
//	password     – string API account password
//	table        – string CMDB table to query (default: "cmdb_ci_server")
func (s *ServiceNow) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	if !connectorkit.Enabled(cfg) {
		return nil, nil // R2/F3: honour enabled:false even when creds are present.
	}

	creds := connectorkit.LoadCredentials(cfg)
	defer creds.Zero() // R1: never let plaintext secrets linger past discovery.

	instanceURL := strings.TrimRight(creds.InstanceURL, "/")
	if s.baseURL != "" {
		instanceURL = strings.TrimRight(s.baseURL, "/")
	}
	username := creds.Username
	password := creds.Password
	table := creds.Table
	if table == "" {
		table = "cmdb_ci_server"
	}

	slog.Info(
		"servicenow: starting discovery",
		"code", string(LogCodeServiceNowStarting),
		"instance_url_set", instanceURL != "",
		"table", table,
	)

	if instanceURL == "" || username == "" || password == "" {
		slog.Warn("servicenow: instance_url, username, or password not configured, skipping discovery", "code", string(LogCodeServiceNowNotConfigured))
		return nil, nil
	}

	client, base, err := s.httpClient(instanceURL)
	if err != nil {
		return nil, err
	}
	baseStr := strings.TrimRight(base.String(), "/")

	cis, err := s.listCIs(ctx, client, baseStr, username, password, table)
	if err != nil {
		return nil, fmt.Errorf("servicenow: listing CIs: %w", err)
	}

	now := time.Now().UTC()
	assets := make([]model.Asset, 0, len(cis))

	for _, ci := range cis {
		osFamily := deriveServiceNowOSFamily(ci.os)

		// R6: ip_address has no dedicated column; keep it in Tags rather than
		// overloading a scalar field.
		tags := map[string]any{}
		if ci.ipAddress != "" {
			tags["ip_address"] = ci.ipAddress
		}

		// F6/R6: sys_id, asset_tag and operational_status now land in dedicated
		// columns instead of being dropped (sys_id, asset_tag) or overloaded
		// into Owner (operational_status).
		asset := model.Asset{
			ID:                uuid.Must(uuid.NewV7()),
			AssetType:         classifyServiceNowCI(table),
			Hostname:          ci.name,
			OSFamily:          osFamily,
			OSVersion:         ci.osVersion,
			CMDBSysID:         ci.sysID,
			AssetTag:          ci.assetTag,
			OperationalStatus: ci.operationalStatus,
			DiscoverySource:   "servicenow",
			FirstSeenAt:       now,
			LastSeenAt:        now,
			IsAuthorized:      model.AuthorizationAuthorized,
			IsManaged:         model.ManagedUnknown,
		}
		if len(tags) > 0 {
			b, _ := json.Marshal(tags)
			asset.Tags = string(b)
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}

	slog.Info("servicenow: discovery complete", "code", string(LogCodeServiceNowComplete), "total_assets", len(assets))
	return assets, nil
}

// httpClient returns the outbound client and validated base URL. When baseURL
// is set (tests) SafeClient is skipped; otherwise connectorkit.SafeClient
// enforces HTTPS + SSRF validation. ServiceNow is SaaS-only, so an
// operator-supplied URL resolving to a private/loopback address is rejected
// (allowPrivate=false).
func (s *ServiceNow) httpClient(instanceURL string) (*http.Client, *url.URL, error) {
	if s.baseURL != "" {
		u, err := url.Parse(s.baseURL)
		if err != nil {
			return nil, nil, fmt.Errorf("servicenow: %w", err)
		}
		return &http.Client{Timeout: cmdbClientTimeout}, u, nil
	}
	client, u, err := connectorkit.SafeClient("servicenow", instanceURL, false)
	if err != nil {
		return nil, nil, fmt.Errorf("servicenow: %w", err)
	}
	return client, u, nil
}

// ---------------------------------------------------------------------------
// ServiceNow Table API types
// ---------------------------------------------------------------------------

// serviceNowCI holds the fields extracted from the ServiceNow Table API
// response.
type serviceNowCI struct {
	name              string
	os                string
	osVersion         string
	operationalStatus string
	sysID             string
	ipAddress         string
	assetTag          string
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

const serviceNowPageSize = 1000

// listCIs calls the ServiceNow Table API to enumerate all configuration items
// from the specified table, handling pagination via sysparm_offset and
// bounding the loop with a pagination guard.
func (s *ServiceNow) listCIs(ctx context.Context, client *http.Client, instanceURL, username, password, table string) ([]serviceNowCI, error) {
	var allCIs []serviceNowCI
	offset := 0
	guard := connectorkit.NewGuard("servicenow")

	for {
		if ctx.Err() != nil {
			return allCIs, fmt.Errorf("servicenow: context cancelled: %w", ctx.Err())
		}

		cis, hasMore, nBytes, err := s.fetchCIPage(ctx, client, instanceURL, username, password, table, offset)
		if err != nil {
			return allCIs, err
		}
		if err := guard.NextPage(nBytes); err != nil {
			return allCIs, fmt.Errorf("servicenow: %w", err)
		}
		allCIs = append(allCIs, cis...)

		if !hasMore {
			break
		}
		offset += serviceNowPageSize
	}

	return allCIs, nil
}

// fetchCIPage fetches a single page of CIs from the Table API and returns
// parsed CIs, whether there are more pages, and the raw page byte count for
// the pagination guard.
func (s *ServiceNow) fetchCIPage(ctx context.Context, client *http.Client, instanceURL, username, password, table string, offset int) ([]serviceNowCI, bool, int64, error) {
	endpoint := fmt.Sprintf(
		"%s/api/now/table/%s?sysparm_limit=%d&sysparm_offset=%d&sysparm_fields=sys_id,name,os,os_version,ip_address,asset_tag,operational_status",
		instanceURL, table, serviceNowPageSize, offset,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) //#nosec G107 -- URL from operator-configured, safenet-validated ServiceNow instance
	if err != nil {
		return nil, false, 0, fmt.Errorf("servicenow: creating request: %w", err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req) //#nosec G107 -- URL from user-configured, safenet-validated endpoint
	if err != nil {
		return nil, false, 0, fmt.Errorf("servicenow: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, false, 0, fmt.Errorf("servicenow: reading response: %w", readErr)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		slog.Warn("servicenow: authentication failed (HTTP 401)", "code", string(LogCodeServiceNowAuthFailed))
		return nil, false, int64(len(body)), nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, false, 0, fmt.Errorf("servicenow: Table API returned %d: %s",
			resp.StatusCode, truncateBytes(body, 500))
	}

	var result struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, false, 0, fmt.Errorf("servicenow: parsing response: %w", err)
	}

	cis := make([]serviceNowCI, 0, len(result.Result))
	for _, raw := range result.Result {
		ci, err := parseServiceNowCI(raw)
		if err != nil {
			slog.Debug("servicenow: skipping unparseable CI entry",
				"code", string(LogCodeServiceNowSkipUnparseable), "error", err)
			continue
		}
		cis = append(cis, ci)
	}

	// If we received a full page, there may be more records.
	hasMore := len(result.Result) >= serviceNowPageSize

	return cis, hasMore, int64(len(body)), nil
}

// parseServiceNowCI extracts the fields we need from a single CI JSON object.
// It decodes all seven requested sysparm_fields (F6 fix): previously sys_id,
// ip_address and asset_tag were requested from the API but silently dropped
// here.
func parseServiceNowCI(data json.RawMessage) (serviceNowCI, error) {
	var raw struct {
		SysID             string `json:"sys_id"`
		Name              string `json:"name"`
		OS                string `json:"os"`
		OSVersion         string `json:"os_version"`
		IPAddress         string `json:"ip_address"`
		AssetTag          string `json:"asset_tag"`
		OperationalStatus string `json:"operational_status"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return serviceNowCI{}, fmt.Errorf("unmarshal servicenow CI: %w", err)
	}

	return serviceNowCI{
		name:              raw.Name,
		os:                raw.OS,
		osVersion:         raw.OSVersion,
		operationalStatus: raw.OperationalStatus,
		sysID:             raw.SysID,
		ipAddress:         raw.IPAddress,
		assetTag:          raw.AssetTag,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// deriveServiceNowOSFamily normalises the ServiceNow os field to a standard
// OS family string.
func deriveServiceNowOSFamily(os string) string {
	lower := strings.ToLower(os)
	switch {
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "linux"),
		strings.Contains(lower, "ubuntu"),
		strings.Contains(lower, "centos"),
		strings.Contains(lower, "red hat"),
		strings.Contains(lower, "rhel"),
		strings.Contains(lower, "debian"),
		strings.Contains(lower, "suse"):
		return "linux"
	case strings.Contains(lower, "mac os"),
		strings.Contains(lower, "macos"),
		strings.Contains(lower, "darwin"):
		return "darwin"
	case strings.Contains(lower, "aix"):
		return "aix"
	case strings.Contains(lower, "solaris"),
		strings.Contains(lower, "sunos"):
		return "solaris"
	default:
		return strings.ToLower(os)
	}
}

// classifyServiceNowCI maps the CMDB table name to an asset type.
func classifyServiceNowCI(table string) model.AssetType {
	switch table {
	case "cmdb_ci_server", "cmdb_ci_linux_server", "cmdb_ci_win_server", "cmdb_ci_unix_server":
		return model.AssetTypeServer
	case "cmdb_ci_computer", "cmdb_ci_pc_hardware":
		return model.AssetTypeWorkstation
	case "cmdb_ci_netgear":
		return model.AssetTypeNetworkDevice
	default:
		return model.AssetTypeServer
	}
}

// ensure ServiceNow satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*ServiceNow)(nil)
