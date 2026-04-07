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

// ServiceNow implements discovery.Source by listing configuration items from
// a ServiceNow CMDB instance via the Table API. All CIs present in the CMDB
// are considered authorised.
type ServiceNow struct{}

// NewServiceNow returns a new ServiceNow CMDB discovery source.
func NewServiceNow() *ServiceNow {
	return &ServiceNow{}
}

// Name returns the stable identifier for this source.
func (s *ServiceNow) Name() string { return "servicenow" }

// Discover lists configuration items from ServiceNow CMDB and returns them
// as assets. If credentials are not available the method logs a warning and
// returns nil (graceful degradation).
//
// Supported config keys:
//
//	instance_url – string base URL of the ServiceNow instance (e.g. "https://myorg.service-now.com")
//	username     – string API account username
//	password     – string API account password
//	table        – string CMDB table to query (default: "cmdb_ci_server")
func (s *ServiceNow) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	instanceURL := strings.TrimRight(toString(cfg["instance_url"]), "/")
	username := toString(cfg["username"])
	password := toString(cfg["password"])
	table := toString(cfg["table"])

	if table == "" {
		table = "cmdb_ci_server"
	}

	slog.Info("servicenow: starting discovery",
		"instance_url_set", instanceURL != "",
		"table", table,
	)

	if instanceURL == "" || username == "" || password == "" {
		slog.Warn("servicenow: instance_url, username, or password not configured, skipping discovery")
		return nil, nil
	}

	cis, err := s.listCIs(ctx, instanceURL, username, password, table)
	if err != nil {
		return nil, fmt.Errorf("servicenow: listing CIs: %w", err)
	}

	now := time.Now().UTC()
	var assets []model.Asset

	for _, ci := range cis {
		osFamily := deriveServiceNowOSFamily(ci.os)

		asset := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			AssetType:       classifyServiceNowCI(table),
			Hostname:        ci.name,
			OSFamily:        osFamily,
			OSVersion:       ci.osVersion,
			Owner:           ci.operationalStatus,
			DiscoverySource: "servicenow",
			FirstSeenAt:     now,
			LastSeenAt:      now,
			IsAuthorized:    model.AuthorizationAuthorized,
			IsManaged:       model.ManagedUnknown,
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}

	slog.Info("servicenow: discovery complete", "total_assets", len(assets))
	return assets, nil
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
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

const serviceNowPageSize = 1000

// listCIs calls the ServiceNow Table API to enumerate all configuration items
// from the specified table, handling pagination via sysparm_offset.
func (s *ServiceNow) listCIs(ctx context.Context, instanceURL, username, password, table string) ([]serviceNowCI, error) {
	var allCIs []serviceNowCI
	offset := 0

	for {
		if ctx.Err() != nil {
			return allCIs, ctx.Err()
		}

		cis, hasMore, err := s.fetchCIPage(ctx, instanceURL, username, password, table, offset)
		if err != nil {
			return allCIs, err
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
// parsed CIs plus whether there are more pages.
func (s *ServiceNow) fetchCIPage(ctx context.Context, instanceURL, username, password, table string, offset int) ([]serviceNowCI, bool, error) {
	endpoint := fmt.Sprintf(
		"%s/api/now/table/%s?sysparm_limit=%d&sysparm_offset=%d&sysparm_fields=sys_id,name,os,os_version,ip_address,asset_tag,operational_status",
		instanceURL, table, serviceNowPageSize, offset,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) //#nosec G107 -- URL from operator-configured ServiceNow instance
	if err != nil {
		return nil, false, fmt.Errorf("creating request: %w", err)
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req) //#nosec G107
	if err != nil {
		return nil, false, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		slog.Warn("servicenow: authentication failed (HTTP 401)")
		return nil, false, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("ServiceNow Table API returned %d: %s",
			resp.StatusCode, truncateBytes(body, 500))
	}

	var result struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, false, fmt.Errorf("parsing response: %w", err)
	}

	var cis []serviceNowCI
	for _, raw := range result.Result {
		ci, err := parseServiceNowCI(raw)
		if err != nil {
			slog.Debug("servicenow: skipping unparseable CI entry", "error", err)
			continue
		}
		cis = append(cis, ci)
	}

	// If we received a full page, there may be more records.
	hasMore := len(result.Result) >= serviceNowPageSize

	return cis, hasMore, nil
}

// parseServiceNowCI extracts the fields we need from a single CI JSON
// object.
func parseServiceNowCI(data json.RawMessage) (serviceNowCI, error) {
	var raw struct {
		Name              string `json:"name"`
		OS                string `json:"os"`
		OSVersion         string `json:"os_version"`
		OperationalStatus string `json:"operational_status"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return serviceNowCI{}, err
	}

	return serviceNowCI{
		name:              raw.Name,
		os:                raw.OS,
		osVersion:         raw.OSVersion,
		operationalStatus: raw.OperationalStatus,
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
