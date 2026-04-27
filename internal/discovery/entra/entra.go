// Package entra implements a discovery.Source that enumerates Microsoft Entra
// ID users, service principals, security groups, and cloud-joined devices as
// kite assets per RFC-0121. Findings are produced separately in audit/entra.go
// (Phase 2).
//
// Authentication uses OAuth2 client credentials (service principal) via the
// Microsoft Graph API, consistent with the Intune MDM source pattern. Missing
// or invalid credentials cause the source to log a warning and return nil
// (graceful degradation), matching the behaviour of internal/discovery/mdm.
package entra

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

	"github.com/vulnertrack/kite-collector/internal/model"
)

// SourceName is the stable identifier emitted on the
// security.asset.discovery.source attribute and the discover.<source>
// span suffix per RFC-0115.
const SourceName = "entra"

// privilegedRoleTemplateIDs is the closed set of tier-0/tier-1 Entra role
// template GUIDs that drive ENTRA-003 (overprivileged service principal)
// findings in Phase 2. The map is exported via PrivilegedRoleTemplateIDs so
// the auditor can reuse the same reference list without duplicating GUIDs.
var privilegedRoleTemplateIDs = map[string]string{
	"62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
	"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
	"158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
	"7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
	"e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
}

// PrivilegedRoleTemplateIDs returns a copy of the privileged role template
// GUID → display name map. The auditor module imports this for ENTRA-003.
func PrivilegedRoleTemplateIDs() map[string]string {
	out := make(map[string]string, len(privilegedRoleTemplateIDs))
	for k, v := range privilegedRoleTemplateIDs {
		out[k] = v
	}
	return out
}

// httpClient is the minimal subset of *http.Client used by this source.
// Defining it as an interface lets the test suite swap in a recording or
// fault-injecting transport without touching real Graph endpoints.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// EntraID implements discovery.Source for Microsoft Entra ID.
type EntraID struct {
	tokenBaseURL string
	graphBaseURL string
	httpClient   httpClient
	now          func() time.Time
}

// New returns a new Microsoft Entra ID discovery source pointed at the
// production Microsoft identity and Graph endpoints.
func New() *EntraID {
	return &EntraID{ //#nosec G101 -- base URLs, not credentials
		tokenBaseURL: defaultTokenBaseURL,
		graphBaseURL: defaultGraphBaseURL,
		httpClient:   http.DefaultClient,
		now:          func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the stable identifier for this source.
func (e *EntraID) Name() string { return SourceName }

// Discover enumerates users, service principals, groups, and devices from
// the configured Entra ID tenant and returns the device set as kite assets.
// Users / service principals / groups are stored separately by the SQLite
// store (Phase 2 wiring); this method emits only the asset set so the
// existing discovery.Registry contract keeps working.
//
// Returns nil, nil when:
//   - the source is disabled by configuration,
//   - tenant_id / client_id / client_secret are not all set,
//   - OAuth2 token acquisition fails (e.g. credentials revoked / tenant
//     unreachable). This mirrors the Intune source for graceful degradation.
//
// Supported config keys (full schema in RFC-0121 §5.4):
//
//	enabled                  – bool   (default: true)
//	tenant_id                – string Azure AD tenant GUID (required)
//	client_id                – string Application (client) ID (required)
//	client_secret            – string Client secret value (required)
//	stale_account_days       – int    (default: 90; finding ENTRA-001)
//	max_users                – int    circuit-breaker (default: 50000)
//	max_service_principals   – int    circuit-breaker (default: 10000)
//	max_groups               – int    circuit-breaker (default: 50000)
//	max_devices              – int    circuit-breaker (default: 50000)
//	request_timeout_seconds  – int    per-call HTTP timeout (default: 60)
//	page_size                – int    Graph $top page size (default: 999)
func (e *EntraID) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	conf, err := parseConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("entra: %w", err)
	}
	if !conf.enabled {
		slog.Debug("entra: disabled by configuration")
		return nil, nil
	}
	if conf.tenantID == "" || conf.clientID == "" || conf.clientSecret == "" {
		slog.Warn("entra: tenant_id, client_id, or client_secret not configured, skipping")
		return nil, nil
	}

	// Graph base URL overrides may be injected via config for testing; the
	// production constructor sets the real Microsoft endpoints. Honour
	// per-instance test overrides first, then config-supplied overrides.
	if conf.tokenBaseURL != "" && e.tokenBaseURL == defaultTokenBaseURL {
		e.tokenBaseURL = conf.tokenBaseURL
	}
	if conf.graphBaseURL != "" && e.graphBaseURL == defaultGraphBaseURL {
		e.graphBaseURL = conf.graphBaseURL
	}

	token, err := e.acquireToken(ctx, conf)
	if err != nil {
		slog.Warn("entra: failed to acquire OAuth2 token, skipping", "error", err)
		return nil, nil
	}
	defer func() { token = strings.Repeat("\x00", len(token)) }()

	users, err := e.listUsers(ctx, token, conf)
	if err != nil {
		return nil, fmt.Errorf("entra: listing users: %w", err)
	}
	sps, err := e.listServicePrincipals(ctx, token, conf)
	if err != nil {
		return nil, fmt.Errorf("entra: listing service principals: %w", err)
	}
	groups, err := e.listGroups(ctx, token, conf)
	if err != nil {
		return nil, fmt.Errorf("entra: listing groups: %w", err)
	}
	devices, err := e.listDevices(ctx, token, conf)
	if err != nil {
		return nil, fmt.Errorf("entra: listing devices: %w", err)
	}

	slog.Info("entra: discovery complete",
		"users", len(users),
		"service_principals", len(sps),
		"groups", len(groups),
		"devices", len(devices),
		"tenant_id", conf.tenantID,
	)
	return e.buildDeviceAssets(devices, conf), nil
}

// acquireToken exchanges client credentials for an OAuth2 bearer token for
// the Graph API scope, using the same pattern as
// internal/discovery/mdm/intune.go.
func (e *EntraID) acquireToken(ctx context.Context, conf *entraConfig) (string, error) {
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token",
		e.tokenBaseURL, url.PathEscape(conf.tenantID))

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {conf.clientID},
		"client_secret": {conf.clientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, //#nosec G107 -- operator-configured tenant URL
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s",
			resp.StatusCode, truncateBytes(body, 300))
	}

	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if jErr := json.Unmarshal(body, &tr); jErr != nil {
		return "", fmt.Errorf("decoding token response: %w", jErr)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("empty access_token in response")
	}
	return tr.AccessToken, nil
}

// entraUser is the typed view of a single /v1.0/users response element. Only
// the fields RFC-0121 needs are extracted; unknown keys are dropped.
type entraUser struct {
	signInActivity *struct {
		LastSignInDateTime  string `json:"lastSignInDateTime"`
		LastSignInRequestID string `json:"lastSignInRequestId"`
	}
	ID                       string `json:"id"`
	UserPrincipalName        string `json:"userPrincipalName"`
	DisplayName              string `json:"displayName"`
	Department               string `json:"department"`
	JobTitle                 string `json:"jobTitle"`
	Mail                     string `json:"mail"`
	OnPremisesSamAccountName string `json:"onPremisesSamAccountName"`
	AccountEnabled           bool   `json:"accountEnabled"`
	OnPremisesSyncEnabled    bool   `json:"onPremisesSyncEnabled"`
}

// entraServicePrincipal is the typed view of a single /v1.0/servicePrincipals
// response element.
type entraServicePrincipal struct {
	ID                     string   `json:"id"`
	AppID                  string   `json:"appId"`
	DisplayName            string   `json:"displayName"`
	ServicePrincipalType   string   `json:"servicePrincipalType"`
	PublisherName          string   `json:"publisherName"`
	OAuth2PermissionScopes []string `json:"oauth2PermissionScopes"`
	AccountEnabled         bool     `json:"accountEnabled"`
}

// entraGroup is the typed view of a single /v1.0/groups response element.
type entraGroup struct {
	ID                            string   `json:"id"`
	DisplayName                   string   `json:"displayName"`
	GroupTypes                    []string `json:"groupTypes"`
	MembershipRule                string   `json:"membershipRule"`
	MembershipRuleProcessingState string   `json:"membershipRuleProcessingState"`
	SecurityEnabled               bool     `json:"securityEnabled"`
	MailEnabled                   bool     `json:"mailEnabled"`
	IsAssignableToRole            bool     `json:"isAssignableToRole"`
}

// entraDevice is the typed view of a single /v1.0/devices response element.
type entraDevice struct {
	ApproximateLastSignInDateTime string `json:"approximateLastSignInDateTime"`
	RegistrationDateTime          string `json:"registrationDateTime"`
	ID                            string `json:"id"`
	DeviceID                      string `json:"deviceId"`
	DisplayName                   string `json:"displayName"`
	OperatingSystem               string `json:"operatingSystem"`
	OperatingSystemVersion        string `json:"operatingSystemVersion"`
	TrustType                     string `json:"trustType"`
	IsCompliant                   *bool  `json:"isCompliant,omitempty"`
	IsManaged                     *bool  `json:"isManaged,omitempty"`
}

// listUsers fetches all users from Graph /v1.0/users with pagination.
func (e *EntraID) listUsers(ctx context.Context, token string, conf *entraConfig) ([]entraUser, error) {
	fields := "id,userPrincipalName,displayName,accountEnabled,department,jobTitle," +
		"mail,onPremisesSyncEnabled,onPremisesSamAccountName,signInActivity"
	apiURL := fmt.Sprintf("%s/v1.0/users?$select=%s&$top=%d",
		e.graphBaseURL, url.QueryEscape(fields), conf.pageSize)
	return fetchAllPages[entraUser](ctx, e.httpClient, apiURL, token, conf.maxUsers)
}

// listServicePrincipals fetches all service principals from Graph
// /v1.0/servicePrincipals with pagination.
func (e *EntraID) listServicePrincipals(ctx context.Context, token string, conf *entraConfig) ([]entraServicePrincipal, error) {
	fields := "id,appId,displayName,servicePrincipalType,publisherName,accountEnabled," +
		"oauth2PermissionScopes"
	apiURL := fmt.Sprintf("%s/v1.0/servicePrincipals?$select=%s&$top=%d",
		e.graphBaseURL, url.QueryEscape(fields), conf.pageSize)
	return fetchAllPages[entraServicePrincipal](ctx, e.httpClient, apiURL, token, conf.maxServicePrincipal)
}

// listGroups fetches all groups from Graph /v1.0/groups with pagination.
func (e *EntraID) listGroups(ctx context.Context, token string, conf *entraConfig) ([]entraGroup, error) {
	fields := "id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole," +
		"membershipRule,membershipRuleProcessingState"
	apiURL := fmt.Sprintf("%s/v1.0/groups?$select=%s&$top=%d",
		e.graphBaseURL, url.QueryEscape(fields), conf.pageSize)
	return fetchAllPages[entraGroup](ctx, e.httpClient, apiURL, token, conf.maxGroups)
}

// listDevices fetches all devices from Graph /v1.0/devices with pagination.
func (e *EntraID) listDevices(ctx context.Context, token string, conf *entraConfig) ([]entraDevice, error) {
	fields := "id,deviceId,displayName,operatingSystem,operatingSystemVersion," +
		"trustType,isCompliant,isManaged,approximateLastSignInDateTime,registrationDateTime"
	apiURL := fmt.Sprintf("%s/v1.0/devices?$select=%s&$top=%d",
		e.graphBaseURL, url.QueryEscape(fields), conf.pageSize)
	return fetchAllPages[entraDevice](ctx, e.httpClient, apiURL, token, conf.maxDevices)
}

// buildDeviceAssets converts discovered Entra devices to model.Asset records
// tagged with the entra.* attribute set declared in convert.go. Devices
// without a display name fall back to the device GUID so the natural-key
// computation has stable input.
func (e *EntraID) buildDeviceAssets(devices []entraDevice, conf *entraConfig) []model.Asset {
	now := e.now()
	assets := make([]model.Asset, 0, len(devices))
	for _, d := range devices {
		hostname := d.DisplayName
		if hostname == "" {
			hostname = d.DeviceID
		}
		if hostname == "" {
			continue
		}

		tags, _ := json.Marshal(deviceTags(d, conf.tenantID))

		asset := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			AssetType:       classifyEntraDevice(d.OperatingSystem),
			Hostname:        hostname,
			OSFamily:        normalizeOS(d.OperatingSystem),
			OSVersion:       d.OperatingSystemVersion,
			DiscoverySource: SourceName,
			TenantID:        conf.tenantID,
			FirstSeenAt:     now,
			LastSeenAt:      now,
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       managedStateFromEntraDevice(d),
			Tags:            string(tags),
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}
	return assets
}

// fetchAllPages walks @odata.nextLink pages until exhaustion or until the
// circuit-breaker (max objects) trips. Empty / missing pages are tolerated.
func fetchAllPages[T any](ctx context.Context, hc httpClient, apiURL, token string, maxObjects int) ([]T, error) {
	out := make([]T, 0, 64)
	current := apiURL
	for current != "" {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("graph list cancelled: %w", err)
		}
		page, next, err := fetchPage[T](ctx, hc, current, token)
		if err != nil {
			return out, err
		}
		out = append(out, page...)
		if maxObjects > 0 && len(out) >= maxObjects {
			slog.Warn("entra: max_objects circuit breaker tripped — truncating",
				"max_objects", maxObjects,
			)
			if len(out) > maxObjects {
				out = out[:maxObjects]
			}
			break
		}
		current = next
	}
	return out, nil
}

// fetchPage fetches a single Graph page and returns the parsed values plus
// the next-page URL (empty when no more pages).
func fetchPage[T any](ctx context.Context, hc httpClient, apiURL, token string) ([]T, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil) //#nosec G107 -- operator-configured Graph URL
	if err != nil {
		return nil, "", fmt.Errorf("creating graph request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("executing graph request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading graph response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("graph API returned %d: %s",
			resp.StatusCode, truncateBytes(body, 500))
	}

	var page struct {
		NextLink string `json:"@odata.nextLink"`
		Value    []T    `json:"value"`
	}
	if jErr := json.Unmarshal(body, &page); jErr != nil {
		return nil, "", fmt.Errorf("parsing graph response: %w", jErr)
	}
	return page.Value, page.NextLink, nil
}

// truncateBytes returns at most maxLen bytes of body as a string for safe
// inclusion in error messages without leaking large response payloads.
func truncateBytes(data []byte, maxLen int) string {
	if len(data) <= maxLen {
		return string(data)
	}
	return string(data[:maxLen]) + "…"
}

// ensure EntraID satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*EntraID)(nil)
