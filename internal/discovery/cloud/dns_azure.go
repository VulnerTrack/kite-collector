// dns_azure.go: Azure DNS zone enumeration source (RFC-0122 Phase 2).
// Reuses azure.go's loadAzureCredentials and acquireToken to authenticate via
// OAuth2 client credentials, then enumerates dnsZones and recordSets across
// the configured subscriptions through the Azure ARM REST API.
package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	defaultAzureARMBaseURL = "https://management.azure.com"
	azureDNSAPIVersion     = "2018-05-01"
)

// AzureDNS implements discovery.Source for Azure DNS zones (public + private).
type AzureDNS struct {
	httpClient   httpDoer
	now          func() time.Time
	lastSnapshot *DNSSnapshot
	baseURL      string
	mu           sync.Mutex
}

// NewDNSAzure returns an Azure DNS discovery source.
func NewDNSAzure() *AzureDNS {
	return &AzureDNS{
		baseURL:    defaultAzureARMBaseURL,
		httpClient: http.DefaultClient,
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the stable identifier for this source.
func (a *AzureDNS) Name() string { return DNSSourceNameAzure }

// Snapshot returns the most recent successful Discover() result.
func (a *AzureDNS) Snapshot() *DNSSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastSnapshot
}

// Discover enumerates every Azure DNS zone in the configured subscriptions
// (or every accessible subscription if none configured) along with its
// recordSets. Discover never returns assets.
//
// Supported config keys:
//
//	enabled         – bool   (default: true)
//	subscription_id – string optional override of AZURE_SUBSCRIPTION_ID
func (a *AzureDNS) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	if cfg != nil {
		if enabled, ok := cfg["enabled"].(bool); ok && !enabled {
			slog.Debug("cloud_dns_azure: disabled by configuration")
			return nil, nil
		}
	}

	creds := loadAzureCredentials()
	subscriptionID := toString(cfg["subscription_id"])
	if subscriptionID == "" {
		subscriptionID = creds.subscriptionID
	}
	if creds.tenantID == "" || creds.clientID == "" || creds.clientSecret == "" {
		if cfg != nil {
			return nil, fmt.Errorf("cloud_dns_azure: source enabled but AZURE_TENANT_ID, AZURE_CLIENT_ID, or AZURE_CLIENT_SECRET not set")
		}
		slog.Warn("cloud_dns_azure: Azure credentials not set, skipping discovery")
		return nil, nil
	}

	token, err := (&Azure{}).acquireToken(ctx, creds)
	if err != nil {
		return nil, fmt.Errorf("cloud_dns_azure: token: %w", err)
	}

	var subscriptionIDs []string
	if subscriptionID != "" {
		subscriptionIDs = []string{subscriptionID}
	} else {
		ids, lErr := (&Azure{}).listSubscriptions(ctx, token)
		if lErr != nil {
			return nil, fmt.Errorf("cloud_dns_azure: list subscriptions: %w", lErr)
		}
		subscriptionIDs = ids
	}

	now := a.now().UTC()
	snap := &DNSSnapshot{Provider: DNSProviderAzureDNS}

	for _, subID := range subscriptionIDs {
		if cErr := ctx.Err(); cErr != nil {
			return nil, fmt.Errorf("cloud_dns_azure: cancelled: %w", cErr)
		}

		zones, zErr := a.listZones(ctx, token, subID)
		if zErr != nil {
			slog.Error("cloud_dns_azure: list zones failed",
				"subscription_id", subID,
				"error", zErr,
			)
			continue
		}

		for _, z := range zones {
			zoneUUID := uuid.Must(uuid.NewV7()).String()
			zoneName := normalizeZoneName(z.Name)
			isPrivate := strings.EqualFold(z.Type, "Microsoft.Network/privateDnsZones")

			records, rErr := a.listRecordSets(ctx, token, z.ID, isPrivate)
			if rErr != nil {
				slog.Error("cloud_dns_azure: list record sets failed, partial zone data",
					"zone", z.ID,
					"error", rErr,
				)
				records = nil
			}
			recordCount := len(records)

			metadataBytes, _ := json.Marshal(map[string]any{
				"resource_id":           z.ID,
				"resource_group":        extractResourceGroup(z.ID),
				"location":              z.Location,
				"type":                  z.Type,
				"number_of_records":     z.Properties.NumberOfRecordSets,
				"max_number_of_records": z.Properties.MaxNumberOfRecordSets,
			})

			snap.Zones = append(snap.Zones, DNSZone{
				ID:             zoneUUID,
				Provider:       DNSProviderAzureDNS,
				ProviderZoneID: z.ID,
				ZoneName:       zoneName,
				AccountRef:     "azure:" + subID,
				IsPrivate:      isPrivate,
				RecordCount:    &recordCount,
				DNSSECEnabled:  false,
				FirstSeenAt:    now,
				LastSyncedAt:   now,
				RawMetadata:    string(metadataBytes),
			})

			for _, rec := range records {
				recType := strings.ToUpper(extractAzureRecordType(rec.Type))
				if !IsValidDNSRecordType(recType) {
					slog.Debug("cloud_dns_azure: skipping unsupported record type",
						"zone", z.ID,
						"type", rec.Type,
					)
					continue
				}
				values := extractAzureRecordValues(recType, rec.Properties)
				valuesJSON, _ := json.Marshal(values)

				ttl := uint32(rec.Properties.TTL) //#nosec G115 -- Azure TTL is bounded
				if ttl == 0 {
					ttl = 300
				}

				snap.Records = append(snap.Records, DNSRecord{
					ID:           uuid.Must(uuid.NewV7()).String(),
					ZoneID:       zoneUUID,
					RecordName:   normalizeZoneName(rec.Name + "." + strings.TrimSuffix(z.Name, ".")),
					RecordType:   recType,
					TTL:          ttl,
					ValuesJSON:   string(valuesJSON),
					FirstSeenAt:  now,
					LastSyncedAt: now,
				})

				slog.Info("cloud_dns_record_discovered",
					"cloud_dns.provider", DNSProviderAzureDNS,
					"cloud_dns.zone_id", z.ID,
					"cloud_dns.zone_name", zoneName,
					"cloud_dns.record_name", rec.Name,
					"cloud_dns.record_type", recType,
					"cloud_dns.ttl", ttl,
					"cloud_dns.values_json", string(valuesJSON),
				)
			}

			slog.Info("cloud_dns_zone_discovered",
				"cloud_dns.provider", DNSProviderAzureDNS,
				"cloud_dns.zone_id", z.ID,
				"cloud_dns.zone_name", zoneName,
				"cloud_dns.account_ref", "azure:"+subID,
				"cloud_dns.is_private", isPrivate,
				"cloud_dns.record_count", recordCount,
				"cloud_dns.dnssec_enabled", false,
			)
		}
	}

	a.mu.Lock()
	a.lastSnapshot = snap
	a.mu.Unlock()

	slog.Info("cloud_dns_azure: discovery complete",
		"zones", len(snap.Zones),
		"records", len(snap.Records),
		"subscriptions", len(subscriptionIDs),
	)
	return nil, nil
}

// listZones enumerates all public + private DNS zones in a subscription. Two
// ARM endpoints (one per zone type) are queried and their results merged.
func (a *AzureDNS) listZones(ctx context.Context, token, subscriptionID string) ([]azureDNSZone, error) {
	var all []azureDNSZone
	for _, kind := range []string{"dnsZones", "privateDnsZones"} {
		apiVersion := azureDNSAPIVersion
		if kind == "privateDnsZones" {
			apiVersion = "2020-06-01"
		}
		apiURL := fmt.Sprintf(
			"%s/subscriptions/%s/providers/Microsoft.Network/%s?api-version=%s",
			a.baseURL,
			url.PathEscape(subscriptionID),
			kind,
			apiVersion,
		)
		zones, err := a.fetchAllPages(ctx, token, apiURL)
		if err != nil {
			return all, fmt.Errorf("listZones %s: %w", kind, err)
		}
		all = append(all, zones...)
	}
	return all, nil
}

// listRecordSets enumerates every record set in a single zone. zoneID is the
// full ARM resource ID returned by listZones.
func (a *AzureDNS) listRecordSets(ctx context.Context, token, zoneID string, isPrivate bool) ([]azureDNSRecordSet, error) {
	apiVersion := azureDNSAPIVersion
	if isPrivate {
		apiVersion = "2020-06-01"
	}
	apiURL := fmt.Sprintf("%s%s/recordsets?api-version=%s", a.baseURL, zoneID, apiVersion)

	var all []azureDNSRecordSet
	for apiURL != "" {
		body, err := a.bearerGet(ctx, token, apiURL)
		if err != nil {
			return all, err
		}
		var resp azureDNSRecordSetsResponse
		if uErr := json.Unmarshal(body, &resp); uErr != nil {
			return all, fmt.Errorf("recordsets parse: %w", uErr)
		}
		all = append(all, resp.Value...)
		apiURL = resp.NextLink
	}
	return all, nil
}

// fetchAllPages drives the ARM nextLink pagination protocol for zone listing.
func (a *AzureDNS) fetchAllPages(ctx context.Context, token, apiURL string) ([]azureDNSZone, error) {
	var all []azureDNSZone
	for apiURL != "" {
		body, err := a.bearerGet(ctx, token, apiURL)
		if err != nil {
			return all, err
		}
		var resp azureDNSZonesResponse
		if uErr := json.Unmarshal(body, &resp); uErr != nil {
			return all, fmt.Errorf("zones parse: %w", uErr)
		}
		all = append(all, resp.Value...)
		apiURL = resp.NextLink
	}
	return all, nil
}

// bearerGet executes a GET against an ARM URL with the supplied bearer token.
func (a *AzureDNS) bearerGet(ctx context.Context, token, apiURL string) ([]byte, error) {
	resp, err := doWithRetry(ctx, "cloud_dns_azure", func() (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
		if reqErr != nil {
			return nil, fmt.Errorf("creating request: %w", reqErr)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		return a.httpClient.Do(req)
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	return body, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// extractResourceGroup pulls the resource group out of an Azure resource ID.
// Returns empty string when the ID does not contain a resourceGroups segment.
func extractResourceGroup(resourceID string) string {
	const marker = "/resourceGroups/"
	idx := strings.Index(resourceID, marker)
	if idx == -1 {
		return ""
	}
	rest := resourceID[idx+len(marker):]
	end := strings.Index(rest, "/")
	if end == -1 {
		return rest
	}
	return rest[:end]
}

// extractAzureRecordType strips the "Microsoft.Network/dnsZones/" prefix from
// a record set type, returning just the bare DNS record type ("A", "CNAME", ...).
func extractAzureRecordType(typeStr string) string {
	if idx := strings.LastIndex(typeStr, "/"); idx >= 0 {
		return typeStr[idx+1:]
	}
	return typeStr
}

// extractAzureRecordValues maps the Azure record-type-specific JSON shape onto
// a flat list of strings suitable for ValuesJSON.
func extractAzureRecordValues(recType string, props azureDNSRecordSetProperties) []string {
	switch recType {
	case "A":
		out := make([]string, 0, len(props.ARecords))
		for _, r := range props.ARecords {
			out = append(out, r.IPv4Address)
		}
		return out
	case "AAAA":
		out := make([]string, 0, len(props.AAAARecords))
		for _, r := range props.AAAARecords {
			out = append(out, r.IPv6Address)
		}
		return out
	case "CNAME":
		if props.CNAMERecord.CNAME != "" {
			return []string{props.CNAMERecord.CNAME}
		}
	case "MX":
		out := make([]string, 0, len(props.MXRecords))
		for _, r := range props.MXRecords {
			out = append(out, fmt.Sprintf("%d %s", r.Preference, r.Exchange))
		}
		return out
	case "TXT":
		out := make([]string, 0, len(props.TXTRecords))
		for _, r := range props.TXTRecords {
			out = append(out, strings.Join(r.Value, ""))
		}
		return out
	case "NS":
		out := make([]string, 0, len(props.NSRecords))
		for _, r := range props.NSRecords {
			out = append(out, r.NSDName)
		}
		return out
	case "SOA":
		if props.SOARecord.Email != "" {
			return []string{fmt.Sprintf("%s %s %d %d %d %d %d",
				props.SOARecord.Host, props.SOARecord.Email,
				props.SOARecord.SerialNumber, props.SOARecord.RefreshTime,
				props.SOARecord.RetryTime, props.SOARecord.ExpireTime,
				props.SOARecord.MinimumTTL)}
		}
	case "SRV":
		out := make([]string, 0, len(props.SRVRecords))
		for _, r := range props.SRVRecords {
			out = append(out, fmt.Sprintf("%d %d %d %s",
				r.Priority, r.Weight, r.Port, r.Target))
		}
		return out
	case "PTR":
		out := make([]string, 0, len(props.PTRRecords))
		for _, r := range props.PTRRecords {
			out = append(out, r.PTRDName)
		}
		return out
	case "CAA":
		out := make([]string, 0, len(props.CAARecords))
		for _, r := range props.CAARecords {
			out = append(out, fmt.Sprintf("%d %s %s", r.Flags, r.Tag, r.Value))
		}
		return out
	}
	return []string{}
}

// ---------------------------------------------------------------------------
// Azure DNS API response structures
// ---------------------------------------------------------------------------

type azureDNSZonesResponse struct {
	NextLink string         `json:"nextLink"`
	Value    []azureDNSZone `json:"value"`
}

type azureDNSZone struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Location   string                 `json:"location"`
	Properties azureDNSZoneProperties `json:"properties"`
}

type azureDNSZoneProperties struct {
	NumberOfRecordSets    int64 `json:"numberOfRecordSets"`
	MaxNumberOfRecordSets int64 `json:"maxNumberOfRecordSets"`
}

type azureDNSRecordSetsResponse struct {
	NextLink string              `json:"nextLink"`
	Value    []azureDNSRecordSet `json:"value"`
}

type azureDNSRecordSet struct {
	ID         string                      `json:"id"`
	Name       string                      `json:"name"`
	Type       string                      `json:"type"`
	Properties azureDNSRecordSetProperties `json:"properties"`
}

type azureDNSRecordSetProperties struct {
	CNAMERecord azureDNSCNAMERecord  `json:"CNAMERecord"`
	ARecords    []azureDNSARecord    `json:"ARecords"`
	AAAARecords []azureDNSAAAARecord `json:"AAAARecords"`
	MXRecords   []azureDNSMXRecord   `json:"MXRecords"`
	TXTRecords  []azureDNSTXTRecord  `json:"TXTRecords"`
	NSRecords   []azureDNSNSRecord   `json:"NSRecords"`
	SRVRecords  []azureDNSSRVRecord  `json:"SRVRecords"`
	PTRRecords  []azureDNSPTRRecord  `json:"PTRRecords"`
	CAARecords  []azureDNSCAARecord  `json:"CAARecords"`
	SOARecord   azureDNSSOARecord    `json:"SOARecord"`
	TTL         int64                `json:"TTL"`
}

type azureDNSARecord struct {
	IPv4Address string `json:"ipv4Address"`
}

type azureDNSAAAARecord struct {
	IPv6Address string `json:"ipv6Address"`
}

type azureDNSCNAMERecord struct {
	CNAME string `json:"cname"`
}

type azureDNSMXRecord struct {
	Exchange   string `json:"exchange"`
	Preference int    `json:"preference"`
}

type azureDNSTXTRecord struct {
	Value []string `json:"value"`
}

type azureDNSNSRecord struct {
	NSDName string `json:"nsdname"`
}

type azureDNSSOARecord struct {
	Host         string `json:"host"`
	Email        string `json:"email"`
	SerialNumber int64  `json:"serialNumber"`
	RefreshTime  int64  `json:"refreshTime"`
	RetryTime    int64  `json:"retryTime"`
	ExpireTime   int64  `json:"expireTime"`
	MinimumTTL   int64  `json:"minimumTtl"`
}

type azureDNSSRVRecord struct {
	Target   string `json:"target"`
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
	Port     int    `json:"port"`
}

type azureDNSPTRRecord struct {
	PTRDName string `json:"ptrdname"`
}

type azureDNSCAARecord struct {
	Tag   string `json:"tag"`
	Value string `json:"value"`
	Flags int    `json:"flags"`
}

// Compile-time assertion that AzureDNS satisfies discovery.Source.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*AzureDNS)(nil)
