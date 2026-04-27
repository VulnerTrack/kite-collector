// dns_gcp.go: GCP Cloud DNS zone enumeration source (RFC-0122 Phase 2).
// Reuses gcp.go's obtainGCPToken to acquire an OAuth2 access token, then
// enumerates managedZones and resourceRecordSets via the Cloud DNS REST API
// (https://dns.googleapis.com/dns/v1). Results land on the in-memory
// DNSSnapshot so the engine can persist them via store.UpsertCloudDNSSnapshot.
// Discover never returns assets.
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
	defaultGCPCloudDNSBaseURL = "https://dns.googleapis.com/dns/v1"
)

// GCPDNS implements discovery.Source for GCP Cloud DNS managed zones.
type GCPDNS struct {
	httpClient   httpDoer
	now          func() time.Time
	lastSnapshot *DNSSnapshot
	baseURL      string
	mu           sync.Mutex
}

// NewDNSGCP returns a GCP Cloud DNS discovery source.
func NewDNSGCP() *GCPDNS {
	return &GCPDNS{
		baseURL:    defaultGCPCloudDNSBaseURL,
		httpClient: http.DefaultClient,
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the stable identifier for this source.
func (g *GCPDNS) Name() string { return DNSSourceNameGCP }

// Snapshot returns the most recent successful Discover() result.
func (g *GCPDNS) Snapshot() *DNSSnapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastSnapshot
}

// Discover enumerates every Cloud DNS managed zone and its resource record
// sets in the configured project. Discover never returns assets.
//
// Supported config keys:
//
//	enabled    – bool   (default: true)
//	project_id – string GCP project ID to enumerate zones from (required)
func (g *GCPDNS) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	if cfg != nil {
		if enabled, ok := cfg["enabled"].(bool); ok && !enabled {
			slog.Debug("cloud_dns_gcp: disabled by configuration")
			return nil, nil
		}
	}

	projectID := toString(cfg["project_id"])
	if projectID == "" {
		if cfg != nil {
			return nil, fmt.Errorf("cloud_dns_gcp: source enabled but project_id not specified in config")
		}
		slog.Warn("cloud_dns_gcp: project_id not specified, skipping discovery")
		return nil, nil
	}

	token, err := obtainGCPToken(ctx)
	if err != nil {
		if cfg != nil {
			return nil, fmt.Errorf("cloud_dns_gcp: source enabled but could not obtain access token: %w", err)
		}
		slog.Warn("cloud_dns_gcp: could not obtain access token, skipping discovery",
			"error", err,
		)
		return nil, nil
	}

	zones, err := g.listManagedZones(ctx, token, projectID)
	if err != nil {
		return nil, fmt.Errorf("cloud_dns_gcp: %w", err)
	}

	now := g.now().UTC()
	snap := &DNSSnapshot{Provider: DNSProviderGCPCloudDNS}

	for _, z := range zones {
		if cErr := ctx.Err(); cErr != nil {
			return nil, fmt.Errorf("cloud_dns_gcp: cancelled: %w", cErr)
		}

		zoneUUID := uuid.Must(uuid.NewV7()).String()
		zoneName := normalizeZoneName(z.DNSName)
		isPrivate := strings.EqualFold(z.Visibility, "private")
		dnssecEnabled := z.DNSSECConfig != nil &&
			strings.EqualFold(z.DNSSECConfig.State, "on")

		records, rErr := g.listResourceRecordSets(ctx, token, projectID, z.Name)
		if rErr != nil {
			slog.Error("cloud_dns_gcp: list record sets failed, partial zone data",
				"zone", z.Name,
				"error", rErr,
			)
			records = nil
		}
		recordCount := len(records)

		metadataBytes, _ := json.Marshal(map[string]any{
			"managed_zone_id": z.ID,
			"description":     z.Description,
			"name_servers":    z.NameServers,
			"visibility":      z.Visibility,
			"dnssec_state":    dnssecState(z.DNSSECConfig),
		})

		snap.Zones = append(snap.Zones, DNSZone{
			ID:             zoneUUID,
			Provider:       DNSProviderGCPCloudDNS,
			ProviderZoneID: z.Name,
			ZoneName:       zoneName,
			AccountRef:     "gcp:" + projectID,
			IsPrivate:      isPrivate,
			RecordCount:    &recordCount,
			DNSSECEnabled:  dnssecEnabled,
			FirstSeenAt:    now,
			LastSyncedAt:   now,
			RawMetadata:    string(metadataBytes),
		})

		for _, rec := range records {
			recType := strings.ToUpper(rec.Type)
			if !IsValidDNSRecordType(recType) {
				slog.Debug("cloud_dns_gcp: skipping unsupported record type",
					"zone", z.Name,
					"type", rec.Type,
				)
				continue
			}
			values := rec.RRDatas
			if values == nil {
				values = []string{}
			}
			valuesJSON, _ := json.Marshal(values)

			ttl := uint32(rec.TTL) //#nosec G115 -- Cloud DNS TTL is bounded
			if ttl == 0 {
				ttl = 300
			}

			snap.Records = append(snap.Records, DNSRecord{
				ID:           uuid.Must(uuid.NewV7()).String(),
				ZoneID:       zoneUUID,
				RecordName:   normalizeZoneName(rec.Name),
				RecordType:   recType,
				TTL:          ttl,
				ValuesJSON:   string(valuesJSON),
				FirstSeenAt:  now,
				LastSyncedAt: now,
			})

			slog.Info("cloud_dns_record_discovered",
				"cloud_dns.provider", DNSProviderGCPCloudDNS,
				"cloud_dns.zone_id", z.Name,
				"cloud_dns.zone_name", zoneName,
				"cloud_dns.record_name", normalizeZoneName(rec.Name),
				"cloud_dns.record_type", recType,
				"cloud_dns.ttl", ttl,
				"cloud_dns.values_json", string(valuesJSON),
			)
		}

		slog.Info("cloud_dns_zone_discovered",
			"cloud_dns.provider", DNSProviderGCPCloudDNS,
			"cloud_dns.zone_id", z.Name,
			"cloud_dns.zone_name", zoneName,
			"cloud_dns.account_ref", "gcp:"+projectID,
			"cloud_dns.is_private", isPrivate,
			"cloud_dns.record_count", recordCount,
			"cloud_dns.dnssec_enabled", dnssecEnabled,
		)
	}

	g.mu.Lock()
	g.lastSnapshot = snap
	g.mu.Unlock()

	slog.Info("cloud_dns_gcp: discovery complete",
		"zones", len(snap.Zones),
		"records", len(snap.Records),
		"project_id", projectID,
	)
	return nil, nil
}

// listManagedZones pages through GET /projects/{p}/managedZones.
func (g *GCPDNS) listManagedZones(ctx context.Context, token, projectID string) ([]gcpManagedZone, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/managedZones",
		g.baseURL, url.PathEscape(projectID))

	var all []gcpManagedZone
	for apiURL != "" {
		body, err := g.bearerGet(ctx, token, apiURL)
		if err != nil {
			return all, fmt.Errorf("managedZones list: %w", err)
		}
		var resp gcpManagedZonesResponse
		if uErr := json.Unmarshal(body, &resp); uErr != nil {
			return all, fmt.Errorf("managedZones parse: %w", uErr)
		}
		all = append(all, resp.ManagedZones...)
		apiURL = nextPageURL(apiURL, resp.NextPageToken)
	}
	return all, nil
}

// listResourceRecordSets pages through GET
// /projects/{p}/managedZones/{z}/rrsets.
func (g *GCPDNS) listResourceRecordSets(ctx context.Context, token, projectID, zoneName string) ([]gcpResourceRecordSet, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/managedZones/%s/rrsets",
		g.baseURL, url.PathEscape(projectID), url.PathEscape(zoneName))

	var all []gcpResourceRecordSet
	for apiURL != "" {
		body, err := g.bearerGet(ctx, token, apiURL)
		if err != nil {
			return all, fmt.Errorf("rrsets list: %w", err)
		}
		var resp gcpResourceRecordSetsResponse
		if uErr := json.Unmarshal(body, &resp); uErr != nil {
			return all, fmt.Errorf("rrsets parse: %w", uErr)
		}
		all = append(all, resp.RRSets...)
		apiURL = nextPageURL(apiURL, resp.NextPageToken)
	}
	return all, nil
}

// bearerGet executes a Cloud DNS API call with the supplied bearer token.
func (g *GCPDNS) bearerGet(ctx context.Context, token, apiURL string) ([]byte, error) {
	resp, err := doWithRetry(ctx, "cloud_dns_gcp", func() (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
		if reqErr != nil {
			return nil, fmt.Errorf("creating request: %w", reqErr)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		return g.httpClient.Do(req)
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

// nextPageURL returns the next page URL for Cloud DNS pagination, or empty
// string when there are no more pages.
func nextPageURL(currentURL, pageToken string) string {
	if pageToken == "" {
		return ""
	}
	u, err := url.Parse(currentURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("pageToken", pageToken)
	u.RawQuery = q.Encode()
	return u.String()
}

// dnssecState extracts the DNSSEC state string from a managedZone's config,
// returning empty string when DNSSEC is unconfigured.
func dnssecState(cfg *gcpDNSSECConfig) string {
	if cfg == nil {
		return ""
	}
	return cfg.State
}

// ---------------------------------------------------------------------------
// GCP Cloud DNS API response structures
// ---------------------------------------------------------------------------

type gcpManagedZonesResponse struct {
	NextPageToken string           `json:"nextPageToken"`
	ManagedZones  []gcpManagedZone `json:"managedZones"`
}

type gcpManagedZone struct {
	DNSSECConfig *gcpDNSSECConfig `json:"dnssecConfig,omitempty"`
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	DNSName      string           `json:"dnsName"`
	Description  string           `json:"description"`
	Visibility   string           `json:"visibility"`
	NameServers  []string         `json:"nameServers"`
}

type gcpDNSSECConfig struct {
	State        string `json:"state"`
	NonExistence string `json:"nonExistence"`
}

type gcpResourceRecordSetsResponse struct {
	NextPageToken string                 `json:"nextPageToken"`
	RRSets        []gcpResourceRecordSet `json:"rrsets"`
}

type gcpResourceRecordSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	RRDatas []string `json:"rrdatas"`
	TTL     int64    `json:"ttl"`
}

// Compile-time assertion that GCPDNS satisfies discovery.Source.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*GCPDNS)(nil)
