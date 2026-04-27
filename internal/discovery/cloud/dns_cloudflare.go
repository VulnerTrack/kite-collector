// dns_cloudflare.go: Cloudflare DNS zone enumeration source (RFC-0122 Phase 2).
// The source authenticates via a Bearer token (CF_API_TOKEN) and lists every
// zone the token can see plus its DNS records via the Cloudflare API v4.
// Results land on the in-memory DNSSnapshot so the engine can persist them
// via store.UpsertCloudDNSSnapshot. Discover returns no assets.
package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	defaultCloudflareBaseURL = "https://api.cloudflare.com/client/v4"
	cloudflareDefaultPerPage = 50
)

// CloudflareDNS implements discovery.Source for Cloudflare-managed DNS zones.
type CloudflareDNS struct {
	httpClient   httpDoer
	now          func() time.Time
	lastSnapshot *DNSSnapshot
	baseURL      string
	mu           sync.Mutex
}

// NewDNSCloudflare returns a Cloudflare DNS discovery source.
func NewDNSCloudflare() *CloudflareDNS {
	return &CloudflareDNS{
		baseURL:    defaultCloudflareBaseURL,
		httpClient: http.DefaultClient,
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the stable identifier for this source.
func (c *CloudflareDNS) Name() string { return DNSSourceNameCloudflare }

// Snapshot returns the most recent successful Discover() result.
func (c *CloudflareDNS) Snapshot() *DNSSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastSnapshot
}

// Discover enumerates every Cloudflare zone visible to the API token plus its
// DNS records. The result is captured on the source's snapshot for the engine
// to persist; the returned []model.Asset is always empty.
//
// Supported config keys:
//
//	enabled    – bool   (default: true)
//	account_id – string optional Cloudflare account scope filter
func (c *CloudflareDNS) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	if cfg != nil {
		if enabled, ok := cfg["enabled"].(bool); ok && !enabled {
			slog.Debug("cloud_dns_cloudflare: disabled by configuration")
			return nil, nil
		}
	}

	token := os.Getenv("CF_API_TOKEN")
	if token == "" {
		if cfg != nil {
			return nil, fmt.Errorf("cloud_dns_cloudflare: source enabled but CF_API_TOKEN not set")
		}
		slog.Warn("cloud_dns_cloudflare: CF_API_TOKEN not set, skipping discovery")
		return nil, nil
	}

	accountID := toString(cfg["account_id"])

	zones, err := c.listZones(ctx, token, accountID)
	if err != nil {
		return nil, fmt.Errorf("cloud_dns_cloudflare: %w", err)
	}

	now := c.now().UTC()
	snap := &DNSSnapshot{Provider: DNSProviderCloudflare}

	for _, z := range zones {
		if cErr := ctx.Err(); cErr != nil {
			return nil, fmt.Errorf("cloud_dns_cloudflare: cancelled: %w", cErr)
		}

		zoneUUID := uuid.Must(uuid.NewV7()).String()
		zoneName := normalizeZoneName(z.Name)

		records, rErr := c.listRecords(ctx, token, z.ID)
		if rErr != nil {
			slog.Error("cloud_dns_cloudflare: list records failed, partial zone data",
				"zone", z.ID,
				"error", rErr,
			)
			records = nil
		}
		recordCount := len(records)

		metadataBytes, _ := json.Marshal(map[string]any{
			"status":       z.Status,
			"plan":         z.Plan.Name,
			"name_servers": z.NameServers,
			"original_ns":  z.OriginalNameServers,
			"paused":       z.Paused,
			"type":         z.Type,
		})

		acctRef := z.Account.ID
		if acctRef == "" {
			acctRef = "cloudflare"
		}

		snap.Zones = append(snap.Zones, DNSZone{
			ID:             zoneUUID,
			Provider:       DNSProviderCloudflare,
			ProviderZoneID: z.ID,
			ZoneName:       zoneName,
			AccountRef:     "cloudflare:" + acctRef,
			IsPrivate:      false,
			RecordCount:    &recordCount,
			DNSSECEnabled:  false,
			FirstSeenAt:    now,
			LastSyncedAt:   now,
			RawMetadata:    string(metadataBytes),
		})

		for _, rec := range records {
			recType := strings.ToUpper(rec.Type)
			if !IsValidDNSRecordType(recType) {
				slog.Debug("cloud_dns_cloudflare: skipping unsupported record type",
					"zone", z.ID,
					"type", rec.Type,
				)
				continue
			}
			values := []string{rec.Content}
			valuesJSON, _ := json.Marshal(values)

			ttl := uint32(rec.TTL) //#nosec G115 -- Cloudflare TTL is bounded
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
				"cloud_dns.provider", DNSProviderCloudflare,
				"cloud_dns.zone_id", z.ID,
				"cloud_dns.zone_name", zoneName,
				"cloud_dns.record_name", normalizeZoneName(rec.Name),
				"cloud_dns.record_type", recType,
				"cloud_dns.ttl", ttl,
				"cloud_dns.values_json", string(valuesJSON),
			)
		}

		slog.Info("cloud_dns_zone_discovered",
			"cloud_dns.provider", DNSProviderCloudflare,
			"cloud_dns.zone_id", z.ID,
			"cloud_dns.zone_name", zoneName,
			"cloud_dns.account_ref", "cloudflare:"+acctRef,
			"cloud_dns.is_private", false,
			"cloud_dns.record_count", recordCount,
			"cloud_dns.dnssec_enabled", false,
		)
	}

	c.mu.Lock()
	c.lastSnapshot = snap
	c.mu.Unlock()

	slog.Info("cloud_dns_cloudflare: discovery complete",
		"zones", len(snap.Zones),
		"records", len(snap.Records),
	)
	return nil, nil
}

// listZones pages through GET /zones, returning every zone visible to the token.
func (c *CloudflareDNS) listZones(ctx context.Context, token, accountID string) ([]cloudflareZone, error) {
	var (
		all  []cloudflareZone
		page = 1
	)
	for {
		path := fmt.Sprintf("/zones?per_page=%d&page=%d", cloudflareDefaultPerPage, page)
		if accountID != "" {
			path += "&account.id=" + accountID
		}
		body, err := c.bearerGet(ctx, token, path)
		if err != nil {
			return nil, fmt.Errorf("zones list: %w", err)
		}
		var resp cloudflareZonesResponse
		if uErr := json.Unmarshal(body, &resp); uErr != nil {
			return nil, fmt.Errorf("zones parse: %w", uErr)
		}
		if !resp.Success {
			return nil, fmt.Errorf("zones api failure: %v", resp.Errors)
		}
		all = append(all, resp.Result...)
		if resp.ResultInfo.Page >= resp.ResultInfo.TotalPages || len(resp.Result) == 0 {
			break
		}
		page++
	}
	return all, nil
}

// listRecords pages through GET /zones/:id/dns_records.
func (c *CloudflareDNS) listRecords(ctx context.Context, token, zoneID string) ([]cloudflareRecord, error) {
	var (
		all  []cloudflareRecord
		page = 1
	)
	for {
		path := fmt.Sprintf("/zones/%s/dns_records?per_page=%d&page=%d",
			zoneID, cloudflareDefaultPerPage, page)
		body, err := c.bearerGet(ctx, token, path)
		if err != nil {
			return nil, fmt.Errorf("records list: %w", err)
		}
		var resp cloudflareRecordsResponse
		if uErr := json.Unmarshal(body, &resp); uErr != nil {
			return nil, fmt.Errorf("records parse: %w", uErr)
		}
		if !resp.Success {
			return nil, fmt.Errorf("records api failure: %v", resp.Errors)
		}
		all = append(all, resp.Result...)
		if resp.ResultInfo.Page >= resp.ResultInfo.TotalPages || len(resp.Result) == 0 {
			break
		}
		page++
	}
	return all, nil
}

// bearerGet executes a Cloudflare API call with the supplied Bearer token.
func (c *CloudflareDNS) bearerGet(ctx context.Context, token, path string) ([]byte, error) {
	endpoint := c.baseURL + path
	resp, err := doWithRetry(ctx, "cloud_dns_cloudflare", func() (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
		if reqErr != nil {
			return nil, fmt.Errorf("creating request: %w", reqErr)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		return c.httpClient.Do(req)
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
// Cloudflare API response structures
// ---------------------------------------------------------------------------

type cloudflareResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

type cloudflareAPIError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type cloudflareZonesResponse struct {
	Errors     []cloudflareAPIError `json:"errors"`
	Result     []cloudflareZone     `json:"result"`
	ResultInfo cloudflareResultInfo `json:"result_info"`
	Success    bool                 `json:"success"`
}

type cloudflareRecordsResponse struct {
	Errors     []cloudflareAPIError `json:"errors"`
	Result     []cloudflareRecord   `json:"result"`
	ResultInfo cloudflareResultInfo `json:"result_info"`
	Success    bool                 `json:"success"`
}

type cloudflareZone struct {
	Account             cloudflareZoneAccount `json:"account"`
	Plan                cloudflareZonePlan    `json:"plan"`
	ID                  string                `json:"id"`
	Name                string                `json:"name"`
	Status              string                `json:"status"`
	Type                string                `json:"type"`
	NameServers         []string              `json:"name_servers"`
	OriginalNameServers []string              `json:"original_name_servers"`
	Paused              bool                  `json:"paused"`
}

type cloudflareZoneAccount struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cloudflareZonePlan struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cloudflareRecord struct {
	ID      string `json:"id"`
	ZoneID  string `json:"zone_id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

// Compile-time assertion that CloudflareDNS satisfies discovery.Source.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*CloudflareDNS)(nil)
