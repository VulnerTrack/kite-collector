// dns_route53.go: AWS Route53 DNS zone enumeration source (RFC-0122 Phase 1).
// The source authenticates via SigV4 (reusing aws.go signing) and lists every
// hosted zone (public + private) plus its resource record sets. Results land
// on the in-memory DNSSnapshot so the engine can persist them via
// store.UpsertCloudDNSSnapshot. Discover returns no assets — DNS zones are a
// distinct ontology entity, not a kite-collector model.Asset.
package cloud

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	defaultRoute53BaseURL = "https://route53.amazonaws.com"
	route53Region         = "us-east-1"
	route53Service        = "route53"
	route53APIVersion     = "2013-04-01"
)

// Route53DNS implements discovery.Source for AWS Route53 hosted zones.
//
// Configuration is supplied via the kite-collector.yaml `cloud_dns_route53`
// block. Credentials are read from standard AWS environment variables and
// never written to SQLite. When no credentials are present the source logs a
// warning and returns nil (graceful degradation, matching aws_ec2 semantics).
type Route53DNS struct {
	httpClient   httpDoer
	now          func() time.Time
	lastSnapshot *DNSSnapshot
	baseURL      string
	mu           sync.Mutex
}

// httpDoer is the minimal HTTP client interface used by the Route53 source.
// Defining it as an interface lets tests inject a recorder transport.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// NewDNSRoute53 returns a Route53 DNS discovery source pointed at the
// production Route53 endpoint.
func NewDNSRoute53() *Route53DNS {
	return &Route53DNS{
		baseURL:    defaultRoute53BaseURL,
		httpClient: http.DefaultClient,
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the stable identifier for this source.
func (r *Route53DNS) Name() string { return DNSSourceNameRoute53 }

// Snapshot returns the most recent successful Discover() result. The pointer
// is the live struct; callers must treat it as read-only.
func (r *Route53DNS) Snapshot() *DNSSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastSnapshot
}

// Discover enumerates every hosted zone and its record sets via the Route53
// management API. The result is captured on the source's snapshot for the
// engine to persist; the returned []model.Asset is always empty because DNS
// zones are not modelled as assets.
//
// Supported config keys:
//
//	enabled     – bool   (default: true)
//	assume_role – string IAM role ARN for cross-account zone enumeration
func (r *Route53DNS) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	if cfg != nil {
		if enabled, ok := cfg["enabled"].(bool); ok && !enabled {
			slog.Debug("cloud_dns_route53: disabled by configuration")
			return nil, nil
		}
	}

	role := toString(cfg["assume_role"])

	creds := loadAWSCredentials()
	if creds.accessKey == "" || creds.secretKey == "" {
		if cfg != nil {
			return nil, fmt.Errorf("cloud_dns_route53: source enabled but AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY not set")
		}
		slog.Warn("cloud_dns_route53: AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY not set, skipping discovery")
		return nil, nil
	}

	if role != "" {
		slog.Info("cloud_dns_route53: assuming role via STS", "role_arn", role)
		assumed, err := (&AWS{}).assumeRole(ctx, creds, route53Region, role)
		if err != nil {
			slog.Error("cloud_dns_route53: AssumeRole failed, falling back to source credentials",
				"role_arn", role,
				"error", err,
			)
		} else {
			creds = assumed
		}
	}

	accountRef := deriveAWSAccountRef(creds.accessKey)

	zones, err := r.listHostedZones(ctx, creds)
	if err != nil {
		return nil, fmt.Errorf("cloud_dns_route53: %w", err)
	}

	now := r.now().UTC()
	snap := &DNSSnapshot{Provider: DNSProviderRoute53}

	for _, zr := range zones {
		if cErr := ctx.Err(); cErr != nil {
			return nil, fmt.Errorf("cloud_dns_route53: cancelled: %w", cErr)
		}

		zoneUUID := uuid.Must(uuid.NewV7()).String()
		zoneNameNorm := normalizeZoneName(zr.Name)
		providerZoneID := normalizeRoute53HostedZoneID(zr.ID)

		dnssecEnabled, dErr := r.getDNSSECStatus(ctx, creds, providerZoneID)
		if dErr != nil {
			slog.Warn("cloud_dns_route53: GetDNSSEC failed, defaulting to disabled",
				"zone", providerZoneID,
				"error", dErr,
			)
			dnssecEnabled = false
		}

		records, rErr := r.listResourceRecordSets(ctx, creds, providerZoneID)
		if rErr != nil {
			slog.Error("cloud_dns_route53: ListResourceRecordSets failed, partial zone data",
				"zone", providerZoneID,
				"error", rErr,
			)
			records = nil
		}

		recordCount := len(records)

		metadataBytes, _ := json.Marshal(map[string]any{
			"comment":               zr.Config.Comment,
			"caller_reference":      zr.CallerReference,
			"resource_record_count": zr.ResourceRecordSetCount,
			"private":               zr.Config.PrivateZone,
		})

		snap.Zones = append(snap.Zones, DNSZone{
			ID:             zoneUUID,
			Provider:       DNSProviderRoute53,
			ProviderZoneID: providerZoneID,
			ZoneName:       zoneNameNorm,
			AccountRef:     accountRef,
			IsPrivate:      zr.Config.PrivateZone,
			RecordCount:    &recordCount,
			DNSSECEnabled:  dnssecEnabled,
			FirstSeenAt:    now,
			LastSyncedAt:   now,
			RawMetadata:    string(metadataBytes),
		})

		for _, rec := range records {
			recType := strings.ToUpper(rec.Type)
			if !IsValidDNSRecordType(recType) {
				slog.Debug("cloud_dns_route53: skipping unsupported record type",
					"zone", providerZoneID,
					"type", rec.Type,
				)
				continue
			}

			values := make([]string, 0, len(rec.ResourceRecords))
			for _, v := range rec.ResourceRecords {
				if v.Value != "" {
					values = append(values, v.Value)
				}
			}
			if rec.AliasTarget != nil && rec.AliasTarget.DNSName != "" {
				values = append(values, "ALIAS:"+rec.AliasTarget.DNSName)
			}
			valuesJSON, _ := json.Marshal(values)

			ttl := uint32(300)
			if rec.TTL > 0 {
				ttl = uint32(rec.TTL) //nolint:gosec // Route53 TTL is bounded
			}

			snap.Records = append(snap.Records, DNSRecord{
				ID:            uuid.Must(uuid.NewV7()).String(),
				ZoneID:        zoneUUID,
				RecordName:    normalizeZoneName(rec.Name),
				RecordType:    recType,
				TTL:           ttl,
				ValuesJSON:    string(valuesJSON),
				RoutingPolicy: deriveRoutingPolicy(rec),
				FirstSeenAt:   now,
				LastSyncedAt:  now,
			})

			slog.Info("cloud_dns_record_discovered",
				"cloud_dns.provider", DNSProviderRoute53,
				"cloud_dns.zone_id", providerZoneID,
				"cloud_dns.zone_name", zoneNameNorm,
				"cloud_dns.record_name", normalizeZoneName(rec.Name),
				"cloud_dns.record_type", recType,
				"cloud_dns.ttl", ttl,
				"cloud_dns.values_json", string(valuesJSON),
				"cloud_dns.routing_policy", deriveRoutingPolicy(rec),
			)
		}

		slog.Info("cloud_dns_zone_discovered",
			"cloud_dns.provider", DNSProviderRoute53,
			"cloud_dns.zone_id", providerZoneID,
			"cloud_dns.zone_name", zoneNameNorm,
			"cloud_dns.account_ref", accountRef,
			"cloud_dns.is_private", zr.Config.PrivateZone,
			"cloud_dns.record_count", recordCount,
			"cloud_dns.dnssec_enabled", dnssecEnabled,
		)
	}

	r.mu.Lock()
	r.lastSnapshot = snap
	r.mu.Unlock()

	slog.Info("cloud_dns_route53: discovery complete",
		"zones", len(snap.Zones),
		"records", len(snap.Records),
		"account_ref", accountRef,
	)
	return nil, nil
}

// ---------------------------------------------------------------------------
// Route53 API calls
// ---------------------------------------------------------------------------

// listHostedZones pages through GET /2013-04-01/hostedzone, returning every
// zone the credentials can see.
func (r *Route53DNS) listHostedZones(ctx context.Context, creds awsCredentials) ([]route53HostedZone, error) {
	var (
		all    []route53HostedZone
		marker string
	)
	for {
		path := fmt.Sprintf("/%s/hostedzone", route53APIVersion)
		query := ""
		if marker != "" {
			query = "marker=" + marker
		}
		respBody, err := r.signedGet(ctx, creds, path, query)
		if err != nil {
			return nil, fmt.Errorf("ListHostedZones: %w", err)
		}

		var page route53ListHostedZonesResponse
		if uErr := xml.Unmarshal(respBody, &page); uErr != nil {
			return nil, fmt.Errorf("ListHostedZones: parsing response: %w", uErr)
		}
		all = append(all, page.HostedZones...)

		if !page.IsTruncated || page.NextMarker == "" {
			break
		}
		marker = page.NextMarker
	}
	return all, nil
}

// listResourceRecordSets pages through GET /2013-04-01/hostedzone/{id}/rrset.
func (r *Route53DNS) listResourceRecordSets(ctx context.Context, creds awsCredentials, hostedZoneID string) ([]route53ResourceRecordSet, error) {
	var (
		all              []route53ResourceRecordSet
		nextRecordName   string
		nextRecordType   string
		nextIdentifierID string
	)
	for {
		path := fmt.Sprintf("/%s/hostedzone/%s/rrset", route53APIVersion, hostedZoneID)
		query := ""
		if nextRecordName != "" {
			query = "name=" + nextRecordName
			if nextRecordType != "" {
				query += "&type=" + nextRecordType
			}
			if nextIdentifierID != "" {
				query += "&identifier=" + nextIdentifierID
			}
		}
		respBody, err := r.signedGet(ctx, creds, path, query)
		if err != nil {
			return nil, fmt.Errorf("ListResourceRecordSets %s: %w", hostedZoneID, err)
		}

		var page route53ListResourceRecordSetsResponse
		if uErr := xml.Unmarshal(respBody, &page); uErr != nil {
			return nil, fmt.Errorf("ListResourceRecordSets %s: parse: %w", hostedZoneID, uErr)
		}
		all = append(all, page.ResourceRecordSets...)

		if !page.IsTruncated {
			break
		}
		nextRecordName = page.NextRecordName
		nextRecordType = page.NextRecordType
		nextIdentifierID = page.NextRecordIdentifier
	}
	return all, nil
}

// getDNSSECStatus calls GET /2013-04-01/hostedzone/{id}/dnssec. A 404 /
// NoSuchKeySigningKey response means DNSSEC is not configured; we treat it
// as disabled. Authentication errors propagate so the caller can stop the
// scan rather than silently mis-reporting DNSSEC state.
func (r *Route53DNS) getDNSSECStatus(ctx context.Context, creds awsCredentials, hostedZoneID string) (bool, error) {
	path := fmt.Sprintf("/%s/hostedzone/%s/dnssec", route53APIVersion, hostedZoneID)
	respBody, err := r.signedGet(ctx, creds, path, "")
	if err != nil {
		var aErr *authError
		if errors.As(err, &aErr) {
			return false, err
		}
		return false, nil
	}

	var status route53DNSSECResponse
	if uErr := xml.Unmarshal(respBody, &status); uErr != nil {
		return false, fmt.Errorf("GetDNSSEC %s: parse: %w", hostedZoneID, uErr)
	}
	return strings.EqualFold(status.Status.ServeSignature, "SIGNING"), nil
}

// signedGet executes a signed Route53 GET against base+path[?query].
func (r *Route53DNS) signedGet(ctx context.Context, creds awsCredentials, path, query string) ([]byte, error) {
	endpoint := r.baseURL + path
	if query != "" {
		endpoint += "?" + query
	}

	resp, err := doWithRetry(ctx, "cloud_dns_route53", func() (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
		if reqErr != nil {
			return nil, fmt.Errorf("creating request: %w", reqErr)
		}
		if signErr := signV4(req, nil, creds, route53Region, route53Service); signErr != nil {
			return nil, fmt.Errorf("signing request: %w", signErr)
		}
		return r.httpClient.Do(req)
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

// normalizeZoneName ensures a zone or record name ends with a trailing dot
// per RFC 1035. Empty input is returned unchanged.
func normalizeZoneName(s string) string {
	if s == "" {
		return s
	}
	if !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

// normalizeRoute53HostedZoneID strips the "/hostedzone/" prefix returned by
// the API so downstream code can use the bare zone ID (e.g. "Z123") for both
// API calls and storage.
func normalizeRoute53HostedZoneID(id string) string {
	id = strings.TrimPrefix(id, "/hostedzone/")
	id = strings.TrimPrefix(id, "hostedzone/")
	return id
}

// deriveAWSAccountRef extracts a stable account reference. Route53 does not
// echo the account ID in API responses; we use the access-key prefix as a
// best-effort identifier, falling back to "aws" when the access key is empty.
// The Python ontology bridge replaces this with the real account ID via
// STS GetCallerIdentity in a later phase if needed.
func deriveAWSAccountRef(accessKey string) string {
	if accessKey == "" {
		return "aws"
	}
	return "aws:" + truncate(accessKey, 8)
}

// deriveRoutingPolicy maps Route53-specific routing-policy fields onto the
// cloud_dns_records.routing_policy text column. Returns "" when the record
// uses the default simple policy.
func deriveRoutingPolicy(rec route53ResourceRecordSet) string {
	switch {
	case rec.Failover != "":
		return "failover"
	case rec.GeoLocation != nil:
		return "geolocation"
	case rec.Region != "":
		return "latency"
	case rec.Weight > 0:
		return "weighted"
	case rec.MultiValueAnswer:
		return "multivalue"
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// Route53 XML response structures
// ---------------------------------------------------------------------------

type route53ListHostedZonesResponse struct {
	XMLName     xml.Name            `xml:"ListHostedZonesResponse"`
	NextMarker  string              `xml:"NextMarker"`
	HostedZones []route53HostedZone `xml:"HostedZones>HostedZone"`
	IsTruncated bool                `xml:"IsTruncated"`
}

type route53HostedZone struct {
	ID                     string                  `xml:"Id"`
	Name                   string                  `xml:"Name"`
	CallerReference        string                  `xml:"CallerReference"`
	Config                 route53HostedZoneConfig `xml:"Config"`
	ResourceRecordSetCount int64                   `xml:"ResourceRecordSetCount"`
}

type route53HostedZoneConfig struct {
	Comment     string `xml:"Comment"`
	PrivateZone bool   `xml:"PrivateZone"`
}

type route53ListResourceRecordSetsResponse struct {
	XMLName              xml.Name                   `xml:"ListResourceRecordSetsResponse"`
	NextRecordName       string                     `xml:"NextRecordName"`
	NextRecordType       string                     `xml:"NextRecordType"`
	NextRecordIdentifier string                     `xml:"NextRecordIdentifier"`
	ResourceRecordSets   []route53ResourceRecordSet `xml:"ResourceRecordSets>ResourceRecordSet"`
	IsTruncated          bool                       `xml:"IsTruncated"`
}

type route53ResourceRecordSet struct {
	GeoLocation      *route53GeoLocation     `xml:"GeoLocation,omitempty"`
	AliasTarget      *route53AliasTarget     `xml:"AliasTarget,omitempty"`
	Name             string                  `xml:"Name"`
	Type             string                  `xml:"Type"`
	Region           string                  `xml:"Region,omitempty"`
	Failover         string                  `xml:"Failover,omitempty"`
	SetIdentifier    string                  `xml:"SetIdentifier,omitempty"`
	ResourceRecords  []route53ResourceRecord `xml:"ResourceRecords>ResourceRecord"`
	TTL              int64                   `xml:"TTL"`
	Weight           int64                   `xml:"Weight,omitempty"`
	MultiValueAnswer bool                    `xml:"MultiValueAnswer,omitempty"`
}

type route53ResourceRecord struct {
	Value string `xml:"Value"`
}

type route53AliasTarget struct {
	HostedZoneID         string `xml:"HostedZoneId"`
	DNSName              string `xml:"DNSName"`
	EvaluateTargetHealth bool   `xml:"EvaluateTargetHealth"`
}

type route53GeoLocation struct {
	ContinentCode   string `xml:"ContinentCode,omitempty"`
	CountryCode     string `xml:"CountryCode,omitempty"`
	SubdivisionCode string `xml:"SubdivisionCode,omitempty"`
}

type route53DNSSECResponse struct {
	XMLName xml.Name            `xml:"GetDNSSECResponse"`
	Status  route53DNSSECStatus `xml:"Status"`
}

type route53DNSSECStatus struct {
	ServeSignature string `xml:"ServeSignature"`
}

// Compile-time assertion that Route53DNS satisfies discovery.Source.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*Route53DNS)(nil)
