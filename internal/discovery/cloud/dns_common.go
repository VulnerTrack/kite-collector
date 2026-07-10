// dns_common.go: shared types for the cloud DNS zone discovery sources
// (Route53, Cloudflare, Azure DNS, GCP Cloud DNS) defined in RFC-0122.
//
// Each source.Snapshot() returns a *DNSSnapshot that the engine persists via
// store.UpsertCloudDNSSnapshot. The Python ontology bridge reads the SQLite
// tables created by migration 20260430000000_cloud_dns_discovery.sql to
// materialize CloudDNSZone and DNSRecord ontology entities.
package cloud

import (
	"fmt"
	"time"

	"github.com/vulnertrack/kite-collector/internal/discovery/connectorkit"
)

// DNS provider identifiers — closed set enforced by the SQLite CHECK
// constraint on cloud_dns_zones.provider.
const (
	DNSProviderRoute53      = "route53"
	DNSProviderCloudflare   = "cloudflare"
	DNSProviderAzureDNS     = "azure_dns"
	DNSProviderGCPCloudDNS  = "gcp_cloud_dns"
	DNSSourceNameRoute53    = "cloud_dns_route53"
	DNSSourceNameCloudflare = "cloud_dns_cloudflare"
	DNSSourceNameAzure      = "cloud_dns_azure"
	DNSSourceNameGCP        = "cloud_dns_gcp"
)

// RFC-0137 hardening source names — the stable per-connector identifier used
// for pagination-guard attribution, SafeClient TLS env namespacing
// (KITE_<NAME>_INSECURE / KITE_<NAME>_CA_CERT), and the ConnectorSecurityProfile
// source_name. These match the ontology source_name enum in RFC-0137 §4.1.1,
// which differs from the discovery.Source Name() values ("cloud_dns_*").
const (
	HardeningSourceRoute53    = "route53"
	HardeningSourceCloudflare = "cloudflare_dns"
	HardeningSourceAzure      = "azure_dns"
	HardeningSourceGCP        = "gcp_cloud_dns"
)

// maxDNSResponseBytes bounds how many bytes are read from any single cloud DNS
// API response. It is a hard backstop against a hostile or misbehaving endpoint
// streaming an unbounded body before the pagination guard's byte cap can
// evaluate it (RFC-0137 F5).
const maxDNSResponseBytes int64 = 64 << 20 // 64 MiB

// dnsSafeClient returns the HTTP client a cloud DNS source should use. In
// production (baseURL == prodDefault, the hardcoded provider endpoint) it builds
// the client through connectorkit.SafeClient, adopting the shared 30s timeout,
// safenet TLS config, and KITE_<NAME>_INSECURE / KITE_<NAME>_CA_CERT escape
// hatches (RFC-0137 R5/R10). The hardcoded endpoint has no SSRF surface, but
// routing through SafeClient makes TLS handling consistent with every other
// connector. In tests (baseURL overridden to an httptest server) the
// already-injected client is returned unchanged so loopback http endpoints stay
// reachable — matching the baseURL-override convention the MDM connectors use.
func dnsSafeClient(sourceName, baseURL, prodDefault string, existing httpDoer) (httpDoer, error) {
	if baseURL != prodDefault {
		return existing, nil
	}
	client, _, err := connectorkit.SafeClient(sourceName, baseURL, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sourceName, err)
	}
	return client, nil
}

// AllowedDNSRecordTypes is the closed set enforced by the
// cloud_dns_records.record_type CHECK constraint. Sources MUST coerce or
// drop unknown record types before adding to a snapshot.
var AllowedDNSRecordTypes = map[string]struct{}{
	"A":     {},
	"AAAA":  {},
	"CNAME": {},
	"MX":    {},
	"TXT":   {},
	"NS":    {},
	"SOA":   {},
	"SRV":   {},
	"PTR":   {},
	"CAA":   {},
	"DS":    {},
}

// IsValidDNSRecordType reports whether t is in the closed record-type set.
func IsValidDNSRecordType(t string) bool {
	_, ok := AllowedDNSRecordTypes[t]
	return ok
}

// DNSZone is the per-zone snapshot produced by a discovery source. ID is the
// stable agent UUID v7 reused as the ClickHouse zone_id in the Python
// workspace; this lets zone ↔ record relationships survive across syncs even
// when provider-native IDs change format.
type DNSZone struct {
	FirstSeenAt    time.Time
	LastSyncedAt   time.Time
	RecordCount    *int
	ID             string
	Provider       string
	ProviderZoneID string
	ZoneName       string
	AccountRef     string
	RawMetadata    string
	IsPrivate      bool
	DNSSECEnabled  bool
}

// DNSRecord is a single resource record set discovered within a zone.
// ZoneID is the surrogate UUID of the parent DNSZone. ValuesJSON is a JSON
// array of record-data strings (e.g. `["93.184.216.34"]` for an A record).
type DNSRecord struct {
	FirstSeenAt   time.Time
	LastSyncedAt  time.Time
	DeletedAt     *time.Time
	ID            string
	ZoneID        string
	RecordName    string
	RecordType    string
	ValuesJSON    string
	RoutingPolicy string
	TTL           uint32
}

// DNSSnapshot is the in-memory result of the most recent Discover() call for
// a given cloud DNS source. The engine persists it once per scan via
// store.UpsertCloudDNSSnapshot, and the Python workflow reads the resulting
// SQLite rows to upsert ClickHouse cloud_dns_zones / cloud_dns_records.
type DNSSnapshot struct {
	Provider string
	Zones    []DNSZone
	Records  []DNSRecord
}
