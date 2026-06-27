// dns_common.go: shared types for the cloud DNS zone discovery sources
// (Route53, Cloudflare, Azure DNS, GCP Cloud DNS) defined in RFC-0122.
//
// Each source.Snapshot() returns a *DNSSnapshot that the engine persists via
// store.UpsertCloudDNSSnapshot. The Python ontology bridge reads the SQLite
// tables created by migration 20260430000000_cloud_dns_discovery.sql to
// materialize CloudDNSZone and DNSRecord ontology entities.
package cloud

import "time"

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
