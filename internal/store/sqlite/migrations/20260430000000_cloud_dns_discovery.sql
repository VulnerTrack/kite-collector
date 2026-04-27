-- 20260430000000_cloud_dns_discovery.sql: tables for the cloud DNS zone
-- enumeration source (RFC-0122). Additive-only: two new tables that store
-- DNS zones and resource records discovered via authenticated cloud
-- management APIs (Route53, Cloudflare, Azure DNS, GCP Cloud DNS).
-- No existing tables are modified.

CREATE TABLE IF NOT EXISTS cloud_dns_zones (
    id               TEXT PRIMARY KEY NOT NULL,
    provider         TEXT NOT NULL
                         CHECK(provider IN ('route53','cloudflare','azure_dns','gcp_cloud_dns')),
    provider_zone_id TEXT NOT NULL,
    zone_name        TEXT NOT NULL,
    account_ref      TEXT NOT NULL,
    is_private       INTEGER NOT NULL DEFAULT 0,
    record_count     INTEGER,
    dnssec_enabled   INTEGER NOT NULL DEFAULT 0,
    first_seen_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    last_synced_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    raw_metadata     TEXT NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_dns_zones_provider_id
    ON cloud_dns_zones(provider, provider_zone_id);

CREATE INDEX IF NOT EXISTS idx_cloud_dns_zones_name
    ON cloud_dns_zones(zone_name);

CREATE TABLE IF NOT EXISTS cloud_dns_records (
    id              TEXT PRIMARY KEY NOT NULL,
    zone_id         TEXT NOT NULL REFERENCES cloud_dns_zones(id) ON DELETE CASCADE,
    record_name     TEXT NOT NULL,
    record_type     TEXT NOT NULL
                        CHECK(record_type IN
                            ('A','AAAA','CNAME','MX','TXT','NS','SOA','SRV','PTR','CAA','DS')),
    ttl             INTEGER NOT NULL DEFAULT 300,
    values_json     TEXT NOT NULL DEFAULT '[]',
    routing_policy  TEXT,
    first_seen_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    last_synced_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    deleted_at      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_cloud_dns_records_zone
    ON cloud_dns_records(zone_id);

CREATE INDEX IF NOT EXISTS idx_cloud_dns_records_type
    ON cloud_dns_records(record_type);

CREATE INDEX IF NOT EXISTS idx_cloud_dns_records_name
    ON cloud_dns_records(record_name);

CREATE INDEX IF NOT EXISTS idx_cloud_dns_records_staleness
    ON cloud_dns_records(last_synced_at) WHERE deleted_at IS NULL;
