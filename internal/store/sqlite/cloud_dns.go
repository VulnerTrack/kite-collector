// cloud_dns.go: SQLite persistence for cloud DNS zone discovery snapshots
// (RFC-0122 Phase 1). The Go agent calls UpsertCloudDNSSnapshot once per scan
// cycle, per provider, to materialize the in-memory cloud.DNSSnapshot into
// the cloud_dns_zones and cloud_dns_records tables created by migration
// 20260430000000_cloud_dns_discovery.sql. The Python ontology bridge then
// reads those tables read-only to upsert ClickHouse and the unified ontology.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	cloud "github.com/vulnertrack/kite-collector/internal/discovery/cloud"
)

// validDNSProviders mirrors the SQLite CHECK constraint on
// cloud_dns_zones.provider. Empty / unrecognized values are coerced to
// "route53" before insert so the constraint is always satisfied.
var validDNSProviders = map[string]struct{}{
	cloud.DNSProviderRoute53:     {},
	cloud.DNSProviderCloudflare:  {},
	cloud.DNSProviderAzureDNS:    {},
	cloud.DNSProviderGCPCloudDNS: {},
}

// UpsertCloudDNSSnapshot persists every zone and record in the supplied
// snapshot into the SQLite tables created by migration 20260430000000.
// The whole operation runs in a single transaction so a partial scan never
// leaves the store half-populated. Snapshots with empty Provider or nil
// receivers are silently skipped.
func (s *SQLiteStore) UpsertCloudDNSSnapshot(ctx context.Context, snap *cloud.DNSSnapshot) error {
	if snap == nil || snap.Provider == "" {
		return nil
	}
	if _, ok := validDNSProviders[snap.Provider]; !ok {
		return fmt.Errorf("cloud_dns upsert: invalid provider %q", snap.Provider)
	}
	if len(snap.Zones) == 0 && len(snap.Records) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cloud_dns upsert: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Unix()
	if err := upsertCloudDNSZones(ctx, tx, snap.Zones, now); err != nil {
		return err
	}
	if err := upsertCloudDNSRecords(ctx, tx, snap.Records, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cloud_dns upsert: commit: %w", err)
	}
	return nil
}

// upsertCloudDNSZones writes each DNSZone into cloud_dns_zones. The natural
// key is (provider, provider_zone_id); on conflict the existing surrogate id
// is preserved so foreign-key references in cloud_dns_records survive across
// scans.
func upsertCloudDNSZones(ctx context.Context, tx *sql.Tx, zones []cloud.DNSZone, now int64) error {
	if len(zones) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO cloud_dns_zones (
			id, provider, provider_zone_id, zone_name, account_ref,
			is_private, record_count, dnssec_enabled,
			first_seen_at, last_synced_at, raw_metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider, provider_zone_id) DO UPDATE SET
			zone_name      = excluded.zone_name,
			account_ref    = excluded.account_ref,
			is_private     = excluded.is_private,
			record_count   = excluded.record_count,
			dnssec_enabled = excluded.dnssec_enabled,
			last_synced_at = excluded.last_synced_at,
			raw_metadata   = excluded.raw_metadata
	`)
	if err != nil {
		return fmt.Errorf("cloud_dns upsert: prepare zones: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, z := range zones {
		firstSeen := z.FirstSeenAt.Unix()
		if z.FirstSeenAt.IsZero() {
			firstSeen = now
		}
		lastSynced := z.LastSyncedAt.Unix()
		if z.LastSyncedAt.IsZero() {
			lastSynced = now
		}
		metadata := z.RawMetadata
		if metadata == "" {
			metadata = "{}"
		}
		if _, eErr := stmt.ExecContext(ctx,
			z.ID,
			z.Provider,
			z.ProviderZoneID,
			z.ZoneName,
			z.AccountRef,
			boolToInt(z.IsPrivate),
			nullableInt(z.RecordCount),
			boolToInt(z.DNSSECEnabled),
			firstSeen,
			lastSynced,
			metadata,
		); eErr != nil {
			return fmt.Errorf("cloud_dns upsert: exec zone %s/%s: %w",
				z.Provider, z.ProviderZoneID, eErr)
		}
	}
	return nil
}

// upsertCloudDNSRecords writes each DNSRecord into cloud_dns_records. There
// is no natural key suitable for ON CONFLICT because (zone_id, record_name,
// record_type) can collide with multiple routing-policy records (Route53);
// rows are upserted on the surrogate primary key with INSERT OR REPLACE.
// The Python sync layer reconciles records via (zone_id, record_name,
// record_type) using ReplacingMergeTree on the ClickHouse side.
func upsertCloudDNSRecords(ctx context.Context, tx *sql.Tx, records []cloud.DNSRecord, now int64) error {
	if len(records) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR REPLACE INTO cloud_dns_records (
			id, zone_id, record_name, record_type,
			ttl, values_json, routing_policy,
			first_seen_at, last_synced_at, deleted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("cloud_dns upsert: prepare records: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, r := range records {
		if !cloud.IsValidDNSRecordType(r.RecordType) {
			return fmt.Errorf("cloud_dns upsert: record %s has invalid type %q",
				r.ID, r.RecordType)
		}
		firstSeen := r.FirstSeenAt.Unix()
		if r.FirstSeenAt.IsZero() {
			firstSeen = now
		}
		lastSynced := r.LastSyncedAt.Unix()
		if r.LastSyncedAt.IsZero() {
			lastSynced = now
		}
		ttl := r.TTL
		if ttl == 0 {
			ttl = 300
		}
		values := r.ValuesJSON
		if values == "" {
			values = "[]"
		}
		var routingPolicy sql.NullString
		if r.RoutingPolicy != "" {
			routingPolicy = sql.NullString{String: r.RoutingPolicy, Valid: true}
		}
		var deletedAt sql.NullInt64
		if r.DeletedAt != nil {
			deletedAt = sql.NullInt64{Int64: r.DeletedAt.Unix(), Valid: true}
		}
		if _, eErr := stmt.ExecContext(ctx,
			r.ID,
			r.ZoneID,
			r.RecordName,
			r.RecordType,
			ttl,
			values,
			routingPolicy,
			firstSeen,
			lastSynced,
			deletedAt,
		); eErr != nil {
			return fmt.Errorf("cloud_dns upsert: exec record %s: %w", r.ID, eErr)
		}
	}
	return nil
}
