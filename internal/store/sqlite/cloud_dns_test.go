package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cloud "github.com/vulnertrack/kite-collector/internal/discovery/cloud"
)

// makeFullDNSSnapshot builds a small but complete cloud.DNSSnapshot covering
// the cloud_dns_zones and cloud_dns_records tables. Values are deterministic
// so assertions can hard-code expectations.
func makeFullDNSSnapshot(t *testing.T) *cloud.DNSSnapshot {
	t.Helper()
	now := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	count := 4
	return &cloud.DNSSnapshot{
		Provider: cloud.DNSProviderRoute53,
		Zones: []cloud.DNSZone{
			{
				ID:             "11111111-1111-1111-1111-111111111111",
				Provider:       cloud.DNSProviderRoute53,
				ProviderZoneID: "Z1ABCDEFG",
				ZoneName:       "example.com.",
				AccountRef:     "aws:AKIA...",
				IsPrivate:      false,
				RecordCount:    &count,
				DNSSECEnabled:  false,
				FirstSeenAt:    now,
				LastSyncedAt:   now,
				RawMetadata:    `{"caller_reference":"abc"}`,
			},
		},
		Records: []cloud.DNSRecord{
			{
				ID:            "22222222-2222-2222-2222-222222222222",
				ZoneID:        "11111111-1111-1111-1111-111111111111",
				RecordName:    "example.com.",
				RecordType:    "A",
				TTL:           300,
				ValuesJSON:    `["192.0.2.1"]`,
				RoutingPolicy: "",
				FirstSeenAt:   now,
				LastSyncedAt:  now,
				DeletedAt:     nil,
			},
			{
				ID:           "33333333-3333-3333-3333-333333333333",
				ZoneID:       "11111111-1111-1111-1111-111111111111",
				RecordName:   "www.example.com.",
				RecordType:   "CNAME",
				TTL:          60,
				ValuesJSON:   `["example.com."]`,
				FirstSeenAt:  now,
				LastSyncedAt: now,
			},
		},
	}
}

func TestUpsertCloudDNSSnapshot_NilOrEmpty(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.UpsertCloudDNSSnapshot(ctx, nil))
	assert.Equal(t, 0, countRows(ctx, t, s, "cloud_dns_zones"))

	require.NoError(t, s.UpsertCloudDNSSnapshot(ctx, &cloud.DNSSnapshot{}))
	assert.Equal(t, 0, countRows(ctx, t, s, "cloud_dns_zones"))

	require.NoError(t, s.UpsertCloudDNSSnapshot(ctx, &cloud.DNSSnapshot{
		Provider: cloud.DNSProviderRoute53,
	}))
	assert.Equal(t, 0, countRows(ctx, t, s, "cloud_dns_zones"))
}

func TestUpsertCloudDNSSnapshot_InsertsBothTables(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	snap := makeFullDNSSnapshot(t)
	require.NoError(t, s.UpsertCloudDNSSnapshot(ctx, snap))

	assert.Equal(t, 1, countRows(ctx, t, s, "cloud_dns_zones"))
	assert.Equal(t, 2, countRows(ctx, t, s, "cloud_dns_records"))

	var (
		zoneName    string
		recordCount int
	)
	require.NoError(t, s.RawDB().QueryRowContext(ctx, `
		SELECT zone_name, record_count
		FROM cloud_dns_zones
		WHERE provider_zone_id = 'Z1ABCDEFG'
	`).Scan(&zoneName, &recordCount))
	assert.Equal(t, "example.com.", zoneName)
	assert.Equal(t, 4, recordCount)
}

func TestUpsertCloudDNSSnapshot_IdempotentOnNaturalKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	snap := makeFullDNSSnapshot(t)
	require.NoError(t, s.UpsertCloudDNSSnapshot(ctx, snap))

	var firstZoneID string
	require.NoError(t, s.RawDB().QueryRowContext(ctx,
		`SELECT id FROM cloud_dns_zones WHERE provider_zone_id = 'Z1ABCDEFG'`,
	).Scan(&firstZoneID))

	// Re-upsert with a different surrogate id but the same natural key —
	// the existing row's surrogate id must be preserved so FK references
	// from cloud_dns_records survive across scans.
	snap.Zones[0].ID = "99999999-9999-9999-9999-999999999999"
	snap.Zones[0].ZoneName = "example.com." // unchanged
	require.NoError(t, s.UpsertCloudDNSSnapshot(ctx, snap))

	assert.Equal(t, 1, countRows(ctx, t, s, "cloud_dns_zones"))

	var afterZoneID string
	require.NoError(t, s.RawDB().QueryRowContext(ctx,
		`SELECT id FROM cloud_dns_zones WHERE provider_zone_id = 'Z1ABCDEFG'`,
	).Scan(&afterZoneID))
	assert.Equal(t, firstZoneID, afterZoneID,
		"surrogate id must be preserved on conflict")
}

func TestUpsertCloudDNSSnapshot_RejectsInvalidProvider(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	err := s.UpsertCloudDNSSnapshot(ctx, &cloud.DNSSnapshot{
		Provider: "bogus",
		Zones:    []cloud.DNSZone{{ID: "x", ProviderZoneID: "z", ZoneName: "n"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid provider")
}

func TestUpsertCloudDNSSnapshot_RejectsInvalidRecordType(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	snap := makeFullDNSSnapshot(t)
	snap.Records[0].RecordType = "BOGUS"
	err := s.UpsertCloudDNSSnapshot(ctx, snap)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid type")
}

func TestUpsertCloudDNSSnapshot_DefaultsAppliedOnEmptyFields(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	snap := &cloud.DNSSnapshot{
		Provider: cloud.DNSProviderRoute53,
		Zones: []cloud.DNSZone{
			{
				ID:             "44444444-4444-4444-4444-444444444444",
				Provider:       cloud.DNSProviderRoute53,
				ProviderZoneID: "ZDEFAULT",
				ZoneName:       "defaults.test.",
				// FirstSeenAt / LastSyncedAt zero -> defaulted to now
				// RawMetadata empty -> defaulted to "{}"
			},
		},
		Records: []cloud.DNSRecord{
			{
				ID:         "55555555-5555-5555-5555-555555555555",
				ZoneID:     "44444444-4444-4444-4444-444444444444",
				RecordName: "defaults.test.",
				RecordType: "TXT",
				// TTL zero -> defaulted to 300
				// ValuesJSON empty -> defaulted to "[]"
			},
		},
	}
	require.NoError(t, s.UpsertCloudDNSSnapshot(ctx, snap))

	var (
		rawMetadata string
		ttl         uint32
		values      string
	)
	require.NoError(t, s.RawDB().QueryRowContext(ctx,
		`SELECT raw_metadata FROM cloud_dns_zones WHERE provider_zone_id = 'ZDEFAULT'`,
	).Scan(&rawMetadata))
	require.NoError(t, s.RawDB().QueryRowContext(ctx,
		`SELECT ttl, values_json FROM cloud_dns_records WHERE record_name = 'defaults.test.' AND record_type = 'TXT'`,
	).Scan(&ttl, &values))

	assert.Equal(t, "{}", rawMetadata)
	assert.Equal(t, uint32(300), ttl)
	assert.Equal(t, "[]", values)
}
