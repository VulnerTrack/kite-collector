package model

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeDetails parses a Details JSON blob into a map for assertion.
func decodeDetails(t *testing.T, raw string) map[string]string {
	t.Helper()
	var out map[string]string
	require.NoError(t, json.Unmarshal([]byte(raw), &out),
		"BuildEventDetails must produce valid JSON")
	return out
}

func TestBuildEventDetails_IncludesEventTypeAndAssetID(t *testing.T) {
	a := Asset{ID: uuid.Must(uuid.NewV7())}

	got := BuildEventDetails(a, EventAssetDiscovered)
	parsed := decodeDetails(t, got)

	assert.Equal(t, string(EventAssetDiscovered), parsed["event_type"])
	assert.Equal(t, EventAssetDiscovered.Name(), parsed["event_name"])
	assert.Equal(t, "kite.asset.discovered", parsed["event_name"])
	assert.Equal(t, a.ID.String(), parsed["asset_id"])
}

func TestBuildEventDetails_OmitsEmptyOptionalFields(t *testing.T) {
	a := Asset{ID: uuid.Must(uuid.NewV7())}

	got := BuildEventDetails(a, EventAssetDiscovered)
	parsed := decodeDetails(t, got)

	for _, key := range []string{
		"hostname",
		"asset_type",
		"os_family",
		"environment",
		"owner",
		"criticality",
		"discovery_source",
		"is_authorized",
		"is_managed",
		"first_seen_at",
		"last_seen_at",
	} {
		_, present := parsed[key]
		assert.False(t, present, "expected key %q to be absent on a minimal asset", key)
	}
}

func TestBuildEventDetails_IncludesPopulatedOptionalFields(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a := Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "host-01",
		AssetType:       AssetTypeServer,
		OSFamily:        "linux",
		Environment:     "production",
		Owner:           "platform-team",
		Criticality:     "tier-1",
		DiscoverySource: "agent",
		IsAuthorized:    AuthorizationAuthorized,
		IsManaged:       ManagedManaged,
		FirstSeenAt:     now.Add(-48 * time.Hour),
		LastSeenAt:      now,
	}

	got := BuildEventDetails(a, EventAssetDiscovered)
	parsed := decodeDetails(t, got)

	assert.Equal(t, "host-01", parsed["hostname"])
	assert.Equal(t, string(AssetTypeServer), parsed["asset_type"])
	assert.Equal(t, "linux", parsed["os_family"])
	assert.Equal(t, "production", parsed["environment"])
	assert.Equal(t, "platform-team", parsed["owner"])
	assert.Equal(t, "tier-1", parsed["criticality"])
	assert.Equal(t, "agent", parsed["discovery_source"])
	assert.Equal(t, string(AuthorizationAuthorized), parsed["is_authorized"])
	assert.Equal(t, string(ManagedManaged), parsed["is_managed"])
	assert.Equal(t, a.FirstSeenAt.Format(time.RFC3339), parsed["first_seen_at"])
	assert.Equal(t, a.LastSeenAt.Format(time.RFC3339), parsed["last_seen_at"])
}

func TestBuildEventDetails_TimestampsRFC3339(t *testing.T) {
	first := time.Date(2025, 6, 1, 12, 30, 45, 0, time.UTC)
	last := time.Date(2025, 6, 5, 8, 15, 0, 0, time.UTC)
	a := Asset{
		ID:          uuid.Must(uuid.NewV7()),
		FirstSeenAt: first,
		LastSeenAt:  last,
	}

	parsed := decodeDetails(t, BuildEventDetails(a, EventAssetUpdated))

	parsedFirst, err := time.Parse(time.RFC3339, parsed["first_seen_at"])
	require.NoError(t, err, "first_seen_at must be RFC3339")
	parsedLast, err := time.Parse(time.RFC3339, parsed["last_seen_at"])
	require.NoError(t, err, "last_seen_at must be RFC3339")

	assert.True(t, first.Equal(parsedFirst), "first_seen_at must round-trip")
	assert.True(t, last.Equal(parsedLast), "last_seen_at must round-trip")
}

func TestBuildEventDetails_OmitsZeroTimestamps(t *testing.T) {
	a := Asset{ID: uuid.Must(uuid.NewV7())} // zero FirstSeenAt / LastSeenAt

	parsed := decodeDetails(t, BuildEventDetails(a, EventAssetNotSeen))

	_, hasFirst := parsed["first_seen_at"]
	_, hasLast := parsed["last_seen_at"]
	assert.False(t, hasFirst, "first_seen_at must be absent when zero")
	assert.False(t, hasLast, "last_seen_at must be absent when zero")
}

// TestEventType_Name_AllEventTypes pins the namespaced wire names returned by
// EventType.Name() for every known event type. These strings are part of the
// public OTLP schema (they appear on the wire as LogRecord.eventName and as
// the "event_name" attribute) so accidental drift here would be a backend
// breakage. The unknown-row asserts the documented fallback shape.
func TestEventType_Name_AllEventTypes(t *testing.T) {
	cases := []struct {
		eventType EventType
		want      string
	}{
		{EventAssetDiscovered, "kite.asset.discovered"},
		{EventAssetUpdated, "kite.asset.updated"},
		{EventAssetAnalyzed, "kite.asset.analyzed"},
		{EventUnauthorizedAssetDetected, "kite.asset.unauthorized_detected"},
		{EventUnmanagedAssetDetected, "kite.asset.unmanaged_detected"},
		{EventAssetNotSeen, "kite.asset.not_seen"},
		{EventAssetRemoved, "kite.asset.removed"},
		{EventType("FooBar"), "kite.asset.unknown.foobar"},
	}
	for _, tc := range cases {
		t.Run(string(tc.eventType), func(t *testing.T) {
			assert.Equal(t, tc.want, tc.eventType.Name())
		})
	}
}
