package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/connectorkit"
)

// newHardeningStore returns a fully-migrated store on a throwaway DB.
func newHardeningStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "hardening.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.Migrate(context.Background()))
	return s
}

func TestUpsertAndListConnectorSecurityProfiles(t *testing.T) {
	s := newHardeningStore(t)
	ctx := context.Background()

	entra := connectorkit.AssessConnectorWithTier("entra", true, true, true,
		connectorkit.TLSModeSystemCA, connectorkit.PrivilegeTierIdentityDirectoryAdmin)
	route53 := connectorkit.AssessConnectorWithTier("route53", true, true, false,
		connectorkit.TLSModeSystemCA, connectorkit.PrivilegeTierDNSZoneAdmin)

	require.NoError(t, s.UpsertConnectorSecurityProfile(ctx, entra))
	require.NoError(t, s.UpsertConnectorSecurityProfile(ctx, route53))

	profiles, err := s.ListConnectorSecurityProfiles(ctx)
	require.NoError(t, err)
	require.Len(t, profiles, 2)

	byName := make(map[string]connectorkit.SecurityProfile, len(profiles))
	for _, p := range profiles {
		byName[p.SourceName] = p
	}

	e := byName["entra"]
	assert.True(t, e.EndpointValidated)
	assert.True(t, e.PaginationGuarded)
	assert.True(t, e.CredentialsZeroed)
	assert.True(t, e.CircuitBreakerAttached)
	assert.Equal(t, connectorkit.TLSModeSystemCA, e.TLSMode)
	assert.Equal(t, connectorkit.PrivilegeTierIdentityDirectoryAdmin, e.CredentialPrivilegeTier)
	assert.InDelta(t, 1.0, e.HardeningScore, 0.0001)

	r := byName["route53"]
	assert.Equal(t, connectorkit.PrivilegeTierDNSZoneAdmin, r.CredentialPrivilegeTier)
	assert.False(t, r.CircuitBreakerAttached)
	assert.InDelta(t, 5.0/6.0, r.HardeningScore, 0.0001)
}

func TestUpsertConnectorSecurityProfile_DefaultsEmptyEnums(t *testing.T) {
	s := newHardeningStore(t)
	ctx := context.Background()

	// A zero-ish profile with empty tls_mode / tier must not violate the
	// tls_mode CHECK constraint; the store coerces empties to schema defaults.
	require.NoError(t, s.UpsertConnectorSecurityProfile(ctx, connectorkit.SecurityProfile{
		SourceName: "cloudflare_dns",
	}))

	profiles, err := s.ListConnectorSecurityProfiles(ctx)
	require.NoError(t, err)
	require.Len(t, profiles, 1)
	assert.Equal(t, connectorkit.TLSModeSystemCA, profiles[0].TLSMode)
	assert.Equal(t, connectorkit.PrivilegeTierUnknown, profiles[0].CredentialPrivilegeTier)
}

func TestInsertConnectorGuardEvent(t *testing.T) {
	s := newHardeningStore(t)
	ctx := context.Background()

	require.NoError(t, s.InsertConnectorGuardEvent(ctx, ConnectorGuardEvent{
		ID:             "cge:entra:pagination_byte_cap:1",
		SourceName:     "entra",
		GuardEventType: "pagination_byte_cap",
		BlockedValue:   "142MiB",
		ActionTaken:    "capped",
	}))

	var count int
	require.NoError(t, s.RawDB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM connector_guard_event WHERE source_name = ?`, "entra").Scan(&count))
	assert.Equal(t, 1, count)

	// An empty severity is defaulted to "medium".
	var severity string
	require.NoError(t, s.RawDB().QueryRowContext(ctx,
		`SELECT severity FROM connector_guard_event WHERE id = ?`,
		"cge:entra:pagination_byte_cap:1").Scan(&severity))
	assert.Equal(t, "medium", severity)
}
