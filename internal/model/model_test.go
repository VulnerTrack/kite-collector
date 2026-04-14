package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// AssetType.Valid()
// ---------------------------------------------------------------------------

func TestAssetType_Valid(t *testing.T) {
	valid := []AssetType{
		AssetTypeServer,
		AssetTypeWorkstation,
		AssetTypeNetworkDevice,
		AssetTypeCloudInstance,
		AssetTypeContainer,
		AssetTypeVirtualMachine,
		AssetTypeIOTDevice,
		AssetTypeAppliance,
	}
	for _, at := range valid {
		assert.True(t, at.Valid(), "expected %q to be valid", at)
	}

	invalid := []AssetType{"", "desktop", "phone", "UNKNOWN", "SERVER"}
	for _, at := range invalid {
		assert.False(t, at.Valid(), "expected %q to be invalid", at)
	}
}

// ---------------------------------------------------------------------------
// Asset.ComputeNaturalKey()
// ---------------------------------------------------------------------------

func TestComputeNaturalKey_Deterministic(t *testing.T) {
	a := Asset{Hostname: "web-01", AssetType: AssetTypeServer}
	a.ComputeNaturalKey()
	key1 := a.NaturalKey

	b := Asset{Hostname: "web-01", AssetType: AssetTypeServer}
	b.ComputeNaturalKey()
	key2 := b.NaturalKey

	require.NotEmpty(t, key1)
	assert.Equal(t, key1, key2, "same hostname+type must produce the same key")
}

func TestComputeNaturalKey_DifferentForDifferentInput(t *testing.T) {
	a := Asset{Hostname: "web-01", AssetType: AssetTypeServer}
	a.ComputeNaturalKey()

	b := Asset{Hostname: "web-02", AssetType: AssetTypeServer}
	b.ComputeNaturalKey()

	c := Asset{Hostname: "web-01", AssetType: AssetTypeWorkstation}
	c.ComputeNaturalKey()

	assert.NotEqual(t, a.NaturalKey, b.NaturalKey, "different hostname must produce different key")
	assert.NotEqual(t, a.NaturalKey, c.NaturalKey, "different asset_type must produce different key")
}

func TestComputeNaturalKey_StableOnRepeatedCall(t *testing.T) {
	a := Asset{Hostname: "db-01", AssetType: AssetTypeAppliance}
	a.ComputeNaturalKey()
	first := a.NaturalKey

	a.ComputeNaturalKey()
	assert.Equal(t, first, a.NaturalKey, "repeated call must not change the key")
}

func TestComputeNaturalKey_SHA256Hex(t *testing.T) {
	a := Asset{Hostname: "host", AssetType: AssetTypeContainer}
	a.ComputeNaturalKey()

	// SHA-256 hex digest is always 64 hex chars
	assert.Len(t, a.NaturalKey, 64)
}

// ---------------------------------------------------------------------------
// Tenant-scoped natural key (RFC-0063)
// ---------------------------------------------------------------------------

func TestComputeNaturalKey_TenantScoped(t *testing.T) {
	// Same hostname+type but different tenants must produce different keys.
	a := Asset{Hostname: "web-01", AssetType: AssetTypeServer, TenantID: "tenant-alpha"}
	a.ComputeNaturalKey()

	b := Asset{Hostname: "web-01", AssetType: AssetTypeServer, TenantID: "tenant-beta"}
	b.ComputeNaturalKey()

	assert.NotEqual(t, a.NaturalKey, b.NaturalKey,
		"same hostname+type in different tenants must produce different keys")
}

func TestComputeNaturalKey_TenantEmpty_BackwardsCompatible(t *testing.T) {
	// An asset without TenantID must produce the same key as before RFC-0063.
	withTenant := Asset{Hostname: "web-01", AssetType: AssetTypeServer, TenantID: ""}
	withTenant.ComputeNaturalKey()

	withoutTenant := Asset{Hostname: "web-01", AssetType: AssetTypeServer}
	withoutTenant.ComputeNaturalKey()

	assert.Equal(t, withoutTenant.NaturalKey, withTenant.NaturalKey,
		"empty TenantID must produce the same key as no TenantID (backwards compat)")
}

func TestComputeNaturalKey_TenantScoped_Deterministic(t *testing.T) {
	a := Asset{Hostname: "db-01", AssetType: AssetTypeServer, TenantID: "tenant-x"}
	a.ComputeNaturalKey()
	key1 := a.NaturalKey

	b := Asset{Hostname: "db-01", AssetType: AssetTypeServer, TenantID: "tenant-x"}
	b.ComputeNaturalKey()

	assert.Equal(t, key1, b.NaturalKey, "same inputs must produce the same key")
}
