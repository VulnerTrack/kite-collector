package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// MachineType.Valid()
// ---------------------------------------------------------------------------

func TestMachineType_Valid(t *testing.T) {
	valid := []MachineType{
		MachineTypeServer,
		MachineTypeWorkstation,
		MachineTypeNetworkDevice,
		MachineTypeCloudInstance,
		MachineTypeContainer,
		MachineTypeVirtualMachine,
		MachineTypeIOTDevice,
		MachineTypeAppliance,
	}
	for _, at := range valid {
		assert.True(t, at.Valid(), "expected %q to be valid", at)
	}

	invalid := []MachineType{"", "desktop", "phone", "UNKNOWN", "SERVER"}
	for _, at := range invalid {
		assert.False(t, at.Valid(), "expected %q to be invalid", at)
	}
}

// ---------------------------------------------------------------------------
// Machine.ComputeNaturalKey()
// ---------------------------------------------------------------------------

func TestComputeNaturalKey_Deterministic(t *testing.T) {
	a := Machine{Hostname: "web-01", MachineType: MachineTypeServer}
	a.ComputeNaturalKey()
	key1 := a.NaturalKey

	b := Machine{Hostname: "web-01", MachineType: MachineTypeServer}
	b.ComputeNaturalKey()
	key2 := b.NaturalKey

	require.NotEmpty(t, key1)
	assert.Equal(t, key1, key2, "same hostname+type must produce the same key")
}

func TestComputeNaturalKey_DifferentForDifferentInput(t *testing.T) {
	a := Machine{Hostname: "web-01", MachineType: MachineTypeServer}
	a.ComputeNaturalKey()

	b := Machine{Hostname: "web-02", MachineType: MachineTypeServer}
	b.ComputeNaturalKey()

	c := Machine{Hostname: "web-01", MachineType: MachineTypeWorkstation}
	c.ComputeNaturalKey()

	assert.NotEqual(t, a.NaturalKey, b.NaturalKey, "different hostname must produce different key")
	assert.NotEqual(t, a.NaturalKey, c.NaturalKey, "different machine_type must produce different key")
}

func TestComputeNaturalKey_StableOnRepeatedCall(t *testing.T) {
	a := Machine{Hostname: "db-01", MachineType: MachineTypeAppliance}
	a.ComputeNaturalKey()
	first := a.NaturalKey

	a.ComputeNaturalKey()
	assert.Equal(t, first, a.NaturalKey, "repeated call must not change the key")
}

func TestComputeNaturalKey_SHA256Hex(t *testing.T) {
	a := Machine{Hostname: "host", MachineType: MachineTypeContainer}
	a.ComputeNaturalKey()

	// SHA-256 hex digest is always 64 hex chars
	assert.Len(t, a.NaturalKey, 64)
}

// ---------------------------------------------------------------------------
// Tenant-scoped natural key (RFC-0063)
// ---------------------------------------------------------------------------

func TestComputeNaturalKey_TenantScoped(t *testing.T) {
	// Same hostname+type but different tenants must produce different keys.
	a := Machine{Hostname: "web-01", MachineType: MachineTypeServer, TenantID: "tenant-alpha"}
	a.ComputeNaturalKey()

	b := Machine{Hostname: "web-01", MachineType: MachineTypeServer, TenantID: "tenant-beta"}
	b.ComputeNaturalKey()

	assert.NotEqual(t, a.NaturalKey, b.NaturalKey,
		"same hostname+type in different tenants must produce different keys")
}

func TestComputeNaturalKey_TenantEmpty_BackwardsCompatible(t *testing.T) {
	// An machine without TenantID must produce the same key as before RFC-0063.
	withTenant := Machine{Hostname: "web-01", MachineType: MachineTypeServer, TenantID: ""}
	withTenant.ComputeNaturalKey()

	withoutTenant := Machine{Hostname: "web-01", MachineType: MachineTypeServer}
	withoutTenant.ComputeNaturalKey()

	assert.Equal(t, withoutTenant.NaturalKey, withTenant.NaturalKey,
		"empty TenantID must produce the same key as no TenantID (backwards compat)")
}

func TestComputeNaturalKey_TenantScoped_Deterministic(t *testing.T) {
	a := Machine{Hostname: "db-01", MachineType: MachineTypeServer, TenantID: "tenant-x"}
	a.ComputeNaturalKey()
	key1 := a.NaturalKey

	b := Machine{Hostname: "db-01", MachineType: MachineTypeServer, TenantID: "tenant-x"}
	b.ComputeNaturalKey()

	assert.Equal(t, key1, b.NaturalKey, "same inputs must produce the same key")
}
