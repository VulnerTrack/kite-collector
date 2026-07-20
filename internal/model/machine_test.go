package model

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// baseMachine returns a fully-populated material machine used as the seed for
// fingerprint comparison cases below. Tests mutate copies of this base.
func baseMachine() Machine {
	return Machine{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "web-01.example.com",
		MachineType:     MachineTypeServer,
		OSFamily:        "linux",
		OSVersion:       "ubuntu-22.04",
		KernelVersion:   "5.15.0-101-generic",
		Architecture:    "amd64",
		Environment:     "production",
		Owner:           "platform-team",
		Criticality:     "high",
		DiscoverySource: "agent",
		TenantID:        "tenant-a",
		Tags:            `{"role":"web"}`,
		IsAuthorized:    AuthorizationAuthorized,
		IsManaged:       ManagedManaged,
		FirstSeenAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSeenAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// TestMaterialFingerprint_StableAcrossEqualMachines ensures the helper is
// deterministic: the same material content yields the same digest across
// invocations on equal machine values.
func TestMaterialFingerprint_StableAcrossEqualMachines(t *testing.T) {
	a := baseMachine()
	b := baseMachine()
	// Force differing identity / timestamps so we know the fingerprint
	// excludes them.
	b.ID = uuid.Must(uuid.NewV7())
	b.FirstSeenAt = a.FirstSeenAt.Add(48 * time.Hour)
	b.LastSeenAt = a.LastSeenAt.Add(72 * time.Hour)

	assert.Equal(t, a.MaterialFingerprint(), b.MaterialFingerprint(),
		"two machines with equal material fields must have equal fingerprints")
}

// TestMaterialFingerprint_ChangesWhenHostnameChanges asserts that mutating a
// material field (hostname) flips the digest. Sanity check that the helper is
// not constant.
func TestMaterialFingerprint_ChangesWhenHostnameChanges(t *testing.T) {
	a := baseMachine()
	b := baseMachine()
	b.Hostname = "web-02.example.com"

	assert.NotEqual(t, a.MaterialFingerprint(), b.MaterialFingerprint(),
		"changing hostname must change the fingerprint")
}

// TestMaterialFingerprint_StableWhenOnlyTimestampsChange is the property the
// classifier depends on: scan ticks that update only first_seen_at /
// last_seen_at MUST yield an identical fingerprint so the engine can classify
// the event as MachineAnalyzed instead of MachineUpdated.
func TestMaterialFingerprint_StableWhenOnlyTimestampsChange(t *testing.T) {
	a := baseMachine()
	b := baseMachine()
	b.FirstSeenAt = time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	b.LastSeenAt = time.Date(2026, 4, 22, 17, 30, 0, 0, time.UTC)

	assert.Equal(t, a.MaterialFingerprint(), b.MaterialFingerprint(),
		"timestamps moving alone must NOT change the fingerprint")
}

// TestMaterialFingerprint_StableAcrossEqualMachinesWithDifferentIDs guards
// against a regression where ID accidentally creeps into the digest. ID is
// identity, not content, and must never affect the fingerprint.
func TestMaterialFingerprint_StableAcrossEqualMachinesWithDifferentIDs(t *testing.T) {
	a := baseMachine()
	b := baseMachine()
	b.ID = uuid.Must(uuid.NewV7())

	assert.Equal(t, a.MaterialFingerprint(), b.MaterialFingerprint(),
		"differing IDs must NOT change the fingerprint")
}

// TestMaterialFingerprint_ChangesWhenMaterialFieldsChange is a table-driven
// pin for every other material field beyond hostname so a future field
// reorder or accidental omission gets caught.
func TestMaterialFingerprint_ChangesWhenMaterialFieldsChange(t *testing.T) {
	cases := []struct {
		mutate func(*Machine)
		name   string
	}{
		{name: "OSVersion", mutate: func(a *Machine) { a.OSVersion = "ubuntu-24.04" }},
		{name: "OSFamily", mutate: func(a *Machine) { a.OSFamily = "darwin" }},
		{name: "KernelVersion", mutate: func(a *Machine) { a.KernelVersion = "6.0.0-1-generic" }},
		{name: "Architecture", mutate: func(a *Machine) { a.Architecture = "arm64" }},
		{name: "Environment", mutate: func(a *Machine) { a.Environment = "staging" }},
		{name: "Owner", mutate: func(a *Machine) { a.Owner = "security-team" }},
		{name: "Criticality", mutate: func(a *Machine) { a.Criticality = "low" }},
		{name: "DiscoverySource", mutate: func(a *Machine) { a.DiscoverySource = "intune" }},
		{name: "TenantID", mutate: func(a *Machine) { a.TenantID = "tenant-b" }},
		{name: "Tags", mutate: func(a *Machine) { a.Tags = `{"role":"db"}` }},
		{name: "IsAuthorized", mutate: func(a *Machine) { a.IsAuthorized = AuthorizationUnauthorized }},
		{name: "IsManaged", mutate: func(a *Machine) { a.IsManaged = ManagedUnmanaged }},
		{name: "MachineType", mutate: func(a *Machine) { a.MachineType = MachineTypeWorkstation }},
	}
	base := baseMachine()
	baseFP := base.MaterialFingerprint()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := baseMachine()
			tc.mutate(&a)
			assert.NotEqual(t, baseFP, a.MaterialFingerprint(),
				"changing %s must change the fingerprint", tc.name)
		})
	}
}
