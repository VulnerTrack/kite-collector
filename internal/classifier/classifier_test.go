package classifier

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// ---------------------------------------------------------------------------
// Authorizer
// ---------------------------------------------------------------------------

func TestAuthorizer_NoEntries_ReturnsUnknown(t *testing.T) {
	auth, err := NewAuthorizer("", []string{"hostname"})
	require.NoError(t, err)

	machine := model.Machine{Hostname: "anything"}
	assert.Equal(t, model.AuthorizationUnknown, auth.Authorize(machine))
}

func TestAuthorizer_MatchingHostname_ReturnsAuthorized(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "web-01"}},
		matchFields: []string{"hostname"},
	}

	machine := model.Machine{Hostname: "web-01"}
	assert.Equal(t, model.AuthorizationAuthorized, auth.Authorize(machine))
}

func TestAuthorizer_NonMatchingHostname_ReturnsUnauthorized(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "web-01"}},
		matchFields: []string{"hostname"},
	}

	machine := model.Machine{Hostname: "rogue-box"}
	assert.Equal(t, model.AuthorizationUnauthorized, auth.Authorize(machine))
}

func TestAuthorizer_GlobPattern(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "server-*"}},
		matchFields: []string{"hostname"},
	}

	assert.Equal(t, model.AuthorizationAuthorized,
		auth.Authorize(model.Machine{Hostname: "server-01"}))
	assert.Equal(t, model.AuthorizationAuthorized,
		auth.Authorize(model.Machine{Hostname: "server-99"}))
	assert.Equal(t, model.AuthorizationUnauthorized,
		auth.Authorize(model.Machine{Hostname: "desktop-01"}))
}

func TestAuthorizer_CaseInsensitiveHostname(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "Web-01"}},
		matchFields: []string{"hostname"},
	}

	assert.Equal(t, model.AuthorizationAuthorized,
		auth.Authorize(model.Machine{Hostname: "web-01"}))
}

func TestAuthorizer_NoMatchFields_ReturnsUnauthorized(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "web-01"}},
		matchFields: nil,
	}

	// With entries but no match fields, entryMatches returns false for all
	assert.Equal(t, model.AuthorizationUnauthorized,
		auth.Authorize(model.Machine{Hostname: "web-01"}))
}

func TestAuthorizer_NonexistentFile_ReturnsUnknown(t *testing.T) {
	auth, err := NewAuthorizer("/tmp/nonexistent-kite-test-file.yaml", []string{"hostname"})
	require.NoError(t, err)

	// File not found results in zero entries, so "unknown"
	assert.Equal(t, model.AuthorizationUnknown,
		auth.Authorize(model.Machine{Hostname: "web-01"}))
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

func TestManager_EmptyControls_ReturnsUnknown(t *testing.T) {
	mgr := NewManager(nil)

	machine := model.Machine{Hostname: "host-01"}
	assert.Equal(t, model.ManagedUnknown, mgr.Evaluate(machine))
}

func TestManager_WithControls_ReturnsUnmanaged(t *testing.T) {
	mgr := NewManager([]string{"edr_agent", "config_mgmt"})

	machine := model.Machine{Hostname: "host-01"}
	assert.Equal(t, model.ManagedUnmanaged, mgr.Evaluate(machine))
}

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

func TestClassifier_ClassifyAll(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "known-*"}},
		matchFields: []string{"hostname"},
	}
	mgr := NewManager([]string{"edr"})
	cls := New(auth, mgr)

	machines := []model.Machine{
		{Hostname: "known-01", MachineType: model.MachineTypeServer},
		{Hostname: "rogue-01", MachineType: model.MachineTypeWorkstation},
	}

	result := cls.ClassifyAll(machines)
	require.Len(t, result, 2)

	assert.Equal(t, model.AuthorizationAuthorized, result[0].IsAuthorized)
	assert.Equal(t, model.ManagedUnmanaged, result[0].IsManaged)

	assert.Equal(t, model.AuthorizationUnauthorized, result[1].IsAuthorized)
	assert.Equal(t, model.ManagedUnmanaged, result[1].IsManaged)
}

func TestClassifier_ClassifySingle(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "web-01"}},
		matchFields: []string{"hostname"},
	}
	mgr := NewManager(nil)
	cls := New(auth, mgr)

	machine := model.Machine{Hostname: "web-01"}
	cls.Classify(&machine)

	assert.Equal(t, model.AuthorizationAuthorized, machine.IsAuthorized)
	assert.Equal(t, model.ManagedUnknown, machine.IsManaged)
}

// ---------------------------------------------------------------------------
// Manager — EvaluateWithSoftware (Phase 2)
// ---------------------------------------------------------------------------

func TestManager_EvaluateWithSoftware_EmptyControls_ReturnsUnknown(t *testing.T) {
	mgr := NewManager(nil)

	machine := model.Machine{Hostname: "host-01"}
	sw := []model.InstalledSoftware{{SoftwareName: "CrowdStrike Falcon"}}
	assert.Equal(t, model.ManagedUnknown, mgr.EvaluateWithSoftware(machine, sw))
}

func TestManager_EvaluateWithSoftware_AllControlsPresent_ReturnsManaged(t *testing.T) {
	mgr := NewManager([]string{"crowdstrike", "osquery"})

	machine := model.Machine{Hostname: "host-01"}
	sw := []model.InstalledSoftware{
		{SoftwareName: "CrowdStrike Falcon"},
		{SoftwareName: "osquery agent"},
		{SoftwareName: "nginx"},
	}
	assert.Equal(t, model.ManagedManaged, mgr.EvaluateWithSoftware(machine, sw))
}

func TestManager_EvaluateWithSoftware_MissingControl_ReturnsUnmanaged(t *testing.T) {
	mgr := NewManager([]string{"crowdstrike", "osquery"})

	machine := model.Machine{Hostname: "host-01"}
	sw := []model.InstalledSoftware{
		{SoftwareName: "CrowdStrike Falcon"},
		{SoftwareName: "nginx"},
	}
	assert.Equal(t, model.ManagedUnmanaged, mgr.EvaluateWithSoftware(machine, sw))
}

func TestManager_EvaluateWithSoftware_EmptySoftwareList_ReturnsUnmanaged(t *testing.T) {
	mgr := NewManager([]string{"edr_agent"})

	machine := model.Machine{Hostname: "host-01"}
	assert.Equal(t, model.ManagedUnmanaged, mgr.EvaluateWithSoftware(machine, nil))
}

func TestManager_EvaluateWithSoftware_CaseInsensitive(t *testing.T) {
	mgr := NewManager([]string{"CROWDSTRIKE"})

	machine := model.Machine{Hostname: "host-01"}
	sw := []model.InstalledSoftware{{SoftwareName: "crowdstrike falcon sensor"}}
	assert.Equal(t, model.ManagedManaged, mgr.EvaluateWithSoftware(machine, sw))
}

// ---------------------------------------------------------------------------
// Classifier — ClassifyWithSoftware (Phase 2)
// ---------------------------------------------------------------------------

func TestClassifier_ClassifyWithSoftware(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "web-01"}},
		matchFields: []string{"hostname"},
	}
	mgr := NewManager([]string{"edr"})
	cls := New(auth, mgr)

	machine := model.Machine{Hostname: "web-01"}
	sw := []model.InstalledSoftware{{SoftwareName: "EDR Agent v3"}}

	cls.ClassifyWithSoftware(&machine, sw)

	assert.Equal(t, model.AuthorizationAuthorized, machine.IsAuthorized)
	assert.Equal(t, model.ManagedManaged, machine.IsManaged)
}

func TestClassifier_ClassifyWithSoftware_NoMatch(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "web-01"}},
		matchFields: []string{"hostname"},
	}
	mgr := NewManager([]string{"edr"})
	cls := New(auth, mgr)

	machine := model.Machine{Hostname: "web-01"}
	sw := []model.InstalledSoftware{{SoftwareName: "nginx"}}

	cls.ClassifyWithSoftware(&machine, sw)

	assert.Equal(t, model.AuthorizationAuthorized, machine.IsAuthorized)
	assert.Equal(t, model.ManagedUnmanaged, machine.IsManaged)
}

func TestClassifier_ClassifyAllWithSoftware(t *testing.T) {
	auth := &Authorizer{
		entries:     []AllowlistEntry{{Hostname: "known-*"}},
		matchFields: []string{"hostname"},
	}
	mgr := NewManager([]string{"edr"})
	cls := New(auth, mgr)

	id1 := uuid.New()
	id2 := uuid.New()
	id3 := uuid.New()

	machines := []model.Machine{
		{ID: id1, Hostname: "known-01", MachineType: model.MachineTypeServer},
		{ID: id2, Hostname: "known-02", MachineType: model.MachineTypeServer},
		{ID: id3, Hostname: "rogue-01", MachineType: model.MachineTypeWorkstation},
	}

	softwareMap := map[uuid.UUID][]model.InstalledSoftware{
		id1: {{SoftwareName: "EDR Agent"}},
		// id2 has no software entry -- should fall back to Phase 1
		id3: {{SoftwareName: "nginx"}},
	}

	result := cls.ClassifyAllWithSoftware(machines, softwareMap)
	require.Len(t, result, 3)

	// id1: authorized + managed (EDR present)
	assert.Equal(t, model.AuthorizationAuthorized, result[0].IsAuthorized)
	assert.Equal(t, model.ManagedManaged, result[0].IsManaged)

	// id2: authorized + unmanaged (no software data, Phase 1 fallback)
	assert.Equal(t, model.AuthorizationAuthorized, result[1].IsAuthorized)
	assert.Equal(t, model.ManagedUnmanaged, result[1].IsManaged)

	// id3: unauthorized + unmanaged (no EDR in software list)
	assert.Equal(t, model.AuthorizationUnauthorized, result[2].IsAuthorized)
	assert.Equal(t, model.ManagedUnmanaged, result[2].IsManaged)
}
