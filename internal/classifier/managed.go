package classifier

import "github.com/vulnertrack/kite-collector/internal/model"

// Manager determines whether an asset satisfies the organisation's required
// security controls (e.g. EDR agent, configuration management).
type Manager struct {
	requiredControls []string
}

// NewManager creates a Manager that checks for the given required controls.
func NewManager(requiredControls []string) *Manager {
	return &Manager{
		requiredControls: requiredControls,
	}
}

// Evaluate determines the managed state of an asset.
//
// Phase 1 (MVP) behaviour:
//   - If no required controls are configured (empty list), the feature is
//     opt-in and we return "unknown".
//   - If controls are configured, we return "unmanaged" because the agent
//     does not yet report installed control data.  Phase 2 will inspect
//     agent-reported software inventories to verify control presence and
//     return "managed" when all requirements are satisfied.
func (m *Manager) Evaluate(asset model.Asset) model.ManagedState {
	if len(m.requiredControls) == 0 {
		return model.ManagedUnknown
	}

	// Phase 2: iterate asset's installed software / agent telemetry and
	// check against m.requiredControls.  For now we cannot verify anything.
	return model.ManagedUnmanaged
}
