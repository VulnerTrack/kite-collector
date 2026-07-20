package classifier

import (
	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// Classifier orchestrates authorization and managed-state classification for
// discovered machines.
type Classifier struct {
	authorizer *Authorizer
	manager    *Manager
}

// New creates a Classifier backed by the given Authorizer and Manager.
func New(authorizer *Authorizer, manager *Manager) *Classifier {
	return &Classifier{
		authorizer: authorizer,
		manager:    manager,
	}
}

// ClassifyAll applies classification to every machine in the slice, updating
// each machine's IsAuthorized and IsManaged fields in place.  The (possibly
// mutated) slice is returned for convenience.
func (c *Classifier) ClassifyAll(machines []model.Machine) []model.Machine {
	for i := range machines {
		c.Classify(&machines[i])
	}
	return machines
}

// Classify sets the IsAuthorized and IsManaged fields on a single machine.
func (c *Classifier) Classify(machine *model.Machine) {
	machine.IsAuthorized = c.authorizer.Authorize(*machine)
	machine.IsManaged = c.manager.Evaluate(*machine)
}

// ClassifyWithSoftware sets the IsAuthorized and IsManaged fields on a single
// machine, using the provided software inventory for managed-state evaluation.
// This enables Phase 2 classification where installed software is checked
// against required controls.
func (c *Classifier) ClassifyWithSoftware(machine *model.Machine, software []model.InstalledSoftware) {
	machine.IsAuthorized = c.authorizer.Authorize(*machine)
	machine.IsManaged = c.manager.EvaluateWithSoftware(*machine, software)
}

// ClassifyAllWithSoftware applies classification to every machine in the slice,
// using the provided software map to look up installed software by machine ID.
// Machines without an entry in the software map fall back to the Phase 1
// Evaluate method (no software data available).  The (possibly mutated) slice
// is returned for convenience.
func (c *Classifier) ClassifyAllWithSoftware(machines []model.Machine, softwareByMachine map[uuid.UUID][]model.InstalledSoftware) []model.Machine {
	for i := range machines {
		sw, ok := softwareByMachine[machines[i].ID]
		if ok {
			c.ClassifyWithSoftware(&machines[i], sw)
		} else {
			c.Classify(&machines[i])
		}
	}
	return machines
}
