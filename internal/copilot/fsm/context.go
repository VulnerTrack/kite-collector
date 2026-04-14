// Package fsm implements the finite state machine that drives the copilot
// wizard. It walks topologically sorted nodes, resolving each via flag check,
// CEL rule evaluation, or user prompt.
package fsm

import (
	"github.com/vulnertrack/kite-collector/internal/copilot/rules"
	"github.com/vulnertrack/kite-collector/internal/copilot/schema"
)

// WizardContext holds the accumulated state during a wizard session.
type WizardContext struct {
	Goal          string            // Selected preset ID
	Resolved      map[string]any    // Accumulated key-value pairs from resolved nodes
	AutoDiscovery []string          // Services detected by discover-services
	SkipGroups    map[string]bool   // Groups suppressed by the selected goal preset
	PostActions   []string          // Actions to execute after Phase 2
	StateStack    []map[string]any  // Append-only stack for rollback support
	Trace         []rules.TraceEntry // Decision audit log entries
}

// NewContext creates a WizardContext with empty state.
func NewContext() *WizardContext {
	return &WizardContext{
		Resolved:   make(map[string]any),
		SkipGroups: make(map[string]bool),
	}
}

// ApplyPreset injects the preset's context values, skip groups, and post
// actions into the wizard context.
func (wc *WizardContext) ApplyPreset(p *schema.Preset) {
	wc.Goal = p.ID
	for k, v := range p.Context {
		wc.Resolved[k] = v
	}
	for _, sg := range p.SkipGroups {
		wc.SkipGroups[sg] = true
	}
	wc.PostActions = append(wc.PostActions[:0], p.PostActions...)
}

// PushState saves a snapshot of Resolved for rollback.
func (wc *WizardContext) PushState() {
	snap := make(map[string]any, len(wc.Resolved))
	for k, v := range wc.Resolved {
		snap[k] = v
	}
	wc.StateStack = append(wc.StateStack, snap)
}

// PopState restores Resolved from the last snapshot. Returns false if
// the stack is empty.
func (wc *WizardContext) PopState() bool {
	if len(wc.StateStack) == 0 {
		return false
	}
	last := len(wc.StateStack) - 1
	wc.Resolved = wc.StateStack[last]
	wc.StateStack = wc.StateStack[:last]
	return true
}

// CELContext builds the map passed to CEL rule evaluation. It merges
// Resolved values with autodiscovery.
func (wc *WizardContext) CELContext() map[string]any {
	ctx := make(map[string]any, len(wc.Resolved)+1)
	for k, v := range wc.Resolved {
		ctx[k] = v
	}
	if len(wc.AutoDiscovery) > 0 {
		// Convert []string to []any for CEL compatibility.
		ad := make([]any, len(wc.AutoDiscovery))
		for i, s := range wc.AutoDiscovery {
			ad[i] = s
		}
		ctx["autodiscovery"] = ad
	}
	return ctx
}
