package fsm

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/vulnertrack/kite-collector/internal/copilot/rules"
	"github.com/vulnertrack/kite-collector/internal/copilot/schema"
)

// Wizard drives the adaptive configuration wizard using the FSM pattern.
// Fields ordered for optimal GC pointer scanning.
type Wizard struct {
	schema   *schema.Schema
	engine   *rules.Engine
	prompter Prompter
	logger   *slog.Logger
	sorted   []string // topologically sorted node IDs
	explain  bool
}

// WizardOption configures optional wizard behavior.
type WizardOption func(*Wizard)

// WithExplain enables trace logging for --explain mode.
func WithExplain(explain bool) WizardOption {
	return func(w *Wizard) { w.explain = explain }
}

// WithLogger sets the logger for the wizard.
func WithLogger(l *slog.Logger) WizardOption {
	return func(w *Wizard) { w.logger = l }
}

// NewWizard creates a wizard with the given schema, rule engine, node ordering,
// and prompter implementation.
func NewWizard(s *schema.Schema, eng *rules.Engine, sorted []string, p Prompter, opts ...WizardOption) *Wizard {
	w := &Wizard{
		schema:   s,
		engine:   eng,
		sorted:   sorted,
		prompter: p,
		logger:   slog.Default(),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Run executes the full wizard flow: goal selection, then iterates through
// all nodes in topological order, resolving each via the three-step process.
// Returns the fully hydrated WizardContext.
func (w *Wizard) Run(wc *WizardContext) error {
	// Phase 0a: Goal selection (if no goal pre-selected via --goal flag).
	if wc.Goal == "" {
		goalID, err := w.prompter.PromptGoal(w.schema.Presets)
		if err != nil {
			return fmt.Errorf("goal selection: %w", err)
		}
		preset := w.schema.PresetByID(goalID)
		if preset == nil {
			return fmt.Errorf("unknown goal preset: %q", goalID)
		}
		wc.ApplyPreset(preset)
	}

	// Count visible nodes for progress display.
	visible := w.visibleNodes(wc)
	total := len(visible)
	step := 0

	// Phase 1: Iterate topologically sorted nodes.
	for _, nodeID := range w.sorted {
		node := w.schema.NodeByID(nodeID)
		if node == nil {
			continue
		}
		groupID := w.schema.GroupForNode(nodeID)

		// Skip nodes in suppressed groups.
		if wc.SkipGroups[groupID] {
			w.addTrace(wc, rules.TraceEntry{
				NodeID:  nodeID,
				GroupID: groupID,
				Skipped: true,
				Reason:  "skip_when",
			})
			continue
		}

		// [A] Skip Check: evaluate skip_when expression.
		if node.SkipWhen != "" {
			skipResult, err := w.engine.Evaluate(nodeID+"__skip", wc.CELContext())
			if err != nil {
				w.logger.Warn("skip_when evaluation failed", "node", nodeID, "err", err)
			} else if skip, ok := skipResult.(bool); ok && skip {
				w.addTrace(wc, rules.TraceEntry{
					NodeID:     nodeID,
					GroupID:    groupID,
					Expression: node.SkipWhen,
					Result:     true,
					Skipped:    true,
					Reason:     "skip_when",
				})
				continue
			}
		}

		// [B] Flag Check: is node already resolved (from --set, --config, or preset)?
		if _, resolved := wc.Resolved[nodeID]; resolved {
			w.addTrace(wc, rules.TraceEntry{
				NodeID:  nodeID,
				GroupID: groupID,
				Result:  wc.Resolved[nodeID],
				Skipped: true,
				Reason:  "flag_provided",
			})
			continue
		}

		// [C] Rule Check: evaluate default_rule via CEL.
		defaultVal, trace, evalErr := w.engine.EvaluateWithTrace(
			nodeID, groupID, node.DefaultRule, wc.CELContext(),
		)
		if evalErr != nil {
			w.logger.Warn("default_rule evaluation failed", "node", nodeID, "err", evalErr)
			defaultVal = nil
		}

		// [D] Prompt User: render with pre-filled default.
		step++
		group := w.groupTitle(groupID)
		w.prompter.ShowProgress(step, total, group)

		value, err := w.promptNode(node, defaultVal)
		if err != nil {
			return fmt.Errorf("prompt %q: %w", nodeID, err)
		}

		// Store and snapshot.
		wc.PushState()
		wc.Resolved[nodeID] = value

		trace.Result = value
		trace.Reason = "user_input"
		if evalErr == nil && defaultVal != nil && fmt.Sprint(defaultVal) == fmt.Sprint(value) {
			trace.Reason = "rule_strict"
		}
		w.addTrace(wc, trace)
	}

	return nil
}

// RunNonInteractive resolves all nodes using CEL defaults only, without
// user prompts. Used for --non-interactive --accept-defaults.
func (w *Wizard) RunNonInteractive(wc *WizardContext) error {
	for _, nodeID := range w.sorted {
		node := w.schema.NodeByID(nodeID)
		if node == nil {
			continue
		}
		groupID := w.schema.GroupForNode(nodeID)

		if wc.SkipGroups[groupID] {
			continue
		}

		if node.SkipWhen != "" {
			skipResult, err := w.engine.Evaluate(nodeID+"__skip", wc.CELContext())
			if err == nil {
				if skip, ok := skipResult.(bool); ok && skip {
					w.addTrace(wc, rules.TraceEntry{
						NodeID:     nodeID,
						GroupID:    groupID,
						Expression: node.SkipWhen,
						Result:     true,
						Skipped:    true,
						Reason:     "skip_when",
					})
					continue
				}
			}
		}

		if _, resolved := wc.Resolved[nodeID]; resolved {
			w.addTrace(wc, rules.TraceEntry{
				NodeID:  nodeID,
				GroupID: groupID,
				Result:  wc.Resolved[nodeID],
				Skipped: true,
				Reason:  "flag_provided",
			})
			continue
		}

		result, trace, err := w.engine.EvaluateWithTrace(
			nodeID, groupID, node.DefaultRule, wc.CELContext(),
		)
		if err != nil {
			// Non-interactive: if required and no default, fail.
			if node.Required {
				return fmt.Errorf("node %q: required but default_rule failed: %w", nodeID, err)
			}
			continue
		}

		wc.Resolved[nodeID] = result
		w.addTrace(wc, trace)
	}

	return nil
}

// Validate checks an existing config map against the schema. Returns errors
// for any invalid or missing required fields.
func (w *Wizard) Validate(cfg map[string]any) []ValidationError {
	var errs []ValidationError
	for _, nodeID := range w.sorted {
		node := w.schema.NodeByID(nodeID)
		if node == nil {
			continue
		}
		val, exists := cfg[nodeID]
		if !exists && node.Required {
			errs = append(errs, ValidationError{
				NodeID:  nodeID,
				Message: "required field is missing",
			})
			continue
		}
		if exists && node.Type == "select" {
			if !containsOption(node.Options, fmt.Sprint(val)) {
				errs = append(errs, ValidationError{
					NodeID:  nodeID,
					Message: fmt.Sprintf("value %q not in allowed options %v", val, node.Options),
				})
			}
		}
	}
	return errs
}

// ValidationError describes a single validation failure.
type ValidationError struct {
	NodeID  string `json:"node"`
	Message string `json:"message"`
}

// ExplainJSON returns the trace log as indented JSON.
func (w *Wizard) ExplainJSON(wc *WizardContext) ([]byte, error) {
	data, err := json.MarshalIndent(wc.Trace, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal wizard trace: %w", err)
	}
	return data, nil
}

// promptNode dispatches to the appropriate Prompter method based on node type.
func (w *Wizard) promptNode(node *schema.Node, defaultVal any) (any, error) {
	switch node.Type {
	case "confirm":
		defBool := false
		if b, ok := defaultVal.(bool); ok {
			defBool = b
		}
		v, err := w.prompter.PromptConfirm(*node, defBool)
		if err != nil {
			return nil, fmt.Errorf("prompt confirm %s: %w", node.ID, err)
		}
		return v, nil

	case "select":
		defStr := ""
		if s, ok := defaultVal.(string); ok {
			defStr = s
		}
		v, err := w.prompter.PromptSelect(*node, defStr)
		if err != nil {
			return nil, fmt.Errorf("prompt select %s: %w", node.ID, err)
		}
		return v, nil

	case "input":
		defStr := ""
		if s, ok := defaultVal.(string); ok {
			defStr = s
		}
		v, err := w.prompter.PromptInput(*node, defStr)
		if err != nil {
			return nil, fmt.Errorf("prompt input %s: %w", node.ID, err)
		}
		return v, nil

	case "multiselect":
		defSlice := toStringSlice(defaultVal)
		v, err := w.prompter.PromptMultiSelect(*node, defSlice)
		if err != nil {
			return nil, fmt.Errorf("prompt multiselect %s: %w", node.ID, err)
		}
		return v, nil

	case "password":
		v, err := w.prompter.PromptPassword(*node)
		if err != nil {
			return nil, fmt.Errorf("prompt password %s: %w", node.ID, err)
		}
		return v, nil

	default:
		return nil, fmt.Errorf("unknown node type %q", node.Type)
	}
}

// visibleNodes counts nodes that won't be skipped by groups or preset context.
func (w *Wizard) visibleNodes(wc *WizardContext) []string {
	var visible []string
	for _, nodeID := range w.sorted {
		groupID := w.schema.GroupForNode(nodeID)
		if wc.SkipGroups[groupID] {
			continue
		}
		if _, resolved := wc.Resolved[nodeID]; resolved {
			continue
		}
		visible = append(visible, nodeID)
	}
	return visible
}

func (w *Wizard) groupTitle(groupID string) string {
	for _, g := range w.schema.Groups {
		if g.ID == groupID {
			return g.Title
		}
	}
	return groupID
}

func (w *Wizard) addTrace(wc *WizardContext, t rules.TraceEntry) {
	if w.explain {
		wc.Trace = append(wc.Trace, t)
	}
}

func containsOption(options []string, val string) bool {
	for _, o := range options {
		if o == val {
			return true
		}
	}
	return false
}

func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, elem := range s {
			if str, ok := elem.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}
