package fsm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/copilot/rules"
	"github.com/vulnertrack/kite-collector/internal/copilot/schema"
)

// mockPrompter records calls and returns pre-configured answers.
type mockPrompter struct {
	confirmAnswers  map[string]bool
	selectAnswers   map[string]string
	inputAnswers    map[string]string
	multiAnswers    map[string][]string
	passwordAnswers map[string]string
	goalAnswer      string
	progressCalls   int
}

func newMockPrompter() *mockPrompter {
	return &mockPrompter{
		goalAnswer:      "custom",
		confirmAnswers:  make(map[string]bool),
		selectAnswers:   make(map[string]string),
		inputAnswers:    make(map[string]string),
		multiAnswers:    make(map[string][]string),
		passwordAnswers: make(map[string]string),
	}
}

func (m *mockPrompter) PromptGoal(_ []schema.Preset) (string, error) {
	return m.goalAnswer, nil
}

func (m *mockPrompter) PromptConfirm(n schema.Node, def bool) (bool, error) {
	if v, ok := m.confirmAnswers[n.ID]; ok {
		return v, nil
	}
	return def, nil
}

func (m *mockPrompter) PromptSelect(n schema.Node, def string) (string, error) {
	if v, ok := m.selectAnswers[n.ID]; ok {
		return v, nil
	}
	return def, nil
}

func (m *mockPrompter) PromptInput(n schema.Node, def string) (string, error) {
	if v, ok := m.inputAnswers[n.ID]; ok {
		return v, nil
	}
	return def, nil
}

func (m *mockPrompter) PromptMultiSelect(n schema.Node, def []string) ([]string, error) {
	if v, ok := m.multiAnswers[n.ID]; ok {
		return v, nil
	}
	return def, nil
}

func (m *mockPrompter) PromptPassword(n schema.Node) (string, error) {
	if v, ok := m.passwordAnswers[n.ID]; ok {
		return v, nil
	}
	return "", nil
}

func (m *mockPrompter) ShowProgress(_, _ int, _ string) {
	m.progressCalls++
}

// setupWizard loads the default schema, builds the DAG, compiles all rules,
// and returns a ready-to-use wizard.
func setupWizard(t *testing.T, p Prompter, opts ...WizardOption) (*Wizard, *schema.Schema) {
	t.Helper()
	s, err := schema.LoadDefault()
	require.NoError(t, err)

	_, sorted, err := schema.BuildDAG(s)
	require.NoError(t, err)

	eng, err := rules.New()
	require.NoError(t, err)
	for _, node := range s.AllNodes() {
		require.NoError(t, eng.Compile(node.ID, node.DefaultRule))
		if node.SkipWhen != "" {
			require.NoError(t, eng.Compile(node.ID+"__skip", node.SkipWhen))
		}
	}

	return NewWizard(s, eng, sorted, p, opts...), s
}

func TestNonInteractiveAcceptDefaults(t *testing.T) {
	wiz, _ := setupWizard(t, DefaultsPrompter{})
	wc := NewContext()
	wc.Goal = "custom"
	wc.ApplyPreset(&schema.Preset{ID: "custom"})

	err := wiz.RunNonInteractive(wc)
	require.NoError(t, err)

	// Core fields should have defaults.
	assert.Equal(t, "info", wc.Resolved["log_level"])
	assert.Equal(t, "json", wc.Resolved["output_format"])
	assert.Equal(t, "./data", wc.Resolved["data_dir"])
	assert.Equal(t, true, wc.Resolved["discovery.agent.enabled"])
	assert.Equal(t, true, wc.Resolved["audit.enabled"])
	assert.Equal(t, "30m", wc.Resolved["safety.scan_deadline"])
}

func TestNonInteractiveQuickScan(t *testing.T) {
	wiz, s := setupWizard(t, DefaultsPrompter{})
	wc := NewContext()
	preset := s.PresetByID("quick_scan")
	require.NotNil(t, preset)
	wc.ApplyPreset(preset)

	err := wiz.RunNonInteractive(wc)
	require.NoError(t, err)

	// Preset-injected values.
	assert.Equal(t, true, wc.Resolved["discovery.agent.enabled"])
	assert.Equal(t, true, wc.Resolved["discovery.agent.collect_software"])
	assert.Equal(t, false, wc.Resolved["discovery.network.enabled"])
	assert.Equal(t, "table", wc.Resolved["output_format"])

	// Skipped groups should not have resolved values except preset-injected ones.
	// endpoint.primary.address is preset-injected as "".
	assert.Equal(t, "", wc.Resolved["endpoint.primary.address"])
}

func TestNonInteractiveIdenticalToInteractiveDefaults(t *testing.T) {
	// Both paths should produce the same resolved values for "custom" goal
	// when the interactive prompter accepts all defaults.
	wiz1, _ := setupWizard(t, DefaultsPrompter{})
	wc1 := NewContext()
	wc1.Goal = "custom"
	wc1.ApplyPreset(&schema.Preset{ID: "custom"})
	require.NoError(t, wiz1.RunNonInteractive(wc1))

	mp := newMockPrompter()
	mp.goalAnswer = "custom"
	wiz2, _ := setupWizard(t, mp)
	wc2 := NewContext()
	wc2.Goal = "custom"
	wc2.ApplyPreset(&schema.Preset{ID: "custom"})
	require.NoError(t, wiz2.Run(wc2))

	// All resolved values should match.
	for key, v1 := range wc1.Resolved {
		assert.Equalf(t, v1, wc2.Resolved[key],
			"mismatch for key %q: non-interactive=%v, interactive=%v", key, v1, wc2.Resolved[key])
	}
}

func TestSkipGroupsSuppressNodes(t *testing.T) {
	wiz, _ := setupWizard(t, DefaultsPrompter{}, WithExplain(true))
	wc := NewContext()
	wc.Goal = "quick_scan"
	wc.SkipGroups["endpoints"] = true
	wc.SkipGroups["streaming"] = true

	require.NoError(t, wiz.RunNonInteractive(wc))

	// Endpoint nodes should not be resolved (except preset-injected ones).
	_, hasToken := wc.Resolved["endpoint.primary.enrollment_token"]
	assert.False(t, hasToken, "enrollment_token should not be resolved when endpoints skipped")
}

func TestSkipWhenExpression(t *testing.T) {
	wiz, _ := setupWizard(t, DefaultsPrompter{}, WithExplain(true))
	wc := NewContext()
	wc.Goal = "custom"
	wc.ApplyPreset(&schema.Preset{ID: "custom"})

	require.NoError(t, wiz.RunNonInteractive(wc))

	// discovery.network.enabled defaults to false, so network.scope should
	// be skipped by its skip_when expression.
	_, hasScope := wc.Resolved["discovery.network.scope"]
	assert.False(t, hasScope, "network.scope should be skipped when network.enabled is false")

	// Verify trace entry exists for the skip.
	found := false
	for _, t := range wc.Trace {
		if t.NodeID == "discovery.network.scope" && t.Skipped {
			found = true
			break
		}
	}
	assert.True(t, found, "should have trace entry for skipped network.scope")
}

func TestPresetContextPreFills(t *testing.T) {
	wiz, s := setupWizard(t, DefaultsPrompter{})
	wc := NewContext()
	preset := s.PresetByID("systemd_service")
	require.NotNil(t, preset)
	wc.ApplyPreset(preset)

	require.NoError(t, wiz.RunNonInteractive(wc))

	// Preset sets data_dir to /var/lib/kite-collector.
	assert.Equal(t, "/var/lib/kite-collector", wc.Resolved["data_dir"])
}

func TestFlagProvidedSkipsPrompt(t *testing.T) {
	mp := newMockPrompter()
	wiz, _ := setupWizard(t, mp)
	wc := NewContext()
	wc.Goal = "custom"
	wc.ApplyPreset(&schema.Preset{ID: "custom"})
	wc.Resolved["log_level"] = "debug" // Pre-set via --set flag.

	require.NoError(t, wiz.Run(wc))

	// Flag-provided value should be preserved.
	assert.Equal(t, "debug", wc.Resolved["log_level"])
}

func TestStateStackPushPop(t *testing.T) {
	wc := NewContext()
	wc.Resolved["a"] = "1"
	wc.PushState()

	wc.Resolved["a"] = "2"
	wc.Resolved["b"] = "3"

	assert.True(t, wc.PopState())
	assert.Equal(t, "1", wc.Resolved["a"])
	_, hasB := wc.Resolved["b"]
	assert.False(t, hasB)
}

func TestStateStackEmptyPop(t *testing.T) {
	wc := NewContext()
	assert.False(t, wc.PopState())
}

func TestCELContextIncludesAutoDiscovery(t *testing.T) {
	wc := NewContext()
	wc.Resolved["foo"] = "bar"
	wc.AutoDiscovery = []string{"docker", "otel_collector"}

	ctx := wc.CELContext()
	assert.Equal(t, "bar", ctx["foo"])
	ad, ok := ctx["autodiscovery"].([]any)
	require.True(t, ok)
	assert.Equal(t, []any{"docker", "otel_collector"}, ad)
}

func TestAutoDiscoveryAffectsDefaults(t *testing.T) {
	wiz, _ := setupWizard(t, DefaultsPrompter{})
	wc := NewContext()
	wc.Goal = "custom"
	wc.ApplyPreset(&schema.Preset{ID: "custom"})
	wc.AutoDiscovery = []string{"docker", "otel_collector"}

	require.NoError(t, wiz.RunNonInteractive(wc))

	// Docker detected -> docker.enabled should be true.
	assert.Equal(t, true, wc.Resolved["discovery.docker.enabled"])
}

func TestExplainTraceEntries(t *testing.T) {
	wiz, _ := setupWizard(t, DefaultsPrompter{}, WithExplain(true))
	wc := NewContext()
	wc.Goal = "custom"
	wc.ApplyPreset(&schema.Preset{ID: "custom"})

	require.NoError(t, wiz.RunNonInteractive(wc))

	assert.NotEmpty(t, wc.Trace)
	// Should have trace entries for resolved nodes.
	hasLogLevel := false
	for _, t := range wc.Trace {
		if t.NodeID == "log_level" {
			hasLogLevel = true
			break
		}
	}
	assert.True(t, hasLogLevel)
}

func TestExplainJSON(t *testing.T) {
	wiz, _ := setupWizard(t, DefaultsPrompter{}, WithExplain(true))
	wc := NewContext()
	wc.Goal = "custom"
	wc.ApplyPreset(&schema.Preset{ID: "custom"})
	require.NoError(t, wiz.RunNonInteractive(wc))

	data, err := wiz.ExplainJSON(wc)
	require.NoError(t, err)
	assert.Contains(t, string(data), "log_level")
}

func TestValidateMissingRequired(t *testing.T) {
	wiz, _ := setupWizard(t, DefaultsPrompter{})
	errs := wiz.Validate(map[string]any{})
	assert.NotEmpty(t, errs)

	// log_level is required.
	found := false
	for _, e := range errs {
		if e.NodeID == "log_level" {
			found = true
			break
		}
	}
	assert.True(t, found, "should report missing log_level")
}

func TestValidateInvalidOption(t *testing.T) {
	wiz, _ := setupWizard(t, DefaultsPrompter{})
	errs := wiz.Validate(map[string]any{
		"log_level": "invalid_level",
	})
	found := false
	for _, e := range errs {
		if e.NodeID == "log_level" && e.Message != "" {
			found = true
			break
		}
	}
	assert.True(t, found, "should report invalid log_level option")
}

func TestProgressCallsDuringRun(t *testing.T) {
	mp := newMockPrompter()
	wiz, _ := setupWizard(t, mp)
	wc := NewContext()
	wc.Goal = "custom"
	wc.ApplyPreset(&schema.Preset{ID: "custom"})
	require.NoError(t, wiz.Run(wc))

	assert.Greater(t, mp.progressCalls, 0, "should have called ShowProgress at least once")
}

func TestInteractiveUserOverride(t *testing.T) {
	mp := newMockPrompter()
	mp.selectAnswers["log_level"] = "debug"
	wiz, _ := setupWizard(t, mp)
	wc := NewContext()
	wc.Goal = "custom"
	wc.ApplyPreset(&schema.Preset{ID: "custom"})
	require.NoError(t, wiz.Run(wc))

	assert.Equal(t, "debug", wc.Resolved["log_level"])
}

func TestApplyPresetSetsPostActions(t *testing.T) {
	wc := NewContext()
	wc.ApplyPreset(&schema.Preset{
		ID:          "systemd_service",
		PostActions: []string{"generate_systemd_unit", "enroll_if_token_provided"},
	})
	assert.Equal(t, []string{"generate_systemd_unit", "enroll_if_token_provided"}, wc.PostActions)
}
