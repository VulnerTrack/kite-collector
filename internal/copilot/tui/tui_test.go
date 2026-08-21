package tui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/copilot/schema"
)

// newPrompter wires a LinePrompter to a scripted input string and a
// capture buffer for output.
func newPrompter(input string) (*LinePrompter, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &LinePrompter{In: strings.NewReader(input), Out: out}, out
}

func TestNewLinePrompter(t *testing.T) {
	p := NewLinePrompter()
	require.NotNil(t, p)
	assert.NotNil(t, p.In)
	assert.NotNil(t, p.Out)
}

// -- PromptGoal ---------------------------------------------------

func presets() []schema.Preset {
	return []schema.Preset{
		{ID: "quickstart", Title: "Quick Start"},
		{ID: "advanced", Title: "Advanced Setup"},
	}
}

func TestPromptGoalValid(t *testing.T) {
	p, out := newPrompter("2\n")
	got, err := p.PromptGoal(presets())
	require.NoError(t, err)
	assert.Equal(t, "advanced", got)
	// Menu rendered with both titles and a bounded selection prompt.
	assert.Contains(t, out.String(), "Quick Start")
	assert.Contains(t, out.String(), "Advanced Setup")
	assert.Contains(t, out.String(), "Select [1-2]: ")
}

func TestPromptGoalOutOfRange(t *testing.T) {
	p, _ := newPrompter("9\n")
	_, err := p.PromptGoal(presets())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid selection")
}

func TestPromptGoalNonNumeric(t *testing.T) {
	p, _ := newPrompter("banana\n")
	_, err := p.PromptGoal(presets())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid selection")
}

func TestPromptGoalNoInput(t *testing.T) {
	p, _ := newPrompter("") // EOF immediately
	_, err := p.PromptGoal(presets())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no input")
}

// -- PromptSelect -------------------------------------------------

func selectNode() schema.Node {
	return schema.Node{Prompt: "Pick a driver", Options: []string{"pacman", "apt", "dnf"}}
}

func TestPromptSelectValid(t *testing.T) {
	p, out := newPrompter("3\n")
	got, err := p.PromptSelect(selectNode(), "apt")
	require.NoError(t, err)
	assert.Equal(t, "dnf", got)
	assert.Contains(t, out.String(), "Pick a driver")
	assert.Contains(t, out.String(), "* [2] apt") // default marker on apt
}

func TestPromptSelectEmptyUsesDefault(t *testing.T) {
	p, _ := newPrompter("\n")
	got, err := p.PromptSelect(selectNode(), "apt")
	require.NoError(t, err)
	assert.Equal(t, "apt", got)
}

func TestPromptSelectEOFUsesDefault(t *testing.T) {
	p, _ := newPrompter("")
	got, err := p.PromptSelect(selectNode(), "apt")
	require.NoError(t, err)
	assert.Equal(t, "apt", got)
}

func TestPromptSelectInvalid(t *testing.T) {
	p, _ := newPrompter("7\n")
	_, err := p.PromptSelect(selectNode(), "apt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid selection")
}

// -- PromptInput --------------------------------------------------

func TestPromptInputWithValue(t *testing.T) {
	p, out := newPrompter("myhost\n")
	got, err := p.PromptInput(schema.Node{Prompt: "Hostname"}, "localhost")
	require.NoError(t, err)
	assert.Equal(t, "myhost", got)
	assert.Contains(t, out.String(), "Hostname [localhost]: ")
}

func TestPromptInputEmptyUsesDefault(t *testing.T) {
	p, _ := newPrompter("\n")
	got, err := p.PromptInput(schema.Node{Prompt: "Hostname"}, "localhost")
	require.NoError(t, err)
	assert.Equal(t, "localhost", got)
}

func TestPromptInputNoDefaultPrompt(t *testing.T) {
	p, out := newPrompter("value\n")
	got, err := p.PromptInput(schema.Node{Prompt: "Token"}, "")
	require.NoError(t, err)
	assert.Equal(t, "value", got)
	assert.Contains(t, out.String(), "Token: ")
}

func TestPromptInputEOFReturnsDefault(t *testing.T) {
	p, _ := newPrompter("")
	got, err := p.PromptInput(schema.Node{Prompt: "Token"}, "def")
	require.NoError(t, err)
	assert.Equal(t, "def", got)
}

// -- PromptConfirm ------------------------------------------------

func TestPromptConfirm(t *testing.T) {
	cases := []struct {
		in     string
		def    bool
		want   bool
		render string
	}{
		{"y\n", false, true, "y/N"},
		{"yes\n", false, true, "y/N"},
		{"n\n", true, false, "Y/n"},
		{"no\n", true, false, "Y/n"},
		{"\n", true, true, "Y/n"},      // empty → default true
		{"\n", false, false, "y/N"},    // empty → default false
		{"maybe\n", true, true, "Y/n"}, // garbage → default
		{"", false, false, "y/N"},      // EOF → default
	}
	for _, c := range cases {
		p, out := newPrompter(c.in)
		got, err := p.PromptConfirm(schema.Node{Prompt: "Proceed?"}, c.def)
		require.NoError(t, err)
		assert.Equalf(t, c.want, got, "input %q def %v", c.in, c.def)
		assert.Contains(t, out.String(), c.render)
	}
}

// -- PromptMultiSelect --------------------------------------------

func multiNode() schema.Node {
	return schema.Node{Prompt: "Select sources", Options: []string{"nvd", "cwe", "capec", "epss"}}
}

func TestPromptMultiSelectValid(t *testing.T) {
	p, out := newPrompter("1, 3\n")
	got, err := p.PromptMultiSelect(multiNode(), []string{"nvd"})
	require.NoError(t, err)
	assert.Equal(t, []string{"nvd", "capec"}, got)
	assert.Contains(t, out.String(), "* [1] nvd") // default marker
	assert.Contains(t, out.String(), "comma-separated numbers")
}

func TestPromptMultiSelectSkipsInvalidParts(t *testing.T) {
	p, _ := newPrompter("2, 99, foo, 4\n")
	got, err := p.PromptMultiSelect(multiNode(), nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"cwe", "epss"}, got) // 99 & foo dropped
}

func TestPromptMultiSelectEmptyUsesDefaults(t *testing.T) {
	p, out := newPrompter("\n")
	got, err := p.PromptMultiSelect(multiNode(), []string{"nvd", "cwe"})
	require.NoError(t, err)
	assert.Equal(t, []string{"nvd", "cwe"}, got)
	assert.Contains(t, out.String(), "default: nvd, cwe")
}

func TestPromptMultiSelectEmptyDefaultsRenderNone(t *testing.T) {
	p, out := newPrompter("\n")
	got, err := p.PromptMultiSelect(multiNode(), nil)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Contains(t, out.String(), "default: none")
}

func TestPromptMultiSelectEOFUsesDefaults(t *testing.T) {
	p, _ := newPrompter("")
	got, err := p.PromptMultiSelect(multiNode(), []string{"epss"})
	require.NoError(t, err)
	assert.Equal(t, []string{"epss"}, got)
}

// -- PromptPassword -----------------------------------------------

func TestPromptPassword(t *testing.T) {
	p, out := newPrompter("  s3cr3t  \n")
	got, err := p.PromptPassword(schema.Node{Prompt: "API key"})
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t", got) // trimmed
	assert.Contains(t, out.String(), "API key: ")
}

func TestPromptPasswordEOF(t *testing.T) {
	p, _ := newPrompter("")
	got, err := p.PromptPassword(schema.Node{Prompt: "API key"})
	require.NoError(t, err)
	assert.Equal(t, "", got)
}

// -- ShowProgress -------------------------------------------------

func TestShowProgress(t *testing.T) {
	p, out := newPrompter("")
	p.ShowProgress(2, 5, "Database")
	assert.Contains(t, out.String(), "[2/5] Database")
}

// -- IsInteractiveTerminal ----------------------------------------

func TestIsInteractiveTerminal(t *testing.T) {
	// Under `go test` stdin is typically not a char device; we only assert
	// the call is safe and returns a bool without touching a real TTY.
	_ = IsInteractiveTerminal()
}
