package fsm

import "github.com/vulnertrack/kite-collector/internal/copilot/schema"

// Prompter abstracts user interaction for the wizard. Implementations
// include the TUI prompter, the line-based fallback, and the non-interactive
// defaults-only prompter used in CI/CD.
type Prompter interface {
	// PromptGoal asks the user to select a goal preset. Returns the preset ID.
	PromptGoal(presets []schema.Preset) (string, error)

	// PromptSelect asks the user to choose from a list of options.
	PromptSelect(node schema.Node, defaultVal string) (string, error)

	// PromptInput asks the user for free-text input.
	PromptInput(node schema.Node, defaultVal string) (string, error)

	// PromptConfirm asks the user a yes/no question.
	PromptConfirm(node schema.Node, defaultVal bool) (bool, error)

	// PromptMultiSelect asks the user to select zero or more options.
	PromptMultiSelect(node schema.Node, defaultVals []string) ([]string, error)

	// PromptPassword asks for sensitive input (masked display).
	PromptPassword(node schema.Node) (string, error)

	// ShowProgress displays the current step and total.
	ShowProgress(current, total int, groupTitle string)
}

// DefaultsPrompter returns CEL-computed defaults without user interaction.
// Used for --non-interactive --accept-defaults.
type DefaultsPrompter struct{}

func (DefaultsPrompter) PromptGoal(presets []schema.Preset) (string, error) {
	return "custom", nil
}

func (DefaultsPrompter) PromptSelect(_ schema.Node, defaultVal string) (string, error) {
	return defaultVal, nil
}

func (DefaultsPrompter) PromptInput(_ schema.Node, defaultVal string) (string, error) {
	return defaultVal, nil
}

func (DefaultsPrompter) PromptConfirm(_ schema.Node, defaultVal bool) (bool, error) {
	return defaultVal, nil
}

func (DefaultsPrompter) PromptMultiSelect(_ schema.Node, defaultVals []string) ([]string, error) {
	return defaultVals, nil
}

func (DefaultsPrompter) PromptPassword(_ schema.Node) (string, error) {
	return "", nil
}

func (DefaultsPrompter) ShowProgress(_, _ int, _ string) {}
