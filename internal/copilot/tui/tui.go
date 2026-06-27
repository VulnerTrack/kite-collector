// Package tui implements the interactive terminal prompter for the copilot
// wizard. It detects terminal capabilities and falls back to simple line
// prompts when a full TUI cannot render (SSH, pipe, dumb terminal).
package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/vulnertrack/kite-collector/internal/copilot/schema"
)

// LinePrompter implements fsm.Prompter using simple line-based I/O.
// This is the fallback for non-interactive terminals, SSH sessions,
// and piped stdin.
type LinePrompter struct {
	In  io.Reader
	Out io.Writer
}

// NewLinePrompter creates a LinePrompter using stdin/stdout.
func NewLinePrompter() *LinePrompter {
	return &LinePrompter{In: os.Stdin, Out: os.Stdout}
}

func (p *LinePrompter) PromptGoal(presets []schema.Preset) (string, error) {
	p.writeln("\nWhat do you want to do?")
	p.writeln("")
	for i, preset := range presets {
		p.writef("  [%d] %s\n", i+1, preset.Title)
	}
	p.writeln("")
	p.writef("Select [1-%d]: ", len(presets))

	scanner := bufio.NewScanner(p.In)
	if !scanner.Scan() {
		return "", fmt.Errorf("no input")
	}
	text := strings.TrimSpace(scanner.Text())
	idx, err := strconv.Atoi(text)
	if err != nil || idx < 1 || idx > len(presets) {
		return "", fmt.Errorf("invalid selection: %q", text)
	}
	return presets[idx-1].ID, nil
}

func (p *LinePrompter) PromptSelect(node schema.Node, defaultVal string) (string, error) {
	p.writef("\n%s\n", node.Prompt)
	for i, opt := range node.Options {
		marker := "  "
		if opt == defaultVal {
			marker = "* "
		}
		p.writef("  %s[%d] %s\n", marker, i+1, opt)
	}
	p.writef("Select [default: %s]: ", defaultVal)

	scanner := bufio.NewScanner(p.In)
	if !scanner.Scan() {
		return defaultVal, nil
	}
	text := strings.TrimSpace(scanner.Text())
	if text == "" {
		return defaultVal, nil
	}
	idx, err := strconv.Atoi(text)
	if err != nil || idx < 1 || idx > len(node.Options) {
		return "", fmt.Errorf("invalid selection: %q", text)
	}
	return node.Options[idx-1], nil
}

func (p *LinePrompter) PromptInput(node schema.Node, defaultVal string) (string, error) {
	if defaultVal != "" {
		p.writef("\n%s [%s]: ", node.Prompt, defaultVal)
	} else {
		p.writef("\n%s: ", node.Prompt)
	}

	scanner := bufio.NewScanner(p.In)
	if !scanner.Scan() {
		return defaultVal, nil
	}
	text := strings.TrimSpace(scanner.Text())
	if text == "" {
		return defaultVal, nil
	}
	return text, nil
}

func (p *LinePrompter) PromptConfirm(node schema.Node, defaultVal bool) (bool, error) {
	defStr := "Y/n"
	if !defaultVal {
		defStr = "y/N"
	}
	p.writef("\n%s [%s]: ", node.Prompt, defStr)

	scanner := bufio.NewScanner(p.In)
	if !scanner.Scan() {
		return defaultVal, nil
	}
	text := strings.TrimSpace(strings.ToLower(scanner.Text()))
	switch text {
	case "":
		return defaultVal, nil
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return defaultVal, nil
	}
}

func (p *LinePrompter) PromptMultiSelect(node schema.Node, defaultVals []string) ([]string, error) {
	defaults := make(map[string]bool)
	for _, d := range defaultVals {
		defaults[d] = true
	}

	p.writef("\n%s (comma-separated numbers)\n", node.Prompt)
	for i, opt := range node.Options {
		marker := "  "
		if defaults[opt] {
			marker = "* "
		}
		p.writef("  %s[%d] %s\n", marker, i+1, opt)
	}
	defDisplay := strings.Join(defaultVals, ", ")
	if defDisplay == "" {
		defDisplay = "none"
	}
	p.writef("Select [default: %s]: ", defDisplay)

	scanner := bufio.NewScanner(p.In)
	if !scanner.Scan() {
		return defaultVals, nil
	}
	text := strings.TrimSpace(scanner.Text())
	if text == "" {
		return defaultVals, nil
	}

	var selected []string
	parts := strings.Split(text, ",")
	for _, part := range parts {
		idx, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || idx < 1 || idx > len(node.Options) {
			continue
		}
		selected = append(selected, node.Options[idx-1])
	}
	return selected, nil
}

func (p *LinePrompter) PromptPassword(node schema.Node) (string, error) {
	p.writef("\n%s: ", node.Prompt)
	scanner := bufio.NewScanner(p.In)
	if !scanner.Scan() {
		return "", nil
	}
	return strings.TrimSpace(scanner.Text()), nil
}

func (p *LinePrompter) ShowProgress(current, total int, groupTitle string) {
	p.writef("\n--- [%d/%d] %s ---\n", current, total, groupTitle)
}

// writef is a helper that discards fmt.Fprintf errors for terminal output.
func (p *LinePrompter) writef(format string, args ...any) {
	_, _ = fmt.Fprintf(p.Out, format, args...)
}

// writeln is a helper that discards fmt.Fprintln errors for terminal output.
func (p *LinePrompter) writeln(s string) {
	_, _ = fmt.Fprintln(p.Out, s)
}

// IsInteractiveTerminal returns true if stdin is a terminal (not piped or redirected).
func IsInteractiveTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
