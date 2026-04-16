package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/vulnertrack/kite-collector/internal/copilot/fsm"
	"github.com/vulnertrack/kite-collector/internal/copilot/preflight"
	"github.com/vulnertrack/kite-collector/internal/copilot/rules"
	"github.com/vulnertrack/kite-collector/internal/copilot/schema"
	"github.com/vulnertrack/kite-collector/internal/copilot/tui"
)

func newCopilotCmd() *cobra.Command {
	var (
		goal           string
		nonInteractive bool
		acceptDefaults bool
		exportPath     string
		explain        bool
		validateMode   bool
		configFile     string
		setValues      []string
		listGoals      bool
		dryRun         bool
		strict         bool
	)

	cmd := &cobra.Command{
		Use:   "copilot",
		Short: "Adaptive configuration wizard for kite-collector",
		Long: `Guided, adaptive CLI wizard that resolves 30+ interdependent parameters
using a DAG-based dependency graph, CEL rule engine, and finite state machine.

Supports interactive TUI, headless CI/CD mode, auto-discovery integration,
and pre-flight validation of endpoints, credentials, and infrastructure.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCopilot(cmd, copilotFlags{
				goal:           goal,
				nonInteractive: nonInteractive,
				acceptDefaults: acceptDefaults,
				exportPath:     exportPath,
				explain:        explain,
				validateMode:   validateMode,
				configFile:     configFile,
				setValues:      setValues,
				listGoals:      listGoals,
				dryRun:         dryRun,
				strict:         strict,
			})
		},
	}

	cmd.Flags().StringVar(&goal, "goal", "", "Select a goal preset (use --list-goals to see options)")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "Run without user prompts (CI/CD mode)")
	cmd.Flags().BoolVar(&acceptDefaults, "accept-defaults", false, "Accept all computed defaults")
	cmd.Flags().StringVar(&exportPath, "export", "", "Export resolved config to file")
	cmd.Flags().BoolVar(&explain, "explain", false, "Show decision audit log (which rules fired)")
	cmd.Flags().BoolVar(&validateMode, "validate", false, "Validate an existing config file")
	cmd.Flags().StringVar(&configFile, "config", "", "Load existing config file")
	cmd.Flags().StringSliceVar(&setValues, "set", nil, "Override parameters (key=value)")
	cmd.Flags().BoolVar(&listGoals, "list-goals", false, "List available goal presets")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview output without writing files")
	cmd.Flags().BoolVar(&strict, "strict", false, "Fail on any unresolved required field")

	return cmd
}

type copilotFlags struct {
	goal           string
	exportPath     string
	configFile     string
	setValues      []string
	nonInteractive bool
	acceptDefaults bool
	explain        bool
	validateMode   bool
	listGoals      bool
	dryRun         bool
	strict         bool
}

func runCopilot(cmd *cobra.Command, f copilotFlags) error {
	logger := slog.Default()
	out := cmd.OutOrStdout()

	// Load schema.
	s, err := schema.LoadDefault()
	if err != nil {
		return fmt.Errorf("schema load: %w", err)
	}

	if f.listGoals {
		return printGoals(out, s)
	}

	// Build DAG.
	_, sorted, err := schema.BuildDAG(s)
	if err != nil {
		return fmt.Errorf("DAG build: %w", err)
	}

	// Compile CEL rules.
	eng, err := rules.New()
	if err != nil {
		return fmt.Errorf("rule engine: %w", err)
	}
	for _, node := range s.AllNodes() {
		if compErr := eng.Compile(node.ID, node.DefaultRule); compErr != nil {
			return fmt.Errorf("compile rule %q: %w", node.ID, compErr)
		}
		if node.SkipWhen != "" {
			if compErr := eng.Compile(node.ID+"__skip", node.SkipWhen); compErr != nil {
				return fmt.Errorf("compile skip_when %q: %w", node.ID, compErr)
			}
		}
	}

	// Create wizard context.
	wc := fsm.NewContext()

	if f.configFile != "" {
		cfg, loadErr := loadConfig(f.configFile)
		if loadErr != nil {
			return fmt.Errorf("load config: %w", loadErr)
		}
		for k, v := range cfg {
			wc.Resolved[k] = v
		}
	}

	for _, sv := range f.setValues {
		k, v, ok := strings.Cut(sv, "=")
		if !ok {
			return fmt.Errorf("invalid --set format %q, expected key=value", sv)
		}
		wc.Resolved[k] = v
	}

	if f.goal != "" {
		preset := s.PresetByID(f.goal)
		if preset == nil {
			return fmt.Errorf("unknown goal: %q (use --list-goals to see available goals)", f.goal)
		}
		wc.ApplyPreset(preset)
	}

	// Select prompter.
	var prompter fsm.Prompter
	if f.nonInteractive || f.acceptDefaults {
		prompter = fsm.DefaultsPrompter{}
	} else {
		prompter = tui.NewLinePrompter()
	}

	wiz := fsm.NewWizard(s, eng, sorted, prompter,
		fsm.WithExplain(f.explain),
		fsm.WithLogger(logger),
	)

	// Handle --validate mode.
	if f.validateMode {
		errs := wiz.Validate(wc.Resolved)
		if len(errs) > 0 {
			data, _ := json.MarshalIndent(map[string]any{"errors": errs}, "", "  ")
			_, _ = fmt.Fprintln(out, string(data))
			return fmt.Errorf("%d validation error(s)", len(errs))
		}
		_, _ = fmt.Fprintln(out, "Configuration is valid.")
		return nil
	}

	// Run wizard.
	if f.nonInteractive || f.acceptDefaults {
		if err := wiz.RunNonInteractive(wc); err != nil {
			return err
		}
	} else {
		if err := wiz.Run(wc); err != nil {
			return err
		}
	}

	if f.strict {
		errs := wiz.Validate(wc.Resolved)
		if len(errs) > 0 {
			data, _ := json.MarshalIndent(map[string]any{"errors": errs}, "", "  ")
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), string(data))
			return fmt.Errorf("strict mode: %d unresolved field(s)", len(errs))
		}
	}

	if f.explain {
		data, explainErr := wiz.ExplainJSON(wc)
		if explainErr != nil {
			return fmt.Errorf("explain: %w", explainErr)
		}
		_, _ = fmt.Fprintln(out, string(data))
	}

	// Pre-flight validation.
	specs := collectPreflightSpecs(s, wc)
	if len(specs) > 0 && !f.dryRun {
		runner := preflight.NewRunner(8, logger)
		results := runner.Run(context.Background(), specs)
		passed, failed := preflight.Summary(results)

		_, _ = fmt.Fprintln(out, "\nPre-flight validation:")
		for _, r := range results {
			marker := "  ✓"
			if !r.Passed {
				marker = "  ✗"
			}
			_, _ = fmt.Fprintf(out, "%s %-30s %s\n", marker, r.Check, r.Message)
		}
		_, _ = fmt.Fprintf(out, "\n  %d/%d passed", passed, passed+failed)
		if failed > 0 {
			_, _ = fmt.Fprintf(out, ", %d failed", failed)
		}
		_, _ = fmt.Fprintln(out)

		if failed > 0 && f.nonInteractive {
			data, _ := json.MarshalIndent(map[string]any{
				"errors": failedResults(results),
			}, "", "  ")
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), string(data))
			return fmt.Errorf("pre-flight: %d check(s) failed", failed)
		}
	}

	// Export config — always write so post-actions (e.g. run_first_scan) have
	// a valid config file to reference. --export overrides the default path.
	outPath := f.exportPath
	if outPath == "" {
		outPath = "kite-collector.yaml"
	}

	data, marshalErr := yaml.Marshal(wc.Resolved)
	if marshalErr != nil {
		return fmt.Errorf("marshal config: %w", marshalErr)
	}

	if f.dryRun {
		_, _ = fmt.Fprintf(out, "\n--dry-run: would write config to %s\n", outPath)
		_, _ = fmt.Fprintln(out, string(data))
	} else {
		if writeErr := os.WriteFile(outPath, data, 0o600); writeErr != nil {
			return fmt.Errorf("write config: %w", writeErr)
		}
		_, _ = fmt.Fprintf(out, "\nConfiguration written to %s\n", outPath)
	}

	// Execute post-actions defined by the selected goal preset.
	if len(wc.PostActions) > 0 {
		runner := newPostActionRunner(wc, outPath, f.dryRun, f.nonInteractive, out)
		for _, action := range wc.PostActions {
			if err := runner.Run(action); err != nil {
				return fmt.Errorf("post-action %q: %w", action, err)
			}
		}
	}

	return nil
}

func printGoals(w io.Writer, s *schema.Schema) error {
	_, _ = fmt.Fprintln(w, "Available goals:")
	_, _ = fmt.Fprintln(w)
	for _, p := range s.Presets {
		marker := "  "
		if p.Primary {
			marker = "* "
		}
		_, _ = fmt.Fprintf(w, "  %s%-20s %s\n", marker, p.ID, p.Title)
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "  * = primary (shown by default in interactive mode)")
	return nil
}

func loadConfig(path string) (map[string]any, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- path is user-provided CLI flag
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	return cfg, nil
}

func collectPreflightSpecs(s *schema.Schema, wc *fsm.WizardContext) []preflight.CheckSpec {
	var specs []preflight.CheckSpec
	for _, node := range s.AllNodes() {
		if node.PreflightValidate == "" {
			continue
		}
		val, exists := wc.Resolved[node.ID]
		if !exists {
			continue
		}
		specs = append(specs, preflight.CheckSpec{
			NodeID:   node.ID,
			CheckTag: node.PreflightValidate,
			Value:    val,
			Resolved: wc.Resolved,
		})
	}
	return specs
}

func failedResults(results []preflight.CheckResult) []preflight.CheckResult {
	var failed []preflight.CheckResult
	for _, r := range results {
		if !r.Passed {
			failed = append(failed, r)
		}
	}
	return failed
}
