package software

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Brew collects installed packages using Homebrew on macOS and Linux.
type Brew struct{}

// NewBrew returns a new Brew collector.
func NewBrew() *Brew { return &Brew{} }

// Name returns the stable identifier for this collector.
func (b *Brew) Name() string { return "brew" }

// Available reports whether brew is on the PATH.
func (b *Brew) Available() bool {
	_, err := exec.LookPath("brew")
	return err == nil
}

// Collect runs brew list --versions and returns parsed results.
//
// Homebrew hard-refuses to run as root ("Running Homebrew as root is
// extremely dangerous and no longer supported") and exits 1 — the
// normal state for a privileged agent started with sudo. That is an
// environment condition, not a collector failure: it is reported once
// as an actionable Warn and the inventory is returned empty. Any other
// non-zero exit surfaces as an error carrying brew's stderr.
func (b *Brew) Collect(ctx context.Context) (*Result, error) {
	// Privilege reduction instead of privilege skip: when the agent is
	// root, run brew as the user who owns the brew binary (Homebrew
	// itself requires a non-root owner) with a minimal environment.
	// The inventory then works from a system daemon without ever
	// granting brew root. Falls through to the root-refusal skip below
	// when no demotion target exists (root-owned brew, non-unix).
	demote := demotionFor("brew")
	if demote != nil {
		slog.Info("software: running brew as its owning user (brew refuses root)",
			"code", string(LogCodeExecDemotedToUser),
			"collector", "brew",
			"uid", demote.uid,
			"user", demote.username)
	}
	out, stderr, exitCode, err := runWithLimitsTolerateExitAs(ctx, demote, "brew", "list", "--versions")
	if err != nil {
		return nil, fmt.Errorf("brew list --versions: %w", err)
	}
	if exitCode != 0 {
		if bytes.Contains(stderr, []byte("Running Homebrew as root")) {
			slog.Warn(
				"software: brew refuses to run as root; skipping Homebrew inventory",
				"code", string(LogCodeBrewRootRefused),
				"hint", "run the agent as the Homebrew-owning user (or without sudo) to inventory brew packages",
			)
			return &Result{}, nil
		}
		return nil, fmt.Errorf("brew list --versions: %w", exitError("brew", exitCode, stderr))
	}
	return ParseBrewOutput(string(out)), nil
}

// ParseBrewOutput parses the raw output of brew list --versions.
// Each line is expected as "<package> <version> [version2 ...]".
// Only the first (most recent) version is captured.
func ParseBrewOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "brew",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'package version [version ...]' format"),
			})
			continue
		}

		name := parts[0]
		version := parts[1]

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Vendor:         "homebrew",
			Version:        version,
			PackageManager: "brew",
			CPE23:          BuildCPE23("homebrew", name, version),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*Brew)(nil)
