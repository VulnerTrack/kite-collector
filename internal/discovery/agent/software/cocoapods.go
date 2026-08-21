// cocoapods.go
package software

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

type CocoaPods struct{}

func NewCocoaPods() *CocoaPods { return &CocoaPods{} }

func (c *CocoaPods) Name() string { return "cocoapods" }

func (c *CocoaPods) Available() bool {
	_, err := exec.LookPath("pod")
	return err == nil
}

// Collect runs pod list and returns parsed results.
//
// CocoaPods hard-refuses to run as root ("[!] You cannot run CocoaPods
// as root.") and exits 1 — the normal state for a privileged agent
// started with sudo, same as Homebrew. That is an environment
// condition, not a collector failure: it is reported once as an
// actionable Warn and the inventory is returned empty. Any other
// non-zero exit surfaces as an error carrying pod's stderr.
func (c *CocoaPods) Collect(ctx context.Context) (*Result, error) {
	out, stderr, exitCode, err := runWithLimitsTolerateExit(ctx, "pod", "list", "--no-pager")
	if err != nil {
		return nil, fmt.Errorf("pod list: %w", err)
	}
	if exitCode != 0 {
		// pod prints the refusal wrapped in ANSI color escapes, and on
		// some versions to stdout rather than stderr — check both,
		// stripped.
		combined := stripANSI(string(out)) + stripANSI(string(stderr))
		if strings.Contains(combined, "You cannot run CocoaPods as root") {
			slog.Warn(
				"software: CocoaPods refuses to run as root; skipping pod inventory",
				"code", string(LogCodeCocoaPodsRootRefused),
				"hint", "run the agent as the pod-owning user (or without sudo) to inventory CocoaPods",
			)
			return &Result{}, nil
		}
		return nil, fmt.Errorf("pod list: %w", exitError("pod", exitCode, stderr))
	}
	return ParseCocoaPodsOutput(string(out)), nil
}

// ParseCocoaPodsOutput parses the output of pod list --no-pager.
// Lines look like "-> Name (version)" or "- Name (version)". CLAide
// colorises this output with ANSI SGR escapes when it believes it has
// a TTY (and some CI shims always do), so the raw text is stripped
// before matching — otherwise every entry line fails the prefix check
// and the inventory silently parses to zero packages.
func ParseCocoaPodsOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(stripANSI(raw)))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		trimmed := strings.TrimSpace(line)

		// Pod entries start with "-> " or "- ".
		if !strings.HasPrefix(trimmed, "-> ") && !strings.HasPrefix(trimmed, "- ") {
			continue
		}

		// Strip prefix.
		entry := trimmed
		if strings.HasPrefix(entry, "-> ") {
			entry = entry[3:]
		} else {
			entry = entry[2:]
		}

		// Extract version from parentheses.
		parenOpen := strings.LastIndex(entry, "(")
		parenClose := strings.LastIndex(entry, ")")
		if parenOpen < 0 || parenClose <= parenOpen {
			result.Errs = append(result.Errs, CollectError{
				Collector: "cocoapods",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'Name (version)' format"),
			})
			continue
		}

		name := strings.TrimSpace(entry[:parenOpen])
		version := entry[parenOpen+1 : parenClose]

		if name == "" {
			continue
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "cocoapods",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "ios"),
		})
	}

	return result
}

var _ Collector = (*CocoaPods)(nil)
