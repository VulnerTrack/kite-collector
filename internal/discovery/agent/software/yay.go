package software

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// ansiEscapes matches ANSI CSI sequences (colors, cursor movement). yay
// keeps its message decorations colored even when stdout is a pipe, so
// they must be stripped before line parsing.
var ansiEscapes = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// Yay collects AUR/foreign packages using yay on Arch Linux.
// It complements the Pacman collector which enumerates official packages.
type Yay struct{}

// NewYay returns a new Yay collector.
func NewYay() *Yay { return &Yay{} }

// Name returns the stable identifier for this collector.
func (y *Yay) Name() string { return "yay" }

// Available reports whether yay is on the PATH.
func (y *Yay) Available() bool {
	_, err := exec.LookPath("yay")
	return err == nil
}

// Collect runs yay -Qm and returns parsed results.
func (y *Yay) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "yay", "-Qm")
	if err != nil {
		return nil, fmt.Errorf("yay -Qm: %w", err)
	}
	return ParseYayOutput(string(out)), nil
}

// ParseYayOutput parses the output of yay -Qm.
// Format is identical to pacman: "package version" per line.
func ParseYayOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := ansiEscapes.ReplaceAllString(scanner.Text(), "")
		if line == "" {
			continue
		}

		// yay prefixes its own chatter with "->" / "==>" markers (e.g.
		// " -> Avoid running yay as root/sudo." under the root agent
		// service). Those are messages, not package lines — skip them
		// silently rather than recording a parse error.
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "->") ||
			strings.HasPrefix(trimmed, "==>") {
			continue
		}

		idx := strings.LastIndex(line, " ")
		if idx <= 0 || idx >= len(line)-1 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "yay",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'package version' format"),
			})
			continue
		}

		name := line[:idx]
		version := line[idx+1:]

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "yay",
			CPE23:          BuildCPE23("", name, version),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*Yay)(nil)
