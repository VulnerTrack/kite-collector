package software

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Pacman collects installed packages using pacman on Arch-based systems.
type Pacman struct{}

// NewPacman returns a new Pacman collector.
func NewPacman() *Pacman { return &Pacman{} }

// Name returns the stable identifier for this collector.
func (p *Pacman) Name() string { return "pacman" }

// Available reports whether pacman is on the PATH.
func (p *Pacman) Available() bool {
	_, err := exec.LookPath("pacman")
	return err == nil
}

// Collect runs pacman -Q and returns parsed results.
func (p *Pacman) Collect(ctx context.Context) (*Result, error) {
	out, err := exec.CommandContext(ctx, "pacman", "-Q").Output()
	if err != nil {
		return nil, fmt.Errorf("pacman -Q: %w", err)
	}
	return ParsePacmanOutput(string(out)), nil
}

// ParsePacmanOutput parses the raw output of pacman -Q.
// Each line is expected as "<package> <version>".
func ParsePacmanOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		// pacman -Q outputs "package-name version" separated by a single space.
		// Use last space as separator since package names can't contain spaces
		// but this is the safest split.
		idx := strings.LastIndex(line, " ")
		if idx <= 0 || idx >= len(line)-1 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "pacman",
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
			PackageManager: "pacman",
			CPE23:          BuildCPE23("", name, version),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*Pacman)(nil)
