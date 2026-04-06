// hex.go
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

type Hex struct{}

func NewHex() *Hex { return &Hex{} }

func (h *Hex) Name() string { return "hex" }

func (h *Hex) Available() bool {
	_, err := exec.LookPath("mix")
	return err == nil
}

func (h *Hex) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "mix", "deps", "--all")
	if err != nil {
		return nil, fmt.Errorf("mix deps: %w", err)
	}
	return ParseHexOutput(string(out)), nil
}

// ParseHexOutput parses the output of mix deps --all.
// Dependency lines start with "* " followed by "name version (source)".
func ParseHexOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "* ") {
			continue
		}

		entry := trimmed[2:]
		fields := strings.Fields(entry)
		if len(fields) < 2 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "hex",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected '* name version' format"),
			})
			continue
		}

		name := fields[0]
		version := fields[1]

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "hex",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "elixir"),
		})
	}

	return result
}

var _ Collector = (*Hex)(nil)
