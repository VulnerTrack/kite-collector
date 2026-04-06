// bun.go
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

type Bun struct{}

func NewBun() *Bun { return &Bun{} }

func (b *Bun) Name() string { return "bun" }

func (b *Bun) Available() bool {
	_, err := exec.LookPath("bun")
	return err == nil
}

func (b *Bun) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "bun", "pm", "ls", "-g")
	if err != nil {
		return nil, fmt.Errorf("bun pm ls -g: %w", err)
	}
	return ParseBunOutput(string(out)), nil
}

// ParseBunOutput parses the tree-style output of bun pm ls -g.
// Lines look like "├── package@version" or "└── package@version".
func ParseBunOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Strip tree drawing characters and whitespace.
		trimmed := strings.TrimLeft(line, " │├└─\t")
		trimmed = strings.TrimSpace(trimmed)
		if trimmed == "" || !strings.Contains(trimmed, "@") {
			continue
		}

		// Handle scoped packages: @scope/name@version
		atIdx := strings.LastIndex(trimmed, "@")
		if atIdx <= 0 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "bun",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'package@version' format"),
			})
			continue
		}

		name := trimmed[:atIdx]
		version := trimmed[atIdx+1:]

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "bun",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "node.js"),
		})
	}

	return result
}

var _ Collector = (*Bun)(nil)
