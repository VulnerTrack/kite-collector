// maven.go
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

type Maven struct{}

func NewMaven() *Maven { return &Maven{} }

func (m *Maven) Name() string { return "maven" }

func (m *Maven) Available() bool {
	_, err := exec.LookPath("mvn")
	return err == nil
}

func (m *Maven) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "mvn", "dependency:list", "-DoutputType=text", "-q")
	if err != nil {
		return nil, fmt.Errorf("mvn dependency:list: %w", err)
	}
	return ParseMavenOutput(string(out)), nil
}

// ParseMavenOutput parses the output of mvn dependency:list.
// Lines have the format "   group:artifact:type:version:scope".
func ParseMavenOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Maven dependency lines contain colons as separators.
		parts := strings.Split(trimmed, ":")
		if len(parts) < 4 {
			continue
		}

		group := parts[0]
		artifact := parts[1]
		// parts[2] is type (jar, etc.)
		version := parts[3]

		// Validate it looks like a real dependency line.
		if group == "" || artifact == "" || version == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "maven",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'group:artifact:type:version' format"),
			})
			continue
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   artifact,
			Vendor:         group,
			Version:        version,
			PackageManager: "maven",
			CPE23:          BuildCPE23WithTargetSW(group, artifact, version, "java"),
		})
	}

	return result
}

var _ Collector = (*Maven)(nil)
