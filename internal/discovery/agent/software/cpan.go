// cpan.go
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

type CPAN struct{}

func NewCPAN() *CPAN { return &CPAN{} }

func (c *CPAN) Name() string { return "cpan" }

func (c *CPAN) Available() bool {
	_, err := exec.LookPath("cpan")
	return err == nil
}

func (c *CPAN) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "cpan", "-l")
	if err != nil {
		return nil, fmt.Errorf("cpan -l: %w", err)
	}
	return ParseCPANOutput(string(out)), nil
}

// ParseCPANOutput parses the output of cpan -l.
// Each line is "Module::Name\tversion".
func ParseCPANOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "\t", 2)
		if len(parts) < 2 || parts[0] == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "cpan",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'Module::Name\\tversion' format"),
			})
			continue
		}

		name := parts[0]
		version := parts[1]

		if version == "undef" {
			version = ""
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "cpan",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "perl"),
		})
	}

	return result
}

var _ Collector = (*CPAN)(nil)
