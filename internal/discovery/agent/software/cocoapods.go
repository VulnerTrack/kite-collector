// cocoapods.go
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

type CocoaPods struct{}

func NewCocoaPods() *CocoaPods { return &CocoaPods{} }

func (c *CocoaPods) Name() string { return "cocoapods" }

func (c *CocoaPods) Available() bool {
	_, err := exec.LookPath("pod")
	return err == nil
}

func (c *CocoaPods) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "pod", "list", "--no-pager")
	if err != nil {
		return nil, fmt.Errorf("pod list: %w", err)
	}
	return ParseCocoaPodsOutput(string(out)), nil
}

// ParseCocoaPodsOutput parses the output of pod list --no-pager.
// Lines look like "-> Name (version)" or "- Name (version)".
func ParseCocoaPodsOutput(raw string) *Result {
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
