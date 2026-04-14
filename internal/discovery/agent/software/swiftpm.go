// swiftpm.go
package software

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

type SwiftPM struct{}

func NewSwiftPM() *SwiftPM { return &SwiftPM{} }

func (s *SwiftPM) Name() string { return "swiftpm" }

func (s *SwiftPM) Available() bool {
	_, err := exec.LookPath("swift")
	return err == nil
}

func (s *SwiftPM) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "swift", "package", "show-dependencies", "--format=json")
	if err != nil {
		return nil, fmt.Errorf("swift package show-dependencies: %w", err)
	}
	return ParseSwiftPMJSON(string(out)), nil
}

type swiftDep struct {
	Identity     string     `json:"identity"`
	Version      string     `json:"version"`
	Dependencies []swiftDep `json:"dependencies"`
}

type swiftPMOutput struct {
	Dependencies []swiftDep `json:"dependencies"`
}

// ParseSwiftPMJSON parses the JSON output of swift package show-dependencies.
func ParseSwiftPMJSON(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	var output swiftPMOutput
	if err := json.Unmarshal([]byte(raw), &output); err != nil {
		result.Errs = append(result.Errs, CollectError{
			Collector: "swiftpm",
			Line:      1,
			RawLine:   truncateRaw(raw),
			Err:       fmt.Errorf("json decode: %w", err),
		})
		return result
	}

	// Flatten the dependency tree iteratively.
	seen := make(map[string]bool)
	queue := make([]swiftDep, len(output.Dependencies))
	copy(queue, output.Dependencies)

	for len(queue) > 0 {
		dep := queue[0]
		queue = queue[1:]

		if dep.Identity == "" || seen[dep.Identity] {
			continue
		}
		seen[dep.Identity] = true

		version := dep.Version
		if version == "unspecified" {
			version = ""
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   dep.Identity,
			Version:        version,
			PackageManager: "swiftpm",
			CPE23:          BuildCPE23WithTargetSW("", dep.Identity, version, "ios"),
		})

		queue = append(queue, dep.Dependencies...)
	}

	return result
}

var _ Collector = (*SwiftPM)(nil)
