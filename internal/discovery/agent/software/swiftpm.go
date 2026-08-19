// swiftpm.go
package software

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

type SwiftPM struct{}

func NewSwiftPM() *SwiftPM { return &SwiftPM{} }

func (s *SwiftPM) Name() string { return "swiftpm" }

// Available reports whether swift is on the PATH AND the working
// directory is inside a SwiftPM package. Unlike host-scoped package
// managers, `swift package show-dependencies` only describes the
// package whose Package.swift sits at or above the working directory —
// on a host with the toolchain but no package in scope the command is
// guaranteed to exit 1, so the collector is not applicable.
func (s *SwiftPM) Available() bool {
	if _, err := exec.LookPath("swift"); err != nil {
		return false
	}
	wd, err := os.Getwd()
	if err != nil {
		return false
	}
	return hasSwiftManifest(wd)
}

// hasSwiftManifest walks from dir up to the filesystem root looking for
// a Package.swift manifest — mirroring how `swift package` locates the
// package root.
func hasSwiftManifest(dir string) bool {
	for {
		if _, err := os.Stat(filepath.Join(dir, "Package.swift")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// Collect runs swift package show-dependencies and returns parsed
// results. A "Could not find Package.swift" failure (possible despite
// the Available() gate — the manifest may disappear, or the process may
// change directory between the check and the run) is an environment
// condition, not a collector failure: it yields a benign empty
// inventory. Any other non-zero exit surfaces as an error carrying
// swift's stderr.
func (s *SwiftPM) Collect(ctx context.Context) (*Result, error) {
	out, stderr, exitCode, err := runWithLimitsTolerateExit(ctx, "swift", "package", "show-dependencies", "--format=json")
	if err != nil {
		return nil, fmt.Errorf("swift package show-dependencies: %w", err)
	}
	if exitCode != 0 {
		if isSwiftNoManifest(stderr) {
			slog.Debug(
				"software: no Package.swift in scope; skipping swiftpm inventory",
				"code", string(LogCodeSwiftPMNoManifest),
			)
			return &Result{}, nil
		}
		return nil, fmt.Errorf("swift package show-dependencies: %w", exitError("swift", exitCode, stderr))
	}
	return ParseSwiftPMJSON(string(out)), nil
}

// isSwiftNoManifest matches the SwiftPM diagnostics for "you are not in
// a package": the long-standing "Could not find Package.swift in this
// directory or any of its parent directories" and the newer "root
// manifest not found" variant.
func isSwiftNoManifest(stderr []byte) bool {
	return bytes.Contains(stderr, []byte("Could not find Package.swift")) ||
		bytes.Contains(stderr, []byte("root manifest not found"))
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
