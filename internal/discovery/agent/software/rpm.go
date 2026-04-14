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

// RPM collects installed packages using rpm on Red Hat-based systems.
type RPM struct{}

// NewRPM returns a new RPM collector.
func NewRPM() *RPM { return &RPM{} }

// Name returns the stable identifier for this collector.
func (r *RPM) Name() string { return "rpm" }

// Available reports whether rpm is on the PATH.
func (r *RPM) Available() bool {
	_, err := exec.LookPath("rpm")
	return err == nil
}

// Collect runs rpm -qa and returns parsed results. Output is capped at
// 64 MB and the command is killed after 60 seconds.
func (r *RPM) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{ARCH}\n")
	if err != nil {
		return nil, fmt.Errorf("rpm -qa: %w", err)
	}
	return ParseRPMOutput(string(out)), nil
}

// ParseRPMOutput parses the raw output of rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{ARCH}\n'.
func ParseRPMOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "\t", 4)
		if len(parts) < 2 || parts[0] == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "rpm",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'name\\tversion[\\tvendor[\\tarch]]' format"),
			})
			continue
		}

		vendor := ""
		if len(parts) >= 3 {
			v := strings.TrimSpace(parts[2])
			if v != "(none)" && v != "" {
				vendor = v
			}
		}

		arch := ""
		if len(parts) >= 4 {
			a := strings.TrimSpace(parts[3])
			if a != "(none)" && a != "" {
				arch = a
			}
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   parts[0],
			Version:        parts[1],
			Vendor:         vendor,
			PackageManager: "rpm",
			Architecture:   arch,
			CPE23:          BuildCPE23WithArch(vendor, parts[0], parts[1], arch),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*RPM)(nil)
