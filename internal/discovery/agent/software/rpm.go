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

const rpmFormat = "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{ARCH}\t%{SOURCERPM}\t%{URL}\t%{LICENSE}\t%{SUMMARY}\n"

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
	out, err := runWithLimits(ctx, "rpm", "-qa", "--queryformat", rpmFormat)
	if err != nil {
		return nil, fmt.Errorf("rpm -qa: %w", err)
	}
	return ParseRPMOutput(string(out)), nil
}

// ParseRPMOutput parses rpmFormat and the legacy two/four-column output.
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

		parts := strings.SplitN(line, "\t", 8)
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

		item := model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   parts[0],
			Version:        parts[1],
			Vendor:         vendor,
			PackageManager: "rpm",
			Architecture:   arch,
			CPE23:          BuildCPE23WithArch(vendor, parts[0], parts[1], arch),
		}
		if len(parts) >= 8 {
			item.SourcePackage, item.SourceVersion = rpmSource(parts[4])
			item.Homepage, item.License, item.Description = rpmValue(parts[5]), rpmValue(parts[6]), rpmValue(parts[7])
		}
		result.Items = append(result.Items, item)
	}

	return result
}

func rpmValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "(none)" {
		return ""
	}
	return value
}

// The source header names the source's own version/release, which may differ
// from a subpackage. RPM VERSION and RELEASE cannot contain a dash.
func rpmSource(filename string) (string, string) {
	var nvr string
	switch {
	case strings.HasSuffix(filename, ".src.rpm"):
		nvr = strings.TrimSuffix(filename, ".src.rpm")
	case strings.HasSuffix(filename, ".nosrc.rpm"):
		nvr = strings.TrimSuffix(filename, ".nosrc.rpm")
	default:
		return "", ""
	}
	if strings.ContainsAny(nvr, "/\\ \t\r\n") {
		return "", ""
	}
	release := strings.LastIndexByte(nvr, '-')
	if release <= 0 || release == len(nvr)-1 {
		return "", ""
	}
	version := strings.LastIndexByte(nvr[:release], '-')
	if version <= 0 || version == release-1 {
		return "", ""
	}
	return nvr[:version], nvr[version+1:]
}

// Compile-time interface check.
var _ Collector = (*RPM)(nil)
