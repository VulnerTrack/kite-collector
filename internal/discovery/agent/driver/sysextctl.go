package driver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
)

// SystemExtensionsCtl enumerates DriverKit / System Extension drivers via
// `systemextensionsctl list`. macOS-only.
type SystemExtensionsCtl struct {
	now    func() time.Time
	binary string
}

// NewSystemExtensionsCtl constructs a SystemExtensionsCtl with the
// kernel-default binary path.
func NewSystemExtensionsCtl() *SystemExtensionsCtl {
	return &SystemExtensionsCtl{
		binary: "/usr/bin/systemextensionsctl",
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the registry identifier.
func (s *SystemExtensionsCtl) Name() string { return "darwin-systemextensionsctl" }

// Available returns true on macOS hosts only.
func (s *SystemExtensionsCtl) Available() bool { return runtime.GOOS == "darwin" }

// Collect runs systemextensionsctl and parses its output.
func (s *SystemExtensionsCtl) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, s.binary, "list")
	if err != nil {
		return nil, fmt.Errorf("systemextensionsctl list: %w", err)
	}
	res := ParseSystemExtensionsCtl(string(out))
	now := s.now()
	for i := range res.Drivers {
		res.Drivers[i].CollectedAt = now
		res.Drivers[i].Architecture = runtime.GOARCH
		res.Drivers[i].DriverFramework = FrameworkDEXT
		res.Drivers[i].CPE23 = software.BuildCPE23WithTargetSW(
			res.Drivers[i].Vendor,
			res.Drivers[i].Name,
			res.Drivers[i].Version,
			"macos",
		)
	}
	res.Sort()
	return res, nil
}

// ParseSystemExtensionsCtl parses lines of the form:
//
//	enabled    active  teamID  bundleID (version)  name [state]
//
// A leading "*" marks the entry as enabled / active. Header rows
// ("--- com.apple.system_extension.driver_extension") are skipped.
func ParseSystemExtensionsCtl(raw string) *Result {
	res := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "---") {
			continue
		}
		// Skip the section header that lists totals.
		if strings.HasSuffix(line, "extension(s)") {
			continue
		}

		fields := strings.Fields(line)
		// Minimum: enabled active teamID bundleID(version)
		if len(fields) < 4 {
			res.Errs = append(res.Errs, CollectError{
				Collector: "darwin-systemextensionsctl",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected at least 4 fields"),
			})
			continue
		}

		enabled := fields[0] == "*" || strings.EqualFold(fields[0], "enabled")
		active := fields[1] == "*" || strings.EqualFold(fields[1], "active")
		teamID := fields[2]
		bundle := fields[3]
		version := ""
		if i := strings.Index(bundle, "("); i > 0 && strings.HasSuffix(bundle, ")") {
			version = bundle[i+1 : len(bundle)-1]
			bundle = bundle[:i]
		}

		state := SignatureUnknown
		if enabled {
			state = SignatureValid
		}
		drv := LoadedDriver{
			ID:              uuid.Must(uuid.NewV7()),
			Name:            bundle,
			Version:         version,
			Vendor:          teamID,
			Signer:          teamID,
			SignatureState:  state,
			DriverFramework: FrameworkDEXT,
			State:           "Live",
		}
		if !active {
			drv.State = "Inactive"
		}
		res.Drivers = append(res.Drivers, drv)
	}
	return res
}
