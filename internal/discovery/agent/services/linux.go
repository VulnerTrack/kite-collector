//go:build linux

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// linuxCollector enumerates systemd-managed services via systemctl. Two
// invocations are required because `list-units` knows the *runtime* state
// (active/failed/...) while `list-unit-files` knows the *configured*
// start_mode (enabled/disabled/masked/static). We merge them on unit name.
//
// We shell out rather than talk DBus because:
//   - It works for non-privileged users without a session bus.
//   - It works inside containers where the host DBus socket isn't mounted.
//   - The systemctl JSON output schema is stable across systemd versions.
type linuxCollector struct {
	run runner
}

// runner is the test seam — production substitutes exec.CommandContext.
type runner func(ctx context.Context, name string, args ...string) ([]byte, error)

func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output() //#nosec G204 -- name/args are derived from the collector's hard-coded systemd/launchd command set, not user input
	if err != nil {
		return out, fmt.Errorf("exec %s: %w", name, err)
	}
	return out, nil
}

// NewCollector returns the build-tagged Linux Service collector.
func NewCollector() Collector {
	return &linuxCollector{run: defaultRunner}
}

func (c *linuxCollector) Name() string { return "systemd" }

// systemctlUnit mirrors the JSON object systemctl emits for each unit.
// Field names are case-insensitive against the JSON keys we care about.
type systemctlUnit struct {
	Unit        string `json:"unit"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

// systemctlUnitFile mirrors the JSON object from list-unit-files.
type systemctlUnitFile struct {
	UnitFile string `json:"unit_file"`
	State    string `json:"state"`
	Preset   string `json:"preset"`
}

// Collect enumerates systemd services and returns the merged set.
func (c *linuxCollector) Collect(ctx context.Context) ([]Service, error) {
	now := time.Now().UTC()

	unitsRaw, err := c.run(ctx,
		"systemctl", "list-units", "--type=service", "--all",
		"--output=json", "--no-pager", "--no-legend")
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w", err)
	}
	units, err := parseSystemctlUnits(unitsRaw)
	if err != nil {
		return nil, fmt.Errorf("parse list-units: %w", err)
	}

	filesRaw, err := c.run(ctx,
		"systemctl", "list-unit-files", "--type=service",
		"--output=json", "--no-pager", "--no-legend")
	if err != nil {
		// Soft-fail: emit runtime-only rows with StartUnknown. Better than
		// nothing for restricted environments where list-unit-files is
		// inaccessible (chrooted containers, denied via polkit).
		out := make([]Service, 0, len(units))
		for _, u := range units {
			out = append(out, unitToService(u, "", now))
		}
		SortServices(out)
		return out, nil
	}
	files, err := parseSystemctlUnitFiles(filesRaw)
	if err != nil {
		return nil, fmt.Errorf("parse list-unit-files: %w", err)
	}

	startModeByName := make(map[string]string, len(files))
	for _, f := range files {
		startModeByName[f.UnitFile] = f.State
	}

	out := make([]Service, 0, len(units))
	for _, u := range units {
		out = append(out, unitToService(u, startModeByName[u.Unit], now))
	}
	SortServices(out)
	return out, nil
}

// parseSystemctlUnits accepts both the modern JSON-array output and the
// legacy newline-delimited single-object format that some systemd versions
// emit when --no-legend is set with --output=json.
func parseSystemctlUnits(raw []byte) ([]systemctlUnit, error) {
	trimmed := bytesTrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var arr []systemctlUnit
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("unmarshal array: %w", err)
		}
		return arr, nil
	}
	// Fallback: one object per line.
	var out []systemctlUnit
	for _, line := range strings.Split(string(trimmed), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var u systemctlUnit
		if err := json.Unmarshal([]byte(line), &u); err != nil {
			// Skip malformed lines rather than abort — better partial
			// inventory than no inventory.
			continue
		}
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, errors.New("no parseable units in output")
	}
	return out, nil
}

func parseSystemctlUnitFiles(raw []byte) ([]systemctlUnitFile, error) {
	trimmed := bytesTrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var arr []systemctlUnitFile
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("unmarshal array: %w", err)
		}
		return arr, nil
	}
	var out []systemctlUnitFile
	for _, line := range strings.Split(string(trimmed), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var f systemctlUnitFile
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// unitToService merges runtime and config-file views into one Service row.
func unitToService(u systemctlUnit, startState string, now time.Time) Service {
	return Service{
		Manager:     ManagerSystemd,
		Name:        u.Unit,
		Description: u.Description,
		State:       mapSystemctlActive(u.Active, u.Sub),
		StartMode:   mapSystemctlStart(startState),
		LastSeenAt:  now,
		CollectedAt: now,
	}
}

// mapSystemctlActive maps the (active, sub) pair to our normalised State.
// systemd's `sub` column carries the actionable signal — "failed" lives
// there, not in `active`.
func mapSystemctlActive(active, sub string) State {
	switch strings.ToLower(sub) {
	case "running":
		return StateRunning
	case "exited", "dead":
		// "exited" is normal for one-shot units; "dead" is normal for
		// stopped services. We collapse both into Stopped.
		return StateStopped
	case "failed":
		return StateFailed
	case "start", "start-pre", "start-post", "auto-restart":
		return StateActivating
	case "stop", "stop-pre", "stop-post":
		return StateDeactivating
	}
	switch strings.ToLower(active) {
	case "active":
		return StateRunning
	case "inactive":
		return StateStopped
	case "failed":
		return StateFailed
	case "activating":
		return StateActivating
	case "deactivating":
		return StateDeactivating
	}
	return StateUnknown
}

// mapSystemctlStart maps the list-unit-files state to our StartMode.
func mapSystemctlStart(state string) StartMode {
	switch strings.ToLower(state) {
	case "enabled", "enabled-runtime", "alias":
		return StartAuto
	case "disabled":
		return StartDisabled
	case "static":
		return StartStatic
	case "masked", "masked-runtime":
		return StartMasked
	case "indirect":
		return StartOnDemand
	case "generated":
		return StartAuto
	case "":
		return StartUnknown
	}
	return StartUnknown
}

// bytesTrimSpace avoids an extra `bytes` import for one call.
func bytesTrimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end {
		c := b[start]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		start++
	}
	for end > start {
		c := b[end-1]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		end--
	}
	return b[start:end]
}
