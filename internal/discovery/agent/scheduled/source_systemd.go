package scheduled

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// systemdTimerCollector enumerates systemd .timer units via
// `systemctl list-timers --all --output=json --no-pager --no-legend`.
// Same test seam pattern as services/linux.go — shell-out, not DBus.
type systemdTimerCollector struct {
	run      runner
	lookPath pathLookup
}

// runner / pathLookup are the test seams (also defined elsewhere in
// this package by source_cron is not relevant; we keep them here).
type (
	runner     func(ctx context.Context, name string, args ...string) ([]byte, error)
	pathLookup func(string) (string, error)
)

func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //#nosec G204 -- args are fixed literals
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("exec %s: %w", name, err)
	}
	return out, nil
}

// NewSystemdTimerCollector returns a systemd-timer-backed Collector.
// Empty when systemctl is not on PATH.
func NewSystemdTimerCollector() Collector {
	return &systemdTimerCollector{
		run:      defaultRunner,
		lookPath: exec.LookPath,
	}
}

func (c *systemdTimerCollector) Name() string { return "systemd-timers" }

// systemctlTimer mirrors the JSON object systemctl emits per timer.
type systemctlTimer struct {
	Unit       string `json:"unit"`
	Activates  string `json:"activates"` // companion .service
	Next       string `json:"next"`      // RFC3339-ish next-fire time
	NextLeft   string `json:"left"`
	Last       string `json:"last"` // last-fire time, "-" when never
	LastPassed string `json:"passed"`
}

func (c *systemdTimerCollector) Collect(ctx context.Context) ([]Job, error) {
	if _, err := c.lookPath("systemctl"); err != nil {
		return []Job{}, nil //nolint:nilerr // missing systemctl = "not applicable"
	}
	raw, err := c.run(ctx,
		"systemctl", "list-timers", "--all",
		"--output=json", "--no-pager", "--no-legend")
	if err != nil {
		return []Job{}, fmt.Errorf("systemctl list-timers: %w", err)
	}
	timers, err := parseSystemctlTimers(raw)
	if err != nil {
		return []Job{}, fmt.Errorf("parse list-timers: %w", err)
	}
	if len(timers) > MaxJobs {
		timers = timers[:MaxJobs]
	}
	out := make([]Job, 0, len(timers))
	for _, t := range timers {
		out = append(out, timerToJob(t))
	}
	SortJobs(out)
	return out, nil
}

// parseSystemctlTimers handles both JSON-array and NDJSON outputs that
// different systemd versions produce when --no-legend is set.
func parseSystemctlTimers(raw []byte) ([]systemctlTimer, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var arr []systemctlTimer
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, fmt.Errorf("unmarshal array: %w", err)
		}
		return arr, nil
	}
	var out []systemctlTimer
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var t systemctlTimer
		if err := json.Unmarshal([]byte(line), &t); err != nil {
			continue
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, errors.New("no parseable timers")
	}
	return out, nil
}

// timerToJob converts one timer to our Job shape. The companion service
// (`Activates`) is the actionable command identity; if it's empty we use
// the timer unit itself as a fallback.
func timerToJob(t systemctlTimer) Job {
	command := t.Activates
	if command == "" {
		command = t.Unit
	}
	last := t.Last
	if last == "-" || last == "n/a" {
		last = ""
	}
	next := t.Next
	if next == "-" || next == "n/a" {
		next = ""
	}
	return Job{
		Source:       SourceSystemdTimer,
		Name:         t.Unit,
		SourcePath:   "/etc/systemd/system/" + t.Unit, // best-effort canonical path
		ScheduleKind: ScheduleOnCalendar,
		Command:      command,
		Enabled:      true, // list-timers --all includes disabled? we treat all returned as enabled
		LastRunAt:    last,
		NextRunAt:    next,
		CmdHash:      HashCommand(command),
	}
}
