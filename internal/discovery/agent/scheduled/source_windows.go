//go:build windows

package scheduled

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
)

// windowsTaskCollector shells out to PowerShell with
// WindowsPowerShellScript, captures the JSON array, and parses it via
// ParseWindowsPowerShellOutput.
//
// We use a PowerShell shim instead of the Task Scheduler COM API
// (ITaskService) for the same reasons as the services/windows.go fill:
// the parser is testable on Linux, no new Go deps, identical
// runner-seam pattern to the rest of the windows* track.
type windowsTaskCollector struct {
	run func(ctx context.Context, args ...string) ([]byte, error)
}

// NewWindowsTaskSchedulerCollector returns the Windows Task Scheduler
// collector. Replaces the earlier no-op stub.
func NewWindowsTaskSchedulerCollector() Collector {
	return &windowsTaskCollector{run: defaultWindowsRun}
}

func (c *windowsTaskCollector) Name() string { return "windows-task-scheduler" }

func (c *windowsTaskCollector) Collect(ctx context.Context) ([]Job, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	out, err := c.run(
		ctx,
		"-NoProfile", "-NonInteractive", "-NoLogo",
		"-ExecutionPolicy", "Bypass",
		"-OutputFormat", "Text",
		"-Command", WindowsPowerShellScript,
	)
	if err != nil {
		return nil, fmt.Errorf("powershell run: %w", err)
	}
	jobs, err := ParseWindowsPowerShellOutput(out)
	if err != nil {
		return nil, fmt.Errorf("parse powershell output: %w", err)
	}
	SortJobs(jobs)
	return jobs, nil
}

func defaultWindowsRun(ctx context.Context, args ...string) ([]byte, error) {
	//#nosec G204 -- fixed flags + an inline script; no user input.
	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
}
