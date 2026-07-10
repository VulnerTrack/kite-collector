//go:build windows

package windowsinfo

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
)

// powershellCollector shells out to PowerShell with PowerShellScript,
// captures the single JSON-object payload, and parses it via
// ParsePowerShellOutput.
//
// The runner is a struct field (test seam) so collector_windows_test.go
// can inject a fake without spinning up powershell.exe.
type powershellCollector struct {
	run func(ctx context.Context, args ...string) ([]byte, error)
}

// NewCollector returns the default PowerShell-shim collector.
func NewCollector() Collector {
	return &powershellCollector{
		run: defaultRun,
	}
}

func (c *powershellCollector) Name() string { return "windows-info-powershell" }

func (c *powershellCollector) Collect(ctx context.Context) (Info, error) {
	if err := ctx.Err(); err != nil {
		return Info{}, fmt.Errorf("context cancelled: %w", err)
	}
	out, err := c.run(
		ctx,
		"-NoProfile", "-NonInteractive", "-NoLogo",
		"-ExecutionPolicy", "Bypass",
		"-OutputFormat", "Text",
		"-Command", PowerShellScript,
	)
	if err != nil {
		return Info{}, fmt.Errorf("powershell run: %w", err)
	}
	info, err := ParsePowerShellOutput(out)
	if err != nil {
		return Info{}, fmt.Errorf("parse powershell output: %w", err)
	}
	return info, nil
}

// defaultRun executes powershell.exe with the supplied args and
// returns the combined stdout/stderr output. We use CombinedOutput so
// PowerShell error streams surface in the parser's error message.
func defaultRun(ctx context.Context, args ...string) ([]byte, error) {
	//#nosec G204 -- args are fixed flags + an inline script; no user input.
	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
}
