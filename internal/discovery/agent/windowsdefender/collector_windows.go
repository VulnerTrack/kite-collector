//go:build windows

package windowsdefender

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
)

type powershellCollector struct {
	run func(ctx context.Context, args ...string) ([]byte, error)
}

// NewCollector returns the default PowerShell-shim Defender collector.
func NewCollector() Collector {
	return &powershellCollector{run: defaultRun}
}

func (c *powershellCollector) Name() string { return "windows-defender-powershell" }

func (c *powershellCollector) Collect(ctx context.Context) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{}, fmt.Errorf("context cancelled: %w", err)
	}
	out, err := c.run(
		ctx,
		"-NoProfile", "-NonInteractive", "-NoLogo",
		"-ExecutionPolicy", "Bypass",
		"-OutputFormat", "Text",
		"-Command", PowerShellScript,
	)
	if err != nil {
		return State{}, fmt.Errorf("powershell run: %w", err)
	}
	s, err := ParsePowerShellOutput(out)
	if err != nil {
		return State{}, fmt.Errorf("parse powershell output: %w", err)
	}
	return s, nil
}

func defaultRun(ctx context.Context, args ...string) ([]byte, error) {
	//#nosec G204 -- fixed flags + an inline script; no user input.
	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
}
