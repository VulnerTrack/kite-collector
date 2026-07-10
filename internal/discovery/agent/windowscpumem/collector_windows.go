//go:build windows

package windowscpumem

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
)

type powershellCollector struct {
	run func(ctx context.Context, args ...string) ([]byte, error)
}

// NewCollector returns the default PowerShell-shim CPU/memory collector.
func NewCollector() Collector {
	return &powershellCollector{run: defaultRun}
}

func (c *powershellCollector) Name() string { return "windows-cpumem-powershell" }

func (c *powershellCollector) Collect(ctx context.Context) (Inventory, error) {
	if err := ctx.Err(); err != nil {
		return Inventory{}, fmt.Errorf("context cancelled: %w", err)
	}
	out, err := c.run(
		ctx,
		"-NoProfile", "-NonInteractive", "-NoLogo",
		"-ExecutionPolicy", "Bypass",
		"-OutputFormat", "Text",
		"-Command", PowerShellScript,
	)
	if err != nil {
		return Inventory{}, fmt.Errorf("powershell run: %w", err)
	}
	inv, err := ParsePowerShellOutput(out)
	if err != nil {
		return Inventory{}, fmt.Errorf("parse powershell output: %w", err)
	}
	SortInventory(&inv)
	return inv, nil
}

func defaultRun(ctx context.Context, args ...string) ([]byte, error) {
	//#nosec G204 -- fixed flags + an inline script; no user input.
	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
}
