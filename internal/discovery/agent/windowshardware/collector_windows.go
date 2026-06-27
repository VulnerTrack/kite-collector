//go:build windows

package windowshardware

import (
	"context"
	"fmt"
	"os/exec"
)

type powershellCollector struct {
	run func(ctx context.Context, args ...string) ([]byte, error)
}

// NewCollector returns the default PowerShell-shim collector for
// hardware inventory.
func NewCollector() Collector {
	return &powershellCollector{run: defaultRun}
}

func (c *powershellCollector) Name() string { return "windows-hardware-powershell" }

func (c *powershellCollector) Collect(ctx context.Context) (Hardware, error) {
	if err := ctx.Err(); err != nil {
		return Hardware{}, fmt.Errorf("context cancelled: %w", err)
	}
	out, err := c.run(ctx,
		"-NoProfile", "-NonInteractive", "-NoLogo",
		"-ExecutionPolicy", "Bypass",
		"-OutputFormat", "Text",
		"-Command", PowerShellScript,
	)
	if err != nil {
		return Hardware{}, fmt.Errorf("powershell run: %w", err)
	}
	h, err := ParsePowerShellOutput(out)
	if err != nil {
		return Hardware{}, fmt.Errorf("parse powershell output: %w", err)
	}
	return h, nil
}

func defaultRun(ctx context.Context, args ...string) ([]byte, error) {
	//#nosec G204 -- fixed flags + an inline script; no user input.
	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
	return cmd.CombinedOutput()
}
