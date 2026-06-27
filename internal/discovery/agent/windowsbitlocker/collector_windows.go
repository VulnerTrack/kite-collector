//go:build windows

package windowsbitlocker

import (
	"context"
	"fmt"
	"os/exec"
)

type powershellCollector struct {
	run func(ctx context.Context, args ...string) ([]byte, error)
}

// NewCollector returns the default PowerShell-shim BitLocker collector.
func NewCollector() Collector {
	return &powershellCollector{run: defaultRun}
}

func (c *powershellCollector) Name() string { return "windows-bitlocker-powershell" }

func (c *powershellCollector) Collect(ctx context.Context) ([]Volume, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	out, err := c.run(ctx,
		"-NoProfile", "-NonInteractive", "-NoLogo",
		"-ExecutionPolicy", "Bypass",
		"-OutputFormat", "Text",
		"-Command", PowerShellScript,
	)
	if err != nil {
		return nil, fmt.Errorf("powershell run: %w", err)
	}
	vols, err := ParsePowerShellOutput(out)
	if err != nil {
		return nil, fmt.Errorf("parse powershell output: %w", err)
	}
	return vols, nil
}

func defaultRun(ctx context.Context, args ...string) ([]byte, error) {
	//#nosec G204 -- fixed flags + an inline script; no user input.
	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
	return cmd.CombinedOutput()
}
