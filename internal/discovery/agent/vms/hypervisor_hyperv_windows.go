//go:build windows

package vms

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
)

// hyperVCollector shells out to PowerShell `Get-VM` and parses the
// JSON output via ParseHyperVPowerShellOutput. Matches the architecture
// pattern used by services/windows.go, scheduled/source_windows.go,
// and users/windows.go — PowerShell shim with non-tagged parser.
type hyperVCollector struct {
	run func(ctx context.Context, args ...string) ([]byte, error)
}

// NewHyperVCollector returns the Windows Hyper-V VM collector.
// Replaces the earlier no-op stub.
func NewHyperVCollector() Collector {
	return &hyperVCollector{run: defaultHyperVRun}
}

func (c *hyperVCollector) Name() string { return "hyperv-powershell" }

func (c *hyperVCollector) Collect(ctx context.Context) ([]VM, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	out, err := c.run(ctx,
		"-NoProfile", "-NonInteractive", "-NoLogo",
		"-ExecutionPolicy", "Bypass",
		"-OutputFormat", "Text",
		"-Command", HyperVPowerShellScript,
	)
	if err != nil {
		return nil, fmt.Errorf("powershell run: %w", err)
	}
	vms, err := ParseHyperVPowerShellOutput(out)
	if err != nil {
		return nil, fmt.Errorf("parse powershell output: %w", err)
	}
	SortVMs(vms)
	return vms, nil
}

func defaultHyperVRun(ctx context.Context, args ...string) ([]byte, error) {
	//#nosec G204 -- fixed flags + an inline script; no user input.
	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
}
