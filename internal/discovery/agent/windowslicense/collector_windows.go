//go:build windows

package windowslicense

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
// The runner is a struct field (test seam) so a fake can be injected
// without spinning up powershell.exe.
type powershellCollector struct {
	run func(ctx context.Context, args ...string) ([]byte, error)
}

// NewCollector returns the default PowerShell-shim collector.
func NewCollector() Collector {
	return &powershellCollector{
		run: defaultRun,
	}
}

func (c *powershellCollector) Name() string { return "windows-license-powershell" }

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
// returns the combined stdout/stderr output. CombinedOutput is safe
// here BECAUSE the script hashes the OA3x firmware key in-script —
// no raw key material can appear in the error stream we surface.
func defaultRun(ctx context.Context, args ...string) ([]byte, error) {
	//#nosec G204 -- args are fixed flags + an inline script; no user input.
	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
}
