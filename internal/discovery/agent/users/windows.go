//go:build windows

package users

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
)

// windowsCollector enumerates Windows local user accounts via
// PowerShell (`Get-LocalUser` + `Get-LocalGroupMember Administrators`).
// We use a PowerShell shim instead of the NetUserEnum / netapi32 win32
// API for two reasons:
//
//  1. The parser is testable on Linux via ParseWindowsPowerShellOutput
//     (the parser lives in windows_parser.go, no build tag).
//  2. Matches the architecture of every other windows* collector in
//     this project — no new Go deps, identical runner-seam pattern.
type windowsCollector struct {
	run func(ctx context.Context, args ...string) ([]byte, error)
}

// NewUnixCollector returns the Windows SAM user collector. The name is
// kept as `NewUnixCollector` for cross-OS symbol compatibility with the
// chain that already calls it on Linux + macOS.
func NewUnixCollector() Collector {
	return &windowsCollector{run: defaultWindowsRun}
}

func (c *windowsCollector) Name() string { return "windows-sam" }

func (c *windowsCollector) Collect(ctx context.Context) ([]User, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	out, err := c.run(ctx,
		"-NoProfile", "-NonInteractive", "-NoLogo",
		"-ExecutionPolicy", "Bypass",
		"-OutputFormat", "Text",
		"-Command", WindowsPowerShellScript,
	)
	if err != nil {
		return nil, fmt.Errorf("powershell run: %w", err)
	}
	users, err := ParseWindowsPowerShellOutput(out)
	if err != nil {
		return nil, fmt.Errorf("parse powershell output: %w", err)
	}
	SortUsers(users)
	return users, nil
}

func defaultWindowsRun(ctx context.Context, args ...string) ([]byte, error) {
	//#nosec G204 -- fixed flags + an inline script; no user input.
	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
}
