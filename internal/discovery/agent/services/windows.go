//go:build windows

package services

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// windowsCollector enumerates Windows SCM services via PowerShell
// (`Get-CimInstance Win32_Service`). We use a PowerShell shim instead
// of `golang.org/x/sys/windows/svc/mgr` for two reasons:
//
//  1. The shim is testable on Linux via ParseWindowsPowerShellOutput
//     (the parser lives in windows_parser.go, no build tag).
//  2. Matches the architecture of every other windows* collector in
//     this project — no new Go deps, identical runner-seam pattern.
//
// The trade-off is ~200ms of powershell.exe startup per scan, which
// is fine for a once-per-cycle inventory tool.
type windowsCollector struct {
	run func(ctx context.Context, args ...string) ([]byte, error)
	now func() time.Time
}

// NewCollector returns the Windows SCM Service collector.
func NewCollector() Collector {
	return &windowsCollector{
		run: defaultWindowsRun,
		now: time.Now,
	}
}

func (c *windowsCollector) Name() string { return "windows-scm" }

func (c *windowsCollector) Collect(ctx context.Context) ([]Service, error) {
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
	svcs, err := ParseWindowsPowerShellOutput(out)
	if err != nil {
		return nil, fmt.Errorf("parse powershell output: %w", err)
	}
	StampWindowsServices(svcs, c.now())
	SortServices(svcs)
	return svcs, nil
}

func defaultWindowsRun(ctx context.Context, args ...string) ([]byte, error) {
	//#nosec G204 -- fixed flags + an inline script; no user input.
	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
	return cmd.CombinedOutput()
}
