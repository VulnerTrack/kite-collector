//go:build darwin

package macosposture

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type cliCollector struct {
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// NewCollector returns the default Darwin shell-shim collector.
func NewCollector() Collector {
	return &cliCollector{run: defaultRun}
}

func (c *cliCollector) Name() string { return "macos-posture-cli" }

func (c *cliCollector) Collect(ctx context.Context) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{}, fmt.Errorf("context cancelled: %w", err)
	}
	out := State{Source: SourceDarwinCLI}

	// csrutil status — System Integrity Protection.
	if body, err := c.run(ctx, "csrutil", "status"); err == nil {
		out.CSRUtilRawOutput = strings.TrimSpace(string(body))
		out.SIPStatusRaw = ParseCSRUtilStatus(out.CSRUtilRawOutput)
	} else {
		out.SIPStatusRaw = StatusUnknown
	}

	// spctl --status — Gatekeeper.
	if body, err := c.run(ctx, "spctl", "--status"); err == nil {
		out.SPCTLRawOutput = strings.TrimSpace(string(body))
		out.GatekeeperStatusRaw = ParseSPCTLStatus(out.SPCTLRawOutput)
	} else {
		out.GatekeeperStatusRaw = StatusUnknown
	}

	// fdesetup status — FileVault. Requires root for full output but
	// the headline "FileVault is On/Off" string is returned even to
	// non-privileged callers on macOS 11+.
	if body, err := c.run(ctx, "fdesetup", "status"); err == nil {
		out.FDESetupRawOutput = strings.TrimSpace(string(body))
		out.FileVaultStatusRaw = ParseFDESetupStatus(out.FDESetupRawOutput)
	} else {
		out.FileVaultStatusRaw = StatusUnknown
	}

	AnnotateSecurity(&out)
	return out, nil
}

func defaultRun(ctx context.Context, name string, args ...string) ([]byte, error) {
	//#nosec G204 -- name is a fixed Apple binary; args are static.
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}
