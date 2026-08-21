//go:build !windows

package main

import (
	"errors"
	"fmt"
)

// runSetup rejects installer-style switches off Windows.
//
// /SILENT and friends exist for SCCM/Intune/GPO (RFC-0156 R13), which are
// Windows-only deployment surfaces. The Linux and macOS equivalents already
// exist and are better: `kite-collector install --no-start` for scripted runs,
// or the deb/rpm/snap/Homebrew packages, which the package manager installs
// unattended by definition.
func runSetup(args setupArgs) error {
	if args.Help {
		_, _ = fmt.Print(setupUsage())
		return nil
	}
	return errors.New(
		"unattended setup switches are Windows-only; " +
			"use `kite-collector install` (add --no-start for CI/Ansible), " +
			"or the deb/rpm/snap package for this platform")
}
