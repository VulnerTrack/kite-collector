package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// newWizardCmd registers the `kite-collector wizard` subcommand. The wizard is
// a Windows-only GUI installer (Next → Next → Finish) that wraps the same
// realInstaller used by the dashboard. On non-Windows hosts the command exits
// with a clear message pointing operators at `install`.
func newWizardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "wizard",
		Short: "Launch the graphical installer wizard (Windows only)",
		Long: `Open a native Windows wizard that installs the kite-collector agent as a
service. Smart defaults are pre-filled from the host OS; the operator can
review and override before clicking Install.

The wizard is the default action when kite-collector.exe is launched by
double-clicking from File Explorer, so end users on Windows never have to
touch a terminal.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			if runtime.GOOS != "windows" {
				return fmt.Errorf("the GUI wizard is only available on Windows — use `kite-collector install` on %s", runtime.GOOS)
			}
			return runWizard()
		},
	}
}
